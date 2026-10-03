package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// pair : un remplacement from -> to. Les slices sont préconstruites une fois
// pour éviter toute conversion string->[]byte sur le chemin chaud.
type pair struct{ from, to []byte }

// secretMeta : ce qu'on sait d'un secret, pour la politique de réhydratation.
type secretMeta struct {
	kind  string   // règle qui l'a détecté (« anthropic », « env:DB_PASSWORD »…)
	hosts []string // destinations légitimes connues (hôte de l'URL d'origine…)
}

// Vault garde la correspondance secret <-> placeholder pour toute la session.
//
// Le placeholder dérive d'un HMAC-SHA256 du secret, avec une clé aléatoire
// propre à la machine (persistée) : même secret => même placeholder (stabilité
// pour le modèle et le prompt caching, y compris d'un redémarrage à l'autre),
// mais le placeholder ne permet pas de vérifier hors ligne un secret deviné
// (un hash sans clé de 32 bits le permettait pour les mots de passe faibles).
type Vault struct {
	mu    sync.RWMutex
	fwd   map[string]string // secret -> placeholder
	rev   map[string]string // placeholder -> secret (détection de collision)
	mask  []pair            // secret -> ph, triés par longueur décroissante
	rehy  []pair            // ph (et variantes base64) -> secret
	meta  []*secretMeta     // parallèle à rehy (même index)
	maskM *matcher          // index immuables, reconstruits à chaque ajout
	rehyM *matcher
	key   []byte

	allowed   map[string]struct{} // secrets autorisés vus en clair (mémoire seulement)
	allowHash map[string]struct{} // HMAC hex des secrets autorisés (fichier)
	allowFile string

	gl *gitleaks // règles gitleaks (nil : désactivées)

	version atomic.Uint64 // incrémenté à chaque changement des secrets (cache)
	paused  atomic.Bool
	onNew   func(kind, secret, ph string)
}

// NewVault crée un vault avec une clé éphémère ; main.go la remplace par la
// clé persistée (SetKey) avant de charger l'allowlist.
func NewVault(allowFile string) *Vault {
	k := make([]byte, 32)
	rand.Read(k)
	v := &Vault{fwd: map[string]string{}, rev: map[string]string{}, key: k,
		allowed: map[string]struct{}{}, allowHash: map[string]struct{}{}}
	v.LoadAllow(allowFile)
	return v
}

// LoadKey lit (ou crée, en 0600) la clé de 32 octets qui dérive les placeholders.
func LoadKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if k, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600)
}

func (v *Vault) SetKey(k []byte) {
	v.mu.Lock()
	v.key = k
	v.mu.Unlock()
}

func (v *Vault) mac(secret string) []byte {
	h := hmac.New(sha256.New, v.key)
	h.Write([]byte(secret))
	return h.Sum(nil)
}

// LoadAllow charge l'allowlist : lignes « hmac:<hex> » (format écrit par
// envguard, sans secret en clair) ou valeurs en clair (ancien format).
func (v *Vault) LoadAllow(path string) {
	v.allowFile = path
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	v.mu.Lock()
	defer v.mu.Unlock()
	for sc.Scan() {
		l := string(bytes.TrimSpace(sc.Bytes()))
		switch {
		case l == "" || l[0] == '#':
		case strings.HasPrefix(l, "hmac:"):
			v.allowHash[l[5:]] = struct{}{}
		default:
			v.allowHash[hex.EncodeToString(v.mac(l))] = struct{}{}
		}
	}
}

func (v *Vault) isAllowed(secret string) bool {
	if _, ok := v.allowed[secret]; ok {
		return true
	}
	if len(v.allowHash) == 0 {
		return false
	}
	if _, ok := v.allowHash[hex.EncodeToString(v.mac(secret))]; ok {
		v.allowed[secret] = struct{}{} // les requêtes suivantes l'ignorent sans HMAC
		return true
	}
	return false
}

// Placeholder : préfixe d'origine + REDACTED_ + 8 hex (HMAC), plus long en cas
// de collision avec un autre secret (probabilité ~n²/2³³).
func (v *Vault) Placeholder(pfx, secret string) string {
	if pfx == "" {
		pfx = "SECRET_"
	}
	h := hex.EncodeToString(v.mac(secret))
	for n := 8; ; n += 4 {
		ph := pfx + "REDACTED_" + h[:n]
		if s, ok := v.rev[ph]; !ok || s == secret || n >= len(h) {
			return ph
		}
	}
}

func (v *Vault) register(kind, pfx, secret string, hosts []string) {
	if v.isAllowed(secret) {
		return
	}
	if _, ok := v.fwd[secret]; ok {
		return
	}
	ph := v.Placeholder(pfx, secret)
	v.fwd[secret], v.rev[ph] = ph, secret
	// Nouvelles slices à chaque ajout : un matcher déjà distribué à une
	// requête en cours ne voit jamais son tableau modifié (pas de course).
	mask := make([]pair, len(v.mask), len(v.mask)+1)
	copy(mask, v.mask)
	mask = append(mask, pair{[]byte(secret), []byte(ph)})
	sort.SliceStable(mask, func(i, j int) bool { return len(mask[i].from) > len(mask[j].from) })
	enc := base64.StdEncoding
	rehy := make([]pair, len(v.rehy), len(v.rehy)+2)
	copy(rehy, v.rehy)
	rehy = append(rehy, pair{[]byte(ph), []byte(secret)},
		// Variante base64 : si le modèle encode le placeholder seul.
		pair{[]byte(enc.EncodeToString([]byte(ph))), []byte(enc.EncodeToString([]byte(secret)))})
	m := &secretMeta{kind: kind, hosts: hosts}
	meta := make([]*secretMeta, len(v.meta), len(v.meta)+2)
	copy(meta, v.meta)
	meta = append(meta, m, m)
	v.mask, v.rehy, v.meta = mask, rehy, meta
	v.maskM, v.rehyM = newMatcher(mask), newMatcher(rehy)
	v.version.Add(1)
	if v.onNew != nil {
		v.onNew(kind, secret, ph)
	}
}

// AddKnown enregistre une valeur exacte (fichier .env, règle externe…), qui
// sera masquée partout où elle apparaît, même sans motif reconnaissable.
// Renvoie false si elle était déjà connue ou autorisée.
func (v *Vault) AddKnown(kind, pfx, secret string, hosts []string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.fwd[secret]; ok || v.isAllowed(secret) {
		return false
	}
	v.register(kind, pfx, secret, hosts)
	return true
}

type glFound struct{ id, secret string }

// Mask détecte les nouveaux secrets puis remplace tous les secrets connus.
// Renvoie b tel quel (zéro copie) si rien n'est à masquer.
func (v *Vault) Mask(b []byte) ([]byte, int) { return v.MaskTo(nil, b) }

// MaskTo est Mask avec un buffer de sortie réutilisable (voir matcher.replace).
func (v *Vault) MaskTo(dst, b []byte) ([]byte, int) {
	if v.paused.Load() {
		return b, 0
	}
	// On ne collecte que les secrets inconnus (m[string(bytes)] n'alloue pas) :
	// le tableau sur la pile suffit, les secrets déjà vus ne coûtent rien.
	var arr [32]span
	spans := arr[:0]
	v.mu.RLock()
	onSpan := func(s span) {
		sec := b[s.s:s.e]
		if _, known := v.fwd[string(sec)]; known {
			return
		}
		if _, ok := v.allowed[string(sec)]; ok {
			return
		}
		spans = append(spans, s)
	}
	var glNew []glFound
	if v.gl == nil {
		scan(b, onSpan)
	} else {
		// Un seul parcours : le scan natif signale aussi les débuts de mot
		// aux règles gitleaks.
		known := func(s []byte) bool { _, ok := v.fwd[string(s)]; return ok }
		glEmit := func(id string, sec []byte) {
			if _, ok := v.fwd[string(sec)]; ok {
				return
			}
			if _, ok := v.allowed[string(sec)]; ok {
				return
			}
			glNew = append(glNew, glFound{id, string(sec)})
		}
		sc := v.gl.begin()
		scanHook(b, onSpan, func(i int) { v.gl.try(sc, b, i, known, glEmit) })
		v.gl.end(sc, b, glEmit)
	}
	m := v.maskM
	v.mu.RUnlock()
	if len(spans) > 0 || len(glNew) > 0 { // rare : nouveaux secrets
		v.mu.Lock()
		for _, s := range spans {
			if _, known := v.fwd[string(b[s.s:s.e])]; !known {
				var hosts []string
				if s.he > s.hs {
					hosts = []string{strings.ToLower(string(b[s.hs:s.he]))}
				}
				v.register(s.kind, s.pfx, string(b[s.s:s.e]), hosts)
			}
		}
		for _, f := range glNew {
			if _, known := v.fwd[f.secret]; !known {
				v.register("gitleaks:"+f.id, "", f.secret, nil)
			}
		}
		m = v.maskM
		v.mu.Unlock()
	}
	return m.replace(dst, b)
}

// Rehydrate remplace les placeholders par les vrais secrets.
func (v *Vault) Rehydrate(b []byte) ([]byte, int) { return v.RehydrateTo(nil, b) }

// RehydrateTo est Rehydrate avec un buffer de sortie réutilisable.
func (v *Vault) RehydrateTo(dst, b []byte) ([]byte, int) {
	v.mu.RLock()
	m := v.rehyM
	v.mu.RUnlock()
	return m.replace(dst, b)
}

// RehydrateToolTo réhydrate b, un morceau d'arguments d'appel d'outil, selon
// la politique. args est l'appel complet (sert à trouver les hôtes cités).
// onBlock est appelé pour chaque placeholder laissé intact (ou seulement
// signalé en mode warn). Les variantes base64 ne sont jamais réhydratées.
func (v *Vault) RehydrateToolTo(dst, b, args []byte, pol *Policy, onBlock func(kind, host, ph string)) ([]byte, int) {
	if !pol.active() {
		return v.RehydrateTo(dst, b)
	}
	v.mu.RLock()
	m, meta := v.rehyM, v.meta
	v.mu.RUnlock()
	var hosts []string
	var fileChecked, isFile bool
	var fileTarget string
	return m.replaceIf(dst, b, func(k int) bool {
		if k%2 == 1 {
			return false // variante base64
		}
		if !fileChecked {
			isFile, fileTarget = detectFilePersistence(args)
			fileChecked = true
		}
		if isFile {
			ok, bad := pol.decideFile(meta[k], fileTarget)
			if !ok && onBlock != nil {
				onBlock(meta[k].kind, bad, string(m.pairs[k].from))
			}
			return ok || pol.mode == polWarn
		}
		if hosts == nil {
			hosts = extractHosts(args)
		}
		ok, bad := pol.decide(meta[k], hosts)
		if !ok && onBlock != nil {
			onBlock(meta[k].kind, bad, string(m.pairs[k].from))
		}
		return ok || pol.mode == polWarn
	})
}

// RehydrateDocTo réhydrate un document JSON (réponse complète ou event SSE
// à partir de start) : librement dans le texte, selon la politique dans les
// arguments d'appels d'outils.
func (v *Vault) RehydrateDocTo(dst, b []byte, start int, pol *Policy, onBlock func(kind, host, ph string)) ([]byte, int) {
	if !pol.active() {
		return v.RehydrateTo(dst, b)
	}
	spans := toolSpans(b, start, nil)
	if len(spans) == 0 {
		return v.RehydrateTo(dst, b)
	}
	out, total, last := dst[:0], 0, 0
	var tmp []byte
	for i := 0; i < len(spans); i += 2 {
		s, e := spans[i], spans[i+1]
		r, n := v.RehydrateTo(tmp, b[last:s])
		out = append(out, r...)
		r, n2 := v.RehydrateToolTo(tmp, b[s:e], b[s:e], pol, onBlock)
		out = append(out, r...)
		total, last = total+n+n2, e
	}
	r, n := v.RehydrateTo(tmp, b[last:])
	out = append(out, r...)
	if total+n == 0 {
		return b, 0
	}
	return out, total + n
}

// Holdback : nombre d'octets de fin de s qui pourraient être le début d'un
// placeholder coupé entre deux chunks. On les retient jusqu'au chunk suivant.
func (v *Vault) Holdback(s []byte) int {
	v.mu.RLock()
	rehy := v.rehy
	v.mu.RUnlock()
	best := 0
	for i := 0; i < len(rehy); i += 2 { // placeholders seulement (pas base64)
		ph := rehy[i].from
		max := len(ph) - 1
		if max > len(s) {
			max = len(s)
		}
		for k := max; k > best; k-- {
			if bytes.Equal(s[len(s)-k:], ph[:k]) {
				best = k
				break
			}
		}
	}
	return best
}

// Allow arrête de masquer un secret. Le fichier ne reçoit que son HMAC.
func (v *Vault) Allow(secret string) {
	v.mu.Lock()
	v.allowed[secret] = struct{}{}
	h := hex.EncodeToString(v.mac(secret))
	v.allowHash[h] = struct{}{}
	delete(v.fwd, secret)
	mask := make([]pair, 0, len(v.mask))
	for _, p := range v.mask {
		if string(p.from) != secret {
			mask = append(mask, p)
		}
	}
	v.mask, v.maskM = mask, newMatcher(mask)
	v.version.Add(1)
	v.mu.Unlock()
	if v.allowFile != "" {
		if f, err := os.OpenFile(v.allowFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			f.WriteString("hmac:" + h + "\n")
			f.Close()
		}
	}
}

func (v *Vault) HasSecrets() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.mask) > 0
}

// SetPaused change l'état de pause (et invalide le cache de masquage).
func (v *Vault) SetPaused(p bool) {
	v.paused.Store(p)
	v.version.Add(1)
}
