package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"os"
	"sort"
	"sync"
	"sync/atomic"
)

// pair : un remplacement from -> to. Les slices sont préconstruites une fois
// pour éviter toute conversion string->[]byte sur le chemin chaud.
type pair struct{ from, to []byte }

// Vault garde la correspondance secret <-> placeholder pour toute la session.
// Le placeholder est dérivé d'un hash du secret : même secret => même
// placeholder (stabilité pour le modèle et pour le prompt caching).
type Vault struct {
	mu    sync.RWMutex
	fwd   map[string]string // secret -> placeholder
	mask  []pair            // secret -> ph, triés par longueur décroissante
	rehy  []pair            // ph (et variantes base64) -> secret
	maskM *matcher          // index immuable reconstruit à chaque ajout
	rehyM *matcher
	allow map[string]struct{}
	maxPh int

	allowFile string
	paused    atomic.Bool
	onNew     func(kind, secret, ph string)
}

func NewVault(allowFile string) *Vault {
	v := &Vault{fwd: map[string]string{}, allow: map[string]struct{}{}, allowFile: allowFile}
	if f, err := os.Open(allowFile); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 && l[0] != '#' {
				v.allow[string(l)] = struct{}{}
			}
		}
		f.Close()
	}
	return v
}

// placeholder : préfixe d'origine + REDACTED_ + 8 hex (fnv-1a), construit sur la pile.
func placeholder(pfx, secret string) string {
	h := uint64(14695981039346656037)
	for i := 0; i < len(secret); i++ {
		h ^= uint64(secret[i])
		h *= 1099511628211
	}
	if pfx == "" {
		pfx = "SECRET_"
	}
	var buf [48]byte
	n := copy(buf[:], pfx)
	n += copy(buf[n:], "REDACTED_")
	const hx = "0123456789abcdef"
	for s := 28; s >= 0; s -= 4 {
		buf[n] = hx[(h>>uint(s))&0xf]
		n++
	}
	return string(buf[:n])
}

func (v *Vault) register(kind, pfx, secret string) {
	if _, ok := v.allow[secret]; ok {
		return
	}
	if _, ok := v.fwd[secret]; ok {
		return
	}
	ph := placeholder(pfx, secret)
	v.fwd[secret] = ph
	v.mask = append(v.mask, pair{[]byte(secret), []byte(ph)})
	sort.Slice(v.mask, func(i, j int) bool { return len(v.mask[i].from) > len(v.mask[j].from) })
	v.rehy = append(v.rehy, pair{[]byte(ph), []byte(secret)})
	// Variante base64 : si le modèle encode le placeholder seul.
	enc := base64.StdEncoding
	v.rehy = append(v.rehy, pair{[]byte(enc.EncodeToString([]byte(ph))), []byte(enc.EncodeToString([]byte(secret)))})
	v.maskM, v.rehyM = newMatcher(v.mask), newMatcher(v.rehy)
	if len(ph) > v.maxPh {
		v.maxPh = len(ph)
	}
	if v.onNew != nil {
		v.onNew(kind, secret, ph)
	}
}

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
	scan(b, func(s span) {
		if _, known := v.fwd[string(b[s.s:s.e])]; !known {
			spans = append(spans, s)
		}
	})
	m := v.maskM
	v.mu.RUnlock()
	if len(spans) > 0 { // rare : nouveaux secrets
		v.mu.Lock()
		for _, s := range spans {
			if _, known := v.fwd[string(b[s.s:s.e])]; !known {
				v.register(s.kind, s.pfx, string(b[s.s:s.e]))
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

// Holdback : nombre d'octets de fin de s qui pourraient être le début d'un
// placeholder coupé entre deux chunks. On les retient jusqu'au chunk suivant.
func (v *Vault) Holdback(s []byte) int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	best := 0
	for i := 0; i < len(v.rehy); i += 2 { // placeholders seulement (pas base64)
		ph := v.rehy[i].from
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

func (v *Vault) Allow(secret string) {
	v.mu.Lock()
	v.allow[secret] = struct{}{}
	delete(v.fwd, secret)
	for i, p := range v.mask {
		if string(p.from) == secret {
			v.mask = append(v.mask[:i:i], v.mask[i+1:]...) // copie : Mask en cours garde l'ancienne slice
			v.maskM = newMatcher(v.mask)
			break
		}
	}
	v.mu.Unlock()
	if v.allowFile != "" {
		if f, err := os.OpenFile(v.allowFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			f.WriteString(secret + "\n")
			f.Close()
		}
	}
}

func (v *Vault) HasSecrets() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.mask) > 0
}
