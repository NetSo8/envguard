package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// Règles gitleaks (https://github.com/gitleaks/gitleaks, licence MIT, copie
// dans third_party/gitleaks) : ~200 types de secrets maintenus par la
// communauté, en plus des règles natives d'envguard.
//
// Vitesse : exécuter 200 expressions régulières sur tout le corps serait 10
// à 100 fois trop lent. Comme gitleaks, chaque règle a des mots-clés : un seul
// passage (filtre sur deux octets en minuscules, comme replace.go) repère
// leurs occurrences, et l'expression d'une règle ne tourne que sur une fenêtre
// autour de chaque occurrence de l'un de ses mots-clés. Le texte sans aucun
// mot-clé ne coûte qu'un test de bit par octet.
//
// Exactitude : une valeur trouvée est enregistrée comme valeur connue, donc
// masquée PARTOUT ensuite. Un faux positif court serait désastreux : on exige
// 10 caractères ASCII imprimables au moins, sans guillemet ni backslash (leur
// forme dans le JSON envoyé diffère de la valeur), en plus des listes
// d'exclusion de gitleaks.
//
// Règles exclues par défaut : generic-api-key (mots-clés api/key/token…
// omniprésents dans du code ; envguard a son propre détecteur générique) et
// jwt (mot-clé « ey » présent dans chaque « key » ; détecté nativement).

//go:embed third_party/gitleaks/rules.json
var gitleaksJSON []byte

var gitleaksDefaultExclude = []string{"generic-api-key", "jwt", "private-key"}

const (
	glCtxBefore = 128 // règle à contexte : la ligne du mot-clé, bornée
	glCtxAfter  = 384
	glAnchAfter = 320 // règle ancrée : du mot-clé jusqu'à cette distance
	glMinLen    = 10
	glMinEnt    = 2.0 // valeurs factices (UUID nul, « xxxx… ») : jamais masquées partout
)

type glAllow struct {
	res    []*regexp.Regexp
	target string // secret (défaut), match ou line
	stop   []string
	and    bool
}

type glRule struct {
	id      string
	re      *regexp.Regexp
	entropy float64
	group   int
	allow   []glAllow
}

// glHit : une règle déclenchée par un mot-clé. Ancrée : le mot-clé est le
// début du secret (s., ghp_, pul-…), déduit de l'arbre syntaxique de
// l'expression ; sinon c'est un mot de contexte (datadog_api: …).
type glHit struct {
	rule     uint16
	anchored bool
}

type gitleaks struct {
	rules   []glRule
	kw      []string  // mots-clés (minuscules)
	kwRules [][]glHit // mot-clé -> règles
	// Mots-clés de 4 octets et plus : filtre sur un hash des 4 premiers
	// octets (en minuscules), puis table exacte.
	long4  [1 << 16 / 64]uint64
	longKw map[uint32][]uint16
	// Mots-clés de 2 ou 3 octets (s., sk, hf_…) : filtre exact sur 2 octets.
	short2     [1 << 16 / 64]uint64
	shortFirst [256][]uint16
	// Deux premiers octets de tous les mots-clés : filtre avant at().
	first2 [1 << 16 / 64]uint64
	global glAllow
	pool   sync.Pool // *glScratch
}

func h4(w uint32) uint32 { return (w * 0x9E3779B1) >> 16 }

func word4(k string) uint32 {
	return uint32(k[0]) | uint32(k[1])<<8 | uint32(k[2])<<16 | uint32(k[3])<<24
}

type glWin struct{ s, e int }

type glScratch struct {
	pend    []glWin  // fenêtre en attente par règle (e == 0 : aucune)
	touched []uint16 // règles ayant une fenêtre en attente
	dec     []byte
}

var lowerTab = func() (t [256]byte) {
	for i := range t {
		t[i] = lower(byte(i))
	}
	return
}()

func compileAll(src []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, s := range src {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

// loadGitleaks compile les règles embarquées, sauf celles de exclude.
func loadGitleaks(exclude []string) (*gitleaks, error) {
	var raw struct {
		Rules []struct {
			ID          string   `json:"id"`
			Regex       string   `json:"regex"`
			Keywords    []string `json:"keywords"`
			Entropy     float64  `json:"entropy"`
			SecretGroup int      `json:"secretGroup"`
			Allowlists  []struct {
				Regexes     []string `json:"regexes"`
				RegexTarget string   `json:"regexTarget"`
				Stopwords   []string `json:"stopwords"`
				Condition   string   `json:"condition"`
			} `json:"allowlists"`
		} `json:"rules"`
		Allowlist struct {
			Regexes   []string `json:"regexes"`
			Stopwords []string `json:"stopwords"`
		} `json:"allowlist"`
	}
	if err := json.Unmarshal(gitleaksJSON, &raw); err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, e := range exclude {
		skip[e] = true
	}
	g := &gitleaks{longKw: map[uint32][]uint16{}}
	var err error
	if g.global.res, err = compileAll(raw.Allowlist.Regexes); err != nil {
		return nil, err
	}
	g.global.stop = raw.Allowlist.Stopwords
	kwIndex := map[string]int{}
	for _, r := range raw.Rules {
		if skip[r.ID] || len(r.Keywords) == 0 {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("règle gitleaks %s : %v", r.ID, err)
		}
		rule := glRule{id: r.ID, re: re, entropy: r.Entropy, group: r.SecretGroup}
		for _, a := range r.Allowlists {
			res, err := compileAll(a.Regexes)
			if err != nil {
				return nil, fmt.Errorf("règle gitleaks %s : %v", r.ID, err)
			}
			rule.allow = append(rule.allow, glAllow{res: res, target: a.RegexTarget, stop: a.Stopwords, and: strings.EqualFold(a.Condition, "AND")})
		}
		ri := uint16(len(g.rules))
		g.rules = append(g.rules, rule)
		for _, k := range r.Keywords {
			k = strings.ToLower(k)
			if len(k) < 2 {
				continue
			}
			ki, ok := kwIndex[k]
			if !ok {
				ki = len(g.kw)
				kwIndex[k] = ki
				g.kw = append(g.kw, k)
				g.kwRules = append(g.kwRules, nil)
				x2 := uint16(k[0])<<8 | uint16(k[1])
				g.first2[x2>>6] |= 1 << (x2 & 63)
				if len(k) >= 4 {
					w := word4(k)
					g.longKw[w] = append(g.longKw[w], uint16(ki))
					h := h4(w)
					g.long4[h>>6] |= 1 << (h & 63)
				} else {
					g.shortFirst[k[0]] = append(g.shortFirst[k[0]], uint16(ki))
					x := uint16(k[0])<<8 | uint16(k[1])
					g.short2[x>>6] |= 1 << (x & 63)
				}
			}
			anch := anchoredOn(capturePrefixes(r.Regex), k)
			g.kwRules[ki] = append(g.kwRules[ki], glHit{ri, anch})
		}
	}
	g.pool.New = func() any { return &glScratch{pend: make([]glWin, len(g.rules))} }
	return g, nil
}

// find appelle emit(règle, secret) pour chaque secret trouvé dans b (body
// JSON brut). secret pointe dans un buffer temporaire : à copier si gardé.
// known (facultatif) dit si une valeur est déjà un secret enregistré : le
// token qui commence à un mot-clé ancré n'est alors pas revérifié (cas
// courant : la conversation renvoie les mêmes secrets à chaque tour).
func (g *gitleaks) find(b []byte, known func([]byte) bool, emit func(id string, secret []byte)) {
	sc := g.begin()
	scanHook(b, func(span) {}, func(i int) { g.try(sc, b, i, known, emit) })
	g.end(sc, b, emit)
}

// begin / try / end : recherche intégrée au scan natif (un seul parcours).
func (g *gitleaks) begin() *glScratch { return g.pool.Get().(*glScratch) }

// try : pré-filtre sur les deux premiers octets, puis at().
func (g *gitleaks) try(sc *glScratch, b []byte, i int, known func([]byte) bool, emit func(string, []byte)) {
	if i+1 < len(b) {
		x := uint16(lowerTab[b[i]])<<8 | uint16(lowerTab[b[i+1]])
		if g.first2[x>>6]&(1<<(x&63)) != 0 {
			g.at(sc, b, i, known, emit)
		}
	}
}

func (g *gitleaks) end(sc *glScratch, b []byte, emit func(string, []byte)) {
	for _, r := range sc.touched {
		p := &sc.pend[r]
		g.run(sc, r, b[p.s:p.e], emit)
		*p = glWin{}
	}
	sc.touched = sc.touched[:0]
	g.pool.Put(sc)
}

// at teste les mots-clés qui commencent en i et ouvre les fenêtres à analyser.
func (g *gitleaks) at(sc *glScratch, b []byte, i int, known func([]byte) bool, emit func(string, []byte)) {
	n := len(b)
	if i+1 >= n {
		return
	}
	var w uint32 // 4 octets à partir de i, en minuscules (b[i] en poids faible)
	for j := 0; j < 4 && i+j < n; j++ {
		w |= uint32(lowerTab[b[i+j]]) << (8 * j)
	}
	h := h4(w)
	hitLong := i+4 <= n && g.long4[h>>6]&(1<<(h&63)) != 0
	x := uint16(w&0xff)<<8 | uint16(w>>8&0xff)
	hitShort := g.short2[x>>6]&(1<<(x&63)) != 0
	if !hitLong && !hitShort {
		return
	}
	var cands []uint16
	if hitLong {
		cands = g.longKw[w]
	}
	for pass := 0; pass < 2; pass++ {
		if pass == 1 {
			if !hitShort {
				break
			}
			cands = g.shortFirst[w&0xff]
		}
		for _, k := range cands {
			kw := g.kw[k]
			if i+len(kw) > n || !hasFold(b[i:], kw) {
				continue
			}
			ke := i + len(kw)
			// Le caractère suivant peut-il prolonger un secret ? (« s. » en
			// fin de phrase, « sk » dans « task » : non, on passe.)
			cont := ke < n && (cls[b[ke]]&cVal != 0)
			if cont && known != nil {
				te := ke
				for te < n && cls[b[te]]&cVal != 0 {
					te++
				}
				for te > ke && (b[te-1] == '.' || b[te-1] == '=') {
					te-- // ponctuation finale
				}
				if known(b[i:te]) {
					cont = false // secret déjà enregistré : rien à revérifier
				}
			}
			for _, h := range g.kwRules[k] {
				var ws, we int
				if h.anchored {
					if !cont {
						continue
					}
					ws, we = max(0, i-1), min(n, ke+glAnchAfter)
				} else {
					ws, we = lineBounds(b, i, ke)
				}
				r := h.rule
				p := &sc.pend[r]
				switch {
				case p.e == 0:
					*p = glWin{ws, we}
					sc.touched = append(sc.touched, r)
				case ws <= p.e: // fenêtres qui se chevauchent : fusion
					p.e = max(p.e, we)
				default:
					g.run(sc, r, b[p.s:p.e], emit)
					*p = glWin{ws, we}
				}
			}
		}
	}
}

// wordCont : caractère qui continue un mot (le mot-clé ne peut pas commencer après).
var wordCont = func() (t [256]bool) {
	for c := 0; c < 256; c++ {
		t[c] = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	}
	return
}()

func isLowerASCII(c byte) bool { return c >= 'a' && c <= 'z' }
func isUpperASCII(c byte) bool { return c >= 'A' && c <= 'Z' }

func nextLower(b []byte, j int) uint32 {
	if j < len(b) {
		return uint32(lowerTab[b[j]])
	}
	return 0
}

// lineBounds : la ligne du mot-clé (vrai \n ou \n / \r échappés du JSON), bornée.
func lineBounds(b []byte, i, ke int) (int, int) {
	s, e := i, ke
	for lim := max(0, i-glCtxBefore); s > lim && b[s-1] != '\n' && !(s >= 2 && b[s-2] == '\\' && (b[s-1] == 'n' || b[s-1] == 'r')); s-- {
	}
	for lim := min(len(b), ke+glCtxAfter); e < lim && b[e] != '\n' && !(b[e] == '\\' && e+1 < len(b) && (b[e+1] == 'n' || b[e+1] == 'r')); e++ {
	}
	return s, min(len(b), e+2) // garde « \n » : les expressions s'en servent comme fin de secret
}

// capturePrefixes : préfixes littéraux possibles (minuscules) du premier
// groupe capturant (ou de l'expression), une entrée par branche d'une
// alternative ; nil si l'un d'eux est inconnu.
func capturePrefixes(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	skipAssert := func(op syntax.Op) bool {
		return op == syntax.OpWordBoundary || op == syntax.OpBeginLine || op == syntax.OpBeginText
	}
	var pre func(*syntax.Regexp) ([]string, bool) // (préfixes, entièrement littéral ?)
	pre = func(r *syntax.Regexp) ([]string, bool) {
		switch r.Op {
		case syntax.OpLiteral:
			return []string{strings.ToLower(string(r.Rune))}, true
		case syntax.OpCapture:
			return pre(r.Sub[0])
		case syntax.OpAlternate:
			var out []string
			for _, sub := range r.Sub {
				p, _ := pre(sub)
				if len(p) == 0 {
					return nil, false
				}
				out = append(out, p...)
			}
			return out, false
		case syntax.OpConcat:
			acc := []string{""}
			for _, sub := range r.Sub {
				if skipAssert(sub.Op) {
					continue
				}
				p, full := pre(sub)
				if len(p) == 0 {
					return acc, false
				}
				var next []string
				for _, a := range acc {
					for _, x := range p {
						next = append(next, a+x)
					}
				}
				acc = next
				if !full || len(acc) > 16 {
					return acc, false
				}
			}
			return acc, true
		}
		return nil, false
	}
	// Premier groupe capturant en tête de l'expression (après \b, ^…).
	cur := re
	for cur.Op == syntax.OpConcat && len(cur.Sub) > 0 {
		i := 0
		for i < len(cur.Sub) && skipAssert(cur.Sub[i].Op) {
			i++
		}
		if i == len(cur.Sub) || cur.Sub[i].Op != syntax.OpCapture {
			break
		}
		cur = cur.Sub[i]
		break
	}
	p, _ := pre(cur)
	for _, x := range p {
		if x == "" {
			return nil
		}
	}
	return p
}

// anchoredOn : le mot-clé k est-il le début du secret (pour une des branches) ?
func anchoredOn(prefixes []string, k string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(p, k) || strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// run applique une règle sur une fenêtre, décodée du JSON (les expressions
// gitleaks attendent du texte, pas des \" ou \n échappés).
func (g *gitleaks) run(sc *glScratch, ri uint16, win []byte, emit func(string, []byte)) {
	r := &g.rules[ri]
	sc.dec = appendUnescape(sc.dec[:0], win)
	text := sc.dec
	for _, m := range r.re.FindAllSubmatchIndex(text, -1) {
		s, e := m[0], m[1]
		if r.group > 0 && 2*r.group+1 < len(m) {
			s, e = m[2*r.group], m[2*r.group+1]
		} else if r.group == 0 {
			for gi := 1; 2*gi+1 < len(m); gi++ { // premier groupe non vide (comme gitleaks)
				if m[2*gi] >= 0 && m[2*gi+1] > m[2*gi] {
					s, e = m[2*gi], m[2*gi+1]
					break
				}
			}
		}
		if s < 0 || e-s < glMinLen || e-s > 4096 {
			continue
		}
		sec := text[s:e]
		if !plainASCII(sec) || bytes.Contains(sec, marker) || entropy(sec) < max(r.entropy, glMinEnt) || g.global.hit(sec, nil, nil) {
			continue
		}
		allowed := false
		for i := range r.allow {
			if r.allow[i].hit(sec, text[m[0]:m[1]], lineAt(text, m[0], m[1])) {
				allowed = true
				break
			}
		}
		if !allowed {
			emit(r.id, sec)
		}
	}
}

// plainASCII : imprimable, sans guillemet ni backslash (forme identique dans le JSON).
func plainASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func lineAt(t []byte, s, e int) []byte {
	for s > 0 && t[s-1] != '\n' {
		s--
	}
	for e < len(t) && t[e] != '\n' {
		e++
	}
	return t[s:e]
}

// hit : la liste d'exclusion s'applique-t-elle ? (condition OR par défaut)
func (a *glAllow) hit(secret, match, line []byte) bool {
	target := secret
	switch a.target {
	case "match":
		target = match
	case "line":
		target = line
	}
	if target == nil {
		target = secret
	}
	reHit := false
	for _, re := range a.res {
		if re.Match(target) {
			reHit = true
			break
		}
	}
	stopHit := false
	if len(a.stop) > 0 {
		low := strings.ToLower(string(secret))
		for _, s := range a.stop {
			if strings.Contains(low, s) {
				stopHit = true
				break
			}
		}
	}
	if a.and {
		return (len(a.res) == 0 || reHit) && (len(a.stop) == 0 || stopHit)
	}
	return reHit || stopHit
}
