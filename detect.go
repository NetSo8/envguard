package main

import (
	"bytes"
	"math"
)

// Détection sans regexp : un seul passage sur les octets bruts du body JSON.
// Les séquences d'échappement JSON (\n, \", \\) sont traitées comme des
// frontières de token, ce qui évite de décoder le JSON (zéro allocation).

type rule struct {
	kind   string
	prefix string
	min    int // longueur minimale après le préfixe
}

// Ordre important : préfixes les plus longs d'abord (sk-ant- avant sk-).
var rules = [...]rule{
	{"anthropic", "sk-ant-", 20},
	{"openai", "sk-proj-", 20},
	{"openrouter", "sk-or-v1-", 32},
	{"xai", "xai-", 30},
	{"perplexity", "pplx-", 30},
	{"replicate", "r8_", 30},
	{"stripe", "sk_live_", 16},
	{"stripe", "rk_live_", 16},
	{"stripe", "sk_test_", 16},
	{"github", "github_pat_", 30},
	{"github", "ghp_", 30},
	{"github", "gho_", 30},
	{"github", "ghs_", 30},
	{"github", "ghu_", 30},
	{"gitlab", "glpat-", 20},
	{"slack", "xoxb-", 20},
	{"slack", "xoxp-", 20},
	{"google", "AIza", 30},
	{"groq", "gsk_", 30},
	{"hf", "hf_", 30},
	{"npm", "npm_", 30},
	{"aws", "AKIA", 16},
	{"openai", "sk-", 32},
}

var marker = []byte("REDACTED_")

type span struct {
	s, e int
	kind string
	pfx  string
}

func isTok(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// isVal : charset d'une valeur d'assignation (plus large qu'un token).
func isVal(c byte) bool { return isTok(c) || c == '.' || c == '/' || c == '+' || c == '=' || c == '~' }

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// hasKeyword : l'identifiant contient-il key/secret/token/passw (insensible à la casse, sans alloc).
func hasKeyword(id []byte) bool {
	for _, kw := range [...]string{"key", "secret", "token", "passw", "credential"} {
		n := len(kw)
		for i := 0; i+n <= len(id); i++ {
			j := 0
			for j < n && lower(id[i+j]) == kw[j] {
				j++
			}
			if j == n {
				return true
			}
		}
	}
	return false
}

// entropy : entropie de Shannon, compteurs sur la pile.
func entropy(b []byte) float64 {
	var cnt [256]uint16
	for _, c := range b {
		cnt[c]++
	}
	h, n := 0.0, float64(len(b))
	for _, c := range cnt {
		if c != 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// looksBenign : hash de commit, UUID, nombres… (faux positifs classiques).
func looksBenign(v []byte) bool {
	hex, digits := true, true
	for _, c := range v {
		isHex := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-'
		hex = hex && isHex
		digits = digits && (c >= '0' && c <= '9' || c == '.')
	}
	return hex || digits
}

// skipEsc : si b[i] est un backslash, renvoie l'index après la séquence d'échappement.
func skipEsc(b []byte, i int) int {
	if i+1 < len(b) && b[i+1] == 'u' {
		return i + 6
	}
	return i + 2
}

// skipSep saute espaces, guillemets (y compris \") et renvoie la position.
func skipSep(b []byte, i int) int {
	for i < len(b) {
		switch c := b[i]; {
		case c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '`':
			i++
		case c == '\\' && i+1 < len(b) && b[i+1] == '"':
			i += 2
		default:
			return i
		}
	}
	return i
}

func valEnd(b []byte, i int) int {
	for i < len(b) && isVal(b[i]) {
		i++
	}
	return i
}

// lineStart : début de ligne logique (vrai \n ou échappement \n dans une string JSON).
func lineStart(b []byte, i int) int {
	for i > 0 {
		if b[i-1] == '\n' || b[i-1] == '"' && i >= 2 && b[i-2] != '\\' {
			return i
		}
		if b[i-1] == 'n' && i >= 2 && b[i-2] == '\\' {
			return i
		}
		i--
	}
	return 0
}

// scan appelle emit pour chaque secret candidat. Aucun tas sur le chemin chaud.
func scan(b []byte, emit func(span)) {
	n := len(b)
	for i := 0; i < n; {
		c := b[i]
		if c == '\\' {
			i = skipEsc(b, i)
			continue
		}
		// Marquage manuel : "# secret:" ou "// secret:"
		if c == '#' || c == '/' && i+1 < n && b[i+1] == '/' {
			if sp, ok := manual(b, i); ok {
				emit(sp)
			}
		}
		if !isTok(c) {
			i++
			continue
		}
		// Début de token.
		j := i
		for j < n && isTok(b[j]) {
			j++
		}
		tok := b[i:j]
		matched := false
		for k := range rules {
			r := &rules[k]
			if len(tok)-len(r.prefix) >= r.min && string(tok[:len(r.prefix)]) == r.prefix {
				if !bytes.Contains(tok, marker) {
					emit(span{i, j, r.kind, r.prefix})
				}
				matched = true
				break
			}
		}
		// Assignation générique : API_KEY = "valeur"
		if !matched && hasKeyword(tok) {
			k := skipSep(b, j)
			if k < n && (b[k] == '=' || b[k] == ':') {
				vs := skipSep(b, k+1)
				ve := valEnd(b, vs)
				v := b[vs:ve]
				if len(v) >= 12 && len(v) <= 256 && !looksBenign(v) && entropy(v) >= 3.5 && !bytes.Contains(v, marker) {
					emit(span{vs, ve, "generic", ""})
					j = ve
				}
			}
		}
		i = j
	}
}

// manual gère « valeur # secret: » et « # secret: valeur ».
func manual(b []byte, i int) (span, bool) {
	k := i + 1
	if b[i] == '/' {
		k++
	}
	for k < len(b) && b[k] == ' ' {
		k++
	}
	const kw = "secret:"
	if k+len(kw) > len(b) || string(b[k:k+len(kw)]) != kw {
		return span{}, false
	}
	// Forme 1 : la valeur suit le marqueur.
	vs := skipSep(b, k+len(kw))
	if ve := valEnd(b, vs); ve-vs >= 4 {
		return span{vs, ve, "manual", ""}, !bytes.Contains(b[vs:ve], marker)
	}
	// Forme 2 : dernière valeur après = ou : sur la même ligne.
	ls := lineStart(b, i)
	for p := i - 1; p >= ls; p-- {
		if b[p] == '=' || b[p] == ':' {
			vs := skipSep(b, p+1)
			ve := valEnd(b, vs)
			if ve-vs >= 4 && ve <= i {
				return span{vs, ve, "manual", ""}, !bytes.Contains(b[vs:ve], marker)
			}
			return span{}, false
		}
	}
	return span{}, false
}
