package main

import (
	"bytes"
	"math"
)

// Détection sans regexp : un seul passage sur les octets bruts du body JSON.
// Les séquences d'échappement JSON (\n, \", \\) sont traitées comme des
// frontières de token, ce qui évite de décoder le JSON (zéro allocation).
//
// Chemin chaud : une table de classes de caractères remplace les
// comparaisons ; les règles à préfixe ne sont essayées que pour les tokens
// assez longs et commençant par un octet qui ouvre au moins une règle ; la
// recherche de mot-clé (API_KEY = …) n'a lieu que devant un '=' ou un ':'.

type rule struct {
	kind   string
	prefix string
	min    int               // longueur minimale après le préfixe
	dot    bool              // le secret peut contenir des '.' (JWT, SendGrid…)
	check  func([]byte) bool // validation supplémentaire (facultative)
}

// Ordre important : préfixes les plus longs d'abord (sk-ant- avant sk-).
var rules = [...]rule{
	{kind: "anthropic", prefix: "sk-ant-", min: 20},
	{kind: "openai", prefix: "sk-proj-", min: 20},
	{kind: "openai", prefix: "sk-svcacct-", min: 20},
	{kind: "openrouter", prefix: "sk-or-v1-", min: 32},
	{kind: "xai", prefix: "xai-", min: 30},
	{kind: "perplexity", prefix: "pplx-", min: 30},
	{kind: "replicate", prefix: "r8_", min: 30},
	{kind: "stripe", prefix: "sk_live_", min: 16},
	{kind: "stripe", prefix: "rk_live_", min: 16},
	{kind: "stripe", prefix: "sk_test_", min: 16},
	{kind: "stripe", prefix: "whsec_", min: 24},
	{kind: "github", prefix: "github_pat_", min: 30},
	{kind: "github", prefix: "ghp_", min: 30},
	{kind: "github", prefix: "gho_", min: 30},
	{kind: "github", prefix: "ghs_", min: 30},
	{kind: "github", prefix: "ghu_", min: 30},
	{kind: "github", prefix: "ghr_", min: 30},
	{kind: "gitlab", prefix: "glpat-", min: 20},
	{kind: "gitlab", prefix: "glptt-", min: 20},
	{kind: "slack", prefix: "xoxb-", min: 20},
	{kind: "slack", prefix: "xoxp-", min: 20},
	{kind: "slack", prefix: "xoxa-", min: 20},
	{kind: "slack", prefix: "xoxr-", min: 20},
	{kind: "slack", prefix: "xoxs-", min: 20},
	{kind: "slack", prefix: "xapp-", min: 20},
	{kind: "google", prefix: "AIza", min: 30},
	{kind: "groq", prefix: "gsk_", min: 30},
	{kind: "hf", prefix: "hf_", min: 30},
	{kind: "npm", prefix: "npm_", min: 30},
	{kind: "pypi", prefix: "pypi-", min: 50},
	{kind: "docker", prefix: "dckr_pat_", min: 20},
	{kind: "shopify", prefix: "shpat_", min: 32},
	{kind: "shopify", prefix: "shpss_", min: 32},
	{kind: "shopify", prefix: "shpca_", min: 32},
	{kind: "shopify", prefix: "shppa_", min: 32},
	{kind: "digitalocean", prefix: "dop_v1_", min: 40},
	{kind: "linear", prefix: "lin_api_", min: 30},
	{kind: "notion", prefix: "ntn_", min: 30},
	{kind: "sendgrid", prefix: "SG.", min: 40, dot: true},
	{kind: "vault", prefix: "hvs.", min: 20, dot: true},
	{kind: "doppler", prefix: "dp.pt.", min: 30, dot: true},
	{kind: "jwt", prefix: "eyJ", min: 30, dot: true, check: isJWT},
	{kind: "aws", prefix: "AKIA", min: 16},
	{kind: "aws", prefix: "ASIA", min: 16},
	{kind: "openai", prefix: "sk-", min: 32},
}

var marker = []byte("REDACTED_")

type span struct {
	s, e int
	kind string
	pfx  string
	// hs:he : hôte de destination légitime dans b (mot de passe d'URL), sinon 0:0.
	hs, he int
}

// Classes de caractères (table de 256 octets : une lecture par caractère).
const (
	cTok = 1 << iota // a-z A-Z 0-9 - _
	cVal             // cTok + . / + = ~  (valeur d'assignation)
	cB64             // A-Z a-z 0-9 + / =  (corps de clé PEM)
)

var (
	cls        [256]uint8
	byFirst    [256][]uint8 // règles candidates par premier octet
	minRuleLen = 1 << 30    // plus court token pouvant correspondre à une règle
)

func init() {
	for c := 0; c < 256; c++ {
		b := byte(c)
		alnum := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
		if alnum || b == '-' || b == '_' {
			cls[c] |= cTok | cVal
		}
		if b == '.' || b == '/' || b == '+' || b == '=' || b == '~' {
			cls[c] |= cVal
		}
		if alnum || b == '+' || b == '/' || b == '=' {
			cls[c] |= cB64
		}
	}
	for k := range rules {
		r := &rules[k]
		byFirst[r.prefix[0]] = append(byFirst[r.prefix[0]], uint8(k))
		if l := len(r.prefix) + r.min; l < minRuleLen {
			minRuleLen = l
		}
	}
}

func isTok(c byte) bool { return cls[c]&cTok != 0 }

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// hasFold : b commence-t-il par kw (kw en minuscules), sans tenir compte de la casse.
func hasFold(b []byte, kw string) bool {
	if len(b) < len(kw) {
		return false
	}
	for i := 0; i < len(kw); i++ {
		if lower(b[i]) != kw[i] {
			return false
		}
	}
	return true
}

// hasKeyword : l'identifiant contient-il key/secret/token/passw/credential/auth.
// Une seule passe, sans alloc.
func hasKeyword(id []byte) bool {
	for i := 0; i < len(id); i++ {
		var kw string
		switch lower(id[i]) {
		case 'k':
			kw = "key"
		case 's':
			kw = "secret"
		case 't':
			kw = "token"
		case 'p':
			kw = "passw"
		case 'c':
			kw = "credential"
		case 'a':
			kw = "auth"
		default:
			continue
		}
		if hasFold(id[i:], kw) {
			return true
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

// isJWT : en-tête.charge.signature, trois segments base64url non vides.
func isJWT(t []byte) bool {
	if bytes.Count(t, []byte{'.'}) != 2 {
		return false
	}
	a := bytes.IndexByte(t, '.')
	b := a + 1 + bytes.IndexByte(t[a+1:], '.')
	return a >= 10 && b-a > 10 && len(t)-b > 10
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
	for i < len(b) && cls[b[i]]&cVal != 0 {
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

// matchRule : règle à préfixe correspondant au token b[i:j] (jd : fin en
// acceptant les '.'). Renvoie l'index de règle et la fin du secret.
func matchRule(b []byte, i, j, jd int) (int, int) {
	for _, k := range byFirst[b[i]] {
		r := &rules[k]
		e := j
		if r.dot {
			e = jd
		}
		if e-i-len(r.prefix) >= r.min && string(b[i:i+len(r.prefix)]) == r.prefix &&
			(r.check == nil || r.check(b[i:e])) {
			return int(k), e
		}
	}
	return -1, j
}

// dotEnd : fin du token en acceptant aussi les '.'.
func dotEnd(b []byte, j int) int {
	for j < len(b) && (cls[b[j]]&cTok != 0 || b[j] == '.') {
		j++
	}
	return j
}

var (
	pemBegin = []byte("-----BEGIN ")
	pemEnd   = []byte("-----END ")
	pemDash  = []byte("-----")
	privKey  = []byte("PRIVATE KEY")
)

// pem masque chaque ligne base64 d'une clé privée PEM (lignes séparées par de
// vrais \n ou des \n échappés). Renvoie la position après le bloc.
func pem(b []byte, i int, emit func(span)) int {
	h := i + len(pemBegin)
	he := bytes.Index(b[h:], pemDash)
	if he < 0 || he > 64 || !bytes.Contains(b[h:h+he], privKey) {
		return i + len(pemBegin)
	}
	p := h + he + len(pemDash)
	end := bytes.Index(b[p:], pemEnd)
	if end < 0 || end > 64<<10 {
		return p
	}
	end += p
	for p < end {
		if b[p] == '\\' {
			p = skipEsc(b, p)
			continue
		}
		if cls[b[p]]&cB64 == 0 {
			p++
			continue
		}
		q := p
		for q < end && cls[b[q]]&cB64 != 0 {
			q++
		}
		if q-p >= 4 { // la dernière ligne d'une clé est souvent courte
			emit(span{s: p, e: q, kind: "private_key", pfx: ""})
		}
		p = q
	}
	return end + len(pemEnd)
}

// urlPassword : « scheme://user:motdepasse@hôte » (b[i] est le ':' de « :// »).
func urlPassword(b []byte, i int, emit func(span)) {
	k := i + 3
	colon := -1
	for ; k < len(b) && k-i < 300; k++ {
		switch b[k] {
		case '@':
			if colon > 0 && k-colon-1 >= 3 {
				pw := b[colon+1 : k]
				if bytes.IndexAny(pw, "${}") < 0 && !bytes.Contains(pw, marker) {
					he := k + 1
					for he < len(b) && (cls[b[he]]&cTok != 0 || b[he] == '.') {
						he++
					}
					emit(span{s: colon + 1, e: k, kind: "url_password", hs: k + 1, he: he})
				}
			}
			return
		case ':':
			if colon < 0 {
				colon = k
			}
		case '/', '?', '#', '"', '\\', ' ', '\n', '<', '>', '\'':
			return
		}
	}
}

// scan appelle emit pour chaque secret candidat. Aucun tas sur le chemin chaud.
func scan(b []byte, emit func(span)) { scanHook(b, emit, nil) }

// scanHook : scan, plus word(i) à chaque début de mot (début de token, après
// « - » ou « _ », transition camelCase, et sur chaque « _ ») : sert aux
// mots-clés gitleaks, sans second parcours du texte.
func scanHook(b []byte, emit func(span), word func(int)) {
	n := len(b)
	for i := 0; i < n; {
		c := b[i]
		if cls[c]&cTok == 0 {
			switch c {
			case '\\':
				i = skipEsc(b, i)
				continue
			case '#', '/': // marquage manuel : "# secret:" ou "// secret:"
				if c == '#' || i+1 < n && b[i+1] == '/' {
					if sp, ok := manual(b, i); ok {
						emit(sp)
					}
				}
			case ':':
				if i+2 < n && b[i+1] == '/' && b[i+2] == '/' {
					urlPassword(b, i, emit)
				}
			}
			i++
			continue
		}
		// Début de token.
		j := i + 1
		if word == nil {
			for j < n && cls[b[j]]&cTok != 0 {
				j++
			}
		} else {
			if c != '-' {
				word(i)
			}
			for j < n && cls[b[j]]&cTok != 0 {
				d, p := b[j], b[j-1]
				if d == '_' || (p == '-' || p == '_') && d != '-' || isUpperASCII(d) && isLowerASCII(p) {
					word(j)
				}
				j++
			}
		}
		if c == '-' && bytes.HasPrefix(b[i:], pemBegin) {
			i = pem(b, i, emit)
			continue
		}
		matched := false
		if fr := byFirst[c]; len(fr) > 0 {
			jd := j
			if j < n && b[j] == '.' {
				jd = dotEnd(b, j)
			}
			if jd-i >= minRuleLen {
				if k, e := matchRule(b, i, j, jd); k >= 0 {
					if !bytes.Contains(b[i:e], marker) {
						emit(span{s: i, e: e, kind: rules[k].kind, pfx: rules[k].prefix})
					}
					matched, j = true, e
				}
			}
		}
		if !matched {
			k := skipSep(b, j)
			switch {
			case k < n && (b[k] == '=' || b[k] == ':') && hasKeyword(b[i:j]):
				// Assignation générique : API_KEY = "valeur"
				vs := skipSep(b, k+1)
				ve := valEnd(b, vs)
				v := b[vs:ve]
				if vs < n && len(byFirst[b[vs]]) > 0 {
					te := vs
					for te < n && cls[b[te]]&cTok != 0 {
						te++
					}
					if r, _ := matchRule(b, vs, te, dotEnd(b, te)); r >= 0 {
						j = vs // la règle dédiée (préfixe conservé) s'en charge au tour suivant
						break
					}
				}
				if len(v) >= 12 && len(v) <= 256 && !looksBenign(v) && entropy(v) >= 3.5 && !bytes.Contains(v, marker) {
					emit(span{s: vs, e: ve, kind: "generic", pfx: ""})
					j = ve
				}
			case j-i == 6 && j < n && b[j] == ' ' && hasFold(b[i:j], "bearer"):
				// Authorization: Bearer <jeton> (jeton sans préfixe connu)
				vs := j + 1
				ve := valEnd(b, vs)
				if ve-vs >= 20 && !bytes.Contains(b[vs:ve], marker) && bytes.IndexByte(b[vs:ve], '$') < 0 {
					if k, _ := matchRule(b, vs, ve, ve); k < 0 { // sinon la règle dédiée s'en charge
						emit(span{s: vs, e: ve, kind: "bearer", pfx: ""})
						j = ve
					}
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
		return span{s: vs, e: ve, kind: "manual", pfx: ""}, !bytes.Contains(b[vs:ve], marker)
	}
	// Forme 2 : dernière valeur après = ou : sur la même ligne.
	ls := lineStart(b, i)
	for p := i - 1; p >= ls; p-- {
		if b[p] == '=' || b[p] == ':' {
			vs := skipSep(b, p+1)
			ve := valEnd(b, vs)
			if ve-vs >= 4 && ve <= i {
				return span{s: vs, e: ve, kind: "manual", pfx: ""}, !bytes.Contains(b[vs:ve], marker)
			}
			return span{}, false
		}
	}
	return span{}, false
}
