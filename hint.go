package main

import (
	"encoding/json"
	"strings"
)

// Injection de la consigne par insertion d'octets, sans décoder le JSON :
// on localise le champ voulu au premier niveau avec un mini-scanner, puis on
// insère le texte à la bonne place. Une seule allocation (le body de sortie).

var (
	hintStr, _ = json.Marshal(hint)          // "…" (avec guillemets)
	hintInner  = hintStr[1 : len(hintStr)-1] // contenu échappé
	hintBlock  = []byte(`{"type":"text","text":` + string(hintStr) + `}`)
	hintChat   = []byte(`{"role":"system","content":` + string(hintStr) + `}`)
	hintPart   = []byte(`{"text":` + string(hintStr) + `}`)
	hintGemini = []byte(`{"parts":[` + string(hintPart) + `]}`)
)

// injectHint ajoute une consigne constante. Constante => le préfixe reste
// identique d'un tour à l'autre, le prompt caching tient.
func injectHint(body []byte, path string) []byte {
	switch {
	case strings.HasSuffix(path, "/messages"):
		return textField(body, "system")
	case strings.HasSuffix(path, "/responses"):
		return textField(body, "instructions")
	case strings.Contains(path, ":generateContent") || strings.Contains(path, ":streamGenerateContent"):
		return gemini(body)
	case strings.HasSuffix(path, "/chat/completions"):
		_, vs, ve, ok := field(body, 0, "messages")
		if !ok || body[vs] != '[' {
			return body
		}
		return arrayPrepend(body, vs, ve, hintChat)
	}
	return body
}

// textField : champ absent, null, string ou tableau de blocs texte.
func textField(b []byte, key string) []byte {
	_, vs, ve, ok := field(b, 0, key)
	if !ok {
		return objInsert(b, 0, key, hintStr)
	}
	switch b[vs] {
	case '"': // "…" → "…\n\n<hint>"
		return splice(b, ve-1, ve-1, []byte(`\n\n`), hintInner)
	case '[':
		return arrayAppend(b, vs, ve, hintBlock)
	case 'n': // null
		return splice(b, vs, ve, hintStr)
	}
	return b
}

func gemini(b []byte) []byte {
	key := "systemInstruction"
	_, vs, ve, ok := field(b, 0, key)
	if !ok {
		key = "system_instruction"
		_, vs, ve, ok = field(b, 0, key)
	}
	if !ok {
		return objInsert(b, 0, "systemInstruction", hintGemini)
	}
	if b[vs] != '{' {
		return b
	}
	_, ps, pe, ok := field(b, vs, "parts")
	if !ok {
		return objInsert(b, vs, "parts", []byte(`[`+string(hintPart)+`]`))
	}
	if b[ps] != '[' {
		return b
	}
	_ = ve
	return arrayAppend(b, ps, pe, hintPart)
}

// --- édition ---------------------------------------------------------------

func splice(b []byte, from, to int, ins ...[]byte) []byte {
	n := len(b) - (to - from)
	for _, x := range ins {
		n += len(x)
	}
	out := make([]byte, 0, n)
	out = append(out, b[:from]...)
	for _, x := range ins {
		out = append(out, x...)
	}
	return append(out, b[to:]...)
}

// objInsert ajoute "key":val en tête de l'objet commençant à obj.
func objInsert(b []byte, obj int, key string, val []byte) []byte {
	o := skipWS(b, obj)
	if o >= len(b) || b[o] != '{' {
		return b
	}
	sep := []byte(",")
	if j := skipWS(b, o+1); j < len(b) && b[j] == '}' {
		sep = nil
	}
	return splice(b, o+1, o+1, []byte(`"`+key+`":`), val, sep)
}

func arrayPrepend(b []byte, vs, ve int, el []byte) []byte {
	sep := []byte(",")
	if skipWS(b, vs+1) == ve-1 { // tableau vide
		sep = nil
	}
	return splice(b, vs+1, vs+1, el, sep)
}

func arrayAppend(b []byte, vs, ve int, el []byte) []byte {
	sep := []byte(",")
	if skipWS(b, vs+1) == ve-1 {
		sep = nil
	}
	return splice(b, ve-1, ve-1, sep, el)
}

// --- mini-scanner JSON -------------------------------------------------------

func skipWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	return i
}

// skipString : b[i] == '"', renvoie l'index après le guillemet fermant.
func skipString(b []byte, i int) int {
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(b)
}

// skipValue renvoie l'index de fin de la valeur qui commence en i.
func skipValue(b []byte, i int) int {
	if i >= len(b) {
		return i
	}
	switch b[i] {
	case '"':
		return skipString(b, i)
	case '{', '[':
		depth := 0
		for ; i < len(b); i++ {
			switch b[i] {
			case '"':
				i = skipString(b, i) - 1
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return i + 1
				}
			}
		}
		return len(b)
	}
	for i < len(b) && b[i] != ',' && b[i] != '}' && b[i] != ']' && b[i] != ' ' && b[i] != '\n' && b[i] != '\r' && b[i] != '\t' {
		i++
	}
	return i
}

// field cherche key parmi les champs directs de l'objet commençant en obj.
// Renvoie le début de la clé et les bornes [vs, ve) de la valeur.
func field(b []byte, obj int, key string) (ks, vs, ve int, ok bool) {
	i := skipWS(b, obj)
	if i >= len(b) || b[i] != '{' {
		return
	}
	i++
	for {
		i = skipWS(b, i)
		if i >= len(b) || b[i] != '"' {
			return
		}
		ks = i
		ke := skipString(b, i)
		i = skipWS(b, ke)
		if i >= len(b) || b[i] != ':' {
			return
		}
		vs = skipWS(b, i+1)
		ve = skipValue(b, vs)
		if ke-ks-2 == len(key) && string(b[ks+1:ke-1]) == key {
			return ks, vs, ve, vs < len(b)
		}
		i = skipWS(b, ve)
		if i >= len(b) || b[i] != ',' {
			return
		}
		i++
	}
}
