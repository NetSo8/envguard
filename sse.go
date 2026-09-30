package main

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// Réécriture des flux SSE : Anthropic Messages, OpenAI Chat Completions,
// OpenAI Responses et Gemini natif.
//
// Un placeholder peut être coupé entre deux events (ex: "sk-ant-RED" puis
// "ACTED_7f3a…"). Chaque flux de texte (content block, choice, tool call,
// output item, candidate…) a son « slot » : on y retient la fin qui ressemble
// au début d'un placeholder, on la recolle au fragment suivant, et on vide le
// slot à la fin du bloc. Les arguments de tool calls sont ainsi réhydratés
// avant que le client n'exécute l'outil.
//
// Aucun décodage JSON : le mini-scanner (hint.go) localise les strings de
// texte dans les octets de l'event, seules ces strings sont décodées (dans le
// buffer du slot) puis ré-encodées en place. Tout le reste de l'event est
// recopié tel quel. Les events de vidage sont préconstruits une fois par slot.

const (
	kAnth uint8 = iota + 1
	kChat
	kChatTool
	kResp
	kGem
)

// skey identifie un flux de texte sans allouer de string.
type skey struct {
	kind, f uint8
	a, b    int32
}

type slot struct {
	used bool
	k    skey
	buf  []byte // texte en attente, décodé
	pre  []byte // event synthétique jusqu'à la valeur de la string
	suf  []byte // après la valeur, "\n\n" compris
}

type edit struct {
	vs, ve int
	s      *slot
	final  bool
}

type sseRewriter struct {
	v     *Vault
	w     io.Writer
	fl    http.Flusher
	slots [32]slot // tableau fixe, recherche linéaire : plus rapide qu'une map à cette taille
	edits [32]edit // strings à réécrire dans l'event courant
	ne    int
	out   []byte // buffers réutilisés d'un event à l'autre
	tmp   []byte
	reh   []byte // sortie des réhydratations
	count int    // nb de réhydratations
}

// Lecteurs de 32 Ko réutilisés d'un flux à l'autre.
var readerPool = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 32<<10) }}

// rehydrate réhydrate b dans le buffer réutilisé r.reh (b tel quel si rien à faire).
func (r *sseRewriter) rehydrate(b []byte) []byte {
	out, n := r.v.RehydrateTo(r.reh, b)
	if n > 0 {
		r.reh = out
		r.count += n
	}
	return out
}

var (
	pData      = []byte("data: ")
	pDone      = []byte("[DONE]")
	pAnthDelta = []byte(`"type":"content_block_delta"`)
	pAnthStop  = []byte(`"type":"content_block_stop"`)
	pMsgStop   = []byte(`"type":"message_stop"`)
	pChoices   = []byte(`"choices"`)
	pRespType  = []byte(`"type":"response.`)
	pCands     = []byte(`"candidates"`)
	sDelta     = []byte(".delta")
	sDone      = []byte(".done")
)

// run lit le flux amont event par event. Les events sont écrits sans flush ;
// on ne flush que lorsque tout ce que l'amont a envoyé a été traité
// (br.Buffered() == 0) : un seul envoi réseau par rafale, et aucune latence
// ajoutée puisque rien de ce qui est déjà arrivé n'est retenu.
func (r *sseRewriter) run(src io.Reader) error {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(src)
	defer func() { br.Reset(nil); readerPool.Put(br) }()
	defer r.flushOut()
	var ev []byte // event courant, buffer réutilisé
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			ev = append(ev, line...)
			if line[0] == '\n' || line[0] == '\r' {
				if werr := r.event(ev); werr != nil {
					return werr
				}
				ev = ev[:0]
				if br.Buffered() == 0 {
					r.flushOut()
				}
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if len(bytes.TrimSpace(ev)) > 0 {
				r.event(ev)
			}
			r.flush(0, -1)
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// dataSpan renvoie les bornes de la valeur de la ligne "data: ".
func dataSpan(ev []byte) (int, int) {
	i := bytes.Index(ev, pData)
	if i < 0 {
		return -1, -1
	}
	s := i + len(pData)
	e := s + bytes.IndexByte(ev[s:], '\n')
	if e < s {
		e = len(ev)
	}
	for e > s && ev[e-1] == '\r' {
		e--
	}
	return s, e
}

func (r *sseRewriter) event(ev []byte) error {
	ds, de := dataSpan(ev)
	// Chemin rapide : aucun secret connu => rien à réhydrater, on relaie tel quel.
	if ds < 0 || !r.v.HasSecrets() {
		return r.write(ev)
	}
	data := ev[ds:de]
	r.ne = 0
	handled := false
	switch {
	case bytes.Equal(data, pDone):
		r.flush(0, -1)
		return r.write(ev)
	case bytes.Contains(data, pAnthDelta):
		handled = r.anthDelta(ev, ds)
	case bytes.Contains(data, pAnthStop):
		if _, vs, ve, ok := field(ev, ds, "index"); ok {
			r.flush(kAnth, atoi(ev[vs:ve]))
		}
	case bytes.Contains(data, pMsgStop):
		r.flush(0, -1)
	case bytes.Contains(data, pRespType):
		handled = r.responses(ev, ds)
	case bytes.Contains(data, pCands):
		handled = r.gemini(ev, ds)
	case bytes.Contains(data, pChoices):
		handled = r.chat(ev, ds)
	}
	if handled && r.ne > 0 {
		return r.apply(ev)
	}
	return r.write(r.rehydrate(ev))
}

// apply recopie l'event en réécrivant les strings collectées (ordre du document).
func (r *sseRewriter) apply(ev []byte) error {
	out, last := r.out[:0], 0
	for i := 0; i < r.ne; i++ {
		e := &r.edits[i]
		out = append(out, ev[last:e.vs]...)
		out = r.feed(e.s, ev[e.vs+1:e.ve-1], e.final, out)
		last = e.ve
	}
	out = append(out, ev[last:]...)
	r.out = out
	// Placeholders complets hors des strings de texte (functionCall, ids…).
	if bytes.Contains(out, marker) {
		out = r.rehydrate(out)
	}
	return r.write(out)
}

// --- slots -------------------------------------------------------------

func (r *sseRewriter) slot(k skey) (*slot, bool) {
	free := -1
	for i := range r.slots {
		s := &r.slots[i]
		if s.used && s.k == k {
			return s, false
		}
		if !s.used && free < 0 {
			free = i
		}
	}
	if free < 0 {
		return nil, false // plus de slots libres : pas de holdback pour ce flux
	}
	s := &r.slots[free]
	s.used, s.k = true, k
	s.buf, s.pre, s.suf = s.buf[:0], s.pre[:0], s.suf[:0]
	return s, true
}

func (r *sseRewriter) addEdit(vs, ve int, s *slot, final bool) {
	if r.ne < len(r.edits) {
		r.edits[r.ne] = edit{vs, ve, s, final}
		r.ne++
	}
}

// feed décode le fragment dans le buffer du slot, retient la fin qui pourrait
// être un début de placeholder, et ajoute à out la string JSON émissible.
func (r *sseRewriter) feed(s *slot, raw []byte, final bool, out []byte) []byte {
	if s == nil {
		r.tmp = appendUnescape(r.tmp[:0], raw)
		return appendJSONString(out, r.rehydrate(r.tmp))
	}
	s.buf = appendUnescape(s.buf, raw)
	keep := 0
	if !final {
		keep = r.v.Holdback(s.buf)
	}
	out = appendJSONString(out, r.rehydrate(s.buf[:len(s.buf)-keep])) // copie avant de décaler le buffer
	s.buf = s.buf[:copy(s.buf, s.buf[len(s.buf)-keep:])]
	if final {
		s.used = false
	}
	return out
}

func (r *sseRewriter) flushSlot(s *slot) {
	s.used = false
	if len(s.buf) == 0 {
		return
	}
	reh := r.rehydrate(s.buf)
	t := append(r.tmp[:0], s.pre...)
	t = appendJSONString(t, reh)
	t = append(t, s.suf...)
	r.tmp = t
	r.write(t)
}

// flush vide les slots d'un type (0 = tous) et d'un index (-1 = tous).
// Pour kChat, les tool calls du même choice sont inclus.
func (r *sseRewriter) flush(kind uint8, a int32) {
	for i := range r.slots {
		s := &r.slots[i]
		if !s.used || a >= 0 && s.k.a != a {
			continue
		}
		if kind == 0 || s.k.kind == kind || kind == kChat && s.k.kind == kChatTool {
			r.flushSlot(s)
		}
	}
}

// flushExcept vide, avant l'event courant, les slots du flux a absents de cet event.
func (r *sseRewriter) flushExcept(k1, k2 uint8, a int32, present []skey) {
	for i := range r.slots {
		s := &r.slots[i]
		if !s.used || s.k.a != a || s.k.kind != k1 && s.k.kind != k2 {
			continue
		}
		keep := false
		for _, p := range present {
			if p == s.k {
				keep = true
				break
			}
		}
		if !keep {
			r.flushSlot(s)
		}
	}
}

// --- Anthropic ---------------------------------------------------------

func (r *sseRewriter) anthDelta(ev []byte, ds int) bool {
	_, is, ie, ok := field(ev, ds, "index")
	if !ok {
		return false
	}
	_, dv, _, ok := field(ev, ds, "delta")
	if !ok || ev[dv] != '{' {
		return false
	}
	_, ts, te, ok := field(ev, dv, "type")
	if !ok {
		return false
	}
	var name string
	var f uint8
	switch string(ev[ts:te]) {
	case `"text_delta"`:
		name, f = "text", 1
	case `"input_json_delta"`:
		name, f = "partial_json", 2
	case `"thinking_delta"`:
		name, f = "thinking", 3
	default:
		return false
	}
	_, vs, ve, ok := field(ev, dv, name)
	if !ok || ev[vs] != '"' {
		return false
	}
	s, isNew := r.slot(skey{kAnth, f, atoi(ev[is:ie]), 0})
	if isNew {
		s.pre = append(s.pre, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":"...)
		s.pre = append(s.pre, ev[is:ie]...)
		s.pre = append(s.pre, `,"delta":{"type":`...)
		s.pre = append(s.pre, ev[ts:te]...)
		s.pre = append(s.pre, `,"`...)
		s.pre = append(s.pre, name...)
		s.pre = append(s.pre, `":`...)
		s.suf = append(s.suf, "}}\n\n"...)
	}
	r.addEdit(vs, ve, s, false)
	return true
}

// --- OpenAI Chat Completions --------------------------------------------

var chatFields = [...]string{"content", "reasoning_content", "reasoning", "refusal"}

func chatField(key []byte) uint8 {
	for i, f := range chatFields {
		if string(key) == f {
			return uint8(i + 1)
		}
	}
	return 0
}

var zero = []byte("0")

func (r *sseRewriter) chat(ev []byte, ds int) bool {
	_, cs, _, ok := field(ev, ds, "choices")
	if !ok || ev[cs] != '[' {
		return false
	}
	elems(ev, cs, func(c0, _ int) {
		if ev[c0] != '{' {
			return
		}
		a, araw := int32(0), zero
		if _, is, ie, ok := field(ev, c0, "index"); ok {
			a, araw = atoi(ev[is:ie]), ev[is:ie]
		}
		final := false
		if _, fs, _, ok := field(ev, c0, "finish_reason"); ok && ev[fs] != 'n' {
			final = true
		}
		_, dv, _, ok := field(ev, c0, "delta")
		if !ok || ev[dv] != '{' {
			if final {
				r.flush(kChat, a)
			}
			return
		}
		if final { // vider d'abord les flux du choice absents de ce chunk
			var arr [8]skey
			present := arr[:0]
			each(ev, dv, func(ks, ke, vs, ve int) {
				if f := chatField(ev[ks+1 : ke-1]); f != 0 && ev[vs] == '"' {
					present = append(present, skey{kChat, f, a, 0})
				} else if string(ev[ks+1:ke-1]) == "tool_calls" {
					elems(ev, vs, func(t0, _ int) {
						if _, is, ie, ok := field(ev, t0, "index"); ok {
							present = append(present, skey{kChatTool, 0, a, atoi(ev[is:ie])})
						}
					})
				}
			})
			r.flushExcept(kChat, kChatTool, a, present)
		}
		each(ev, dv, func(ks, ke, vs, ve int) {
			key := ev[ks+1 : ke-1]
			if f := chatField(key); f != 0 && ev[vs] == '"' {
				s, isNew := r.slot(skey{kChat, f, a, 0})
				if isNew {
					chatPre(s, ev, ds, araw)
					s.pre = append(s.pre, '"')
					s.pre = append(s.pre, key...)
					s.pre = append(s.pre, `":`...)
					s.suf = append(s.suf, "}}]}\n\n"...)
				}
				r.addEdit(vs, ve, s, final)
				return
			}
			if string(key) != "tool_calls" || ev[vs] != '[' {
				return
			}
			elems(ev, vs, func(t0, _ int) {
				_, is, ie, ok := field(ev, t0, "index")
				if !ok {
					return
				}
				_, fv, _, ok := field(ev, t0, "function")
				if !ok || ev[fv] != '{' {
					return
				}
				_, as, ae, ok := field(ev, fv, "arguments")
				if !ok || ev[as] != '"' {
					return
				}
				s, isNew := r.slot(skey{kChatTool, 0, a, atoi(ev[is:ie])})
				if isNew {
					chatPre(s, ev, ds, araw)
					s.pre = append(s.pre, `"tool_calls":[{"index":`...)
					s.pre = append(s.pre, ev[is:ie]...)
					s.pre = append(s.pre, `,"function":{"arguments":`...)
					s.suf = append(s.suf, "}}]}}]}\n\n"...)
				}
				r.addEdit(as, ae, s, final)
			})
		})
	})
	return true
}

func chatPre(s *slot, ev []byte, ds int, araw []byte) {
	s.pre = append(s.pre, `data: {"id":`...)
	s.pre = appendRaw(s.pre, ev, ds, "id", `""`)
	s.pre = append(s.pre, `,"object":"chat.completion.chunk","created":`...)
	s.pre = appendRaw(s.pre, ev, ds, "created", "0")
	s.pre = append(s.pre, `,"model":`...)
	s.pre = appendRaw(s.pre, ev, ds, "model", `""`)
	s.pre = append(s.pre, `,"choices":[{"index":`...)
	s.pre = append(s.pre, araw...)
	s.pre = append(s.pre, `,"delta":{`...)
}

func appendRaw(dst, b []byte, obj int, key, def string) []byte {
	if _, vs, ve, ok := field(b, obj, key); ok {
		return append(dst, b[vs:ve]...)
	}
	return append(dst, def...)
}

// --- OpenAI Responses ----------------------------------------------------

func (r *sseRewriter) responses(ev []byte, ds int) bool {
	_, ts, te, ok := field(ev, ds, "type")
	if !ok || te-ts < 2 {
		return false
	}
	typ := ev[ts+1 : te-1]
	oi := int32(-1)
	if _, s0, s1, ok := field(ev, ds, "output_index"); ok {
		oi = atoi(ev[s0:s1])
	}
	switch {
	case bytes.HasSuffix(typ, sDelta):
		_, vs, ve, ok := field(ev, ds, "delta")
		if !ok || ev[vs] != '"' {
			return false
		}
		ci := int32(0)
		if _, s0, s1, ok := field(ev, ds, "content_index"); ok {
			ci = atoi(ev[s0:s1])
		}
		s, isNew := r.slot(skey{kResp, hash8(typ), oi, ci})
		if isNew { // même event, tous champs sauf "delta" (générique pour tous les *.delta)
			s.pre = append(s.pre, "event: "...)
			s.pre = append(s.pre, typ...)
			s.pre = append(s.pre, "\ndata: {"...)
			each(ev, ds, func(ks, ke, vs, ve int) {
				if string(ev[ks+1:ke-1]) != "delta" {
					s.pre = append(s.pre, ev[ks:ke]...)
					s.pre = append(s.pre, ':')
					s.pre = append(s.pre, ev[vs:ve]...)
					s.pre = append(s.pre, ',')
				}
			})
			s.pre = append(s.pre, `"delta":`...)
			s.suf = append(s.suf, "}\n\n"...)
		}
		r.addEdit(vs, ve, s, false)
		return true
	case bytes.HasSuffix(typ, sDone) && oi >= 0:
		r.flush(kResp, oi)
	case string(typ) == "response.completed" || string(typ) == "response.failed" || string(typ) == "response.incomplete":
		r.flush(0, -1)
	}
	return false // l'event (texte complet) est réhydraté par remplacement simple
}

func hash8(b []byte) uint8 {
	h := uint8(0x9d)
	for _, c := range b {
		h = (h ^ c) * 0x1b
	}
	return h
}

// --- Gemini natif (streamGenerateContent?alt=sse) -------------------------
//
// Les fragments de texte arrivent dans candidates[].content.parts[].text.
// Les functionCall arrivent entiers : le remplacement simple de apply suffit.

func (r *sseRewriter) gemini(ev []byte, ds int) bool {
	_, cs, _, ok := field(ev, ds, "candidates")
	if !ok || ev[cs] != '[' {
		return false
	}
	elems(ev, cs, func(c0, _ int) {
		if ev[c0] != '{' {
			return
		}
		a := int32(0)
		var araw []byte
		if _, is, ie, ok := field(ev, c0, "index"); ok {
			a, araw = atoi(ev[is:ie]), ev[is:ie]
		}
		_, fr, _, final := field(ev, c0, "finishReason")
		final = final && ev[fr] != 'n'
		_, cv, _, ok := field(ev, c0, "content")
		pv := -1
		if ok && ev[cv] == '{' {
			if _, p, _, ok := field(ev, cv, "parts"); ok && ev[p] == '[' {
				pv = p
			}
		}
		if pv < 0 {
			if final {
				r.flush(kGem, a)
			}
			return
		}
		if final {
			var arr [4]skey
			present := arr[:0]
			elems(ev, pv, func(p0, _ int) {
				if _, _, _, ok := field(ev, p0, "text"); ok {
					present = append(present, skey{kGem, geminiThought(ev, p0), a, 0})
				}
			})
			r.flushExcept(kGem, kGem, a, present)
		}
		elems(ev, pv, func(p0, _ int) {
			if ev[p0] != '{' {
				return
			}
			_, vs, ve, ok := field(ev, p0, "text")
			if !ok || ev[vs] != '"' {
				return
			}
			th := geminiThought(ev, p0)
			s, isNew := r.slot(skey{kGem, th, a, 0})
			if isNew {
				s.pre = append(s.pre, `data: {"candidates":[{`...)
				if araw != nil {
					s.pre = append(s.pre, `"index":`...)
					s.pre = append(s.pre, araw...)
					s.pre = append(s.pre, ',')
				}
				s.pre = append(s.pre, `"content":{"role":"model","parts":[{`...)
				if th == 1 {
					s.pre = append(s.pre, `"thought":true,`...)
				}
				s.pre = append(s.pre, `"text":`...)
				s.suf = append(s.suf, "}]}}]}\n\n"...)
			}
			r.addEdit(vs, ve, s, final)
		})
	})
	return true
}

func geminiThought(ev []byte, part int) uint8 {
	if _, vs, ve, ok := field(ev, part, "thought"); ok && string(ev[vs:ve]) == "true" {
		return 1
	}
	return 0
}

// --- helpers -------------------------------------------------------------

// each appelle fn pour chaque champ de l'objet commençant en obj.
func each(b []byte, obj int, fn func(ks, ke, vs, ve int)) {
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
		ks := i
		ke := skipString(b, i)
		i = skipWS(b, ke)
		if i >= len(b) || b[i] != ':' {
			return
		}
		vs := skipWS(b, i+1)
		ve := skipValue(b, vs)
		fn(ks, ke, vs, ve)
		i = skipWS(b, ve)
		if i >= len(b) || b[i] != ',' {
			return
		}
		i++
	}
}

// elems appelle fn pour chaque élément du tableau commençant en arr.
func elems(b []byte, arr int, fn func(vs, ve int)) {
	i := skipWS(b, arr)
	if i >= len(b) || b[i] != '[' {
		return
	}
	i++
	for {
		i = skipWS(b, i)
		if i >= len(b) || b[i] == ']' {
			return
		}
		vs := i
		ve := skipValue(b, vs)
		if ve == vs {
			return
		}
		fn(vs, ve)
		i = skipWS(b, ve)
		if i >= len(b) || b[i] != ',' {
			return
		}
		i++
	}
}

func atoi(b []byte) int32 {
	n := int32(0)
	for _, c := range b {
		if c >= '0' && c <= '9' {
			n = n*10 + int32(c-'0')
		}
	}
	return n
}

const hexd = "0123456789abcdef"

// appendJSONString encode s en string JSON (guillemets compris).
func appendJSONString(dst, s []byte) []byte {
	dst = append(dst, '"')
	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		dst = append(dst, s[last:i]...)
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&0xf])
		}
		last = i + 1
	}
	dst = append(dst, s[last:]...)
	return append(dst, '"')
}

// appendUnescape décode le contenu d'une string JSON (sans guillemets).
func appendUnescape(dst, raw []byte) []byte {
	for {
		i := bytes.IndexByte(raw, '\\')
		if i < 0 || i+1 >= len(raw) {
			return append(dst, raw...)
		}
		dst = append(dst, raw[:i]...)
		adv := 2
		switch c := raw[i+1]; c {
		case 'n':
			dst = append(dst, '\n')
		case 't':
			dst = append(dst, '\t')
		case 'r':
			dst = append(dst, '\r')
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'u':
			if i+6 > len(raw) {
				return dst
			}
			r1 := hex4(raw[i+2 : i+6])
			adv = 6
			if utf16.IsSurrogate(r1) && i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
				if d := utf16.DecodeRune(r1, hex4(raw[i+8:i+12])); d != utf8.RuneError {
					r1, adv = d, 12
				}
			}
			dst = utf8.AppendRune(dst, r1)
		default: // \" \\ \/
			dst = append(dst, c)
		}
		raw = raw[i+adv:]
	}
}

func hex4(b []byte) rune {
	var r rune
	for _, c := range b {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r |= rune(c - 'A' + 10)
		}
	}
	return r
}

func (r *sseRewriter) write(b []byte) error {
	_, err := r.w.Write(b)
	return err
}

func (r *sseRewriter) flushOut() {
	if r.fl != nil {
		r.fl.Flush()
	}
}
