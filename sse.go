package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Réécriture des flux SSE : Anthropic Messages, OpenAI Chat Completions et
// OpenAI Responses.
//
// Un placeholder peut être coupé entre deux events (ex: "sk-ant-RED" puis
// "ACTED_7f3a…"). Chaque flux de texte (content block, choice, tool call,
// output item…) a son « slot » : on y retient la fin qui ressemble au début
// d'un placeholder, on la recolle au fragment suivant, et on vide le slot à
// la fin du bloc. Les arguments de tool calls sont ainsi réhydratés avant
// que le client n'exécute l'outil.

type slot struct {
	used  bool
	key   string
	buf   []byte
	synth func(text string) []byte // event SSE complet pour vider le reliquat
}

type sseRewriter struct {
	v     *Vault
	w     io.Writer
	fl    http.Flusher
	slots [32]slot // tableau fixe, recherche linéaire : plus rapide qu'une map à cette taille
	count int      // nb de réhydratations
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
)

func (r *sseRewriter) run(src io.Reader) error {
	br := bufio.NewReaderSize(src, 32<<10)
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
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if len(bytes.TrimSpace(ev)) > 0 {
				r.event(ev)
			}
			r.flushPrefix("")
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func dataOf(ev []byte) []byte {
	i := bytes.Index(ev, pData)
	if i < 0 {
		return nil
	}
	d := ev[i+len(pData):]
	if j := bytes.IndexByte(d, '\n'); j >= 0 {
		d = d[:j]
	}
	return bytes.TrimRight(d, "\r")
}

func (r *sseRewriter) event(ev []byte) error {
	data := dataOf(ev)
	// Chemin rapide : aucun secret connu => rien à réhydrater, on relaie tel quel.
	if data == nil || !r.v.HasSecrets() {
		return r.write(ev)
	}
	switch {
	case bytes.Equal(data, pDone):
		r.flushPrefix("")
		return r.write(ev)
	case bytes.Contains(data, pAnthDelta):
		if r.anthDelta(ev, data) {
			return nil
		}
	case bytes.Contains(data, pAnthStop):
		var s struct{ Index int }
		json.Unmarshal(data, &s)
		r.flushPrefix("a" + strconv.Itoa(s.Index) + ":")
	case bytes.Contains(data, pMsgStop):
		r.flushPrefix("")
	case bytes.Contains(data, pRespType):
		if r.responses(ev, data) {
			return nil
		}
	case bytes.Contains(data, pCands):
		if r.gemini(ev, data) {
			return nil
		}
	case bytes.Contains(data, pChoices):
		if r.chat(ev, data) {
			return nil
		}
	}
	out, n := r.v.Rehydrate(ev)
	r.count += n
	return r.write(out)
}

// --- slots -------------------------------------------------------------

func (r *sseRewriter) slot(key string) *slot {
	free := -1
	for i := range r.slots {
		s := &r.slots[i]
		if s.used && s.key == key {
			return s
		}
		if !s.used && free < 0 {
			free = i
		}
	}
	if free < 0 {
		return nil
	}
	s := &r.slots[free]
	s.used, s.key, s.buf = true, key, s.buf[:0]
	return s
}

// feed ajoute un fragment et renvoie le texte réhydraté émissible maintenant.
// final=true : rien n'est retenu (fin du flux pour ce slot).
func (r *sseRewriter) feed(key, frag string, final bool, synth func(string) []byte) string {
	s := r.slot(key)
	if s == nil { // plus de slots libres : pas de holdback, réhydratation simple
		out, n := r.v.Rehydrate([]byte(frag))
		r.count += n
		return string(out)
	}
	s.synth = synth
	s.buf = append(s.buf, frag...)
	keep := 0
	if !final {
		keep = r.v.Holdback(s.buf)
	}
	out, n := r.v.Rehydrate(s.buf[:len(s.buf)-keep])
	r.count += n
	str := string(out) // copie avant de décaler le buffer
	s.buf = s.buf[:copy(s.buf, s.buf[len(s.buf)-keep:])]
	if final {
		s.used = false
	}
	return str
}

func (r *sseRewriter) flushPrefix(prefix string) {
	for i := range r.slots {
		s := &r.slots[i]
		if !s.used || !strings.HasPrefix(s.key, prefix) {
			continue
		}
		s.used = false
		if len(s.buf) > 0 && s.synth != nil {
			out, n := r.v.Rehydrate(s.buf)
			r.count += n
			r.write(s.synth(string(out)))
		}
	}
}

// --- Anthropic ---------------------------------------------------------

type delta struct {
	Type        string `json:"type"`
	Text        string `json:"text,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
	Thinking    string `json:"thinking,omitempty"`
}

type deltaEvent struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta delta  `json:"delta"`
}

func (d *delta) field() *string {
	switch d.Type {
	case "text_delta":
		return &d.Text
	case "input_json_delta":
		return &d.PartialJSON
	case "thinking_delta":
		return &d.Thinking
	}
	return nil
}

func anthSynth(idx int, typ string) func(string) []byte {
	return func(text string) []byte {
		de := deltaEvent{Type: "content_block_delta", Index: idx, Delta: delta{Type: typ}}
		*de.Delta.field() = text
		js, _ := json.Marshal(de)
		return sseBytes("content_block_delta", js)
	}
}

func (r *sseRewriter) anthDelta(ev, data []byte) bool {
	var de deltaEvent
	if json.Unmarshal(data, &de) != nil {
		return false
	}
	f := de.Delta.field()
	if f == nil {
		return false
	}
	*f = r.feed("a"+strconv.Itoa(de.Index)+":", *f, false, anthSynth(de.Index, de.Delta.Type))
	if *f == "" {
		return true // tout est retenu pour l'instant
	}
	js, _ := json.Marshal(de)
	r.write(sseBytes("content_block_delta", js))
	return true
}

// --- OpenAI Chat Completions --------------------------------------------

var chatTextFields = [...]string{"content", "reasoning_content", "reasoning", "refusal"}

func (r *sseRewriter) chat(ev, data []byte) bool {
	m, ok := decode(data)
	if !ok {
		return false
	}
	choices, _ := m["choices"].([]any)
	base := map[string]any{"id": m["id"], "object": m["object"], "created": m["created"], "model": m["model"]}
	for _, ci := range choices {
		c, _ := ci.(map[string]any)
		if c == nil {
			continue
		}
		idx := numStr(c["index"])
		cp := "c" + idx + ":"
		final := c["finish_reason"] != nil
		d, _ := c["delta"].(map[string]any)
		tcs, _ := d["tool_calls"].([]any)
		if final { // vider d'abord les slots du choice absents de ce chunk
			present := map[string]bool{}
			for _, f := range chatTextFields {
				if _, ok := d[f].(string); ok {
					present[cp+f] = true
				}
			}
			for _, ti := range tcs {
				tc, _ := ti.(map[string]any)
				present[cp+"t"+numStr(tc["index"])] = true
			}
			r.flushOthers(cp, present)
		}
		for _, f := range chatTextFields {
			if s, ok := d[f].(string); ok {
				d[f] = r.feed(cp+f, s, final, chatSynth(base, c["index"], f, nil))
			}
		}
		for _, ti := range tcs {
			tc, _ := ti.(map[string]any)
			fn, _ := tc["function"].(map[string]any)
			if s, ok := fn["arguments"].(string); ok {
				fn["arguments"] = r.feed(cp+"t"+numStr(tc["index"]), s, final, chatSynth(base, c["index"], "", tc["index"]))
			}
		}
	}
	r.write(sseBytes("", encode(m)))
	return true
}

// flushOthers vide, avant le chunk courant, les slots du choice absents de ce chunk.
func (r *sseRewriter) flushOthers(prefix string, present map[string]bool) {
	for i := range r.slots {
		s := &r.slots[i]
		if s.used && strings.HasPrefix(s.key, prefix) && !present[s.key] {
			s.used = false
			if len(s.buf) > 0 && s.synth != nil {
				out, n := r.v.Rehydrate(s.buf)
				r.count += n
				r.write(s.synth(string(out)))
			}
		}
	}
}

func chatSynth(base map[string]any, idx any, field string, toolIdx any) func(string) []byte {
	return func(text string) []byte {
		d := map[string]any{}
		if field != "" {
			d[field] = text
		} else {
			d["tool_calls"] = []any{map[string]any{"index": toolIdx, "function": map[string]any{"arguments": text}}}
		}
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m["choices"] = []any{map[string]any{"index": idx, "delta": d}}
		return sseBytes("", encode(m))
	}
}

// --- OpenAI Responses ----------------------------------------------------

func (r *sseRewriter) responses(ev, data []byte) bool {
	m, ok := decode(data)
	if !ok {
		return false
	}
	typ, _ := m["type"].(string)
	prefix := "r" + numStr(m["output_index"]) + ":"
	switch {
	case strings.HasSuffix(typ, ".delta"):
		s, ok := m["delta"].(string)
		if !ok {
			return false
		}
		tmpl := make(map[string]any, len(m))
		for k, v := range m {
			tmpl[k] = v
		}
		key := prefix + numStr(m["content_index"]) + ":" + typ
		m["delta"] = r.feed(key, s, false, func(text string) []byte {
			tmpl["delta"] = text
			return sseBytes(typ, encode(tmpl))
		})
		if m["delta"] == "" {
			return true
		}
		r.write(sseBytes(typ, encode(m)))
		return true
	case strings.HasSuffix(typ, ".done") && m["output_index"] != nil:
		r.flushPrefix(prefix)
	case typ == "response.completed" || typ == "response.failed" || typ == "response.incomplete":
		r.flushPrefix("")
	}
	return false // l'event (texte complet) est réhydraté par remplacement simple
}

// --- Gemini natif (streamGenerateContent?alt=sse) -------------------------
//
// Les fragments de texte arrivent dans candidates[].content.parts[].text.
// Les functionCall arrivent entiers : un remplacement simple suffit.

func (r *sseRewriter) gemini(ev, data []byte) bool {
	m, ok := decode(data)
	if !ok {
		return false
	}
	cands, _ := m["candidates"].([]any)
	for _, ci := range cands {
		c, _ := ci.(map[string]any)
		if c == nil {
			continue
		}
		idx := numStr(c["index"])
		cp := "g" + idx + ":"
		final := c["finishReason"] != nil
		content, _ := c["content"].(map[string]any)
		parts, _ := content["parts"].([]any)
		if final {
			present := map[string]bool{}
			for _, pi := range parts {
				if pt, _ := pi.(map[string]any); pt != nil {
					present[cp+geminiKind(pt)] = true
				}
			}
			r.flushOthers(cp, present)
		}
		for _, pi := range parts {
			pt, _ := pi.(map[string]any)
			s, ok := pt["text"].(string)
			if !ok {
				continue
			}
			kind := geminiKind(pt)
			pt["text"] = r.feed(cp+kind, s, final, geminiSynth(c["index"], kind == "thought"))
		}
	}
	out, n := r.v.Rehydrate(encode(m)) // functionCall.args & co
	r.count += n
	r.write(sseBytes("", out))
	return true
}

func geminiKind(pt map[string]any) string {
	if t, _ := pt["thought"].(bool); t {
		return "thought"
	}
	return "text"
}

func geminiSynth(idx any, thought bool) func(string) []byte {
	return func(text string) []byte {
		part := map[string]any{"text": text}
		if thought {
			part["thought"] = true
		}
		c := map[string]any{"content": map[string]any{"role": "model", "parts": []any{part}}}
		if idx != nil {
			c["index"] = idx
		}
		return sseBytes("", encode(map[string]any{"candidates": []any{c}}))
	}
}

// --- helpers -------------------------------------------------------------

func decode(data []byte) (map[string]any, bool) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber() // préserve les nombres tels quels
	var m map[string]any
	return m, d.Decode(&m) == nil
}

func encode(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}

func numStr(v any) string {
	switch n := v.(type) {
	case json.Number:
		return n.String()
	case float64:
		return strconv.Itoa(int(n))
	case int:
		return strconv.Itoa(n)
	}
	return "0"
}

func sseBytes(event string, js []byte) []byte {
	b := make([]byte, 0, len(js)+len(event)+16)
	if event != "" {
		b = append(b, "event: "...)
		b = append(b, event...)
		b = append(b, '\n')
	}
	b = append(b, pData...)
	b = append(b, js...)
	return append(b, '\n', '\n')
}

func (r *sseRewriter) write(b []byte) error {
	_, err := r.w.Write(b)
	if r.fl != nil {
		r.fl.Flush()
	}
	return err
}
