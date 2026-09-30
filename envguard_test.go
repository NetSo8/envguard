package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const key = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

func TestDetect(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{"text":"export ANTHROPIC_API_KEY=` + key + `\n"}`, key},
		{`{"text":"gh` + `p_abcdefghijklmnopqrstuvwxyz0123456789"}`, "gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789"},
		{`{"text":"db_password = \"Zk8qLm2vPx9Tr4w\""}`, "Zk8qLm2vPx9Tr4w"},
		{`{"text":"MY_TOKEN: aZ9kQ2mX7pL4vR8tW1\nnext"}`, "aZ9kQ2mX7pL4vR8tW1"},
		{`{"text":"host = \"internal-thing-42\" # secret:"}`, "internal-thing-42"},
		{`{"text":"# secret: hunter2hunter"}`, "hunter2hunter"},
	}
	for _, c := range cases {
		var got []string
		scan([]byte(c.in), func(s span) { got = append(got, c.in[s.s:s.e]) })
		ok := false
		for _, g := range got {
			ok = ok || strings.HasPrefix(g, c.want)
		}
		if !ok {
			t.Errorf("%s: got %v, want %s", c.in, got, c.want)
		}
	}
}

func TestNoFalsePositive(t *testing.T) {
	for _, in := range []string{
		`{"text":"commit 3f9a2c1e8b7d6f5a4e3d2c1b0a9f8e7d6c5b4a39"}`,
		`{"text":"id = 550e8400-e29b-41d4-a716-446655440000"}`,
		`{"text":"api_key = sk-ant-REDACTED_deadbeef"}`,
		`{"text":"token_count: 123456789012"}`,
	} {
		scan([]byte(in), func(s span) { t.Errorf("faux positif %q dans %s", in[s.s:s.e], in) })
	}
}

func TestDeterministic(t *testing.T) {
	v := NewVault("")
	a, _ := v.Mask([]byte(`{"a":"` + key + `"}`))
	b, _ := v.Mask([]byte(`{"b":"` + key + `","c":"` + key + `"}`))
	ph := placeholder("sk-ant-", key)
	if !bytes.Contains(a, []byte(ph)) || bytes.Count(b, []byte(ph)) != 2 || bytes.Contains(b, []byte(key)) {
		t.Fatalf("%s / %s", a, b)
	}
	if r, _ := v.Rehydrate(b); !bytes.Contains(r, []byte(key)) {
		t.Fatal("réhydratation")
	}
}

// Placeholder coupé à tous les points possibles entre deux deltas.
func TestSSESplit(t *testing.T) {
	v := NewVault("")
	v.Mask([]byte(key))
	ph := placeholder("sk-ant-", key)
	full := "curl -H \"x-api-key: " + ph + "\" https://x"
	for cut := 1; cut < len(full); cut++ {
		var src bytes.Buffer
		for _, part := range []string{full[:cut], full[cut:]} {
			d, _ := json.Marshal(deltaEvent{Type: "content_block_delta", Index: 1, Delta: delta{Type: "input_json_delta", PartialJSON: part}})
			src.WriteString("event: content_block_delta\ndata: " + string(d) + "\n\n")
		}
		src.WriteString("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n")
		var out bytes.Buffer
		(&sseRewriter{v: v, w: &out}).run(&src)
		if got := collect(t, out.String()); got != strings.Replace(full, ph, key, 1) {
			t.Fatalf("cut %d: %q", cut, got)
		}
	}
}

func collect(t *testing.T, s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if d, ok := strings.CutPrefix(l, "data: "); ok && strings.Contains(d, "content_block_delta") {
			var de deltaEvent
			if err := json.Unmarshal([]byte(d), &de); err != nil {
				t.Fatal(err)
			}
			b.WriteString(*de.Delta.field())
		}
	}
	return b.String()
}

// Bout en bout : l'amont ne voit jamais la clé, le client la récupère.
func TestProxyE2E(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if bytes.Contains(b, []byte(key)) {
			t.Error("la clé a fuité vers l'amont")
		}
		if !bytes.Contains(b, []byte("REDACTED_")) || !bytes.Contains(b, []byte("masked secrets")) {
			t.Errorf("body amont: %s", b)
		}
		w.Write([]byte(`{"content":[{"type":"text","text":"use ` + placeholder("sk-ant-", key) + `"}]}`))
	}))
	defer up.Close()
	ps, _ := parseProviders([]provider{{name: "anthropic", base: up.URL}, {name: "openai", base: up.URL}})
	p := &Proxy{providers: ps, v: NewVault(""), cl: up.Client(), hint: true, events: make(chan Event, 16)}
	srv := httptest.NewServer(p)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"system":"be nice","messages":[{"role":"user","content":"my key `+key+`"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(b, []byte(key)) {
		t.Fatalf("réponse non réhydratée: %s", b)
	}
}

func BenchmarkMaskClean(b *testing.B) {
	body := bytes.Repeat([]byte(`{"type":"text","text":"func main() { fmt.Println(\"hello world\") }\n"},`), 2000)
	v := NewVault("")
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		v.Mask(body)
	}
}

// OpenAI Chat Completions : contenu + arguments de tool call, coupés partout.
func TestChatSplit(t *testing.T) {
	v := NewVault("")
	v.Mask([]byte(key))
	ph := placeholder("sk-ant-", key)
	full := `{"cmd":"curl -H 'x-api-key: ` + ph + `'"}`
	want := strings.Replace(full, ph, key, 1)
	for cut := 1; cut < len(full); cut++ {
		var src bytes.Buffer
		for _, part := range []string{full[:cut], full[cut:]} {
			c, _ := json.Marshal(map[string]any{"id": "x", "object": "chat.completion.chunk", "choices": []any{map[string]any{
				"index": 0, "delta": map[string]any{"content": part, "tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": part}}}}}}})
			src.WriteString("data: " + string(c) + "\n\n")
		}
		src.WriteString(`data: {"id":"x","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}` + "\n\ndata: [DONE]\n\n")
		var out bytes.Buffer
		(&sseRewriter{v: v, w: &out}).run(&src)
		var content, args strings.Builder
		for _, l := range strings.Split(out.String(), "\n") {
			d, ok := strings.CutPrefix(l, "data: ")
			if !ok || d == "[DONE]" {
				continue
			}
			var c struct {
				Choices []struct {
					Delta struct {
						Content   string
						ToolCalls []struct{ Function struct{ Arguments string } } `json:"tool_calls"`
					}
				}
			}
			if err := json.Unmarshal([]byte(d), &c); err != nil {
				t.Fatal(err, d)
			}
			for _, ch := range c.Choices {
				content.WriteString(ch.Delta.Content)
				for _, tc := range ch.Delta.ToolCalls {
					args.WriteString(tc.Function.Arguments)
				}
			}
		}
		if content.String() != want || args.String() != want {
			t.Fatalf("cut %d:\n%q\n%q", cut, content.String(), args.String())
		}
		if !strings.HasSuffix(strings.TrimSpace(out.String()), "[DONE]") {
			t.Fatal("[DONE] doit rester en dernier")
		}
	}
}

// OpenAI Responses : output_text.delta coupé, vidé au .done.
func TestResponsesSplit(t *testing.T) {
	v := NewVault("")
	v.Mask([]byte(key))
	ph := placeholder("sk-ant-", key)
	full := "key=" + ph + " ok"
	for cut := 1; cut < len(full); cut++ {
		var src bytes.Buffer
		for _, part := range []string{full[:cut], full[cut:]} {
			d, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": part})
			src.WriteString("event: response.output_text.delta\ndata: " + string(d) + "\n\n")
		}
		d, _ := json.Marshal(map[string]any{"type": "response.output_text.done", "output_index": 0, "content_index": 0, "text": full})
		src.WriteString("event: response.output_text.done\ndata: " + string(d) + "\n\n")
		var out bytes.Buffer
		(&sseRewriter{v: v, w: &out}).run(&src)
		var got, done string
		for _, l := range strings.Split(out.String(), "\n") {
			if d, ok := strings.CutPrefix(l, "data: "); ok {
				var e struct{ Type, Delta, Text string }
				json.Unmarshal([]byte(d), &e)
				got += e.Delta
				done += e.Text
			}
		}
		want := strings.Replace(full, ph, key, 1)
		if got != want || done != want {
			t.Fatalf("cut %d: %q / %q", cut, got, done)
		}
	}
}

func TestChatHint(t *testing.T) {
	out := injectHint([]byte(`{"model":"gpt","messages":[{"role":"user","content":"hi"}]}`), "/v1/chat/completions")
	if !bytes.Contains(out, []byte(`"role":"system"`)) || bytes.Index(out, []byte("masked secrets")) > bytes.Index(out, []byte(`"hi"`)) {
		t.Fatalf("%s", out)
	}
}

// Gemini natif : texte coupé + functionCall entier réhydraté.
func TestGeminiSplit(t *testing.T) {
	v := NewVault("")
	v.Mask([]byte(key))
	ph := placeholder("sk-ant-", key)
	full := "export KEY=" + ph + "\n"
	want := strings.Replace(full, ph, key, 1)
	for cut := 1; cut < len(full); cut++ {
		var src bytes.Buffer
		for _, part := range []string{full[:cut], full[cut:]} {
			c, _ := json.Marshal(map[string]any{"candidates": []any{map[string]any{"index": 0, "content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": part}}}}}})
			src.WriteString("data: " + string(c) + "\r\n\r\n")
		}
		c, _ := json.Marshal(map[string]any{"candidates": []any{map[string]any{"index": 0, "finishReason": "STOP", "content": map[string]any{"role": "model", "parts": []any{
			map[string]any{"functionCall": map[string]any{"name": "sh", "args": map[string]any{"cmd": "echo " + ph}}}}}}}})
		src.WriteString("data: " + string(c) + "\r\n\r\n")
		var out bytes.Buffer
		(&sseRewriter{v: v, w: &out}).run(&src)
		var text strings.Builder
		fc := false
		for _, l := range strings.Split(out.String(), "\n") {
			d, ok := strings.CutPrefix(strings.TrimRight(l, "\r"), "data: ")
			if !ok {
				continue
			}
			var g struct {
				Candidates []struct {
					Content struct {
						Parts []struct {
							Text         string
							FunctionCall *struct{ Args struct{ Cmd string } }
						}
					}
				}
			}
			if err := json.Unmarshal([]byte(d), &g); err != nil {
				t.Fatal(err, d)
			}
			for _, p := range g.Candidates[0].Content.Parts {
				text.WriteString(p.Text)
				if p.FunctionCall != nil {
					fc = p.FunctionCall.Args.Cmd == "echo "+key
				}
			}
		}
		if text.String() != want || !fc {
			t.Fatalf("cut %d: %q fc=%v", cut, text.String(), fc)
		}
	}
}

func TestRouting(t *testing.T) {
	ps, _ := parseProviders(append([]provider(nil), defaultProviders...))
	p := &Proxy{providers: ps}
	for path, want := range map[string]string{
		"/deepseek/anthropic/v1/messages":               "https://api.deepseek.com/anthropic/v1/messages",
		"/groq/v1/chat/completions":                     "https://api.groq.com/openai/v1/chat/completions",
		"/gemini/v1beta/models/x:streamGenerateContent": "https://generativelanguage.googleapis.com/v1beta/models/x:streamGenerateContent",
		"/meta/v1/responses":                            "https://api.meta.ai/v1/responses",
		"/v1/chat/completions":                          "https://api.openai.com/v1/chat/completions",
	} {
		r := httptest.NewRequest("POST", path, nil)
		pr, rest := p.route(r)
		if got := strings.TrimSuffix(pr.base, "/") + rest; got != want {
			t.Errorf("%s → %s, want %s", path, got, want)
		}
	}
}

func TestGeminiHint(t *testing.T) {
	out := injectHint([]byte(`{"contents":[],"systemInstruction":{"parts":[{"text":"be nice"}]}}`), "/v1beta/models/g:streamGenerateContent")
	if !bytes.Contains(out, []byte("be nice")) || !bytes.Contains(out, []byte("masked secrets")) {
		t.Fatalf("%s", out)
	}
}

// La consigne doit produire du JSON valide et identique à l'ancienne méthode
// (décodage complet), sur toutes les formes de champ.
func TestHintShapes(t *testing.T) {
	cases := []struct{ path, in, want string }{
		{"/v1/messages", `{"model":"m","messages":[]}`, `system`},
		{"/v1/messages", `{"system":"be nice","messages":[]}`, `be nice\n\n`},
		{"/v1/messages", `{"system":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}],"messages":[]}`, `"cache_control"`},
		{"/v1/messages", `{"system":[],"messages":[]}`, `[{"type":"text"`},
		{"/v1/messages", `{"system":null}`, `"system":"Values`},
		{"/v1/messages", `{}`, `{"system":"Values`},
		{"/v1/messages", " {\n \"messages\" : [ {\"content\":\"a \\\"system\\\": x\"} ] ,\n \"system\" : \"s\" }", `s\n\n`},
		{"/v1/responses", `{"input":"hi"}`, `"instructions"`},
		{"/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`, `[{"role":"system"`},
		{"/v1/chat/completions", `{"messages":[]}`, `[{"role":"system","content":"Values matching *REDACTED_* are masked secrets. Always copy them verbatim, character for character: never encode, split, re-case or alter them."}]`},
		{"/v1beta/models/g:generateContent", `{"contents":[]}`, `"systemInstruction":{"parts":[{"text"`},
		{"/v1beta/models/g:generateContent", `{"system_instruction":{"parts":[{"text":"x"}]}}`, `{"text":"x"},{"text"`},
		{"/v1beta/models/g:generateContent", `{"systemInstruction":{"role":"user"}}`, `"parts":[{"text"`},
	}
	for _, c := range cases {
		out := injectHint([]byte(c.in), c.path)
		if !json.Valid(out) {
			t.Errorf("%s: JSON invalide: %s", c.in, out)
		}
		if !strings.Contains(string(out), c.want) || !strings.Contains(string(out), "REDACTED_") {
			t.Errorf("%s:\n got %s\nwant %s", c.in, out, c.want)
		}
	}
}

func BenchmarkHint64KB(b *testing.B) {
	body := convo(64<<10, 0)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		injectHint(body, "/v1/messages")
	}
}
