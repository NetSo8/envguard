package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

// Le scan ne doit jamais paniquer et ses spans doivent rester dans les bornes.
func FuzzScan(f *testing.F) {
	for _, s := range []string{
		`{"text":"export API_KEY=` + key + `"}`, "-----BEGIN PRIVATE KEY-----\\nAAAA", "postgres://a:b@", "Bearer ",
		"# secret:", "eyJ.eyJ.", `\u00`, "::/", `{"k":"\"`, jwt,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		scan(b, func(s span) {
			if s.s < 0 || s.e > len(b) || s.s >= s.e {
				t.Fatalf("span hors bornes %d..%d (len %d)", s.s, s.e, len(b))
			}
		})
	})
}

// Cache par segments : même résultat que le masquage direct, quelle que soit l'entrée.
func FuzzMaskBodyEquivalence(f *testing.F) {
	f.Add([]byte(`{"messages":[{"c":"` + key + `"},{"c":"x"}],"tools":[1,2]}`))
	f.Add([]byte(`{"messages":[ ,]}`))
	f.Add([]byte(`{"system":"\"","messages":[{"a":"db_password = Zk8qLm2vPx9Tr4wQ"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		k := []byte("0123456789abcdef0123456789abcdef")
		v1, v2 := NewVault(""), NewVault("")
		v1.SetKey(k)
		v2.SetKey(k)
		// Rembourrage pour franchir le seuil du cache.
		body := append(bytes.Repeat([]byte(" "), segBodyMin), b...)
		c := newSegCache()
		var mb maskBufs
		got, _ := c.maskBody(v1, &mb, body)
		got = append([]byte(nil), got...)
		want, _ := v2.Mask(body)
		if !bytes.Equal(got, want) {
			t.Fatalf("divergence cache / direct")
		}
		if again, _ := c.maskBody(v1, &mb, body); !bytes.Equal(again, want) { // cache chaud
			t.Fatalf("divergence au second passage")
		}
	})
}

// Le rewriter SSE ne doit jamais paniquer sur un flux arbitraire.
func FuzzSSE(f *testing.F) {
	f.Add([]byte("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"sk-ant-RED\"}}\n\n"))
	f.Add([]byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"x\"}}]},\"finish_reason\":\"stop\"}]}\n\n"))
	f.Add([]byte("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"\\ud83d\"}]}}]}\n\n"))
	f.Add([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"\\u00\"}\n\n"))
	pol, _ := parsePolicy("strict", nil)
	f.Fuzz(func(t *testing.T, b []byte) {
		v := NewVault("")
		v.Mask([]byte(key))
		(&sseRewriter{v: v, w: io.Discard}).run(bytes.NewReader(b))
		(&sseRewriter{v: v, w: io.Discard, pol: pol}).run(bytes.NewReader(b)) // avec politique des outils
	})
}

// L'injection de la consigne ne doit jamais paniquer, et un JSON valide doit le rester.
func FuzzHint(f *testing.F) {
	f.Add([]byte(`{"system":"x","messages":[]}`), uint8(0))
	f.Add([]byte(`{"messages":[`), uint8(2))
	f.Add([]byte(`{"systemInstruction":{"parts":[]}}`), uint8(3))
	paths := []string{"/v1/messages", "/v1/responses", "/v1/chat/completions", "/v1beta/models/g:generateContent"}
	f.Fuzz(func(t *testing.T, b []byte, p uint8) {
		out := injectHint(nil, b, paths[int(p)%len(paths)])
		if json.Valid(b) && !json.Valid(out) {
			t.Fatalf("JSON valide rendu invalide : %s -> %s", b, out)
		}
	})
}

// Règles gitleaks : jamais de panique, secrets dans les bornes et sans placeholder.
func FuzzGitleaks(f *testing.F) {
	g, _ := loadGitleaks(gitleaksDefaultExclude)
	f.Add([]byte(`{"t":"pu` + `l-3f9a2c1e8b7d6f5a4e3d2c1b0a9f8e7d6c5b4a39 datadog_api: a1b2"}`))
	f.Add([]byte("s.\\n_mmk sk"))
	f.Fuzz(func(t *testing.T, b []byte) {
		g.find(b, nil, func(id string, sec []byte) {
			if len(sec) < glMinLen || bytes.Contains(sec, marker) {
				t.Fatalf("%s : %q", id, sec)
			}
		})
	})
}

// Politique : repérage des arguments d'outils et des hôtes sur du JSON arbitraire.
func FuzzToolSpans(f *testing.F) {
	f.Add([]byte(`{"content":[{"type":"tool_use","input":{"command":"curl https://a.example"}}]}`))
	f.Add([]byte(`{"arguments":"x","args":{"a":[1,{"input":2}]}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		sp := toolSpans(b, 0, nil)
		for i := 0; i+1 < len(sp); i += 2 {
			if sp[i] < 0 || sp[i+1] > len(b) || sp[i] > sp[i+1] {
				t.Fatalf("bornes %d..%d (len %d)", sp[i], sp[i+1], len(b))
			}
		}
		extractHosts(b)
	})
}

// Lecteur .env : jamais de panique.
func FuzzDotenv(f *testing.F) {
	f.Add([]byte("A=b\nexport B=\"c\nd\"\nC='e' # x\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, kv := range parseDotenv(b) {
			envSecret(kv.key, kv.val)
		}
	})
}
