package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Données réalistes : une conversation d'agent de code (messages, extraits de
// fichiers, sorties d'outils), d'une taille donnée, avec ou sans secrets.
func convo(size int, secrets int) []byte {
	chunks := []string{
		`func (s *Server) handle(w http.ResponseWriter, r *http.Request) {\n\tctx := r.Context()\n\tid := r.URL.Query().Get(\"id\")\n\tif id == \"\" {\n\t\thttp.Error(w, \"missing id\", 400)\n\t\treturn\n\t}\n}`,
		`$ git log --oneline\n3f9a2c1 fix: race in pool\n8b7d6f5 feat: add retries\n550e8400-e29b-41d4-a716-446655440000 request id\n`,
		`Voici le plan : 1) lire la config, 2) valider les entrées, 3) écrire les tests. Le fichier contient environ 240 lignes et utilise le package net/http.`,
		`{\"name\":\"envguard\",\"version\":\"1.4.2\",\"dependencies\":{\"lodash\":\"^4.17.21\",\"express\":\"^4.19.2\"}}`,
	}
	secretLines := []string{
		`ANTHROPIC_API_KEY=sk-ant-api03-%sAbCdEfGhIjKlMnOpQrStUvWx\n`,
		`GITHUB_TOKEN=ghp_%sabcdefghijklmnopqrstuvwxyz0123\n`,
		`db_password = \"Zk8qLm2vPx9Tr4w%s\"\n`,
	}
	var b bytes.Buffer
	b.WriteString(`{"model":"m","max_tokens":1024,"stream":true,"messages":[`)
	i := 0
	for b.Len() < size {
		if i > 0 {
			b.WriteByte(',')
		}
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		text := chunks[i%len(chunks)]
		if secrets > 0 && i%7 == 3 {
			text += fmt.Sprintf(secretLines[i%len(secretLines)], fmt.Sprintf("%04d", i%secrets))
		}
		fmt.Fprintf(&b, `{"role":"%s","content":"%s"}`, role, text)
		i++
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

var sizes = []int{4 << 10, 64 << 10, 512 << 10, 2 << 20}

func sizeName(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%dMB", n>>20)
	}
	return fmt.Sprintf("%dKB", n>>10)
}

func BenchmarkMask(b *testing.B) {
	for _, sec := range []int{0, 8} {
		for _, sz := range sizes {
			body := convo(sz, sec)
			b.Run(fmt.Sprintf("secrets=%d/%s", sec, sizeName(sz)), func(b *testing.B) {
				v := NewVault("")
				v.Mask(body) // enregistre les secrets (hors mesure)
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				for b.Loop() {
					v.Mask(body)
				}
			})
		}
	}
}

func BenchmarkRehydrate(b *testing.B) {
	v := NewVault("")
	v.Mask(convo(64<<10, 8))
	for _, sz := range sizes {
		masked, _ := v.Mask(convo(sz, 8))
		b.Run(sizeName(sz), func(b *testing.B) {
			b.SetBytes(int64(len(masked)))
			b.ReportAllocs()
			for b.Loop() {
				v.Rehydrate(masked)
			}
		})
	}
}

// Flux SSE réaliste : ~2000 deltas de 4 à 12 caractères, dans chaque format.
func stream(format string, withPh bool, v *Vault) []byte {
	ph := ""
	if withPh {
		ph = placeholder("sk-ant-", key)
	}
	text := strings.Repeat("Le handler valide l'identifiant puis appelle le service. ", 180) + ph + " fin."
	var b bytes.Buffer
	for i := 0; i < len(text); {
		n := 4 + i%9
		if i+n > len(text) {
			n = len(text) - i
		}
		part := text[i : i+n]
		i += n
		var js []byte
		switch format {
		case "anthropic":
			js, _ = json.Marshal(deltaEvent{Type: "content_block_delta", Index: 0, Delta: delta{Type: "text_delta", Text: part}})
			b.WriteString("event: content_block_delta\n")
		case "openai-chat":
			js, _ = json.Marshal(map[string]any{"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "m",
				"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": part}}}})
		case "openai-responses":
			js, _ = json.Marshal(map[string]any{"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": part})
			b.WriteString("event: response.output_text.delta\n")
		case "gemini":
			js, _ = json.Marshal(map[string]any{"candidates": []any{map[string]any{"index": 0,
				"content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": part}}}}}})
		}
		b.WriteString("data: " + string(js) + "\n\n")
	}
	return b.Bytes()
}

func BenchmarkSSE(b *testing.B) {
	for _, known := range []bool{false, true} {
		for _, f := range []string{"anthropic", "openai-chat", "openai-responses", "gemini"} {
			v := NewVault("")
			if known {
				v.Mask([]byte(key))
			}
			src := stream(f, known, v)
			events := bytes.Count(src, []byte("data: "))
			name := "aucun-secret/" + f
			if known {
				name = "secret-connu/" + f
			}
			b.Run(name, func(b *testing.B) {
				b.SetBytes(int64(len(src)))
				b.ReportAllocs()
				for b.Loop() {
					(&sseRewriter{v: v, w: io.Discard}).run(bytes.NewReader(src))
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*events), "ns/event")
			})
		}
	}
}

// --- Test de charge de bout en bout -----------------------------------------

type loadResult struct {
	name              string
	reqs              int
	p50, p95, p99     time.Duration
	direct50          time.Duration
	allocsPerReq      float64
	bytesPerReq       float64
	gcCycles          uint32
	heapInuse, sysMem uint64
	rps               float64
}

func pct(d []time.Duration, p float64) time.Duration {
	return d[int(float64(len(d)-1)*p)]
}

func runLoad(t *testing.T, name string, body []byte, streaming bool, conc, total int) loadResult {
	sse := stream("anthropic", true, nil)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if streaming {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write(sse)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok ` + placeholder("sk-ant-", key) + `"}]}`))
	}))
	defer up.Close()
	ps, _ := parseProviders([]provider{{name: "anthropic", base: up.URL}, {name: "openai", base: up.URL}})
	p := &Proxy{providers: ps, v: NewVault(""), cl: &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}, hint: true, events: make(chan Event, 1)}
	p.v.Mask([]byte(key))
	srv := httptest.NewServer(p)
	defer srv.Close()
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

	fire := func(url string, n int) []time.Duration {
		lat := make([]time.Duration, n)
		var wg sync.WaitGroup
		next := make(chan int, n)
		for i := 0; i < n; i++ {
			next <- i
		}
		close(next)
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					t0 := time.Now()
					resp, err := cl.Post(url+"/anthropic/v1/messages", "application/json", bytes.NewReader(body))
					if err != nil {
						t.Error(err)
						return
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					lat[i] = time.Since(t0)
				}
			}()
		}
		wg.Wait()
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		return lat
	}

	// Référence : même amont, sans proxy (chemin /anthropic ignoré par l'amont).
	fire(up.URL, 200)
	direct := fire(up.URL, total)

	fire(srv.URL, 200) // chauffe
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	t0 := time.Now()
	lat := fire(srv.URL, total)
	el := time.Since(t0)
	runtime.ReadMemStats(&m1)

	// Les allocs incluent client + amont de test (même process) : on
	// retranche la mesure « directe » pour isoler le proxy.
	runtime.GC()
	var d0, d1 runtime.MemStats
	runtime.ReadMemStats(&d0)
	fire(up.URL, total)
	runtime.ReadMemStats(&d1)

	return loadResult{
		name: name, reqs: total,
		p50: pct(lat, .5), p95: pct(lat, .95), p99: pct(lat, .99), direct50: pct(direct, .5),
		allocsPerReq: float64((m1.Mallocs-m0.Mallocs)-(d1.Mallocs-d0.Mallocs)) / float64(total),
		bytesPerReq:  float64((m1.TotalAlloc-m0.TotalAlloc)-(d1.TotalAlloc-d0.TotalAlloc)) / float64(total),
		gcCycles:     m1.NumGC - m0.NumGC,
		heapInuse:    m1.HeapInuse, sysMem: m1.Sys,
		rps: float64(total) / el.Seconds(),
	}
}

// go test -run TestLoad -v   (PERF=1 pour l'activer)
func TestLoad(t *testing.T) {
	if os.Getenv("PERF") == "" {
		t.Skip("PERF=1 pour lancer le test de charge")
	}
	cases := []struct {
		name   string
		size   int
		sec    int
		stream bool
	}{
		{"64KB sans secret, JSON", 64 << 10, 0, false},
		{"64KB 8 secrets, JSON", 64 << 10, 8, false},
		{"512KB 8 secrets, JSON", 512 << 10, 8, false},
		{"64KB 8 secrets, SSE ~2000 events", 64 << 10, 8, true},
	}
	fmt.Printf("\n| scénario | req | req/s | p50 proxy | p50 direct | surcoût p50 | p95 | p99 | allocs/req | Ko alloués/req | cycles GC | heap | RSS Go (Sys) |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, c := range cases {
		conc, n := 32, 3000
		if os.Getenv("CONC") == "1" {
			conc, n = 1, 500
		}
		r := runLoad(t, c.name, convo(c.size, c.sec), c.stream, conc, n)
		fmt.Printf("| %s | %d | %.0f | %v | %v | %v | %v | %v | %.0f | %.0f | %d | %.1f MB | %.1f MB |\n",
			r.name, r.reqs, r.rps, r.p50.Round(time.Microsecond), r.direct50.Round(time.Microsecond),
			(r.p50 - r.direct50).Round(time.Microsecond), r.p95.Round(time.Microsecond), r.p99.Round(time.Microsecond),
			r.allocsPerReq, r.bytesPerReq/1024, r.gcCycles, float64(r.heapInuse)/(1<<20), float64(r.sysMem)/(1<<20))
	}
}

// Variantes « To » : buffer de sortie réutilisé, comme dans le proxy.
func BenchmarkMaskTo(b *testing.B) {
	for _, sz := range sizes {
		body := convo(sz, 8)
		b.Run(sizeName(sz), func(b *testing.B) {
			v := NewVault("")
			v.Mask(body)
			var dst []byte
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			for b.Loop() {
				dst, _ = v.MaskTo(dst, body)
			}
		})
	}
}

func BenchmarkRehydrateTo(b *testing.B) {
	v := NewVault("")
	v.Mask(convo(64<<10, 8))
	for _, sz := range sizes {
		masked, _ := v.Mask(convo(sz, 8))
		b.Run(sizeName(sz), func(b *testing.B) {
			var dst []byte
			b.SetBytes(int64(len(masked)))
			b.ReportAllocs()
			for b.Loop() {
				dst, _ = v.RehydrateTo(dst, masked)
			}
		})
	}
}

func BenchmarkHintTo64KB(b *testing.B) {
	body := convo(64<<10, 0)
	var dst []byte
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		dst = injectHint(dst, body, "/v1/messages")
	}
}
