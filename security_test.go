package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// secProxy : proxy configuré comme en production (écoute locale).
func secProxy(t *testing.T, h http.HandlerFunc, tweak func(*Proxy)) (*Proxy, *httptest.Server) {
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	ps, _ := parseProviders([]provider{{name: "anthropic", base: up.URL}, {name: "openai", base: up.URL}})
	p := &Proxy{providers: ps, v: NewVault(""), cl: up.Client(), events: make(chan Event, 64), loopback: true}
	if tweak != nil {
		tweak(p)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return p, srv
}

func gz(b []byte) *bytes.Buffer {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return &buf
}

// Un corps gzip passait sans être masqué (la clé arrivait en clair).
func TestSecGzipRequestMasked(t *testing.T) {
	var seen []byte
	var ce string
	_, srv := secProxy(t, func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
		ce = r.Header.Get("Content-Encoding")
	}, nil)
	body := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("le code du projet ", 300) + key + `"}]}`)
	req, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", gz(body))
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ce != "" || bytes.Contains(seen, []byte(key)) || !bytes.Contains(seen, []byte("REDACTED_")) {
		t.Fatalf("Content-Encoding amont %q, clé en clair %v", ce, bytes.Contains(seen, []byte(key)))
	}
}

// Encodage inconnu : refus plutôt que relais en aveugle.
func TestSecUnknownEncodingRejected(t *testing.T) {
	called := false
	_, srv := secProxy(t, func(w http.ResponseWriter, r *http.Request) { called = true }, nil)
	req, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", strings.NewReader("xx"))
	req.Header.Set("Content-Encoding", "br")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType || called {
		t.Fatalf("statut %d, amont appelé %v", resp.StatusCode, called)
	}
}

// Requêtes de navigateur (CSRF / DNS rebinding) refusées, CORS jamais relayé.
func TestSecBrowserRequests(t *testing.T) {
	_, srv := secProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}, func(p *Proxy) { p.origins = map[string]bool{"http://localhost:3000": true} })
	do := func(hdr map[string]string, host string) *http.Response {
		req, _ := http.NewRequest("POST", srv.URL+"/openai/v1/chat/completions", strings.NewReader(`{}`))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := do(map[string]string{"Origin": "https://evil.example"}, ""); r.StatusCode != 403 {
		t.Errorf("Origin étrangère : %d", r.StatusCode)
	}
	if r := do(map[string]string{"Sec-Fetch-Site": "cross-site"}, ""); r.StatusCode != 403 {
		t.Errorf("Sec-Fetch-Site cross-site : %d", r.StatusCode)
	}
	if r := do(nil, "evil.example:8787"); r.StatusCode != 403 {
		t.Errorf("Host non local (DNS rebinding) : %d", r.StatusCode)
	}
	r := do(map[string]string{"Origin": "http://localhost:3000"}, "")
	if r.StatusCode != 200 || r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("origine autorisée : %d, ACAO %q", r.StatusCode, r.Header.Get("Access-Control-Allow-Origin"))
	}
	if r := do(nil, "localhost:8787"); r.StatusCode != 200 {
		t.Errorf("client CLI légitime refusé : %d", r.StatusCode)
	}
}

// Réponse gzip malgré Accept-Encoding: identity : réhydratée quand même.
func TestSecGzipResponseRehydrated(t *testing.T) {
	var p *Proxy
	p, srv := secProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.Write(gz([]byte(`{"text":"` + p.v.Placeholder("sk-ant-", key) + `"}`)).Bytes())
	}, nil)
	p.v.Mask([]byte(key))
	resp, _ := http.Post(srv.URL+"/anthropic/v1/messages", "application/json", strings.NewReader(`{}`))
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(b, []byte(key)) || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("réponse : %q (CE %q)", b, resp.Header.Get("Content-Encoding"))
	}
}

func TestSecBodyLimitAndConnectionHeaders(t *testing.T) {
	var got http.Header
	_, srv := secProxy(t, func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() },
		func(p *Proxy) { p.maxBody = 1024 })
	resp, _ := http.Post(srv.URL+"/anthropic/v1/messages", "application/json", strings.NewReader(strings.Repeat("x", 2048)))
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("corps trop gros : %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/anthropic/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Connection", "X-Secret-Hop")
	req.Header.Set("X-Secret-Hop", "ne-doit-pas-passer")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if got.Get("X-Secret-Hop") != "" {
		t.Error("en-tête nommé dans Connection relayé")
	}
}

// Placeholders : HMAC à clé, stables pour une clé donnée, différents sinon.
func TestSecKeyedPlaceholders(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadKey(filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := LoadKey(filepath.Join(dir, "k")) // relu, pas recréé
	if st, _ := os.Stat(filepath.Join(dir, "k")); st.Mode().Perm() != 0o600 || !bytes.Equal(k1, k2) {
		t.Fatalf("clé non persistée ou permissions %v", st.Mode().Perm())
	}
	a, b, c := NewVault(""), NewVault(""), NewVault("")
	a.SetKey(k1)
	b.SetKey(k1)
	if a.Placeholder("sk-ant-", key) != b.Placeholder("sk-ant-", key) {
		t.Error("même clé, placeholders différents")
	}
	if a.Placeholder("sk-ant-", key) == c.Placeholder("sk-ant-", key) {
		t.Error("clés différentes, même placeholder")
	}
}

// L'allowlist ne contient jamais le secret en clair, et survit au redémarrage.
func TestSecAllowlistHashed(t *testing.T) {
	dir := t.TempDir()
	k, _ := LoadKey(filepath.Join(dir, "k"))
	f := filepath.Join(dir, "allow")
	v := NewVault("")
	v.SetKey(k)
	v.LoadAllow(f)
	v.Allow(key)
	raw, _ := os.ReadFile(f)
	if bytes.Contains(raw, []byte(key)) || !bytes.HasPrefix(raw, []byte("hmac:")) {
		t.Fatalf("allowlist : %q", raw)
	}
	v2 := NewVault("")
	v2.SetKey(k)
	v2.LoadAllow(f)
	if out, n := v2.Mask([]byte(`"` + key + `"`)); n != 0 || !bytes.Contains(out, []byte(key)) {
		t.Fatalf("secret autorisé masqué après redémarrage : %s", out)
	}
}

// Enregistrement de secrets pendant des masquages concurrents : aucune fuite
// (le tri en place partagé avec un matcher en cours faisait rater des secrets).
func TestSecConcurrentRegistration(t *testing.T) {
	v := NewVault("")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s := "sk-ant-api03-" + strings.Repeat(string(rune('a'+g)), 10) + strings.Repeat("Z", i%17) + "0123456789abcdefgh"
				out, _ := v.Mask([]byte(`{"c":"` + s + ` ` + key + `"}`))
				if bytes.Contains(out, []byte(key)) || bytes.Contains(out, []byte(s)) {
					t.Errorf("secret non masqué")
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
