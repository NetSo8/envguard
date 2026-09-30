package main

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
	"time"
)

const hint = "Values matching *REDACTED_* are masked secrets. Always copy them verbatim, character for character: never encode, split, re-case or alter them."

type Event struct {
	Kind   uint8 // evReq, evSecret, evErr
	Method string
	Path   string
	Status int
	Masked int
	Rehyd  int
	Dur    time.Duration
	Secret string
	Ph     string
	Rule   string
	Prov   string
}

const (
	evReq uint8 = iota
	evSecret
	evErr
)

type Proxy struct {
	providers []provider
	v         *Vault
	cl        *http.Client
	hint      bool
	events    chan Event
}

var bufPool = sync.Pool{New: func() any { return bytes.NewBuffer(make([]byte, 0, 64<<10)) }}

func (p *Proxy) emit(e Event) {
	select { // jamais bloquant : on préfère perdre un event UI que ralentir le proxy
	case p.events <- e:
	default:
	}
}

var hopHeaders = map[string]struct{}{
	"Connection": {}, "Keep-Alive": {}, "Proxy-Connection": {}, "Transfer-Encoding": {},
	"Upgrade": {}, "Te": {}, "Trailer": {}, "Content-Length": {}, "Accept-Encoding": {}, "Host": {},
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	if _, err := buf.ReadFrom(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, masked := p.v.Mask(buf.Bytes())
	pr, path := p.route(r)
	prov := pr.name
	if p.hint && p.v.HasSecrets() {
		body = injectHint(body, path)
	}

	u := *pr.up
	u.Path = strings.TrimSuffix(pr.up.Path, "/") + path
	u.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		if _, hop := hopHeaders[k]; !hop {
			req.Header[k] = vs
		}
	}
	req.Header.Set("Accept-Encoding", "identity") // on doit lire le texte en clair
	req.ContentLength = int64(len(body))

	resp, err := p.cl.Do(req)
	if err != nil {
		p.emit(Event{Kind: evErr, Method: r.Method, Path: r.URL.Path, Rule: err.Error(), Prov: prov})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if _, hop := hopHeaders[k]; !hop {
			w.Header()[k] = vs
		}
	}
	w.WriteHeader(resp.StatusCode)

	rehyd := 0
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		fl, _ := w.(http.Flusher)
		sr := &sseRewriter{v: p.v, w: w, fl: fl}
		sr.run(resp.Body)
		rehyd = sr.count
	} else {
		buf.Reset()
		buf.ReadFrom(resp.Body)
		out, n := p.v.Rehydrate(buf.Bytes())
		rehyd = n
		w.Write(out)
	}
	p.emit(Event{Kind: evReq, Method: r.Method, Path: r.URL.Path, Status: resp.StatusCode, Masked: masked, Rehyd: rehyd, Dur: time.Since(t0), Prov: prov})
}
