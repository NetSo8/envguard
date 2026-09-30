package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

// bufs regroupe les buffers d'une requête, réutilisés via un pool.
//
// Le client HTTP peut encore lire le corps de la requête amont après avoir
// rendu la réponse (réponse anticipée, nouvel essai…). Les buffers ne
// retournent donc au pool que lorsque le handler a fini ET que chaque corps
// transmis a été fermé : compteur de références.
type bufs struct {
	in, resp          bytes.Buffer
	mask, hinted, out []byte
	refs              atomic.Int32
}

var bufsPool = sync.Pool{New: func() any { return new(bufs) }}

func (b *bufs) retain() { b.refs.Add(1) }

func (b *bufs) release() {
	if b.refs.Add(-1) == 0 {
		bufsPool.Put(b)
	}
}

// reqBody rend sa référence sur les buffers quand le client HTTP le ferme.
type reqBody struct {
	*bytes.Reader
	b    *bufs
	once sync.Once
}

func (r *reqBody) Close() error {
	r.once.Do(r.b.release)
	return nil
}

func (b *bufs) body(p []byte) *reqBody {
	b.retain()
	return &reqBody{Reader: bytes.NewReader(p), b: b}
}

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
	b := bufsPool.Get().(*bufs)
	b.refs.Store(1) // référence du handler
	defer b.release()
	b.in.Reset()
	if _, err := b.in.ReadFrom(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, masked := p.v.MaskTo(b.mask, b.in.Bytes())
	if masked > 0 {
		b.mask = body // garde la capacité pour la prochaine requête
	}
	pr, path := p.route(r)
	prov := pr.name
	if p.hint && p.v.HasSecrets() {
		if out := injectHint(b.hinted, body, path); len(out) != len(body) {
			b.hinted, body = out, out
		}
	}

	u := *pr.up
	u.Path = strings.TrimSuffix(pr.up.Path, "/") + path
	u.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Body = b.body(body)
	req.GetBody = func() (io.ReadCloser, error) { return b.body(body), nil } // nouvel essai du client HTTP
	req.ContentLength = int64(len(body))
	for k, vs := range r.Header {
		if _, hop := hopHeaders[k]; !hop {
			req.Header[k] = vs
		}
	}
	req.Header.Set("Accept-Encoding", "identity") // on doit lire le texte en clair

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
		b.resp.Reset()
		b.resp.ReadFrom(resp.Body)
		out, n := p.v.RehydrateTo(b.out, b.resp.Bytes())
		if n > 0 {
			b.out = out
		}
		rehyd = n
		w.Write(out)
	}
	p.emit(Event{Kind: evReq, Method: r.Method, Path: r.URL.Path, Status: resp.StatusCode, Masked: masked, Rehyd: rehyd, Dur: time.Since(t0), Prov: prov})
}
