package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
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
	evBlocked // placeholder laissé intact dans un appel d'outil (Rule = type, Path = hôte, Ph)
)

type Proxy struct {
	providers []provider
	v         *Vault
	cl        *http.Client
	hint      bool
	events    chan Event

	loopback bool            // écoute locale : n'accepter qu'un Host local (anti DNS rebinding)
	origins  map[string]bool // origines navigateur autorisées (-allow-origin)
	maxBody  int64           // taille max d'un corps de requête (0 = défaut)
	cache    *segCache       // masquage incrémental (nil = désactivé)
	pol      *Policy         // politique de réhydratation des appels d'outils (nil = aucune)
}

// blocked signale un placeholder laissé intact dans un appel d'outil.
func (p *Proxy) blocked(prov string) func(kind, host, ph string) {
	return func(kind, host, ph string) {
		p.emit(Event{Kind: evBlocked, Rule: kind, Path: host, Ph: ph, Prov: prov})
	}
}

const defaultMaxBody = 256 << 20

// bufs regroupe les buffers d'une requête, réutilisés via un pool.
//
// Le client HTTP peut encore lire le corps de la requête amont après avoir
// rendu la réponse (réponse anticipée, nouvel essai…). Les buffers ne
// retournent donc au pool que lorsque le handler a fini ET que chaque corps
// transmis a été fermé : compteur de références.
type bufs struct {
	in, dec, resp bytes.Buffer
	mb            maskBufs
	hinted, out   []byte
	refs          atomic.Int32
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

// checkClient refuse ce qui vient d'un navigateur. Sans ça, n'importe quelle
// page web pourrait utiliser le proxy local (CSRF, DNS rebinding) et lire une
// réponse réhydratée, donc un secret, si le modèle y recopie un placeholder.
// Les SDK et CLI n'envoient ni Origin ni Sec-Fetch-Site.
func (p *Proxy) checkClient(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && !p.origins[o] {
		return "requête de navigateur refusée (Origin " + o + ")"
	}
	if s := r.Header.Get("Sec-Fetch-Site"); (s == "cross-site" || s == "same-site") && !p.origins[r.Header.Get("Origin")] {
		return "requête de navigateur refusée (Sec-Fetch-Site " + s + ")"
	}
	if p.loopback && !isLocalHost(r.Host) {
		return "Host non local refusé : " + r.Host
	}
	return ""
}

func isLocalHost(hostport string) bool {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// decodeBody décompresse un corps de requête : sans ça, un corps gzip passait
// sans être masqué. Encodage inconnu => refus (on ne relaie jamais en aveugle).
func decodeBody(enc string, in []byte, out *bytes.Buffer, limit int64) error {
	var zr io.Reader
	var err error
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip", "x-gzip":
		zr, err = gzip.NewReader(bytes.NewReader(in))
	case "deflate":
		if zr, err = zlib.NewReader(bytes.NewReader(in)); err != nil {
			zr, err = flate.NewReader(bytes.NewReader(in)), nil // deflate brut
		}
	default:
		return fmt.Errorf("Content-Encoding %q non pris en charge : impossible de masquer ce corps", enc)
	}
	if err != nil {
		return err
	}
	out.Reset()
	n, err := out.ReadFrom(io.LimitReader(zr, limit+1)) // borne : bombe de décompression
	if n > limit {
		return fmt.Errorf("corps décompressé trop volumineux")
	}
	return err
}

// skipHeader : hop-by-hop, plus les en-têtes nommés dans Connection (RFC 9110 §7.6.1).
func skipHeader(h http.Header, k string) bool {
	if _, hop := hopHeaders[k]; hop {
		return true
	}
	for _, c := range h["Connection"] {
		for _, t := range strings.Split(c, ",") {
			if textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(t)) == k {
				return true
			}
		}
	}
	return false
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	if why := p.checkClient(r); why != "" {
		p.emit(Event{Kind: evErr, Method: r.Method, Path: r.URL.Path, Rule: why})
		http.Error(w, "envguard : "+why, http.StatusForbidden)
		return
	}
	limit := p.maxBody
	if limit <= 0 {
		limit = defaultMaxBody
	}
	b := bufsPool.Get().(*bufs)
	b.refs.Store(1) // référence du handler
	defer b.release()
	b.in.Reset()
	if _, err := b.in.ReadFrom(http.MaxBytesReader(w, r.Body, limit)); err != nil {
		http.Error(w, "envguard : "+err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	raw := b.in.Bytes()
	decoded := false
	if ce := r.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		if err := decodeBody(ce, raw, &b.dec, limit); err != nil {
			p.emit(Event{Kind: evErr, Method: r.Method, Path: r.URL.Path, Rule: err.Error()})
			http.Error(w, "envguard : "+err.Error(), http.StatusUnsupportedMediaType)
			return
		}
		raw, decoded = b.dec.Bytes(), true // relayé décompressé
	}
	body, masked := p.cache.maskBody(p.v, &b.mb, raw)
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
	if len(body) > 0 {
		req.Body = b.body(body)
		req.GetBody = func() (io.ReadCloser, error) { return b.body(body), nil } // nouvel essai du client HTTP
	}
	req.ContentLength = int64(len(body))
	for k, vs := range r.Header {
		if !skipHeader(r.Header, k) && !(decoded && k == "Content-Encoding") {
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
	src := io.Reader(resp.Body)
	gz := false
	if ce := resp.Header.Get("Content-Encoding"); strings.EqualFold(ce, "gzip") {
		// L'amont a ignoré Accept-Encoding: identity : on décompresse pour
		// pouvoir réhydrater (sinon le client recevrait des placeholders).
		if zr, err := gzip.NewReader(resp.Body); err == nil {
			src, gz = zr, true
		}
	}
	for k, vs := range resp.Header {
		// Pas de CORS : un navigateur ne doit jamais pouvoir lire une réponse réhydratée.
		if skipHeader(resp.Header, k) || strings.HasPrefix(k, "Access-Control-") || (gz && k == "Content-Encoding") {
			continue
		}
		w.Header()[k] = vs
	}
	w.WriteHeader(resp.StatusCode)

	rehyd := 0
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		fl, _ := w.(http.Flusher)
		sr := &sseRewriter{v: p.v, w: w, fl: fl, pol: p.pol, onBlock: p.blocked(prov)}
		sr.run(src)
		rehyd = sr.count
	} else {
		b.resp.Reset()
		b.resp.ReadFrom(src)
		out, n := p.v.RehydrateDocTo(b.out, b.resp.Bytes(), 0, p.pol, p.blocked(prov))
		if n > 0 {
			b.out = out
		}
		rehyd = n
		w.Write(out)
	}
	p.emit(Event{Kind: evReq, Method: r.Method, Path: r.URL.Path, Status: resp.StatusCode, Masked: masked, Rehyd: rehyd, Dur: time.Since(t0), Prov: prov})
}
