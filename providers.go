package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Registre des fournisseurs. On route par préfixe de chemin :
//
//	http://127.0.0.1:8787/<nom>/<chemin officiel>  →  <base>/<chemin officiel>
//
// Presque tous parlent le format OpenAI Chat Completions ; certains exposent
// aussi le format Anthropic Messages (DeepSeek, Meta, Moonshot, Z.ai…) ou
// leur format natif (Gemini). Le rewriter SSE détecte le format au contenu,
// pas au fournisseur : un nouveau fournisseur « compatible » marche d'office.
type provider struct {
	name string
	base string
	env  string // suggestion affichée dans la TUI (base à donner au client)
	up   *url.URL
}

var defaultProviders = []provider{
	{name: "anthropic", base: "https://api.anthropic.com", env: "ANTHROPIC_BASE_URL=%s"},
	{name: "openai", base: "https://api.openai.com", env: "OPENAI_BASE_URL=%s/v1"},
	{name: "gemini", base: "https://generativelanguage.googleapis.com", env: "GOOGLE_GEMINI_BASE_URL=%s  (compat OpenAI: %s/v1beta/openai)"},
	{name: "deepseek", base: "https://api.deepseek.com", env: "base %s  (Anthropic: %s/anthropic)"},
	{name: "meta", base: "https://api.meta.ai", env: "base %s/v1  (Muse Spark)"},
	{name: "xai", base: "https://api.x.ai", env: "base %s/v1"},
	{name: "mistral", base: "https://api.mistral.ai", env: "base %s/v1"},
	{name: "groq", base: "https://api.groq.com/openai", env: "base %s/v1"},
	{name: "openrouter", base: "https://openrouter.ai/api", env: "base %s/v1"},
	{name: "together", base: "https://api.together.xyz", env: "base %s/v1"},
	{name: "fireworks", base: "https://api.fireworks.ai/inference", env: "base %s/v1"},
	{name: "qwen", base: "https://dashscope-intl.aliyuncs.com/compatible-mode", env: "base %s/v1"},
	{name: "moonshot", base: "https://api.moonshot.ai", env: "base %s/v1"},
	{name: "zai", base: "https://api.z.ai/api/paas/v4", env: "base %s"},
	{name: "perplexity", base: "https://api.perplexity.ai", env: "base %s"},
	{name: "cohere", base: "https://api.cohere.ai/compatibility", env: "base %s/v1"},
	{name: "ollama", base: "http://127.0.0.1:11434", env: "base %s/v1"},
}

// providerFlag permet -provider nom=url (ajout ou surcharge), répétable.
// seen (facultatif) retient les noms donnés explicitement.
type providerFlag struct {
	ps   *[]provider
	seen map[string]bool
}

func (f providerFlag) String() string { return "" }

func (f providerFlag) Set(s string) error {
	name, base, ok := strings.Cut(s, "=")
	if !ok || name == "" || base == "" {
		return fmt.Errorf("format attendu nom=url")
	}
	if f.seen != nil {
		f.seen[name] = true
	}
	for i := range *f.ps {
		if (*f.ps)[i].name == name {
			(*f.ps)[i].base = base
			return nil
		}
	}
	*f.ps = append(*f.ps, provider{name: name, base: base, env: "base %s"})
	return nil
}

func parseProviders(ps []provider) ([]provider, error) {
	for i := range ps {
		u, err := url.Parse(ps[i].base)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("provider %s: url invalide %q", ps[i].name, ps[i].base)
		}
		ps[i].up = u
	}
	return ps, nil
}

func (p *Proxy) byName(name string) *provider {
	for i := range p.providers {
		if p.providers[i].name == name {
			return &p.providers[i]
		}
	}
	return nil
}

// route : préfixe /<nom>/ d'abord ; sinon rétrocompat (headers Anthropic →
// anthropic, reste → openai). Renvoie le fournisseur et le chemin amont.
func (p *Proxy) route(r *http.Request) (*provider, string) {
	path := r.URL.Path
	if seg, rest, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/"); seg != "" {
		if pr := p.byName(seg); pr != nil {
			return pr, "/" + rest
		}
	}
	if r.Header.Get("anthropic-version") != "" || r.Header.Get("x-api-key") != "" || strings.HasSuffix(path, "/messages") {
		return p.byName("anthropic"), path
	}
	return p.byName("openai"), path
}
