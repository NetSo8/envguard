package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// options : configuration commune à « envguard » et « envguard run ».
type options struct {
	listen     string
	provs      []provider
	provSet    map[string]bool // fournisseurs donnés explicitement par -provider
	allow      string
	keyFile    string
	noHint     bool
	noTUI      bool
	maxBody    int64
	origins    originsFlag
	envFiles   listFlag
	noEnv      bool
	toolPolicy string
	allowHosts listFlag
	logFile    string // run : journal (l'outil lancé occupe le terminal)
	noGL       bool
	glExclude  listFlag
}

func newFlags(name string, o *options) *flag.FlagSet {
	home, _ := os.UserHomeDir()
	cfgDir, _ := os.UserConfigDir()
	o.provs = append([]provider(nil), defaultProviders...)
	o.provSet = map[string]bool{}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&o.listen, "listen", o.listen, "adresse d'écoute")
	fs.Var(providerFlag{&o.provs, o.provSet}, "provider", "ajoute/surcharge un fournisseur : nom=url (répétable)")
	fs.StringVar(&o.allow, "allow", filepath.Join(home, ".envguard_allow"), "allowlist (envguard n'y écrit que des HMAC)")
	fs.StringVar(&o.keyFile, "key", filepath.Join(cfgDir, "envguard", "key"), "clé qui dérive les placeholders (créée au besoin, 0600)")
	fs.BoolVar(&o.noHint, "no-hint", false, "ne pas injecter la consigne dans le system prompt")
	fs.Int64Var(&o.maxBody, "max-body", defaultMaxBody, "taille max d'un corps de requête, en octets")
	fs.Var(&o.origins, "allow-origin", "origine navigateur autorisée, ex. http://localhost:3000 (répétable)")
	fs.Var(&o.envFiles, "env-file", "fichier .env dont les valeurs sont masquées (répétable ; par défaut : les .env du dossier courant)")
	fs.BoolVar(&o.noEnv, "no-env", false, "ne pas lire les fichiers .env du dossier courant")
	fs.StringVar(&o.toolPolicy, "tool-policy", "strict", "réhydratation dans les appels d'outils : strict, warn ou off")
	fs.Var(&o.allowHosts, "allow-host", "destination autorisée pour un type de secret : type=hôte, ex. env:API_TOKEN=api.exemple.com (répétable)")
	fs.BoolVar(&o.noGL, "no-gitleaks", false, "désactiver les règles gitleaks")
	fs.Var(&o.glExclude, "gitleaks-exclude", "règle gitleaks à ignorer, ex. twilio-api-key (répétable ; generic-api-key et jwt le sont toujours)")
	fs.StringVar(&o.logFile, "log", filepath.Join(cfgDir, "envguard", "run.log"), "journal de « envguard run »")
	return fs
}

// setup construit le vault et le proxy à partir des options.
func setup(o *options) (*Proxy, []string, error) {
	provs, err := parseProviders(o.provs)
	if err != nil {
		return nil, nil, err
	}
	pol, err := parsePolicy(o.toolPolicy, o.allowHosts)
	if err != nil {
		return nil, nil, err
	}
	key, err := LoadKey(o.keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("clé %s : %v", o.keyFile, err)
	}
	v := NewVault("")
	v.SetKey(key)
	v.LoadAllow(o.allow) // après la clé : l'allowlist est stockée en HMAC
	if !o.noGL {
		if v.gl, err = loadGitleaks(append(append([]string(nil), gitleaksDefaultExclude...), o.glExclude...)); err != nil {
			return nil, nil, err
		}
	}
	host, _, _ := net.SplitHostPort(o.listen)
	p := &Proxy{
		providers: provs,
		v:         v,
		hint:      !o.noHint,
		loopback:  isLocalHost(host),
		origins:   o.origins,
		maxBody:   o.maxBody,
		cache:     newSegCache(),
		pol:       pol,
		events:    make(chan Event, 1024),
		cl: &http.Client{Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
			DisableCompression:  true,
		}},
	}
	v.onNew = func(kind, secret, ph string) { p.emit(Event{Kind: evSecret, Rule: kind, Secret: secret, Ph: ph}) }

	// Fichiers .env : chargés avant la première requête, puis surveillés.
	paths := []string(o.envFiles)
	if len(paths) == 0 && !o.noEnv {
		paths = envFiles(".")
	}
	for _, f := range paths {
		if _, err := v.loadEnvFile(f); err != nil {
			return nil, nil, fmt.Errorf("fichier .env %s : %v", f, err)
		}
	}
	if len(paths) > 0 {
		go v.watchEnvFiles(paths, 2*time.Second, func(f string, err error) {
			p.emit(Event{Kind: evErr, Path: f, Rule: err.Error()})
		})
	}
	return p, paths, nil
}

func serve(p *Proxy, ln net.Listener) {
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
}

// logEvent écrit un événement sans jamais écrire de secret (même partiel).
func logEvent(w io.Writer, e Event) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	switch e.Kind {
	case evReq:
		fmt.Fprintf(w, "%s [%s] %s %s %d masqués=%d réhydratés=%d %s\n", ts, e.Prov, e.Method, e.Path, e.Status, e.Masked, e.Rehyd, e.Dur.Round(time.Millisecond))
	case evSecret:
		fmt.Fprintf(w, "%s secret %s → %s\n", ts, e.Rule, e.Ph)
	case evBlocked:
		fmt.Fprintf(w, "%s RÉHYDRATATION BLOQUÉE %s vers %s (si légitime : -allow-host %s=%s)\n", ts, e.Ph, e.Path, e.Rule, e.Path)
	case evErr:
		fmt.Fprintf(w, "%s erreur %s : %s\n", ts, e.Path, e.Rule)
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		os.Exit(runCmd(os.Args[2:]))
	}
	o := options{listen: "127.0.0.1:8787"}
	fs := newFlags("envguard", &o)
	fs.BoolVar(&o.noTUI, "no-tui", false, "mode headless (logs sur stderr)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage :\n  envguard [options]              proxy + TUI\n  envguard run [options] -- cmd   lance cmd derrière le proxy\n\nOptions :\n")
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	p, envPaths, err := setup(&o)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		log.Fatal(err)
	}
	serve(p, ln)

	if !p.loopback {
		fmt.Fprintf(os.Stderr, "ATTENTION : envguard écoute sur %s, accessible depuis le réseau. Toute machine qui l'atteint peut lire des réponses réhydratées.\n", o.listen)
	}
	if o.noTUI {
		fmt.Fprintf(os.Stderr, "envguard écoute sur %s\n", o.listen)
		for _, pr := range p.providers {
			fmt.Fprintf(os.Stderr, "  %-11s http://%s/%s → %s\n", pr.name, o.listen, pr.name, pr.base)
		}
		if len(envPaths) > 0 {
			fmt.Fprintf(os.Stderr, "fichiers .env surveillés : %s\n", strings.Join(envPaths, ", "))
		}
		for e := range p.events {
			logEvent(os.Stderr, e)
		}
		return
	}
	if _, err := tea.NewProgram(&model{p: p, listen: o.listen}, tea.WithAltScreen()).Run(); err != nil {
		log.Fatal(err)
	}
}

// originsFlag : -allow-origin répétable.
type originsFlag map[string]bool

func (o *originsFlag) String() string { return "" }

func (o *originsFlag) Set(s string) error {
	if *o == nil {
		*o = map[string]bool{}
	}
	(*o)[strings.TrimSuffix(s, "/")] = true
	return nil
}

// listFlag : option texte répétable.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }
