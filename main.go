package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	home, _ := os.UserHomeDir()
	listen := flag.String("listen", "127.0.0.1:8787", "adresse d'écoute")
	provs := append([]provider(nil), defaultProviders...)
	flag.Var(providerFlag{&provs}, "provider", "ajoute/surcharge un fournisseur : nom=url (répétable)")
	allow := flag.String("allow", filepath.Join(home, ".envguard_allow"), "fichier allowlist (une valeur par ligne)")
	noHint := flag.Bool("no-hint", false, "ne pas injecter la consigne dans le system prompt")
	noTUI := flag.Bool("no-tui", false, "mode headless (logs sur stderr)")
	flag.Parse()

	provs, err := parseProviders(provs)
	if err != nil {
		log.Fatal(err)
	}
	v := NewVault(*allow)
	p := &Proxy{
		providers: provs,
		v:         v,
		hint:      !*noHint,
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

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)

	if *noTUI {
		fmt.Fprintf(os.Stderr, "envguard écoute sur %s\n", *listen)
		for _, pr := range provs {
			fmt.Fprintf(os.Stderr, "  %-11s http://%s/%s → %s\n", pr.name, *listen, pr.name, pr.base)
		}
		for e := range p.events {
			switch e.Kind {
			case evReq:
				log.Printf("[%s] %s %s %d masqués=%d réhydratés=%d %s", e.Prov, e.Method, e.Path, e.Status, e.Masked, e.Rehyd, e.Dur)
			case evSecret:
				log.Printf("secret %s %s → %s", e.Rule, preview(e.Secret), e.Ph)
			case evErr:
				log.Printf("erreur %s: %s", e.Path, e.Rule)
			}
		}
		return
	}
	if _, err := tea.NewProgram(&model{p: p, listen: *listen}, tea.WithAltScreen()).Run(); err != nil {
		log.Fatal(err)
	}
}
