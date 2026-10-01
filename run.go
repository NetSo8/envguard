package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// envguard run [options] -- commande args…
//
// Lance le proxy sur un port libre, démarre la commande avec les variables
// d'URL de base qui pointent vers lui, et s'arrête avec elle. La commande
// occupe le terminal : le journal va dans un fichier (-log), et un résumé
// s'affiche à la fin.
//
// Si une URL de base est déjà définie (passerelle d'entreprise, autre
// proxy), envguard s'insère devant au lieu de l'écraser : elle devient
// l'amont du fournisseur correspondant.

// baseEnv : variable d'environnement -> fournisseur, et suffixe ajouté quand
// l'URL de base n'existait pas (les SDK OpenAI attendent « …/v1 »).
var baseEnv = []struct {
	name, prov, suffix string
}{
	{"ANTHROPIC_BASE_URL", "anthropic", ""},
	{"OPENAI_BASE_URL", "openai", "/v1"},
	{"OPENAI_API_BASE", "openai", "/v1"}, // ancien nom (aider, litellm…)
	{"GOOGLE_GEMINI_BASE_URL", "gemini", ""},
}

func runCmd(args []string) int {
	o := options{listen: "127.0.0.1:0"}
	fs := newFlags("envguard run", &o)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage : envguard run [options] -- commande [args…]\n\nExemple : envguard run -- claude\n\nOptions :\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fs.Usage()
		return 2
	}

	// Chaînage : une URL de base existante devient l'amont du fournisseur.
	self := os.Getenv("ENVGUARD_URL")
	chained := map[string]bool{}
	for _, b := range baseEnv {
		u := os.Getenv(b.name)
		if u == "" || chained[b.prov] || o.provSet[b.prov] || self != "" && strings.HasPrefix(u, self) {
			continue // -provider explicite : prioritaire sur l'environnement
		}
		providerFlag{ps: &o.provs}.Set(b.prov + "=" + strings.TrimSuffix(u, "/"))
		chained[b.prov] = true
	}

	p, envPaths, err := setup(&o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envguard :", err)
		return 1
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envguard :", err)
		return 1
	}
	serve(p, ln)
	base := "http://" + ln.Addr().String()

	// Journal : jamais sur le terminal (il appartient à la commande lancée).
	var logw *os.File
	if o.logFile != "" {
		os.MkdirAll(filepath.Dir(o.logFile), 0o700)
		logw, _ = os.OpenFile(o.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if logw != nil {
			defer logw.Close()
		}
	}
	var mu sync.Mutex
	var nSecrets, nMasked, nRehyd, nBlocked int
	var blocked []string
	go func() {
		for e := range p.events {
			mu.Lock()
			switch e.Kind {
			case evReq:
				nMasked += e.Masked
				nRehyd += e.Rehyd
			case evSecret:
				nSecrets++
			case evBlocked:
				nBlocked++
				if len(blocked) < 5 {
					blocked = append(blocked, fmt.Sprintf("%s vers %s (si légitime : -allow-host %s=%s)", e.Ph, e.Path, e.Rule, e.Path))
				}
			}
			mu.Unlock()
			if logw != nil {
				logEvent(logw, e)
			}
		}
	}()

	env := os.Environ()
	set := func(k, v string) { env = append(env, k+"="+v) } // la dernière occurrence l'emporte
	for _, b := range baseEnv {
		suffix := b.suffix
		if chained[b.prov] {
			suffix = "" // on reproduit exactement le chemin de l'URL d'origine
		}
		set(b.name, base+"/"+b.prov+suffix)
	}
	set("ENVGUARD_URL", base)

	fmt.Fprintf(os.Stderr, "envguard : proxy actif sur %s", base)
	if len(envPaths) > 0 {
		fmt.Fprintf(os.Stderr, ", %d fichier(s) .env surveillé(s)", len(envPaths))
	}
	if logw != nil {
		fmt.Fprintf(os.Stderr, ", journal : %s", o.logFile)
	}
	fmt.Fprintln(os.Stderr)

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.Env = os.Stdin, os.Stdout, os.Stderr, env

	// Ctrl+C est déjà reçu par la commande (même groupe de processus) : on
	// l'ignore ici pour que le proxy vive jusqu'à sa fin. SIGTERM et SIGHUP,
	// envoyés à envguard seul, sont relayés.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "envguard :", err)
		return 127
	}
	go func() {
		for s := range sigs {
			if s == syscall.SIGTERM || s == syscall.SIGHUP {
				cmd.Process.Signal(s)
			}
		}
	}()
	err = cmd.Wait()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		}
	} else if err != nil {
		code = 1
	}

	// Laisse le temps aux derniers événements d'arriver. Le canal n'est pas
	// fermé : un sous-processus encore vivant peut toujours appeler le proxy.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	fmt.Fprintf(os.Stderr, "envguard : %d secret(s) détecté(s), %d masquage(s), %d réhydratation(s)", nSecrets, nMasked, nRehyd)
	if nBlocked > 0 {
		fmt.Fprintf(os.Stderr, ", %d réhydratation(s) BLOQUÉE(S) :\n", nBlocked)
		for _, b := range blocked {
			fmt.Fprintln(os.Stderr, "  "+b)
		}
	} else {
		fmt.Fprintln(os.Stderr)
	}
	mu.Unlock()
	return code
}
