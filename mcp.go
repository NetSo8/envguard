package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// envguard mcp [options] -- commande args…
//
// Lance un serveur MCP (Model Context Protocol) en sous-processus et s'intercale
// sur ses canaux standard (stdio) :
//   - Serveur -> Client (stdout) : chaque message JSON-RPC émis par le serveur
//     (ex: résultats de requêtes SQL, fetch, lecture de fichiers) est analysé
//     en direct ; les secrets détectés sont remplacés par des placeholders
//     avant d'atteindre le client (Claude Code, Cursor, Windsurf...).
//   - Client -> Serveur (stdin) : les arguments d'appels d'outils (tools/call)
//     sont réhydratés avec leurs vraies valeurs selon la politique de sécurité
//     (blocage des exfiltrations réseau et de l'écriture dans le code source).
//   - stderr : transmis directement pour les journaux de diagnostic du serveur.
//
// Le journal d'audit est écrit dans <config>/envguard/mcp.log (jamais sur stdout).
func mcpCmd(args []string) int {
	cfgDir, _ := os.UserConfigDir()
	o := options{
		logFile: filepath.Join(cfgDir, "envguard", "mcp.log"),
	}
	fs := newFlags("envguard mcp", &o)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage : envguard mcp [options] -- commande [args…]\n\nExemple : envguard mcp -- npx @modelcontextprotocol/server-postgres postgresql://localhost/mydb\n\nOptions :\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fs.Usage()
		return 2
	}

	v, pol, envPaths, err := setupVault(&o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envguard mcp :", err)
		return 1
	}

	var logw *os.File
	if o.logFile != "" {
		os.MkdirAll(filepath.Dir(o.logFile), 0o700)
		logw, _ = os.OpenFile(o.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if logw != nil {
			defer logw.Close()
		}
	}

	var mu sync.Mutex
	onBlock := func(kind, host, ph string) {
		mu.Lock()
		defer mu.Unlock()
		if logw != nil {
			logEvent(logw, Event{Kind: evBlocked, Rule: kind, Path: host, Ph: ph, Prov: "mcp"})
		}
	}
	v.onNew = func(kind, secret, ph string) {
		mu.Lock()
		defer mu.Unlock()
		if logw != nil {
			logEvent(logw, Event{Kind: evSecret, Rule: kind, Secret: secret, Ph: ph, Prov: "mcp"})
		}
	}

	if len(envPaths) > 0 {
		go v.watchEnvFiles(envPaths, 2*time.Second, func(f string, err error) {
			mu.Lock()
			defer mu.Unlock()
			if logw != nil {
				logEvent(logw, Event{Kind: evErr, Path: f, Rule: err.Error()})
			}
		})
	}

	code, err := runMCP(os.Stdin, os.Stdout, os.Stderr, cmdArgs, v, pol, onBlock)
	if err != nil && code == 0 {
		code = 1
	}
	return code
}

func runMCP(clientIn io.Reader, clientOut, clientErr io.Writer, cmdArgs []string, v *Vault, pol *Policy, onBlock func(kind, host, ph string)) (int, error) {
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stderr = clientErr

	childIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, err
	}

	if err := cmd.Start(); err != nil {
		return 127, err
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	go func() {
		for s := range sigs {
			if s == syscall.SIGTERM || s == syscall.SIGHUP || s == os.Interrupt {
				if cmd.Process != nil {
					cmd.Process.Signal(s)
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Serveur (stdin)
	go func() {
		defer wg.Done()
		defer childIn.Close()
		filterClientToChild(clientIn, childIn, v, pol, onBlock)
	}()

	// Serveur -> Client (stdout)
	go func() {
		defer wg.Done()
		filterChildToClient(childOut, clientOut, v)
	}()

	wg.Wait()

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
	return code, err
}

// filterChildToClient lit les messages JSON-RPC émis par le serveur MCP,
// masque les secrets détectés avec un buffer réutilisable (zéro allocation)
// et écrit le résultat sur le stdout du client.
func filterChildToClient(r io.Reader, w io.Writer, v *Vault) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var buf []byte
	var dst []byte
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			buf = append(buf, line...)
			if line[len(line)-1] == '\n' {
				masked, _ := v.MaskTo(dst, buf)
				if _, werr := w.Write(masked); werr != nil {
					return werr
				}
				dst = masked[:0]
				buf = buf[:0]
			}
		}
		if err == bufio.ErrBufferFull {
			continue // ligne > 64 Ko : on accumule dans buf jusqu'au prochain '\n'
		}
		if err != nil {
			if len(buf) > 0 {
				masked, _ := v.MaskTo(dst, buf)
				w.Write(masked)
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// filterClientToChild lit les requêtes JSON-RPC du client (Claude, Cursor...),
// réhydrate les placeholders dans les arguments d'outils selon la politique
// de sécurité et relaie au stdin du serveur MCP.
func filterClientToChild(r io.Reader, w io.Writer, v *Vault, pol *Policy, onBlock func(kind, host, ph string)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var buf []byte
	var dst []byte
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			buf = append(buf, line...)
			if line[len(line)-1] == '\n' {
				var toWrite []byte
				if bytes.Contains(buf, marker) {
					rehydrated, _ := v.RehydrateDocTo(dst, buf, 0, pol, onBlock)
					toWrite = rehydrated
					dst = rehydrated[:0]
				} else {
					toWrite = buf
				}
				if _, werr := w.Write(toWrite); werr != nil {
					return werr
				}
				buf = buf[:0]
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if len(buf) > 0 {
				var toWrite []byte
				if bytes.Contains(buf, marker) {
					rehydrated, _ := v.RehydrateDocTo(dst, buf, 0, pol, onBlock)
					toWrite = rehydrated
				} else {
					toWrite = buf
				}
				w.Write(toWrite)
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
