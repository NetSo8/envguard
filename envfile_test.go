package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleEnv = `# configuration locale
NODE_ENV=development
PORT=3000
DEBUG=true
APP_URL=https://app.example.com
DATABASE_URL=postgres://app:Zq8vLm2pXr9T@db.internal:5432/app
export STRIPE_KEY=sk` + `_live_51HxQ2bKz8Lm4Np6Rq
SESSION_SECRET="k8#Zq2!vLm9@pXr4"   # pas de préfixe, juste un nom évocateur
INTERNAL_SIGNING='9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a'
WEBHOOK_HASHED=Q2xvdWQgaXMgdGhlIGJlc3Q9PT1hYmMxMjM0NTY3ODk
PASSWORD=password
EMPTY=
MULTI="ligne1
ligne2"
LOG_PATH=/var/log/app.log
`

func TestParseDotenv(t *testing.T) {
	got := map[string]string{}
	for _, kv := range parseDotenv([]byte(sampleEnv)) {
		got[kv.key] = kv.val
	}
	want := map[string]string{
		"STRIPE_KEY":       "sk" + "_live_51HxQ2bKz8Lm4Np6Rq",
		"SESSION_SECRET":   "k8#Zq2!vLm9@pXr4",
		"INTERNAL_SIGNING": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
		"MULTI":            "ligne1\nligne2",
		"PORT":             "3000",
		"EMPTY":            "",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, attendu %q", k, got[k], v)
		}
	}
}

func TestEnvSecretSelection(t *testing.T) {
	keep := map[string]bool{}
	for _, kv := range parseDotenv([]byte(sampleEnv)) {
		if envSecret(kv.key, kv.val) {
			keep[kv.key] = true
		}
	}
	for _, k := range []string{"STRIPE_KEY", "SESSION_SECRET", "WEBHOOK_HASHED"} {
		if !keep[k] {
			t.Errorf("%s devrait être masqué", k)
		}
	}
	for _, k := range []string{"NODE_ENV", "PORT", "DEBUG", "APP_URL", "PASSWORD", "EMPTY", "MULTI", "LOG_PATH"} {
		if keep[k] {
			t.Errorf("%s ne devrait pas être masqué (faux positif)", k)
		}
	}
}

func TestEnvFilesDiscovery(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".env", ".env.local", ".envrc", ".env.example", ".env.sample", ".env.production", "README.md"} {
		os.WriteFile(filepath.Join(dir, n), []byte("A=b\n"), 0o600)
	}
	var names []string
	for _, p := range envFiles(dir) {
		names = append(names, filepath.Base(p))
	}
	if got := strings.Join(names, ","); got != ".env,.env.local,.env.production,.envrc" {
		t.Fatalf("fichiers trouvés : %s", got)
	}
}

// Une valeur sans préfixe ni motif est masquée partout grâce au .env.
func TestEnvSecretMaskedEverywhere(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	os.WriteFile(f, []byte(sampleEnv), 0o600)
	v := NewVault("")
	n, err := v.loadEnvFile(f)
	if err != nil || n < 4 {
		t.Fatalf("%d secrets chargés (%v)", n, err)
	}
	body := []byte(`{"text":"le code compare avec k8#Zq2!vLm9@pXr4 et appelle sk` + `_live_51HxQ2bKz8Lm4Np6Rq en development, mot de passe Zq8vLm2pXr9T sur db.internal"}`)
	out, _ := v.Mask(body)
	if bytes.Contains(out, []byte("k8#Zq2!vLm9@pXr4")) || bytes.Contains(out, []byte("sk"+"_live_51HxQ2bKz8Lm4Np6Rq")) ||
		bytes.Contains(out, []byte("Zq8vLm2pXr9T")) || !bytes.Contains(out, []byte("db.internal")) {
		t.Fatalf("secret du .env non masqué : %s", out)
	}
	if !bytes.Contains(out, []byte("sk_live_REDACTED_")) || !bytes.Contains(out, []byte("development")) {
		t.Fatalf("préfixe perdu ou mot banal masqué : %s", out)
	}
}

func TestEnvWatch(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, ".env")
	os.WriteFile(f, []byte("A=b\n"), 0o600)
	v := NewVault("")
	go v.watchEnvFiles([]string{f}, 20*time.Millisecond, nil)
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(f, []byte("NEW_TOKEN=Zk8qLm2vPx9Tr4wQ7nB3\n"), 0o600)
	os.Chtimes(f, time.Now().Add(time.Second), time.Now().Add(time.Second))
	for i := 0; i < 50; i++ {
		if out, n := v.Mask([]byte("Zk8qLm2vPx9Tr4wQ7nB3")); n == 1 && !bytes.Contains(out, []byte("Zk8q")) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("modification du .env non prise en compte")
}
