package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCleanJSONC(t *testing.T) {
	input := `
	{
		// Ceci est un commentaire simple
		"url": "https://example.com/api?a=1&b=2//not-a-comment",
		/* Commentaire
		   multi-lignes */
		"mcpServers": {
			"server1": {
				"command": "npx",
				"args": ["-y", "pkg",], // trailing comma in array
			}, // trailing comma in object
		},
	}
	`
	cleaned := cleanJSONC([]byte(input))
	var out map[string]any
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("cleanJSONC a produit du JSON invalide : %v\nSortie :\n%s", err, string(cleaned))
	}

	url, _ := out["url"].(string)
	if url != "https://example.com/api?a=1&b=2//not-a-comment" {
		t.Fatalf("L'URL a été altérée par le nettoyage des commentaires : %s", url)
	}

	mcpServers, ok := out["mcpServers"].(map[string]any)
	if !ok || mcpServers["server1"] == nil {
		t.Fatalf("Structure mcpServers incorrecte après nettoyage")
	}
}

func TestStandardMCPProtectAndUnprotect(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "claude_desktop_config.json")

	initialJSON := `{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
    },
    "custom-bin": {
      "command": "my-tool"
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Détection initiale
	disc, err := parseMCPConfigFile(cfgPath, "TestTool")
	if err != nil {
		t.Fatalf("parseMCPConfigFile: %v", err)
	}
	if len(disc.Servers) != 2 {
		t.Fatalf("Attendu 2 serveurs, obtenu %d", len(disc.Servers))
	}
	if disc.Servers[0].Protected || disc.Servers[1].Protected {
		t.Fatalf("Les serveurs ne devraient pas être protégés initialement")
	}

	// 2. Protection
	changed, err := applyToConfig(disc, "envguard", false)
	if err != nil || changed != 2 {
		t.Fatalf("applyToConfig protect: changed=%d err=%v", changed, err)
	}

	// Vérifier la structure modifiée
	srvs := disc.Raw["mcpServers"].(map[string]any)
	pg := srvs["postgres"].(map[string]any)
	if pg["command"] != "envguard" {
		t.Fatalf("pg command attendu 'envguard', obtenu '%v'", pg["command"])
	}
	pgArgs, _ := pg["args"].([]any)
	if len(pgArgs) != 6 || pgArgs[0] != "mcp" || pgArgs[1] != "--" || pgArgs[2] != "npx" {
		t.Fatalf("pg args inattendus (len=%d): %v", len(pgArgs), pgArgs)
	}

	custom := srvs["custom-bin"].(map[string]any)
	if custom["command"] != "envguard" {
		t.Fatalf("custom command attendu 'envguard', obtenu '%v'", custom["command"])
	}
	customArgs, _ := custom["args"].([]any)
	if len(customArgs) != 3 || customArgs[0] != "mcp" || customArgs[1] != "--" || customArgs[2] != "my-tool" {
		t.Fatalf("custom args inattendus: %v", customArgs)
	}

	// 3. Idempotence : relancer la protection ne doit rien modifier
	changedSecond, err := applyToConfig(disc, "envguard", false)
	if err != nil || changedSecond != 0 {
		t.Fatalf("Idempotence échouée: changed=%d err=%v", changedSecond, err)
	}

	// 4. Déprotection (Unprotect)
	changedUnprotect, err := applyToConfig(disc, "", true)
	if err != nil || changedUnprotect != 2 {
		t.Fatalf("applyToConfig unprotect: changed=%d err=%v", changedUnprotect, err)
	}

	// Vérifier la restauration
	if pg["command"] != "npx" {
		t.Fatalf("pg restau command attendu 'npx', obtenu '%v'", pg["command"])
	}
	pgArgsRestored, _ := pg["args"].([]any)
	if len(pgArgsRestored) != 3 || pgArgsRestored[0] != "-y" {
		t.Fatalf("pg args restaurés inattendus (len=%d): %v", len(pgArgsRestored), pgArgsRestored)
	}

	if custom["command"] != "my-tool" {
		t.Fatalf("custom restau command attendu 'my-tool', obtenu '%v'", custom["command"])
	}
	if custom["args"] != nil {
		t.Fatalf("custom args devait être nil après restauration: %v", custom["args"])
	}
}

func TestOpenCodeProtectAndUnprotect(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "opencode.jsonc")

	initialJSON := `{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "supabase": {
      "type": "remote",
      "url": "https://mcp.supabase.com/mcp",
      "enabled": true
    },
    "local-postgres": {
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-postgres", "db_url"]
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	disc, err := parseMCPConfigFile(cfgPath, "OpenCode")
	if err != nil {
		t.Fatalf("parseMCPConfigFile: %v", err)
	}
	if len(disc.Servers) != 2 {
		t.Fatalf("Attendu 2 serveurs, obtenu %d", len(disc.Servers))
	}

	// Seul le local doit être modifiable
	changed, err := applyToConfig(disc, "envguard", false)
	if err != nil || changed != 1 {
		t.Fatalf("applyToConfig OpenCode protect: changed=%d err=%v", changed, err)
	}

	mcpMap := disc.Raw["mcp"].(map[string]any)
	local := mcpMap["local-postgres"].(map[string]any)
	cmdList, _ := local["command"].([]any)
	if len(cmdList) != 7 || cmdList[0] != "envguard" || cmdList[1] != "mcp" || cmdList[2] != "--" || cmdList[3] != "npx" {
		t.Fatalf("OpenCode command attendu envguard mcp -- ..., obtenu: %v", cmdList)
	}

	// Restaurer
	changedUnprotect, err := applyToConfig(disc, "", true)
	if err != nil || changedUnprotect != 1 {
		t.Fatalf("applyToConfig OpenCode unprotect: changed=%d err=%v", changedUnprotect, err)
	}

	restoredList, _ := local["command"].([]any)
	expectedList := []any{"npx", "-y", "@modelcontextprotocol/server-postgres", "db_url"}
	if !reflect.DeepEqual(restoredList, expectedList) {
		t.Fatalf("OpenCode restauration attendue %v, obtenu %v", expectedList, restoredList)
	}
}

func TestContinueArrayFormat(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	initialJSON := `{
  "mcpServers": [
    {
      "name": "sqlite",
      "command": "uvx",
      "args": ["mcp-server-sqlite", "--db-path", "test.db"]
    }
  ]
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	disc, err := parseMCPConfigFile(cfgPath, "Continue")
	if err != nil {
		t.Fatalf("parseMCPConfigFile: %v", err)
	}
	if len(disc.Servers) != 1 || disc.Servers[0].Name != "sqlite" {
		t.Fatalf("Serveur Continue non détecté: %v", disc.Servers)
	}

	changed, _ := applyToConfig(disc, "envguard", false)
	if changed != 1 {
		t.Fatalf("Continue protect changed=%d", changed)
	}

	srvList := disc.Raw["mcpServers"].([]any)
	first := srvList[0].(map[string]any)
	if first["command"] != "envguard" {
		t.Fatalf("command attendu envguard, obtenu %v", first["command"])
	}

	// Unprotect
	changedUnprotect, _ := applyToConfig(disc, "", true)
	if changedUnprotect != 1 {
		t.Fatalf("Continue unprotect changed=%d", changedUnprotect)
	}
	if first["command"] != "uvx" {
		t.Fatalf("command restauré attendu uvx, obtenu %v", first["command"])
	}
}

func TestZedContextServers(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "settings.json")

	initialJSON := `{
  "context_servers": {
    "git": {
      "command": "git-mcp",
      "args": ["--readonly"]
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(initialJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	disc, err := parseMCPConfigFile(cfgPath, "Zed")
	if err != nil {
		t.Fatalf("parseMCPConfigFile: %v", err)
	}
	if len(disc.Servers) != 1 || disc.Servers[0].Name != "git" {
		t.Fatalf("Serveur Zed non détecté")
	}

	changed, _ := applyToConfig(disc, "envguard", false)
	if changed != 1 {
		t.Fatalf("Zed protect changed=%d", changed)
	}
}

func TestBackupCreation(t *testing.T) {
	tmpDir := t.TempDir()
	origPath := filepath.Join(tmpDir, "mcp.json")
	origContent := `{"mcpServers":{"demo":{"command":"demo-bin"}}}`
	if err := os.WriteFile(origPath, []byte(origContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := backupFile(origPath); err != nil {
		t.Fatalf("backupFile: %v", err)
	}

	bakPath := origPath + ".envguard.bak"
	bakBytes, err := os.ReadFile(bakPath)
	if err != nil || string(bakBytes) != origContent {
		t.Fatalf("Sauvegarde .bak manquante ou corrompue: %v, contenu=%s", err, string(bakBytes))
	}

	// Modification du fichier original
	os.WriteFile(origPath, []byte(`{"mcpServers":{}}`), 0o644)

	// Un second backup ne doit PAS écraser la sauvegarde originale pristine
	if err := backupFile(origPath); err != nil {
		t.Fatalf("second backupFile: %v", err)
	}
	bakBytesSecond, _ := os.ReadFile(bakPath)
	if string(bakBytesSecond) != origContent {
		t.Fatalf("La sauvegarde originale pristine a été écrasée !")
	}
}

func TestCLIFlow(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "mcp.json")
	initialContent := `{"mcpServers":{"srv":{"command":"python","args":["server.py"]}}}`
	if err := os.WriteFile(cfgPath, []byte(initialContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Status avant
	if code := mcpStatusCmd([]string{cfgPath}); code != 0 {
		t.Fatalf("mcpStatusCmd code %d", code)
	}

	// 2. Protect -dry-run
	if code := mcpProtectCmd([]string{"-dry-run", cfgPath}); code != 0 {
		t.Fatalf("mcpProtectCmd dry-run code %d", code)
	}
	contentAfterDryRun, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(contentAfterDryRun), "python") {
		t.Fatalf("Dry run a modifié le fichier !")
	}

	// 3. Protect réel
	if code := mcpProtectCmd([]string{cfgPath}); code != 0 {
		t.Fatalf("mcpProtectCmd réel code %d", code)
	}
	contentAfterProtect, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(contentAfterProtect), "envguard") {
		t.Fatalf("Le fichier n'a pas été protégé: %s", string(contentAfterProtect))
	}

	// 4. Status après protection
	if code := mcpStatusCmd([]string{cfgPath}); code != 0 {
		t.Fatalf("mcpStatusCmd code %d", code)
	}

	// 5. Unprotect réel
	if code := mcpUnprotectCmd([]string{cfgPath}); code != 0 {
		t.Fatalf("mcpUnprotectCmd réel code %d", code)
	}
	contentAfterUnprotect, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(contentAfterUnprotect), "envguard") || !strings.Contains(string(contentAfterUnprotect), "python") {
		t.Fatalf("Le fichier n'a pas été restauré: %s", string(contentAfterUnprotect))
	}
}
