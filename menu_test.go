package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestMenuModelNavigation(t *testing.T) {
	m := newMenuModel()
	if m.screen != screenMain {
		t.Fatalf("Attendu screenMain, obtenu %v", m.screen)
	}

	// Navigation bas / haut
	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.mainCur != 1 {
		t.Fatalf("Attendu mainCur=1, obtenu %d", m.mainCur)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.mainCur != 0 {
		t.Fatalf("Attendu mainCur=0, obtenu %d", m.mainCur)
	}

	// Touche 2 -> écran MCP
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	if m.screen != screenMCP {
		t.Fatalf("Attendu screenMCP, obtenu %v", m.screen)
	}

	// Échap -> retour écran principal
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != screenMain {
		t.Fatalf("Attendu screenMain après Esc, obtenu %v", m.screen)
	}

	// Touche 3 -> écran Run
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if m.screen != screenRun {
		t.Fatalf("Attendu screenRun, obtenu %v", m.screen)
	}

	// Sélection du premier outil (Claude)
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.action != actionRunCommand || len(m.runArgs) == 0 || m.runArgs[0] != "claude" {
		t.Fatalf("Attendu actionRunCommand avec claude, obtenu action=%v args=%v", m.action, m.runArgs)
	}

	// Touche 1 -> lancer le proxy
	m2 := newMenuModel()
	m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if m2.action != actionStartProxy {
		t.Fatalf("Attendu actionStartProxy, obtenu %v", m2.action)
	}
}

func TestMenuMCPToggle(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "mcp.json")
	initialContent := `{"mcpServers":{"test-srv":{"command":"python","args":["main.py"]}}}`
	if err := os.WriteFile(cfgPath, []byte(initialContent), 0o644); err != nil {
		t.Fatal(err)
	}

	m := newMenuModel()
	m.screen = screenMCP
	m.mcpItems = []mcpRow{
		{
			toolName:  "Test",
			path:      cfgPath,
			name:      "test-srv",
			command:   "python",
			protected: false,
		},
	}
	m.mcpCur = 0

	// Test direct de toggleSingleServer
	newState, err := toggleSingleServer(cfgPath, "Test", "test-srv")
	if err != nil || !newState {
		t.Fatalf("Attendu protection réussie (newState=true), obtenu newState=%v err=%v", newState, err)
	}

	content, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(content), "envguard") {
		t.Fatalf("Le serveur devait être protégé : %s", string(content))
	}

	// 2ème toggle : restauration
	newState2, err := toggleSingleServer(cfgPath, "Test", "test-srv")
	if err != nil || newState2 {
		t.Fatalf("Attendu déprotection réussie (newState2=false), obtenu newState2=%v err=%v", newState2, err)
	}

	contentAfter, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(contentAfter), "envguard") {
		t.Fatalf("Le serveur devait être rétabli : %s", string(contentAfter))
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && filepath.Base(s) != "" && stringContains(s, sub)))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
