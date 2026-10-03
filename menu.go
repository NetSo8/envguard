package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type menuAction int

const (
	actionNone menuAction = iota
	actionStartProxy
	actionRunCommand
	actionQuit
)

type menuScreen int

const (
	screenMain menuScreen = iota
	screenMCP
	screenRun
	screenAudit
)

type mainMenuItem struct {
	icon  string
	title string
	desc  string
}

type menuModel struct {
	screen   menuScreen
	mainCur  int
	mcpCur   int
	runCur   int
	mcpItems []mcpRow
	mcpNote  string
	auditLog []string
	action   menuAction
	runArgs  []string
	w, h     int
}

func newMenuModel() *menuModel {
	m := &menuModel{
		screen: screenMain,
	}
	m.refreshMCP()
	m.refreshAudit()
	return m
}

func (m *menuModel) refreshMCP() {
	files, _ := discoverConfigs(nil)
	var rows []mcpRow
	for _, f := range files {
		for _, s := range f.Servers {
			rows = append(rows, mcpRow{
				toolName:  f.ToolName,
				path:      f.Path,
				name:      s.Name,
				command:   s.Command,
				protected: s.Protected,
				remote:    s.Remote,
			})
		}
	}
	m.mcpItems = rows
	if m.mcpCur >= len(m.mcpItems) && len(m.mcpItems) > 0 {
		m.mcpCur = len(m.mcpItems) - 1
	}
}

func (m *menuModel) refreshAudit() {
	var lines []string
	paths := envFiles(".")
	if len(paths) == 0 {
		lines = append(lines, sMuted.Render("Aucun fichier .env trouvé dans le dossier courant."))
	} else {
		v := NewVault("")
		key, _ := LoadKey(filepath.Join(os.TempDir(), "envguard_audit_key"))
		v.SetKey(key)
		for _, p := range paths {
			count, err := v.loadEnvFile(p)
			if err != nil {
				lines = append(lines, lipgloss.NewStyle().Foreground(cErr).Render("✕ "+p+" : ")+err.Error())
				continue
			}
			lines = append(lines, lipgloss.NewStyle().Foreground(cOK).Bold(true).Render("📄 "+shortenPath(p))+" : "+fmt.Sprintf("%d secret(s)", count))
		}
		v.mu.RLock()
		for sec, ph := range v.fwd {
			lines = append(lines, fmt.Sprintf("   • %-16s → %s", preview(sec), sPh.Render(ph)))
		}
		v.mu.RUnlock()
	}
	m.auditLog = lines
}

func (m *menuModel) Init() tea.Cmd {
	return nil
}

func (m *menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.action = actionQuit
			return m, tea.Quit
		}

		switch m.screen {
		case screenMain:
			return m.updateMain(msg)
		case screenMCP:
			return m.updateMCP(msg)
		case screenRun:
			return m.updateRun(msg)
		case screenAudit:
			return m.updateAudit(msg)
		}
	}
	return m, nil
}

func (m *menuModel) updateMain(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.action = actionQuit
		return m, tea.Quit
	case "j", "down":
		if m.mainCur < 4 {
			m.mainCur++
		}
	case "k", "up":
		if m.mainCur > 0 {
			m.mainCur--
		}
	case "1":
		m.action = actionStartProxy
		return m, tea.Quit
	case "2":
		m.screen = screenMCP
		m.refreshMCP()
	case "3":
		m.screen = screenRun
	case "4":
		m.screen = screenAudit
		m.refreshAudit()
	case "5":
		m.action = actionQuit
		return m, tea.Quit
	case "enter", " ":
		switch m.mainCur {
		case 0: // Lancer Proxy
			m.action = actionStartProxy
			return m, tea.Quit
		case 1: // MCP
			m.screen = screenMCP
			m.refreshMCP()
		case 2: // Run agent
			m.screen = screenRun
		case 3: // Audit .env
			m.screen = screenAudit
			m.refreshAudit()
		case 4: // Quitter
			m.action = actionQuit
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *menuModel) updateMCP(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace":
		m.screen = screenMain
		m.mcpNote = ""
	case "j", "down":
		if m.mcpCur < len(m.mcpItems)-1 {
			m.mcpCur++
		}
	case "k", "up":
		if m.mcpCur > 0 {
			m.mcpCur--
		}
	case " ", "enter", "t":
		if m.mcpCur < len(m.mcpItems) {
			row := m.mcpItems[m.mcpCur]
			if !row.remote {
				newState, err := toggleSingleServer(row.path, row.toolName, row.name)
				if err == nil {
					m.refreshMCP()
					if newState {
						m.mcpNote = "✓ " + row.name + " est maintenant PROTÉGÉ !"
					} else {
						m.mcpNote = "✓ " + row.name + " a été rétabli à l'original."
					}
				}
			}
		}
	case "p", "P":
		mcpProtectCmd(nil)
		m.refreshMCP()
		m.mcpNote = "✅ Tous les serveurs MCP ont été protégés !"
	case "u", "U":
		mcpUnprotectCmd(nil)
		m.refreshMCP()
		m.mcpNote = "✅ Tous les serveurs MCP ont été rétablis !"
	}
	return m, nil
}

var runOptions = []struct {
	name string
	desc string
	cmd  []string
}{
	{"Claude Code (Anthropic)", "Lance l'agent CLI officiel Claude Code", []string{"claude"}},
	{"Aider (AI Pair Programmer)", "Lance Aider avec protection des tokens API", []string{"aider"}},
	{"Cursor IDE", "Lance l'éditeur Cursor sur le dossier courant", []string{"cursor", "."}},
	{"Windsurf IDE", "Lance l'éditeur Windsurf sur le dossier courant", []string{"windsurf", "."}},
	{"Autre commande…", "Saisir manuellement une commande personnalisée", nil},
}

func (m *menuModel) updateRun(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace":
		m.screen = screenMain
	case "j", "down":
		if m.runCur < len(runOptions)-1 {
			m.runCur++
		}
	case "k", "up":
		if m.runCur > 0 {
			m.runCur--
		}
	case "enter", " ":
		opt := runOptions[m.runCur]
		if opt.cmd != nil {
			m.action = actionRunCommand
			m.runArgs = opt.cmd
			return m, tea.Quit
		}
		// Saisie personnalisée
		m.action = actionRunCommand
		m.runArgs = promptCustomCommand()
		return m, tea.Quit
	}
	return m, nil
}

func promptCustomCommand() []string {
	fmt.Print("\nSaisissez la commande à lancer sous envguard (ex: npm test) : ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	return strings.Fields(line)
}

func (m *menuModel) updateAudit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace", "enter":
		m.screen = screenMain
	}
	return m, nil
}

func (m *menuModel) View() string {
	var b strings.Builder
	titleBox := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(cAccent).
		Padding(0, 2).
		Render("🛡️  ENVGUARD — Centre de Contrôle IA & Secrets")

	b.WriteString("\n" + titleBox + "\n\n")

	switch m.screen {
	case screenMain:
		b.WriteString(m.viewMain())
	case screenMCP:
		b.WriteString(m.viewMCPManager())
	case screenRun:
		b.WriteString(m.viewRunPicker())
	case screenAudit:
		b.WriteString(m.viewAudit())
	}

	return lipgloss.NewStyle().Padding(0, 1).Render(b.String())
}

var mainItems = []mainMenuItem{
	{"🚀", "1. Lancer le Proxy HTTP & Dashboard (127.0.0.1:8787)", "Intercepte le trafic de vos agents CLI et affiche la TUI d'audit en temps réel"},
	{"🛡️ ", "2. Gérer la protection MCP (IDEs & IA)", "Bascule 1-clic pour Cursor, Claude Desktop, Trae, JetBrains, OpenCode…"},
	{"⚡", "3. Lancer un agent en mode protégé (envguard run)", "Exécute Claude Code, Aider, Cursor ou un script derrière le proxy"},
	{"📋", "4. Audit de sécurité des secrets (.env)", "Scanne et affiche les secrets locaux et leurs placeholders HMAC"},
	{"✕", "5. Quitter", "Ferme le centre de contrôle"},
}

func (m *menuModel) viewMain() string {
	var b strings.Builder
	b.WriteString(sMuted.Render("Choisissez une action :") + "\n\n")

	for i, item := range mainItems {
		pointer := "  "
		itemStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#E5E7EB"))
		if i == m.mainCur {
			pointer = lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render("› ")
			itemStyle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
		}
		title := itemStyle.Render(item.icon + " " + item.title)
		desc := sMuted.Render("     " + item.desc)
		b.WriteString(pointer + title + "\n" + desc + "\n\n")
	}

	b.WriteString("\n" + helpLine([][2]string{{"↑↓/1-5", "naviguer"}, {"entrée", "choisir"}, {"q", "quitter"}}))
	return b.String()
}

func (m *menuModel) viewMCPManager() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Gestion des Serveurs MCP détectés") + "\n")
	b.WriteString(sMuted.Render("Appuyez sur [Espace] pour basculer la sécurité du serveur sélectionné.") + "\n\n")

	if m.mcpNote != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(cOK).Bold(true).Render(m.mcpNote) + "\n\n")
	}

	if len(m.mcpItems) == 0 {
		b.WriteString(sMuted.Render("Aucun serveur MCP trouvé sur cette machine.") + "\n\n")
	} else {
		b.WriteString(sMuted.Render(fmt.Sprintf("  %-22s %-20s %-12s %s", "SERVEUR", "OUTIL / IDE", "COMMANDE", "STATUT")) + "\n")
		for i, s := range m.mcpItems {
			stStr := lipgloss.NewStyle().Foreground(cOK).Render("🛡️  PROTÉGÉ")
			if s.remote {
				stStr = sMuted.Render("• distant")
			} else if !s.protected {
				stStr = lipgloss.NewStyle().Foreground(cWarn).Bold(true).Render("⚠️  NON PROTÉGÉ")
			}
			line := fmt.Sprintf("%-22s %-20s %-12s %s", truncate(s.name, 21), truncate(s.toolName, 19), truncate(s.command, 11), stStr)
			if i == m.mcpCur {
				b.WriteString(sSel.Render("› " + line) + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
	}

	b.WriteString("\n" + helpLine([][2]string{{"↑↓", "naviguer"}, {"espace/entrée", "basculer"}, {"p", "tout protéger"}, {"u", "tout rétablir"}, {"échap", "retour menu"}}))
	return b.String()
}

func (m *menuModel) viewRunPicker() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Lancer un Agent sous Protection envguard") + "\n")
	b.WriteString(sMuted.Render("L'agent démarrera avec les variables de redirection HTTP pointant sur le proxy.") + "\n\n")

	for i, opt := range runOptions {
		pointer := "  "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("#E5E7EB"))
		if i == m.runCur {
			pointer = lipgloss.NewStyle().Foreground(cAccent).Bold(true).Render("› ")
			style = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
		}
		b.WriteString(pointer + style.Render(opt.name) + "\n")
		b.WriteString(sMuted.Render("     "+opt.desc) + "\n\n")
	}

	b.WriteString("\n" + helpLine([][2]string{{"↑↓", "naviguer"}, {"entrée", "lancer"}, {"échap", "retour menu"}}))
	return b.String()
}

func (m *menuModel) viewAudit() string {
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("Audit des Fichiers .env Locaux") + "\n")
	b.WriteString(sMuted.Render("Secrets chargés et dérivés en HMAC dans le dossier courant :") + "\n\n")

	for _, l := range m.auditLog {
		b.WriteString(l + "\n")
	}

	b.WriteString("\n" + helpLine([][2]string{{"échap / entrée", "retour menu"}}))
	return b.String()
}

// menuCmd démarre le menu interactif Bubble Tea.
func menuCmd(args []string) int {
	p := tea.NewProgram(newMenuModel(), tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur menu : %v\n", err)
		return 1
	}

	m, ok := finalModel.(*menuModel)
	if !ok {
		return 0
	}

	switch m.action {
	case actionStartProxy:
		return runProxy(nil)
	case actionRunCommand:
		if len(m.runArgs) > 0 {
			return runCmd(m.runArgs)
		}
	}
	return 0
}
