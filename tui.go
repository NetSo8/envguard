package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const logCap = 256

type logRow struct {
	at   time.Time
	ev   Event
	note string
}

type secretRow struct{ rule, secret, ph string }

type model struct {
	p       *Proxy
	listen  string
	logs    [logCap]logRow // ring buffer fixe : pas de croissance, pas de GC
	head, n int
	secrets []secretRow
	cur     int
	tab     int
	reqs    int
	masked  int
	rehyd   int
	lat     time.Duration
	w, h    int
}

type evMsg Event

var (
	cAccent = lipgloss.Color("#A78BFA")
	cMuted  = lipgloss.Color("#6B7280")
	cLine   = lipgloss.Color("#374151")
	cOK     = lipgloss.Color("#34D399")
	cWarn   = lipgloss.Color("#FBBF24")
	cErr    = lipgloss.Color("#F87171")

	sLogo   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0B0B0F")).Background(cAccent).Padding(0, 1)
	sMuted  = lipgloss.NewStyle().Foreground(cMuted)
	sCard   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cLine).Padding(0, 2)
	sNum    = lipgloss.NewStyle().Bold(true)
	sTabOn  = lipgloss.NewStyle().Bold(true).Foreground(cAccent).Border(lipgloss.NormalBorder(), false, false, true).BorderForeground(cAccent).Padding(0, 1)
	sTabOff = lipgloss.NewStyle().Foreground(cMuted).Padding(0, 1).MarginBottom(1)
	sSel    = lipgloss.NewStyle().Background(lipgloss.Color("#1F2937")).Bold(true)
	sKey    = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sPh     = lipgloss.NewStyle().Foreground(cAccent)
	badge   = map[string]lipgloss.Style{
		"anthropic": lipgloss.NewStyle().Foreground(lipgloss.Color("#D97757")).Bold(true),
		"openai":    lipgloss.NewStyle().Foreground(lipgloss.Color("#10A37F")).Bold(true),
		"gemini":    lipgloss.NewStyle().Foreground(lipgloss.Color("#4285F4")).Bold(true),
		"deepseek":  lipgloss.NewStyle().Foreground(lipgloss.Color("#4D6BFE")).Bold(true),
		"meta":      lipgloss.NewStyle().Foreground(lipgloss.Color("#0081FB")).Bold(true),
		"xai":       lipgloss.NewStyle().Foreground(lipgloss.Color("#E5E7EB")).Bold(true),
		"mistral":   lipgloss.NewStyle().Foreground(lipgloss.Color("#FA520F")).Bold(true),
	}
)

func wait(ch <-chan Event) tea.Cmd { return func() tea.Msg { return evMsg(<-ch) } }

func (m *model) Init() tea.Cmd { return wait(m.p.events) }

func (m *model) push(r logRow) {
	r.at = time.Now()
	m.logs[(m.head+m.n)%logCap] = r
	if m.n < logCap {
		m.n++
	} else {
		m.head = (m.head + 1) % logCap
	}
}

func preview(s string) string {
	if len(s) <= 10 {
		return strings.Repeat("•", len(s))
	}
	return s[:6] + "…" + s[len(s)-2:]
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case evMsg:
		e := Event(msg)
		switch e.Kind {
		case evReq:
			m.reqs++
			m.masked += e.Masked
			m.rehyd += e.Rehyd
			m.lat += e.Dur
		case evSecret:
			m.secrets = append(m.secrets, secretRow{e.Rule, e.Secret, e.Ph})
		}
		m.push(logRow{ev: e})
		return m, wait(m.p.events)
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "1", "2":
			m.tab ^= 1
		case "j", "down":
			if m.cur < len(m.secrets)-1 {
				m.cur++
			}
		case "k", "up":
			if m.cur > 0 {
				m.cur--
			}
		case "p", " ":
			m.p.v.paused.Store(!m.p.v.paused.Load())
		case "a":
			if m.tab == 1 && m.cur < len(m.secrets) {
				s := m.secrets[m.cur]
				m.p.v.Allow(s.secret)
				m.secrets = append(m.secrets[:m.cur], m.secrets[m.cur+1:]...)
				if m.cur > 0 && m.cur >= len(m.secrets) {
					m.cur--
				}
				m.push(logRow{note: "ajouté à l'allowlist : " + preview(s.secret)})
			}
		}
	}
	return m, nil
}

func (m *model) View() string {
	if m.w == 0 {
		return ""
	}
	w := m.w - 2

	// En-tête
	state := lipgloss.NewStyle().Foreground(cOK).Render("● protection active")
	if m.p.v.paused.Load() {
		state = lipgloss.NewStyle().Foreground(cWarn).Render("❚❚ en pause — rien n'est masqué")
	}
	left := sLogo.Render("envguard") + "  " + state
	right := sMuted.Render(m.listen)
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	header := left + strings.Repeat(" ", max(gap, 1)) + right

	// Cartes de stats
	avg := "—"
	if m.reqs > 0 {
		avg = (m.lat / time.Duration(m.reqs)).Round(time.Millisecond).String()
	}
	cards := []string{
		card("requêtes", fmt.Sprint(m.reqs), lipgloss.Color("#E5E7EB")),
		card("secrets", fmt.Sprint(len(m.secrets)), cWarn),
		card("masqués", fmt.Sprint(m.masked), cAccent),
		card("réhydratés", fmt.Sprint(m.rehyd), cOK),
		card("latence moy.", avg, lipgloss.Color("#E5E7EB")),
	}
	stats := lipgloss.JoinHorizontal(lipgloss.Top, cards...)

	// Onglets
	t0, t1 := sTabOff.Render("Activité"), sTabOff.Render(fmt.Sprintf("Secrets (%d)", len(m.secrets)))
	if m.tab == 0 {
		t0 = sTabOn.Render("Activité")
	} else {
		t1 = sTabOn.Render(fmt.Sprintf("Secrets (%d)", len(m.secrets)))
	}
	tabs := lipgloss.JoinHorizontal(lipgloss.Bottom, t0, " ", t1)

	rows := m.h - lipgloss.Height(header) - lipgloss.Height(stats) - lipgloss.Height(tabs) - 4
	rows = max(rows, 3)
	var body string
	if m.tab == 0 {
		body = m.viewLog(rows)
	} else {
		body = m.viewSecrets(rows)
	}

	help := helpLine([][2]string{{"tab", "onglet"}, {"↑↓", "naviguer"}, {"a", "allowlist"}, {"p", "pause"}, {"q", "quitter"}})

	return lipgloss.NewStyle().Padding(0, 1).Render(lipgloss.JoinVertical(lipgloss.Left,
		header, "", stats, "", tabs, lipgloss.NewStyle().Height(rows).Render(body), "", help))
}

func card(label, val string, c lipgloss.Color) string {
	return sCard.Render(sMuted.Render(label) + "\n" + sNum.Foreground(c).Render(val))
}

func helpLine(kv [][2]string) string {
	parts := make([]string, len(kv))
	for i, p := range kv {
		parts[i] = sKey.Render(p[0]) + " " + sMuted.Render(p[1])
	}
	return strings.Join(parts, sMuted.Render("  ·  "))
}

func (m *model) viewLog(rows int) string {
	if m.n == 0 {
		var b strings.Builder
		b.WriteString(sMuted.Render("En attente de requêtes. Pointe ton client sur une route :") + "\n\n")
		for i, pr := range m.p.providers {
			if i >= rows-3 {
				b.WriteString(sMuted.Render(fmt.Sprintf("  … et %d autres (-no-tui pour tout lister)", len(m.p.providers)-i)))
				break
			}
			b.WriteString("  " + provBadge(pr.name).Width(11).Render(pr.name) + sMuted.Render("http://"+m.listen+"/"+pr.name) + "\n")
		}
		return b.String()
	}
	var b strings.Builder
	for i := max(0, m.n-rows); i < m.n; i++ {
		r := m.logs[(m.head+i)%logCap]
		b.WriteString(sMuted.Render(r.at.Format("15:04:05")) + "  ")
		e := r.ev
		switch {
		case r.note != "":
			b.WriteString(sMuted.Render(r.note))
		case e.Kind == evReq:
			st := lipgloss.NewStyle().Foreground(cOK)
			if e.Status >= 400 {
				st = lipgloss.NewStyle().Foreground(cErr)
			}
			fmt.Fprintf(&b, "%s %s %-28s %s  %s  %s",
				provBadge(e.Prov).Width(11).Render(e.Prov), st.Render(fmt.Sprint(e.Status)),
				truncate(e.Method+" "+e.Path, 28),
				lipgloss.NewStyle().Foreground(cAccent).Render(fmt.Sprintf("▲ %d", e.Masked)),
				lipgloss.NewStyle().Foreground(cOK).Render(fmt.Sprintf("▼ %d", e.Rehyd)),
				sMuted.Render(e.Dur.Round(time.Millisecond).String()))
		case e.Kind == evSecret:
			fmt.Fprintf(&b, "%s %s %s → %s", lipgloss.NewStyle().Foreground(cWarn).Render("◆ secret"),
				sMuted.Render(e.Rule), preview(e.Secret), sPh.Render(e.Ph))
		case e.Kind == evErr:
			b.WriteString(lipgloss.NewStyle().Foreground(cErr).Render("✕ "+e.Path+" : ") + e.Rule)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func (m *model) viewSecrets(rows int) string {
	if len(m.secrets) == 0 {
		return sMuted.Render("Aucun secret détecté pour l'instant.")
	}
	var b strings.Builder
	b.WriteString(sMuted.Render(fmt.Sprintf("  %-10s %-14s %s", "TYPE", "VALEUR", "PLACEHOLDER")) + "\n")
	start := max(0, m.cur-rows+2)
	for i := start; i < len(m.secrets) && i < start+rows-1; i++ {
		s := m.secrets[i]
		line := fmt.Sprintf("%-10s %-14s %s", s.rule, preview(s.secret), sPh.Render(s.ph))
		if i == m.cur {
			b.WriteString(sSel.Render("› " + line))
		} else {
			b.WriteString("  " + line)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func provBadge(name string) lipgloss.Style {
	if st, ok := badge[name]; ok {
		return st
	}
	return lipgloss.NewStyle().Foreground(cAccent).Bold(true)
}
