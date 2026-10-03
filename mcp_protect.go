package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// TargetDef définit une cible d'outil ou IDE avec ses emplacements potentiels de configuration MCP.
type TargetDef struct {
	Name  string
	Paths []string
	Globs []string
}

// ServerInfo décrit un serveur MCP détecté dans un fichier de configuration.
type ServerInfo struct {
	Name      string
	Command   string
	Protected bool
	Remote    bool
}

// DiscoveredFile représente un fichier de configuration MCP trouvé sur la machine.
type DiscoveredFile struct {
	ToolName string
	Path     string
	Servers  []ServerInfo
	Raw      map[string]any
}

// cleanJSONC supprime les commentaires // et /* */ ainsi que les virgules traînantes
// pour permettre à encoding/json de parser les fichiers .jsonc (OpenCode, VS Code, Cursor...).
func cleanJSONC(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data))
	inString := false
	escaped := false
	i := 0
	n := len(data)

	for i < n {
		c := data[i]
		if inString {
			out.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			i++
			continue
		}

		if c == '"' {
			inString = true
			out.WriteByte(c)
			i++
			continue
		}

		// Commentaire sur une ligne //
		if c == '/' && i+1 < n && data[i+1] == '/' {
			i += 2
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		}

		// Commentaire multi-lignes /* ... */
		if c == '/' && i+1 < n && data[i+1] == '*' {
			i += 2
			for i+1 < n && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2
			}
			continue
		}

		out.WriteByte(c)
		i++
	}

	// Suppression des virgules traînantes avant '}' ou ']'
	res := out.Bytes()
	for j := 0; j < len(res); j++ {
		if res[j] == ',' {
			k := j + 1
			for k < len(res) && (res[k] == ' ' || res[k] == '\t' || res[k] == '\r' || res[k] == '\n') {
				k++
			}
			if k < len(res) && (res[k] == '}' || res[k] == ']') {
				res[j] = ' '
			}
		}
	}
	return res
}

// candidateTargets renvoie la liste des outils IA et IDEs supportés avec leurs chemins potentiels.
func candidateTargets() []TargetDef {
	home, _ := os.UserHomeDir()
	appData := os.Getenv("APPDATA")
	cwd, _ := os.Getwd()

	var targets []TargetDef

	// 1. Google Antigravity / Gemini CLI
	targets = append(targets, TargetDef{
		Name: "Google Antigravity",
		Paths: []string{
			filepath.Join(home, ".gemini", "config", "mcp_config.json"),
			filepath.Join(home, ".gemini", "antigravity", "mcp_config.json"),
			filepath.Join(home, ".antigravity", "mcp.json"),
			filepath.Join(home, ".config", "antigravity", "mcp.json"),
		},
	})

	// 2. Claude Desktop
	claudeDesktop := []string{
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
	}
	if appData != "" {
		claudeDesktop = append(claudeDesktop, filepath.Join(appData, "Claude", "claude_desktop_config.json"))
	}
	targets = append(targets, TargetDef{Name: "Claude Desktop", Paths: claudeDesktop})

	// 3. Claude Code
	targets = append(targets, TargetDef{
		Name: "Claude Code",
		Paths: []string{
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".claude", "mcp.json"),
			filepath.Join(cwd, ".claude.json"),
			filepath.Join(cwd, ".claude", "mcp.json"),
		},
	})

	// 4. Cursor
	cursorPaths := []string{
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "mcp.json"),
		filepath.Join(home, ".config", "Cursor", "User", "globalStorage", "mcp.json"),
		filepath.Join(cwd, ".cursor", "mcp.json"),
	}
	if appData != "" {
		cursorPaths = append(cursorPaths, filepath.Join(appData, "Cursor", "User", "globalStorage", "mcp.json"))
	}
	targets = append(targets, TargetDef{Name: "Cursor", Paths: cursorPaths})

	// 5. Trae (ByteDance)
	traePaths := []string{
		filepath.Join(home, ".trae", "mcp.json"),
		filepath.Join(home, "Library", "Application Support", "Trae", "User", "globalStorage", "mcp.json"),
		filepath.Join(home, ".config", "Trae", "User", "globalStorage", "mcp.json"),
		filepath.Join(cwd, ".trae", "mcp.json"),
	}
	if appData != "" {
		traePaths = append(traePaths, filepath.Join(appData, "Trae", "User", "globalStorage", "mcp.json"))
	}
	targets = append(targets, TargetDef{Name: "Trae", Paths: traePaths})

	// 6. JetBrains IDEs (IntelliJ, PyCharm, WebStorm, GoLand, CLion, Rider, Fleet, Junie...)
	jbPaths := []string{
		filepath.Join(home, "Library", "Application Support", "JetBrains", "mcp.json"),
		filepath.Join(home, ".config", "JetBrains", "mcp.json"),
		filepath.Join(cwd, ".idea", "mcp.json"),
	}
	jbGlobs := []string{
		filepath.Join(home, "Library", "Application Support", "JetBrains", "*", "mcp.json"),
		filepath.Join(home, ".config", "JetBrains", "*", "mcp.json"),
	}
	if appData != "" {
		jbPaths = append(jbPaths, filepath.Join(appData, "JetBrains", "mcp.json"))
		jbGlobs = append(jbGlobs, filepath.Join(appData, "JetBrains", "*", "mcp.json"))
	}
	targets = append(targets, TargetDef{Name: "JetBrains IDEs", Paths: jbPaths, Globs: jbGlobs})

	// 7. Windsurf (Codeium)
	wsPaths := []string{
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
		filepath.Join(home, "Library", "Application Support", "Windsurf", "User", "globalStorage", "mcp.json"),
		filepath.Join(home, ".config", "Windsurf", "User", "globalStorage", "mcp.json"),
		filepath.Join(cwd, ".windsurf", "mcp.json"),
		filepath.Join(cwd, ".codeium", "mcp.json"),
	}
	if appData != "" {
		wsPaths = append(wsPaths, filepath.Join(appData, "Windsurf", "User", "globalStorage", "mcp.json"))
	}
	targets = append(targets, TargetDef{Name: "Windsurf", Paths: wsPaths})

	// 8. OpenCode
	targets = append(targets, TargetDef{
		Name: "OpenCode",
		Paths: []string{
			filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
			filepath.Join(home, ".config", "opencode", "opencode.json"),
			filepath.Join(home, ".local", "share", "opencode", "opencode.json"),
			filepath.Join(cwd, "opencode.jsonc"),
			filepath.Join(cwd, "opencode.json"),
		},
	})

	// 9. Extensions VS Code (Cline, Roo Code, Continue, Copilot MCP)
	vscodePaths := []string{
		filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
		filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json"),
		filepath.Join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
		filepath.Join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json"),
		filepath.Join(home, ".continue", "config.json"),
		filepath.Join(cwd, ".vscode", "mcp.json"),
	}
	if appData != "" {
		vscodePaths = append(vscodePaths,
			filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
			filepath.Join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json"),
		)
	}
	targets = append(targets, TargetDef{Name: "VS Code / Cline / Roo", Paths: vscodePaths})

	// 10. Zed Editor
	targets = append(targets, TargetDef{
		Name:  "Zed",
		Paths: []string{filepath.Join(home, ".config", "zed", "settings.json")},
	})

	// 11. Configurations MCP locales au projet courant
	targets = append(targets, TargetDef{
		Name: "Projet local",
		Paths: []string{
			filepath.Join(cwd, ".mcp.json"),
			filepath.Join(cwd, "mcp.json"),
		},
	})

	return targets
}

// discoverConfigs inspecte les chemins standards ou les fichiers spécifiés et renvoie ceux qui existent.
func discoverConfigs(specifiedFiles []string) ([]DiscoveredFile, error) {
	var result []DiscoveredFile
	seen := make(map[string]bool)

	addFile := func(path, toolName string) {
		clean := filepath.Clean(path)
		if seen[clean] {
			return
		}
		seen[clean] = true

		info, err := os.Stat(clean)
		if err != nil || info.IsDir() {
			return
		}

		disc, err := parseMCPConfigFile(clean, toolName)
		if err == nil && len(disc.Servers) > 0 {
			result = append(result, *disc)
		}
	}

	if len(specifiedFiles) > 0 {
		for _, f := range specifiedFiles {
			addFile(f, "Personnalisé")
		}
		return result, nil
	}

	targets := candidateTargets()
	for _, t := range targets {
		for _, p := range t.Paths {
			addFile(p, t.Name)
		}
		for _, g := range t.Globs {
			matches, _ := filepath.Glob(g)
			for _, m := range matches {
				addFile(m, t.Name)
			}
		}
	}

	return result, nil
}

// parseMCPConfigFile lit et analyse un fichier JSON/JSONC pour détecter ses serveurs MCP.
func parseMCPConfigFile(path, toolName string) (*DiscoveredFile, error) {
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	clean := cleanJSONC(rawBytes)
	var root map[string]any
	if err := json.Unmarshal(clean, &root); err != nil {
		return nil, err
	}

	disc := &DiscoveredFile{
		ToolName: toolName,
		Path:     path,
		Raw:      root,
	}

	// 1. Format standard `mcpServers` (map ou list)
	if mcpServers, ok := root["mcpServers"]; ok {
		disc.Servers = append(disc.Servers, extractServersFromMapOrList(mcpServers)...)
	}

	// 2. Format OpenCode `mcp`
	if mcp, ok := root["mcp"]; ok {
		if mcpMap, ok := mcp.(map[string]any); ok {
			for name, val := range mcpMap {
				srvMap, ok := val.(map[string]any)
				if !ok {
					continue
				}
				typ, _ := srvMap["type"].(string)
				if typ == "remote" {
					disc.Servers = append(disc.Servers, ServerInfo{
						Name:   name,
						Remote: true,
					})
					continue
				}
				info := extractServerInfo(name, srvMap)
				disc.Servers = append(disc.Servers, info)
			}
		}
	}

	// 3. Format Zed `context_servers`
	if ctxServers, ok := root["context_servers"]; ok {
		disc.Servers = append(disc.Servers, extractServersFromMapOrList(ctxServers)...)
	}

	return disc, nil
}

func extractServersFromMapOrList(raw any) []ServerInfo {
	var list []ServerInfo
	switch v := raw.(type) {
	case map[string]any:
		for name, srvVal := range v {
			if srvMap, ok := srvVal.(map[string]any); ok {
				list = append(list, extractServerInfo(name, srvMap))
			}
		}
	case []any:
		for _, item := range v {
			if srvMap, ok := item.(map[string]any); ok {
				name, _ := srvMap["name"].(string)
				if name == "" {
					name = "unnamed"
				}
				list = append(list, extractServerInfo(name, srvMap))
			}
		}
	}
	return list
}

func extractServerInfo(name string, srvMap map[string]any) ServerInfo {
	info := ServerInfo{Name: name}

	// Command sous forme de string : "command": "npx", "args": [...]
	if cmd, ok := srvMap["command"].(string); ok {
		info.Command = cmd
		if isEnvguardCommand(cmd, srvMap["args"]) {
			info.Protected = true
		}
		return info
	}

	// Command sous forme de liste : "command": ["npx", "-y", "..."] (OpenCode local)
	if cmdList, ok := srvMap["command"].([]any); ok && len(cmdList) > 0 {
		var parts []string
		for _, p := range cmdList {
			parts = append(parts, fmt.Sprint(p))
		}
		info.Command = strings.Join(parts, " ")
		if len(parts) >= 3 && parts[0] == "envguard" && parts[1] == "mcp" && parts[2] == "--" {
			info.Protected = true
		}
		return info
	}

	return info
}

func isEnvguardCommand(cmd string, argsRaw any) bool {
	base := filepath.Base(cmd)
	if base != "envguard" && base != "envguard.exe" {
		return false
	}
	args, ok := argsRaw.([]any)
	if !ok || len(args) < 2 {
		return false
	}
	// Doit contenir "mcp" et "--"
	hasMcp := false
	hasDash := false
	for _, a := range args {
		s := fmt.Sprint(a)
		if s == "mcp" {
			hasMcp = true
		}
		if s == "--" {
			hasDash = true
		}
	}
	return hasMcp && hasDash
}

// wrapServer modifie un dictionnaire de configuration de serveur pour y insérer "envguard mcp --".
// Renvoie true si le serveur a été modifié, false s'il était déjà protégé ou distant.
func wrapServer(srvMap map[string]any, binName string) bool {
	// 1. Commande sous forme de chaîne : command="npx", args=["-y", ...]
	if cmd, ok := srvMap["command"].(string); ok {
		if isEnvguardCommand(cmd, srvMap["args"]) {
			return false // déjà protégé
		}

		var newArgs []any
		newArgs = append(newArgs, "mcp", "--", cmd)
		if origArgs, ok := srvMap["args"].([]any); ok {
			newArgs = append(newArgs, origArgs...)
		}

		srvMap["command"] = binName
		srvMap["args"] = newArgs
		return true
	}

	// 2. Commande sous forme de liste : command=["npx", "-y", ...] (OpenCode)
	if cmdList, ok := srvMap["command"].([]any); ok && len(cmdList) > 0 {
		var parts []any
		for _, p := range cmdList {
			parts = append(parts, fmt.Sprint(p))
		}
		if len(parts) >= 3 && parts[0] == "envguard" && parts[1] == "mcp" && parts[2] == "--" {
			return false // déjà protégé
		}

		newCmd := []any{binName, "mcp", "--"}
		newCmd = append(newCmd, parts...)
		srvMap["command"] = newCmd
		return true
	}

	return false
}

// unwrapServer retire l'emballage "envguard mcp --" pour restaurer la commande originale.
// Renvoie true si le serveur a été déprotégé, false sinon.
func unwrapServer(srvMap map[string]any) bool {
	// 1. Commande sous forme de chaîne
	if cmd, ok := srvMap["command"].(string); ok {
		base := filepath.Base(cmd)
		if base != "envguard" && base != "envguard.exe" {
			return false
		}
		args, ok := srvMap["args"].([]any)
		if !ok || len(args) < 3 {
			return false
		}
		var strArgs []string
		for _, a := range args {
			strArgs = append(strArgs, fmt.Sprint(a))
		}
		dashIdx := slices.Index(strArgs, "--")
		if dashIdx == -1 || dashIdx+1 >= len(strArgs) {
			return false
		}

		origCmd := strArgs[dashIdx+1]
		var origArgs []any
		for i := dashIdx + 2; i < len(args); i++ {
			origArgs = append(origArgs, args[i])
		}

		srvMap["command"] = origCmd
		if len(origArgs) > 0 {
			srvMap["args"] = origArgs
		} else {
			delete(srvMap, "args")
		}
		return true
	}

	// 2. Commande sous forme de liste
	if cmdList, ok := srvMap["command"].([]any); ok && len(cmdList) >= 4 {
		var strList []string
		for _, p := range cmdList {
			strList = append(strList, fmt.Sprint(p))
		}
		if strList[0] == "envguard" && strList[1] == "mcp" && strList[2] == "--" {
			srvMap["command"] = cmdList[3:]
			return true
		}
	}

	return false
}

// applyToConfig applique la transformation (wrap ou unwrap) à tous les serveurs du fichier.
func applyToConfig(disc *DiscoveredFile, binName string, unwrap bool) (changedCount int, err error) {
	root := disc.Raw

	applySrv := func(srvMap map[string]any) {
		if unwrap {
			if unwrapServer(srvMap) {
				changedCount++
			}
		} else {
			if wrapServer(srvMap, binName) {
				changedCount++
			}
		}
	}

	// 1. mcpServers
	if mcpServers, ok := root["mcpServers"]; ok {
		switch v := mcpServers.(type) {
		case map[string]any:
			for _, srvVal := range v {
				if srvMap, ok := srvVal.(map[string]any); ok {
					applySrv(srvMap)
				}
			}
		case []any:
			for _, item := range v {
				if srvMap, ok := item.(map[string]any); ok {
					applySrv(srvMap)
				}
			}
		}
	}

	// 2. OpenCode mcp
	if mcp, ok := root["mcp"]; ok {
		if mcpMap, ok := mcp.(map[string]any); ok {
			for _, srvVal := range mcpMap {
				if srvMap, ok := srvVal.(map[string]any); ok {
					typ, _ := srvMap["type"].(string)
					if typ != "remote" {
						applySrv(srvMap)
					}
				}
			}
		}
	}

	// 3. Zed context_servers
	if ctxServers, ok := root["context_servers"]; ok {
		if ctxMap, ok := ctxServers.(map[string]any); ok {
			for _, srvVal := range ctxMap {
				if srvMap, ok := srvVal.(map[string]any); ok {
					applySrv(srvMap)
				}
			}
		}
	}

	return changedCount, nil
}

// backupFile crée une sauvegarde .envguard.bak si elle n'existe pas déjà.
func backupFile(path string) error {
	bak := path + ".envguard.bak"
	if _, err := os.Stat(bak); err == nil {
		return nil // ne pas écraser la sauvegarde originale pristine
	}
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(bak, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func resolveBinName(custom string) string {
	if custom != "" {
		return custom
	}
	if runtime.GOOS == "windows" {
		return "envguard.exe"
	}
	return "envguard"
}

// --- Commandes CLI : protect, unprotect, status ---

func mcpProtectCmd(args []string) int {
	var dryRun bool
	var binName string
	fs := flag.NewFlagSet("envguard mcp protect", flag.ContinueOnError)
	fs.BoolVar(&dryRun, "dry-run", false, "afficher les modifications sans écrire sur le disque")
	fs.StringVar(&binName, "bin", "", "nom ou chemin de l'exécutable envguard à injecter (défaut: envguard)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	bin := resolveBinName(binName)
	files, err := discoverConfigs(fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur de détection : %v\n", err)
		return 1
	}

	if len(files) == 0 {
		fmt.Println("🔍 Aucune configuration de serveur MCP trouvée sur la machine.")
		fmt.Println("   Vous pouvez spécifier un chemin de fichier manuellement :")
		fmt.Println("   envguard mcp protect ./mon-fichier-mcp.json")
		return 0
	}

	fmt.Println("🛡️  envguard MCP Protect — Détection des serveurs :")
	totalChanged := 0
	for _, f := range files {
		unprotected := 0
		already := 0
		for _, s := range f.Servers {
			if s.Remote {
				continue
			}
			if s.Protected {
				already++
			} else {
				unprotected++
			}
		}

		fmt.Printf("\n  📁 %s (%s) :\n", f.ToolName, shortenPath(f.Path))
		for _, s := range f.Servers {
			if s.Remote {
				fmt.Printf("     • %s : distant (non concerné)\n", s.Name)
			} else if s.Protected {
				fmt.Printf("     ✓ %s : déjà protégé par envguard\n", s.Name)
			} else {
				fmt.Printf("     ⚠️  %s : non protégé (%s)\n", s.Name, s.Command)
			}
		}

		if unprotected > 0 {
			changed, err := applyToConfig(&f, bin, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "     ❌ Erreur modification: %v\n", err)
				continue
			}
			if !dryRun {
				if err := backupFile(f.Path); err != nil {
					fmt.Fprintf(os.Stderr, "     ❌ Erreur sauvegarde .bak: %v\n", err)
					continue
				}
				data, err := json.MarshalIndent(f.Raw, "", "  ")
				if err != nil {
					fmt.Fprintf(os.Stderr, "     ❌ Erreur encodage JSON: %v\n", err)
					continue
				}
				data = append(data, '\n')
				if err := os.WriteFile(f.Path, data, 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "     ❌ Erreur écriture: %v\n", err)
					continue
				}
				fmt.Printf("     🔒 %d serveur(s) sécurisé(s) (sauvegarde .envguard.bak créée)\n", changed)
			} else {
				fmt.Printf("     [dry-run] %d serveur(s) seraient sécurisés\n", changed)
			}
			totalChanged += changed
		}
	}

	fmt.Println()
	if totalChanged > 0 {
		if dryRun {
			fmt.Printf("✨ [dry-run] %d serveur(s) MCP sont prêts à être protégés. Relancez sans -dry-run pour appliquer.\n", totalChanged)
		} else {
			fmt.Printf("✅ %d serveur(s) MCP sont maintenant blindés contre les fuites de secrets !\n", totalChanged)
			fmt.Println("   Pour rétablir les configurations d'origine : envguard mcp unprotect")
		}
	} else {
		fmt.Println("✨ Tous vos serveurs MCP détectés sont déjà protégés !")
	}
	return 0
}

func mcpUnprotectCmd(args []string) int {
	var dryRun bool
	fs := flag.NewFlagSet("envguard mcp unprotect", flag.ContinueOnError)
	fs.BoolVar(&dryRun, "dry-run", false, "afficher les modifications sans écrire sur le disque")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	files, err := discoverConfigs(fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur de détection : %v\n", err)
		return 1
	}

	if len(files) == 0 {
		fmt.Println("🔍 Aucune configuration de serveur MCP trouvée.")
		return 0
	}

	fmt.Println("🔓 envguard MCP Unprotect — Restauration des configurations :")
	totalChanged := 0
	for _, f := range files {
		changed, err := applyToConfig(&f, "", true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ❌ Erreur sur %s : %v\n", shortenPath(f.Path), err)
			continue
		}
		if changed > 0 {
			if !dryRun {
				data, err := json.MarshalIndent(f.Raw, "", "  ")
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ❌ Erreur encodage JSON: %v\n", err)
					continue
				}
				data = append(data, '\n')
				if err := os.WriteFile(f.Path, data, 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "  ❌ Erreur écriture: %v\n", err)
					continue
				}
				fmt.Printf("  ✓ %s (%s) : %d serveur(s) rétabli(s)\n", f.ToolName, shortenPath(f.Path), changed)
			} else {
				fmt.Printf("  [dry-run] %s (%s) : %d serveur(s) seraient rétablis\n", f.ToolName, shortenPath(f.Path), changed)
			}
			totalChanged += changed
		}
	}

	fmt.Println()
	if totalChanged > 0 {
		if dryRun {
			fmt.Printf("✨ [dry-run] %d serveur(s) MCP seraient rétablis.\n", totalChanged)
		} else {
			fmt.Printf("✅ %d serveur(s) MCP ont été restaurés vers leur commande d'origine.\n", totalChanged)
		}
	} else {
		fmt.Println("✨ Aucun serveur MCP protégé par envguard n'a été trouvé.")
	}
	return 0
}

func mcpStatusCmd(args []string) int {
	files, err := discoverConfigs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
		return 1
	}

	if len(files) == 0 {
		fmt.Println("🔍 Aucune configuration de serveur MCP trouvée sur la machine.")
		return 0
	}

	fmt.Println("📋 État de protection des serveurs MCP détectés :")
	for _, f := range files {
		fmt.Printf("\n  📁 %s — %s\n", f.ToolName, shortenPath(f.Path))
		for _, s := range f.Servers {
			if s.Remote {
				fmt.Printf("     • %s : distant (non concerné)\n", s.Name)
			} else if s.Protected {
				fmt.Printf("     🛡️  %s : PROTÉGÉ (envguard)\n", s.Name)
			} else {
				fmt.Printf("     ⚠️  %s : NON PROTÉGÉ (%s)\n", s.Name, s.Command)
			}
		}
	}
	fmt.Println()
	return 0
}

func shortenPath(p string) string {
	home, err := os.UserHomeDir()
	if err == nil && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	cwd, err := os.Getwd()
	if err == nil && strings.HasPrefix(p, cwd) {
		return "." + strings.TrimPrefix(p, cwd)
	}
	return p
}

// wrapServerByName recherche le serveur targetName dans la config et lui applique wrapServer.
func wrapServerByName(root map[string]any, targetName, binName string) bool {
	if mcpServers, ok := root["mcpServers"]; ok {
		if m, ok := mcpServers.(map[string]any); ok {
			if srv, ok := m[targetName].(map[string]any); ok {
				return wrapServer(srv, binName)
			}
		}
	}
	if mcp, ok := root["mcp"]; ok {
		if m, ok := mcp.(map[string]any); ok {
			if srv, ok := m[targetName].(map[string]any); ok {
				return wrapServer(srv, binName)
			}
		}
	}
	if ctx, ok := root["context_servers"]; ok {
		if m, ok := ctx.(map[string]any); ok {
			if srv, ok := m[targetName].(map[string]any); ok {
				return wrapServer(srv, binName)
			}
		}
	}
	return false
}

// unwrapServerByName recherche le serveur targetName dans la config et lui applique unwrapServer.
func unwrapServerByName(root map[string]any, targetName string) bool {
	if mcpServers, ok := root["mcpServers"]; ok {
		if m, ok := mcpServers.(map[string]any); ok {
			if srv, ok := m[targetName].(map[string]any); ok {
				return unwrapServer(srv)
			}
		}
	}
	if mcp, ok := root["mcp"]; ok {
		if m, ok := mcp.(map[string]any); ok {
			if srv, ok := m[targetName].(map[string]any); ok {
				return unwrapServer(srv)
			}
		}
	}
	if ctx, ok := root["context_servers"]; ok {
		if m, ok := ctx.(map[string]any); ok {
			if srv, ok := m[targetName].(map[string]any); ok {
				return unwrapServer(srv)
			}
		}
	}
	return false
}

// toggleSingleServer bascule l'état de protection d'un unique serveur MCP dans son fichier.
func toggleSingleServer(path, toolName, serverName string) (bool, error) {
	disc, err := parseMCPConfigFile(path, toolName)
	if err != nil {
		return false, err
	}
	var isProt bool
	found := false
	for _, s := range disc.Servers {
		if s.Name == serverName {
			isProt = s.Protected
			found = true
			break
		}
	}
	if !found {
		return false, fmt.Errorf("serveur %s non trouvé dans %s", serverName, path)
	}

	bin := resolveBinName("")
	if isProt {
		if !unwrapServerByName(disc.Raw, serverName) {
			return false, fmt.Errorf("impossible de déprotéger %s", serverName)
		}
	} else {
		backupFile(path)
		if !wrapServerByName(disc.Raw, serverName, bin) {
			return false, fmt.Errorf("impossible de protéger %s", serverName)
		}
	}

	data, err := json.MarshalIndent(disc.Raw, "", "  ")
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return false, err
	}
	return !isProt, nil
}

