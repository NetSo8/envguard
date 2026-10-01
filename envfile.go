package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Import des fichiers .env du projet.
//
// Chaque valeur qui ressemble à un secret est enregistrée telle quelle dans le
// vault : elle est ensuite masquée partout où elle apparaît, même sans préfixe
// connu ni nom de variable évocateur dans le texte envoyé au modèle.
//
// Enregistrer *toutes* les valeurs serait dangereux : NODE_ENV=development
// ferait masquer le mot « development » partout. On ne retient donc que :
//   - les variables au nom évocateur (KEY, SECRET, TOKEN, PASSW…) ;
//   - les valeurs reconnues par une règle (sk-ant-…, JWT…) ;
//   - les valeurs longues à forte entropie (clés sans nom explicite).
// Les fichiers d'exemple (.env.example, .env.sample…) sont ignorés : ils
// contiennent des valeurs factices.

type envVar struct{ key, val string }

// parseDotenv lit le format dotenv courant : KEY=val, export KEY=val,
// guillemets simples ou doubles (échappements \n, \" dans les doubles,
// valeurs multi-lignes entre guillemets), commentaires # en fin de valeur
// non citée. Les lignes qui ne sont pas des affectations sont ignorées
// (utile pour .envrc, qui est un script shell).
func parseDotenv(data []byte) []envVar {
	var out []envVar
	s := string(data)
	for len(s) > 0 {
		line, rest, _ := strings.Cut(s, "\n")
		s = rest
		t := strings.TrimSpace(line)
		t = strings.TrimPrefix(t, "export ")
		eq := strings.IndexByte(t, '=')
		if t == "" || t[0] == '#' || eq <= 0 {
			continue
		}
		key := strings.TrimSpace(t[:eq])
		if !validEnvKey(key) {
			continue
		}
		v := strings.TrimLeft(t[eq+1:], " \t")
		switch {
		case strings.HasPrefix(v, `"`):
			val, rem, ok := quoted(v[1:]+"\n"+s, '"')
			if !ok {
				continue
			}
			s = rem
			out = append(out, envVar{key, val})
		case strings.HasPrefix(v, "'"):
			val, rem, ok := quoted(v[1:]+"\n"+s, '\'')
			if !ok {
				continue
			}
			s = rem
			out = append(out, envVar{key, val})
		default:
			if i := strings.Index(v, " #"); i >= 0 {
				v = v[:i]
			}
			out = append(out, envVar{key, strings.TrimSpace(v)})
		}
	}
	return out
}

// quoted lit une valeur jusqu'au guillemet fermant (éventuellement sur
// plusieurs lignes) ; renvoie la valeur et le texte après la fin de ligne.
func quoted(s string, q byte) (string, string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && q == '"' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		if c == q {
			_, rest, _ := strings.Cut(s[i+1:], "\n")
			return b.String(), rest, true
		}
		b.WriteByte(c)
	}
	return "", "", false
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

var benignValues = map[string]bool{
	"true": true, "false": true, "yes": true, "no": true, "on": true, "off": true, "null": true, "none": true,
	"development": true, "production": true, "staging": true, "test": true, "testing": true, "local": true,
	"localhost": true, "debug": true, "info": true, "warn": true, "warning": true, "error": true, "changeme": true,
	"password": true, "secret": true, "example": true, "default": true,
}

// envSecret dit si une valeur de .env doit être masquée. Les valeurs
// multi-lignes (clés PEM) sont laissées aux règles dédiées : leur forme dans
// le JSON envoyé (avec \n échappés) ne correspond pas à la valeur brute.
func envSecret(key, val string) bool {
	if len(val) < 6 || len(val) > 4096 || strings.ContainsAny(val, "\n\r\"\\") {
		return false
	}
	if strings.Contains(val, "://") {
		return false // URL : seul son mot de passe est enregistré (voir loadEnvFile)
	}
	low := strings.ToLower(val)
	if benignValues[low] || strings.HasPrefix(val, "/") || strings.HasPrefix(val, "./") ||
		strings.HasPrefix(val, "~/") || strings.HasPrefix(val, "${") || strings.Contains(val, "REDACTED_") {
		return false
	}
	b := []byte(val)
	digits := true
	for _, c := range b {
		digits = digits && (c >= '0' && c <= '9' || c == '.')
	}
	if digits {
		return false // port, version, durée…
	}
	if hasKeyword([]byte(key)) && len(val) >= 8 && !strings.ContainsAny(val, " \t") {
		return true
	}
	ruled := false
	scan(b, func(s span) { ruled = ruled || (s.s == 0 && s.e == len(b)) })
	if ruled {
		return true
	}
	return len(val) >= 16 && !strings.ContainsAny(val, " \t") && entropy(b) >= 3.8
}

// envFiles trouve les fichiers .env d'un dossier (hors fichiers d'exemple).
func envFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !(n == ".envrc" || n == ".env" || strings.HasPrefix(n, ".env.")) {
			continue
		}
		low := strings.ToLower(n)
		if strings.Contains(low, "example") || strings.Contains(low, "sample") ||
			strings.Contains(low, "template") || strings.HasSuffix(low, ".dist") || strings.HasSuffix(low, ".schema") {
			continue
		}
		out = append(out, filepath.Join(dir, n))
	}
	sort.Strings(out)
	return out
}

// loadEnvFile enregistre les secrets d'un fichier ; renvoie le nombre ajouté.
func (v *Vault) loadEnvFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, kv := range parseDotenv(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))) {
		if strings.Contains(kv.val, "://") {
			// postgres://user:mdp@hôte : seul le mot de passe est secret, et
			// son hôte devient sa destination légitime (politique des outils).
			b := []byte(kv.val)
			scan(b, func(s span) {
				if s.kind == "url_password" && v.AddKnown("env:"+kv.key, "", string(b[s.s:s.e]),
					[]string{strings.ToLower(string(b[s.hs:s.he]))}) {
					n++
				}
			})
			continue
		}
		if !envSecret(kv.key, kv.val) {
			continue
		}
		pfx := ""
		b := []byte(kv.val)
		scan(b, func(s span) {
			if s.s == 0 && s.e == len(b) {
				pfx = s.pfx // garde un préfixe reconnu (sk-ant-…) dans le placeholder
			}
		})
		if v.AddKnown("env:"+kv.key, pfx, kv.val, nil) {
			n++
		}
	}
	return n, nil
}

// watchEnvFiles recharge les fichiers modifiés (sondage léger, sans dépendance).
func (v *Vault) watchEnvFiles(paths []string, every time.Duration, onErr func(string, error)) {
	mtimes := map[string]time.Time{}
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil {
			mtimes[p] = st.ModTime()
		}
	}
	for range time.Tick(every) {
		for _, p := range paths {
			st, err := os.Stat(p)
			if err != nil || st.ModTime().Equal(mtimes[p]) {
				continue
			}
			mtimes[p] = st.ModTime()
			if _, err := v.loadEnvFile(p); err != nil && onErr != nil {
				onErr(p, err)
			}
		}
	}
}
