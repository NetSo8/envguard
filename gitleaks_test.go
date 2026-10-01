package main

import (
	"bytes"
	"strings"
	"testing"
)

func loadGL(t testing.TB) *gitleaks {
	g, err := loadGitleaks(gitleaksDefaultExclude)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGitleaksLoad(t *testing.T) {
	g := loadGL(t)
	if len(g.rules) < 200 {
		t.Fatalf("%d règles chargées", len(g.rules))
	}
	for _, r := range g.rules {
		if r.id == "generic-api-key" || r.id == "jwt" {
			t.Fatalf("règle exclue chargée : %s", r.id)
		}
	}
}

// Secrets que seules les règles gitleaks reconnaissent (pas de préfixe natif).
func TestGitleaksDetects(t *testing.T) {
	g := loadGL(t)
	cases := map[string]string{
		"postman-api-token":         `{"text":"export PM=PM` + `AK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01\n"}`,
		"pulumi-api-token":          `{"text":"login with pu` + `l-3f9a2c1e8b7d6f5a4e3d2c1b0a9f8e7d6c5b4a39 then deploy"}`,
		"sentry-user-token":         `{"text":"SENTRY=sn` + `tryu_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e\n"}`,
		"datadog-access-token":      `{"text":"datadog_api: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0\n"}`,
		"mailgun-private-api-token": `{"text":"mailgun.key = \"ke` + `y-3f9a2c1e8b7d6f5a4e3d2c1b0a9f8e7d\""}`,
	}
	for id, in := range cases {
		var got []string
		g.find([]byte(in), nil, func(rid string, sec []byte) { got = append(got, rid+"="+string(sec)) })
		ok := false
		for _, x := range got {
			ok = ok || strings.HasPrefix(x, id+"=")
		}
		if !ok {
			t.Errorf("%s non détecté dans %s (trouvé : %v)", id, in, got)
		}
	}
}

// Code ordinaire : aucun secret ne doit sortir (sinon il serait masqué partout).
func TestGitleaksNoFalsePositive(t *testing.T) {
	g := loadGL(t)
	for _, in := range [][]byte{
		convo(256<<10, 0),
		[]byte(`{"text":"task risk desk ask SKILLS: the datadog dashboard shows heroku dynos; mailgun sends mail. curl -X POST https://api.example.com"}`),
		[]byte(`{"text":"sumo: true, datadog_api: ${DATADOG_API_KEY}, heroku: 00000000-0000-0000-0000-000000000000"}`),
	} {
		g.find(in, nil, func(rid string, sec []byte) { t.Errorf("faux positif %s : %q", rid, sec) })
	}
}

// Dans le vault : le secret trouvé par gitleaks est masqué partout, même ailleurs.
func TestGitleaksInVault(t *testing.T) {
	v := NewVault("")
	v.gl = loadGL(t)
	tok := "pu" + "l-3f9a2c1e8b7d6f5a4e3d2c1b0a9f8e7d6c5b4a39"
	out, n := v.Mask([]byte(`{"a":"pulumi login ` + tok + `","b":"rappel : ` + tok + `"}`))
	if n != 2 || bytes.Contains(out, []byte(tok)) {
		t.Fatalf("%d remplacements : %s", n, out)
	}
	if !bytes.Contains(out, []byte("SECRET_REDACTED_")) {
		t.Fatalf("placeholder : %s", out)
	}
}

// Vitesse : masquage avec et sans gitleaks, sur du code ordinaire.
func BenchmarkMaskGitleaks(b *testing.B) {
	for _, sz := range []int{64 << 10, 512 << 10} {
		body := convo(sz, 8)
		for _, gl := range []bool{false, true} {
			name := sizeName(sz) + "/natif"
			if gl {
				name = sizeName(sz) + "/natif+gitleaks"
			}
			b.Run(name, func(b *testing.B) {
				v := NewVault("")
				if gl {
					v.gl = loadGL(b)
				}
				v.Mask(body)
				var dst []byte
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				for b.Loop() {
					dst, _ = v.MaskTo(dst, body)
				}
			})
		}
	}
}

// Sans secret : le coût de la seule recherche de mots-clés.
func BenchmarkMaskGitleaksClean(b *testing.B) {
	body := convo(512<<10, 0)
	for _, gl := range []bool{false, true} {
		b.Run(map[bool]string{false: "natif", true: "natif+gitleaks"}[gl], func(b *testing.B) {
			v := NewVault("")
			if gl {
				v.gl = loadGL(b)
			}
			var dst []byte
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				dst, _ = v.MaskTo(dst, body)
			}
		})
	}
}
