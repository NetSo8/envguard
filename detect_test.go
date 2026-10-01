package main

import (
	"strings"
	"testing"
)

func found(in string) []string {
	var got []string
	scan([]byte(in), func(s span) { got = append(got, s.kind+"="+in[s.s:s.e]) })
	return got
}

const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestDetectNewRules(t *testing.T) {
	pemBody := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\nVJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictG\\neRtKbW8x"
	cases := []struct{ in, want string }{
		{`{"text":"token: ` + jwt + `"}`, "jwt=" + jwt},
		{`{"text":"-----BEGIN RSA PRIVATE KEY-----\n` + pemBody + `\n-----END RSA PRIVATE KEY-----"}`, "private_key=MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"},
		{`{"text":"DATABASE_URL=postgres://admin:S3cr3t-P4ss@db.internal:5432/app"}`, "url_password=S3cr3t-P4ss"},
		{`{"text":"curl -H \"Authorization: Bearer 7f9c2ba4e88f827d616045507605853e\" https://api.x"}`, "bearer=7f9c2ba4e88f827d616045507605853e"},
		{`{"text":"SG` + `.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"}`, "sendgrid=SG" + ".ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"},
		{`{"text":"AS` + `IAIOSFODNN7EXAMPLE1"}`, "aws=AS" + "IAIOSFODNN7EXAMPLE1"},
		{`{"text":"sh` + `pat_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"}`, "shopify=sh" + "pat_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"},
		{`{"text":"auth_header = \"Zk8qLm2vPx9Tr4wQ\""}`, "generic=Zk8qLm2vPx9Tr4wQ"},
	}
	for _, c := range cases {
		got := found(c.in)
		ok := false
		for _, g := range got {
			ok = ok || g == c.want
		}
		if !ok {
			t.Errorf("%.60s…\n  attendu %s\n  obtenu  %v", c.in, c.want, got)
		}
	}
	// Toutes les lignes base64 du corps PEM sont masquées, l'en-tête non.
	got := found(`"-----BEGIN PRIVATE KEY-----\n` + pemBody + `\n-----END PRIVATE KEY-----"`)
	if len(got) != 3 {
		t.Errorf("PEM : %d lignes masquées, attendu 3 : %v", len(got), got)
	}
}

func TestDetectNewRulesNoFalsePositive(t *testing.T) {
	for _, in := range []string{
		`{"text":"https://github.com/org/repo/blob/main/a.go"}`, // URL sans identifiants
		`{"text":"git clone git@github.com:org/repo.git"}`,      // SSH, pas de ://
		`{"text":"postgres://user:${DB_PASSWORD}@db:5432/app"}`, // variable, pas un secret
		`{"text":"https://user@example.com/path"}`,              // utilisateur sans mot de passe
		`{"text":"Authorization: Bearer ${TOKEN}"}`,             // variable
		`{"text":"Bearer token is required"}`,                   // prose
		`{"text":"-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYD\n-----END CERTIFICATE-----"}`, // certificat public
		`{"text":"eyJhbGciOiJIUzI1NiJ9 seul, sans payload"}`,                                                                          // pas un JWT complet
		`{"author":"Jean Dupont","oauth_callback":"https://app.local/cb"}`,                                                            // mots-clés, valeurs anodines
		`{"text":"SGML et hvs sont des sigles"}`,
	} {
		if got := found(in); len(got) > 0 {
			t.Errorf("faux positif dans %.70s : %v", in, got)
		}
	}
}

// Le masquage complet reste réversible pour les nouveaux types.
func TestNewRulesRoundTrip(t *testing.T) {
	v := NewVault("")
	in := `{"text":"` + jwt + ` et postgres://a:S3cr3t-P4ss@h/db"}`
	m, n := v.Mask([]byte(in))
	if n != 2 || strings.Contains(string(m), jwt) || strings.Contains(string(m), "S3cr3t-P4ss") {
		t.Fatalf("%d : %s", n, m)
	}
	if back, _ := v.Rehydrate(m); string(back) != in {
		t.Fatalf("aller-retour : %s", back)
	}
}
