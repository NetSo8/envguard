package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// conversation : body Anthropic réaliste, nMsg messages, secrets çà et là.
func conversation(r *rand.Rand, nMsg int, secrets []string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"model":"m","max_tokens":1024,"system":[{"type":"text","text":"` + strings.Repeat("Tu es un assistant de code. ", 40) + `"}],"tools":[`)
	for t := 0; t < 5; t++ {
		if t > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"outil_%d","description":"%s","input_schema":{"type":"object"}}`, t, strings.Repeat("décrit l'outil ", 50))
	}
	b.WriteString(`],"messages":[`)
	for i := 0; i < nMsg; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		txt := strings.Repeat(fmt.Sprintf("ligne %d du fichier main.go\\n", i), 20+r.Intn(40))
		if len(secrets) > 0 && r.Intn(4) == 0 {
			txt += "export API_KEY=" + secrets[r.Intn(len(secrets))] + "\\n"
		}
		fmt.Fprintf(&b, `{"role":"%s","content":[{"type":"text","text":"%s"}]}`, [2]string{"user", "assistant"}[i%2], txt)
	}
	b.WriteString(`],"stream":true}`)
	return b.Bytes()
}

// Le cache doit produire exactement le même résultat que le masquage direct,
// y compris quand des secrets apparaissent au fil de la conversation.
func TestSegCacheEquivalence(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var secrets []string
	for i := 0; i < 6; i++ {
		secrets = append(secrets, fmt.Sprintf("sk-ant-api03-%02dAbCdEfGhIjKlMnOpQrStUvWx%04d", i, r.Intn(9999)))
	}
	cached, direct := NewVault(""), NewVault("")
	key := []byte("0123456789abcdef0123456789abcdef")
	cached.SetKey(key)
	direct.SetKey(key)
	c := newSegCache()
	var mb maskBufs
	for turn := 1; turn <= 40; turn++ {
		r := rand.New(rand.NewSource(42)) // même préfixe à chaque tour, comme un vrai agent
		body := conversation(r, turn*3, secrets[:min(len(secrets), turn/6)])
		got, n1 := c.maskBody(cached, &mb, body)
		want, n2 := direct.Mask(body)
		if !bytes.Equal(got, want) || n1 != n2 {
			t.Fatalf("tour %d : résultat différent (%d vs %d remplacements)", turn, n1, n2)
		}
		if turn%10 == 0 { // allowlist en cours de route : le cache doit s'invalider
			cached.Allow(secrets[0])
			direct.Allow(secrets[0])
		}
	}
}

// Secret découvert dans le DERNIER message, alors qu'il apparaît aussi dans un
// message plus ancien sous une forme non détectable seule : il faut le masquer
// partout (recommencer le masquage avec le vault à jour).
func TestSegCacheLateSecret(t *testing.T) {
	v := NewVault("")
	c := newSegCache()
	var mb maskBufs
	secret := "Zk8qLm2vPx9Tr4wQ7nB3"
	old := `{"role":"user","content":"` + strings.Repeat("contexte ", 1000) + ` valeur vue : ` + secret + `"}`
	body := []byte(`{"messages":[` + old + `,` + old + `,{"role":"user","content":"` + strings.Repeat("x ", 4000) + `db_password = ` + secret + `"}]}`)
	if len(body) < segBodyMin {
		t.Fatalf("body trop petit (%d) : le cache ne serait pas utilisé", len(body))
	}
	out, _ := c.maskBody(v, &mb, body)
	if bytes.Contains(out, []byte(secret)) {
		t.Fatal("secret laissé en clair dans un segment déjà traité")
	}
}

func TestSegmentsCoverBody(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	body := conversation(r, 50, nil)
	cuts, ok := segments(body, nil)
	if !ok {
		t.Fatal("découpage refusé")
	}
	var re bytes.Buffer
	for i := 0; i < len(cuts); i += 2 {
		if i > 0 && cuts[i] != cuts[i-1] {
			t.Fatal("segments non contigus")
		}
		re.Write(body[cuts[i]:cuts[i+1]])
	}
	if !bytes.Equal(re.Bytes(), body) || len(cuts) < 50*2 {
		t.Fatalf("découpage incomplet : %d segments", len(cuts)/2)
	}
}

// Tour suivant d'une conversation de ~1 Mo : seuls 2 messages sont nouveaux.
func BenchmarkConversationTurn(b *testing.B) {
	secrets := []string{"sk-ant-api03-00AbCdEfGhIjKlMnOpQrStUvWx1234", "gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789"}
	prev := conversation(rand.New(rand.NewSource(3)), 1200, secrets)
	cur := conversation(rand.New(rand.NewSource(3)), 1202, secrets)
	b.Logf("body : %d Ko", len(cur)>>10)
	b.Run("direct", func(b *testing.B) {
		v := NewVault("")
		v.Mask(prev)
		var dst []byte
		b.SetBytes(int64(len(cur)))
		b.ReportAllocs()
		for b.Loop() {
			dst, _ = v.MaskTo(dst, cur)
		}
	})
	b.Run("cache", func(b *testing.B) {
		v := NewVault("")
		c := newSegCache()
		var mb maskBufs
		c.maskBody(v, &mb, prev) // tour précédent : met le cache en place
		b.SetBytes(int64(len(cur)))
		b.ReportAllocs()
		for b.Loop() {
			c.maskBody(v, &mb, cur)
		}
	})
	b.Run("cache+gitleaks", func(b *testing.B) {
		v := NewVault("")
		v.gl = loadGL(b)
		c := newSegCache()
		var mb maskBufs
		c.maskBody(v, &mb, prev) // tour précédent : met le cache en place
		b.SetBytes(int64(len(cur)))
		b.ReportAllocs()
		for b.Loop() {
			c.maskBody(v, &mb, cur)
		}
	})
}
