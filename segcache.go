package main

import (
	"hash/maphash"
	"sync"
)

// Cache de masquage par segment.
//
// Un agent (Claude Code, Codex…) renvoie toute la conversation à chaque tour :
// un contexte de 1 Mo est rescanné entièrement alors que seuls les derniers
// messages sont nouveaux. On découpe donc le body JSON en segments (chaque
// élément de messages / input / contents / tools / system…, et chaque grosse
// valeur de premier niveau) et on mémorise le résultat du masquage de chacun.
//
// Exactitude :
//   - les segments sont coupés entre deux valeurs JSON, jamais dans une
//     string : le scan d'un segment isolé donne exactement le même résultat
//     que le scan du body entier ;
//   - une entrée n'est valable que pour la version du vault qui l'a produite
//     (nouveau secret, allowlist, pause => version incrémentée) ;
//   - si un nouveau secret apparaît pendant le masquage d'une requête, on
//     recommence : les segments déjà traités doivent aussi le masquer ;
//   - clé = hash 64 bits (graine aléatoire par processus) + longueur + 16
//     octets témoins (début et fin du segment) : une fausse correspondance
//     exigerait une collision 64 bits avec la même longueur et les mêmes
//     octets aux deux bouts, sans connaître la graine.

const (
	segBodyMin  = 16 << 10 // en dessous, masquage direct (le découpage ne vaut pas le coup)
	segCacheMin = 512      // segments plus petits : masqués directement, pas mis en cache
	segGenMax   = 1 << 14  // entrées par génération (deux générations : LRU approché)
)

var splitKeys = [...]string{"messages", "input", "contents", "tools", "system", "functions"}

type segKey struct {
	h          uint64
	n          int
	head, tail [8]byte
}

type segEntry struct {
	ver uint64
	out []byte // nil : segment sans secret (renvoyé tel quel)
	n   int    // nombre de remplacements
}

type segCache struct {
	mu       sync.Mutex
	cur, old map[segKey]segEntry
	seed     maphash.Seed
}

func newSegCache() *segCache {
	return &segCache{cur: map[segKey]segEntry{}, seed: maphash.MakeSeed()}
}

func (c *segCache) key(b []byte) segKey { // len(b) >= segCacheMin
	k := segKey{h: maphash.Bytes(c.seed, b), n: len(b)}
	copy(k.head[:], b)
	copy(k.tail[:], b[len(b)-8:])
	return k
}

func (c *segCache) get(k segKey, ver uint64) (segEntry, bool) {
	c.mu.Lock()
	e, ok := c.cur[k]
	if !ok && c.old != nil {
		if e, ok = c.old[k]; ok {
			c.cur[k] = e // promu : encore utilisé
		}
	}
	c.mu.Unlock()
	return e, ok && e.ver == ver
}

func (c *segCache) put(k segKey, e segEntry) {
	c.mu.Lock()
	if len(c.cur) >= segGenMax {
		c.old, c.cur = c.cur, make(map[segKey]segEntry, segGenMax/4)
	}
	c.cur[k] = e
	c.mu.Unlock()
}

// maskBufs : buffers réutilisés d'une requête à l'autre (dans bufs).
type maskBufs struct {
	out, tmp []byte
	cuts     []int // bornes des segments [s0, e0, s1, e1…]
}

// splitKey : valeur dont on découpe les éléments (tableau).
func splitKey(k []byte) bool {
	for _, s := range splitKeys {
		if string(k) == s {
			return true
		}
	}
	return false
}

// segments découpe un objet JSON en segments contigus couvrant tout le body.
func segments(b []byte, cuts []int) ([]int, bool) {
	cuts = cuts[:0]
	i := skipWS(b, 0)
	if i >= len(b) || b[i] != '{' {
		return cuts, false
	}
	gap := 0 // début du segment « interstitiel » courant
	cut := func(s, e int) {
		if s > gap {
			cuts = append(cuts, gap, s)
		}
		cuts = append(cuts, s, e)
		gap = e
	}
	i++
	for {
		i = skipWS(b, i)
		if i < len(b) && b[i] == '}' {
			break
		}
		if i >= len(b) || b[i] != '"' {
			return cuts, false
		}
		ks := i
		ke := skipString(b, i)
		i = skipWS(b, ke)
		if i >= len(b) || b[i] != ':' {
			return cuts, false
		}
		vs := skipWS(b, i+1)
		ve := skipValue(b, vs)
		if vs >= len(b) || ve <= vs {
			return cuts, false
		}
		switch {
		case b[vs] == '[' && splitKey(b[ks+1:ke-1]):
			j := vs + 1
			for {
				j = skipWS(b, j)
				if j >= ve-1 { // ']'
					break
				}
				ee := skipValue(b, j)
				if ee <= j {
					return cuts, false
				}
				cut(j, ee)
				j = skipWS(b, ee)
				if j < ve-1 && b[j] == ',' {
					j++
				}
			}
		case ve-vs >= segCacheMin:
			cut(vs, ve)
		}
		i = skipWS(b, ve)
		if i < len(b) && b[i] == ',' {
			i++
		}
	}
	if gap < len(b) {
		cuts = append(cuts, gap, len(b))
	}
	return cuts, true
}

// maskBody masque b en réutilisant les segments déjà vus. Même résultat que
// v.MaskTo(…, b) ; renvoie b tel quel si rien n'est à masquer.
func (c *segCache) maskBody(v *Vault, mb *maskBufs, b []byte) ([]byte, int) {
	direct := func() ([]byte, int) {
		out, n := v.MaskTo(mb.out, b)
		if n > 0 {
			mb.out = out
		}
		return out, n
	}
	if c == nil || len(b) < segBodyMin || v.paused.Load() {
		return direct()
	}
	cuts, ok := segments(b, mb.cuts)
	mb.cuts = cuts
	if !ok {
		return direct()
	}
	for attempt := 0; attempt < 3; attempt++ {
		ver := v.version.Load()
		out := mb.out[:0]
		total := 0
		for i := 0; i < len(cuts); i += 2 {
			piece := b[cuts[i]:cuts[i+1]]
			var k segKey
			if len(piece) >= segCacheMin {
				k = c.key(piece)
				if e, hit := c.get(k, ver); hit {
					if e.out == nil {
						out = append(out, piece...)
					} else {
						out = append(out, e.out...)
					}
					total += e.n
					continue
				}
			}
			m, n := v.MaskTo(mb.tmp, piece)
			if n > 0 {
				mb.tmp = m
			}
			out = append(out, m...)
			total += n
			if len(piece) >= segCacheMin {
				var stored []byte
				if n > 0 {
					stored = append([]byte(nil), m...)
				}
				c.put(k, segEntry{ver: ver, out: stored, n: n})
			}
		}
		mb.out = out
		if v.version.Load() == ver {
			if total == 0 {
				return b, 0
			}
			return out, total
		}
		// Un secret est apparu pendant ce masquage : les segments déjà
		// traités ne le connaissaient pas, on recommence.
	}
	return direct()
}
