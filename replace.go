package main

// matcher remplace plusieurs motifs en une seule passe sur le buffer.
//
// Filtre sur les deux premiers octets : un bitmap de 65 536 bits (8 Ko, tient
// dans le cache L1) dit si un motif peut commencer à cette position. Le texte
// ordinaire contient beaucoup de 's' ou de 'g', mais rarement « sk » suivi
// d'un motif : la plupart des positions coûtent un seul test de bit. Ensuite,
// index par premier octet (du plus long au plus court). Aucun octet n'est
// recopié tant qu'aucun motif n'a été trouvé ; la sortie est écrite dans dst
// (réutilisé par l'appelant), qui n'est agrandi qu'au besoin.
type matcher struct {
	pairs []pair
	first [256][]uint16
	two   [1 << 16 / 64]uint64 // bit (a<<8|b) : un motif commence par « ab »
	short bool                 // un motif d'un seul octet : filtre inutilisable
}

func newMatcher(ps []pair) *matcher {
	m := &matcher{pairs: ps}
	for i, p := range ps {
		if len(p.from) == 0 {
			continue
		}
		if len(p.from) == 1 {
			m.short = true
		} else {
			x := uint16(p.from[0])<<8 | uint16(p.from[1])
			m.two[x>>6] |= 1 << (x & 63)
		}
		c := p.from[0]
		// insertion triée par longueur décroissante : le plus long gagne
		l := m.first[c]
		j := len(l)
		for j > 0 && len(ps[l[j-1]].from) < len(p.from) {
			j--
		}
		l = append(l, 0)
		copy(l[j+1:], l[j:])
		l[j] = uint16(i)
		m.first[c] = l
	}
	return m
}

// replace renvoie b tel quel si aucun motif n'est présent (dst intact),
// sinon dst[:0] rempli. dst ne doit pas chevaucher b.
func (m *matcher) replace(dst, b []byte) ([]byte, int) { return m.replaceIf(dst, b, nil) }

// replaceIf : comme replace, mais un motif trouvé n'est remplacé que si
// keep(index de la paire) l'accepte ; sinon il est recopié tel quel.
func (m *matcher) replaceIf(dst, b []byte, keep func(int) bool) ([]byte, int) {
	if m == nil || len(m.pairs) == 0 {
		return b, 0
	}
	var out []byte
	last, n := 0, 0
	for i := 0; i < len(b); {
		if !m.short {
			// Avance tant qu'aucun motif ne peut commencer ici (cas courant).
			for i+1 < len(b) {
				x := uint16(b[i])<<8 | uint16(b[i+1])
				if m.two[x>>6]&(1<<(x&63)) != 0 {
					break
				}
				i++
			}
			if i+1 >= len(b) {
				break
			}
		}
		hit := -1
		for _, k := range m.first[b[i]] {
			f := m.pairs[k].from
			if len(b)-i >= len(f) && string(b[i:i+len(f)]) == string(f) {
				hit = int(k)
				break
			}
		}
		if hit < 0 {
			i++
			continue
		}
		if keep != nil && !keep(hit) {
			i += len(m.pairs[hit].from) // motif refusé : laissé intact
			continue
		}
		if n == 0 {
			out = dst[:0]
			if want := len(b) + len(b)>>4 + 64; cap(out) < want {
				out = make([]byte, 0, want)
			}
		}
		p := &m.pairs[hit]
		out = append(out, b[last:i]...)
		out = append(out, p.to...)
		i += len(p.from)
		last = i
		n++
	}
	if n == 0 {
		return b, 0
	}
	return append(out, b[last:]...), n
}
