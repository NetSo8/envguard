package main

// matcher remplace plusieurs motifs en une seule passe sur le buffer.
//
// Index par premier octet : pour chaque position, on ne teste que les motifs
// qui commencent par cet octet (du plus long au plus court). Aucun octet
// n'est recopié tant qu'aucun motif n'a été trouvé ; ensuite, une seule
// allocation pour la sortie, quel que soit le nombre de secrets.
type matcher struct {
	pairs []pair
	first [256][]uint16
}

func newMatcher(ps []pair) *matcher {
	m := &matcher{pairs: ps}
	for i, p := range ps {
		if len(p.from) == 0 {
			continue
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

func (m *matcher) replace(b []byte) ([]byte, int) {
	if m == nil || len(m.pairs) == 0 {
		return b, 0
	}
	var out []byte
	last, n := 0, 0
	for i := 0; i < len(b); {
		cands := m.first[b[i]]
		hit := -1
		for _, k := range cands {
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
		if out == nil {
			out = make([]byte, 0, len(b)+len(b)>>4+64)
		}
		p := &m.pairs[hit]
		out = append(out, b[last:i]...)
		out = append(out, p.to...)
		i += len(p.from)
		last = i
		n++
	}
	if out == nil {
		return b, 0
	}
	return append(out, b[last:]...), n
}
