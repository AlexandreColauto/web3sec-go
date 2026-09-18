// pyre_match.go: the pyre backtracking matcher and the Python re surface.

package structidx

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ---- matcher --------------------------------------------------------------

type reCont func(pos int) bool

type reState struct {
	p    *pyre
	s    string
	caps []int
}

func decodeAt(s string, pos int) (rune, int) {
	if pos < 0 || pos >= len(s) {
		return 0, 0
	}
	return utf8.DecodeRuneInString(s[pos:])
}

func isWordRune(r rune) bool {
	// Python's \w / \b: Py_UNICODE_ISALNUM (letters + numbers) or '_'.
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// isDigitRune is Python's \d over str: Unicode decimal digits (Nd).
func isDigitRune(r rune) bool { return unicode.IsDigit(r) }

// isSpaceRune is Python's \s over str: the ASCII whitespace plus the four
// C0 separators, NEL and the Unicode space categories (Zs/Zl/Zp).
func isSpaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r',
		0x1c, 0x1d, 0x1e, 0x1f, 0x85:
		return true
	}
	return unicode.Is(unicode.Zs, r) || unicode.Is(unicode.Zl, r) ||
		unicode.Is(unicode.Zp, r)
}

// setMatch evaluates a predefined Python set id.
func setMatch(id uint8, r rune) bool {
	switch id {
	case setWord:
		return isWordRune(r)
	case setSpace:
		return isSpaceRune(r)
	case setDigit:
		return isDigitRune(r)
	}
	return false
}

func isWordAt(s string, pos int) bool {
	r, size := decodeAt(s, pos)
	return size > 0 && isWordRune(r)
}

// isWordBefore is isWordAt for the rune ENDING at pos (a boundary check looks
// backwards from a byte offset, which may sit inside a multi-byte rune).
func isWordBefore(s string, pos int) bool {
	if pos <= 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:pos])
	return isWordRune(r)
}

func runeEq(a, b rune, fold bool) bool {
	if a == b {
		return true
	}
	if !fold {
		return false
	}
	return foldEq(a, b)
}

// foldEq is Python's case-insensitive character comparison over str: equal
// under simple case folding (so s/\u017f and k/\u212a match), but no
// multi-character fold (\u00df never equals "ss").
func foldEq(a, b rune) bool {
	if a == b || toLowerRune(a) == toLowerRune(b) {
		return true
	}
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}
	return false
}

// anyFold reports whether pred holds for r or any rune in its case-fold orbit.
func anyFold(r rune, pred func(rune) bool) bool {
	if pred(r) {
		return true
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if pred(f) {
			return true
		}
	}
	return false
}

func toLowerRune(r rune) rune { return unicode.ToLower(r) }

func classMatch(n *reNode, r rune, fold bool) bool {
	in := func(rr rune) bool {
		for _, rg := range n.cls {
			if rg.set != 0 {
				if setMatch(rg.set, rr) {
					return true
				}
				continue
			}
			if rr >= rg.lo && rr <= rg.hi {
				return true
			}
		}
		return false
	}
	hit := in(r)
	if !hit && fold {
		hit = anyFold(r, in)
	}
	if n.neg {
		return !hit
	}
	return hit
}

func (x *reState) m(n *reNode, pos int, k reCont) bool {
	switch n.op {
	case opCat:
		return x.cat(n.subs, 0, pos, k)
	case opAlt:
		for _, sub := range n.subs {
			if x.m(sub, pos, k) {
				return true
			}
		}
		return false
	case opLit:
		r, size := decodeAt(x.s, pos)
		if size == 0 || !runeEq(r, n.r, n.fold && x.p.fold) {
			return false
		}
		return k(pos + size)
	case opAny:
		r, size := decodeAt(x.s, pos)
		if size == 0 || r == '\n' {
			return false
		}
		return k(pos + size)
	case opClass:
		r, size := decodeAt(x.s, pos)
		if size == 0 || !classMatch(n, r, n.fold && x.p.fold) {
			return false
		}
		return k(pos + size)
	case opGroup:
		return x.group(n, pos, k)
	case opRep:
		return x.rep(n, pos, 0, k)
	case opBol:
		if pos == 0 || (x.p.multi && x.s[pos-1] == '\n') {
			return k(pos)
		}
		return false
	case opEol:
		if pos == len(x.s) ||
			(pos == len(x.s)-1 && x.s[pos] == '\n') ||
			(x.p.multi && x.s[pos] == '\n') {
			return k(pos)
		}
		return false
	case opWordB:
		if isWordBefore(x.s, pos) != isWordAt(x.s, pos) {
			return k(pos)
		}
		return false
	case opWordNB:
		if isWordBefore(x.s, pos) == isWordAt(x.s, pos) {
			return k(pos)
		}
		return false
	case opAhead:
		matched := x.m(n.subs[0], pos, func(int) bool { return true })
		if matched == n.neg {
			return false
		}
		return k(pos)
	case opBehind:
		start := pos - n.width
		if start < 0 {
			if n.neg {
				return k(pos)
			}
			return false
		}
		matched := x.m(n.subs[0], start, func(end int) bool { return end == pos })
		if matched == n.neg {
			return false
		}
		return k(pos)
	}
	return false
}

func (x *reState) cat(subs []*reNode, i, pos int, k reCont) bool {
	if i == len(subs) {
		return k(pos)
	}
	return x.m(subs[i], pos, func(end int) bool {
		return x.cat(subs, i+1, end, k)
	})
}

func (x *reState) group(n *reNode, pos int, k reCont) bool {
	if n.gidx < 0 {
		return x.m(n.subs[0], pos, k)
	}
	start := pos
	si, ei := x.caps[2*n.gidx], x.caps[2*n.gidx+1]
	ok := x.m(n.subs[0], pos, func(end int) bool {
		x.caps[2*n.gidx], x.caps[2*n.gidx+1] = start, end
		if k(end) {
			return true
		}
		x.caps[2*n.gidx], x.caps[2*n.gidx+1] = si, ei
		return false
	})
	if !ok {
		x.caps[2*n.gidx], x.caps[2*n.gidx+1] = si, ei
	}
	return ok
}

func (x *reState) rep(n *reNode, pos, count int, k reCont) bool {
	if n.lazy {
		if count >= n.min && k(pos) {
			return true
		}
		if n.max >= 0 && count >= n.max {
			return false
		}
		return x.m(n.subs[0], pos, func(end int) bool {
			if end == pos {
				return false
			}
			return x.rep(n, end, count+1, k)
		})
	}
	if n.max < 0 || count < n.max {
		if x.m(n.subs[0], pos, func(end int) bool {
			if end == pos {
				return false
			}
			return x.rep(n, end, count+1, k)
		}) {
			return true
		}
	}
	if count >= n.min {
		return k(pos)
	}
	return false
}

// ---- public surface (Python re methods) -----------------------------------

func (p *pyre) newState(s string) *reState {
	return &reState{p: p, s: s, caps: make([]int, 2*(p.nGrp+1))}
}

func (x *reState) tryAt(pos int) bool {
	for i := range x.caps {
		x.caps[i] = -1
	}
	return x.m(x.p.root, pos, func(end int) bool {
		x.caps[0], x.caps[1] = pos, end
		return true
	})
}

// search is re.search from *from*: the leftmost match, or false.
func (p *pyre) search(s string, from int) ([]int, bool) {
	for i := from; i <= len(s); {
		x := p.newState(s)
		if x.tryAt(i) {
			return x.caps, true
		}
		if i == len(s) {
			break
		}
		_, size := decodeAt(s, i)
		i += size
	}
	return nil, false
}

// match is re.match from *at*: anchored, no scan.
func (p *pyre) match(s string, at int) ([]int, bool) {
	x := p.newState(s)
	if x.tryAt(at) {
		return x.caps, true
	}
	return nil, false
}

// findAll is re.finditer: non-overlapping matches left to right, an empty
// match advancing by one character (Python's infinite-loop guard).
func (p *pyre) findAll(s string) [][]int {
	var out [][]int
	for pos := 0; pos <= len(s); {
		caps, ok := p.search(s, pos)
		if !ok {
			break
		}
		out = append(out, caps)
		if caps[1] == caps[0] {
			if caps[1] >= len(s) {
				break
			}
			_, size := decodeAt(s, caps[1])
			pos = caps[1] + size
		} else {
			pos = caps[1]
		}
	}
	return out
}

// sub is re.sub with a literal replacement (our only uses).
func (p *pyre) sub(s, repl string) string {
	var b strings.Builder
	pos := 0
	for pos <= len(s) {
		caps, ok := p.search(s, pos)
		if !ok {
			break
		}
		b.WriteString(s[pos:caps[0]])
		b.WriteString(repl)
		if caps[1] == caps[0] {
			if caps[1] >= len(s) {
				pos = len(s)
				break
			}
			_, size := decodeAt(s, caps[1])
			b.WriteString(s[caps[1] : caps[1]+size])
			pos = caps[1] + size
		} else {
			pos = caps[1]
		}
	}
	b.WriteString(s[pos:])
	return b.String()
}

// capsGroup returns the byte span of capture *idx* (0 = whole match).
func capsGroup(caps []int, idx int) (int, int, bool) {
	if 2*idx+1 >= len(caps) || caps[2*idx] < 0 {
		return 0, 0, false
	}
	return caps[2*idx], caps[2*idx+1], true
}
