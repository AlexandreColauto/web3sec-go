// pyre.go: a small backtracking regex engine with Python `re` semantics.
//
// structural_index.py leans on four constructs Go's RE2 (regexp) does not
// have — lookahead, lookbehind, lazy quantifiers and `$`-before-trailing-
// newline — and its state-variable regex (`_STATE_RE`) is a lazy-quantified
// multiline pattern whose byte-exact match set decides which state variables
// land in the artifact. Rewriting those patterns by hand is where parity
// bugs hide, so this file ports the *matcher* instead: a backtracking engine
// over a parsed AST with Python's preference order (alternation left to
// right, greedy/lazy quantifiers), Python's Unicode \w/\s/\d and its
// `^`/`$` semantics. The compatible (majority) patterns still go through
// Go's regexp for speed; only the incompatible ones compile here.
//
// Scope note: `\b`/`\B` use the same Unicode word predicate as `\w`, which
// is what Python's str patterns do. The Go-regexp fast path in parser.go
// cannot express that (RE2 has no lookaround), so its `\b` stays ASCII-word
// based; a Unicode word character directly adjacent to a keyword boundary is
// the one remaining divergence, and it cannot occur in valid Solidity (the
// compiler requires ASCII identifiers).
package structidx

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type reOp uint8

const (
	opCat reOp = iota
	opAlt
	opLit
	opAny
	opClass
	opGroup
	opRep
	opBol
	opEol
	opWordB
	opWordNB
	opAhead
	opBehind
)

// Predefined Python character-set ids. A `reRange` with set != 0 stands for
// one of these sets rather than a literal rune range, so `\w` inside a
// bracket expression (`[\w\[\]\.]`) keeps its Python meaning.
const (
	setWord uint8 = iota + 1
	setSpace
	setDigit
)

type reRange struct {
	lo, hi rune
	set    uint8
}

type reNode struct {
	op    reOp
	subs  []*reNode
	r     rune
	cls   []reRange
	neg   bool
	fold  bool
	gidx  int
	min   int
	max   int // -1 = unbounded
	lazy  bool
	width int // fixed width, lookbehind only
}

type pyre struct {
	root  *reNode
	fold  bool
	multi bool
	nGrp  int
}

var (
	// Python's str-pattern sets: `\w` is alphanumeric-or-underscore over the
	// whole Unicode range, `\d` is Nd, `\s` is Unicode whitespace.
	reWordRanges  = []reRange{{set: setWord}}
	reSpaceRanges = []reRange{{set: setSpace}}
	reDigitRanges = []reRange{{set: setDigit}}
)

// compilePyre parses a Python pattern. fold is re.I, multi is re.M; an
// inline `(?i)`/`(?m)` flips the same flags for the rest of the pattern.
func compilePyre(pattern string, fold, multi bool) *pyre {
	p := &reParser{src: []rune(pattern), fold: fold, multi: multi}
	root := p.parseAlt()
	if p.i != len(p.src) {
		panic("structidx: unparsed regex tail: " + pattern)
	}
	return &pyre{root: root, fold: p.fold, multi: p.multi, nGrp: p.nGrp}
}

// ---- parser ---------------------------------------------------------------

type reParser struct {
	src   []rune
	i     int
	fold  bool
	multi bool
	nGrp  int
}

func (p *reParser) peek() rune {
	if p.i < len(p.src) {
		return p.src[p.i]
	}
	return 0
}

func (p *reParser) expect(c rune) {
	if p.peek() != c {
		panic("structidx: expected regex char")
	}
	p.i++
}

func (p *reParser) parseAlt() *reNode {
	first := p.parseCat()
	if p.peek() != '|' {
		return first
	}
	subs := []*reNode{first}
	for p.peek() == '|' {
		p.i++
		subs = append(subs, p.parseCat())
	}
	return &reNode{op: opAlt, subs: subs}
}

func (p *reParser) parseCat() *reNode {
	var subs []*reNode
	for p.i < len(p.src) {
		if c := p.src[p.i]; c == '|' || c == ')' {
			break
		}
		subs = append(subs, p.parseRepeat())
	}
	if len(subs) == 1 {
		return subs[0]
	}
	return &reNode{op: opCat, subs: subs}
}

func (p *reParser) parseRepeat() *reNode {
	atom := p.parseAtom()
	for p.i < len(p.src) {
		var min, max int
		switch p.src[p.i] {
		case '*':
			min, max = 0, -1
			p.i++
		case '+':
			min, max = 1, -1
			p.i++
		case '?':
			min, max = 0, 1
			p.i++
		case '{':
			save := p.i
			p.i++
			n1, ok := p.parseNum()
			if !ok {
				p.i = save
				return atom
			}
			switch p.peek() {
			case '}':
				p.i++
				min, max = n1, n1
			case ',':
				p.i++
				if p.peek() == '}' {
					p.i++
					min, max = n1, -1
				} else {
					n2, ok2 := p.parseNum()
					if !ok2 || p.peek() != '}' {
						p.i = save
						return atom
					}
					p.i++
					min, max = n1, n2
				}
			default:
				p.i = save
				return atom
			}
		default:
			return atom
		}
		lazy := false
		if p.peek() == '?' {
			lazy = true
			p.i++
		}
		atom = &reNode{op: opRep, subs: []*reNode{atom},
			min: min, max: max, lazy: lazy}
	}
	return atom
}

func (p *reParser) parseNum() (int, bool) {
	start := p.i
	n := 0
	for p.i < len(p.src) && p.src[p.i] >= '0' && p.src[p.i] <= '9' {
		n = n*10 + int(p.src[p.i]-'0')
		p.i++
	}
	return n, p.i > start
}

func (p *reParser) parseAtom() *reNode {
	switch c := p.src[p.i]; c {
	case '(':
		return p.parseGroup()
	case '[':
		return p.parseClass()
	case '.':
		p.i++
		return &reNode{op: opAny}
	case '^':
		p.i++
		return &reNode{op: opBol}
	case '$':
		p.i++
		return &reNode{op: opEol}
	case '\\':
		return p.parseEscape()
	default:
		p.i++
		return &reNode{op: opLit, r: c, fold: p.fold}
	}
}

func (p *reParser) parseGroup() *reNode {
	p.i++ // '('
	if p.peek() == '?' {
		p.i++
		switch p.peek() {
		case ':':
			p.i++
			sub := p.parseAlt()
			p.expect(')')
			return &reNode{op: opGroup, subs: []*reNode{sub}, gidx: -1}
		case '=':
			p.i++
			sub := p.parseAlt()
			p.expect(')')
			return &reNode{op: opAhead, subs: []*reNode{sub}}
		case '!':
			p.i++
			sub := p.parseAlt()
			p.expect(')')
			return &reNode{op: opAhead, subs: []*reNode{sub}, neg: true}
		case '<':
			p.i++
			neg := false
			if p.peek() == '!' {
				neg = true
			}
			if p.peek() != '=' && p.peek() != '!' {
				panic("structidx: bad lookbehind")
			}
			p.i++
			sub := p.parseAlt()
			p.expect(')')
			return &reNode{op: opBehind, subs: []*reNode{sub}, neg: neg,
				width: nodeWidth(sub)}
		case 'i':
			p.i++
			p.expect(')')
			p.fold = true
			return &reNode{op: opCat}
		case 'm':
			p.i++
			p.expect(')')
			p.multi = true
			return &reNode{op: opCat}
		}
		panic("structidx: unsupported group")
	}
	p.nGrp++
	idx := p.nGrp
	sub := p.parseAlt()
	p.expect(')')
	return &reNode{op: opGroup, subs: []*reNode{sub}, gidx: idx}
}

func (p *reParser) parseClass() *reNode {
	p.i++ // '['
	neg := false
	if p.peek() == '^' {
		neg = true
		p.i++
	}
	var cls []reRange
	first := true
	for p.i < len(p.src) && (p.src[p.i] != ']' || first) {
		first = false
		lo, setID := p.classRune()
		if setID != 0 {
			cls = append(cls, reRange{set: setID})
			continue
		}
		if p.peek() == '-' && p.i+1 < len(p.src) && p.src[p.i+1] != ']' {
			p.i++
			hi, setID2 := p.classRune()
			if setID2 != 0 {
				panic("structidx: class escape in range")
			}
			cls = append(cls, reRange{lo, hi, 0})
		} else {
			cls = append(cls, reRange{lo, lo, 0})
		}
	}
	p.expect(']')
	return &reNode{op: opClass, cls: cls, neg: neg, fold: p.fold}
}

// classRune reads one class item. A non-zero set id reports a predefined set
// (\w/\s/\d); otherwise the rune is a literal.
func (p *reParser) classRune() (rune, uint8) {
	c := p.src[p.i]
	if c != '\\' {
		p.i++
		return c, 0
	}
	p.i++
	if p.i >= len(p.src) {
		panic("structidx: dangling class escape")
	}
	e := p.src[p.i]
	p.i++
	switch e {
	case 'w':
		return 0, setWord
	case 's':
		return 0, setSpace
	case 'd':
		return 0, setDigit
	case 'n':
		return '\n', 0
	case 't':
		return '\t', 0
	case 'r':
		return '\r', 0
	case 'f':
		return '\f', 0
	case 'v':
		return '\v', 0
	case 'u':
		if r, ok := p.readHex(4); ok {
			return r, 0
		}
		return 'u', 0
	case 'x':
		if r, ok := p.readHex(2); ok {
			return r, 0
		}
		return 'x', 0
	default:
		return e, 0
	}
}

func (p *reParser) parseEscape() *reNode {
	p.i++ // '\'
	if p.i >= len(p.src) {
		panic("structidx: dangling escape")
	}
	e := p.src[p.i]
	p.i++
	switch e {
	case 'w':
		return &reNode{op: opClass, cls: reWordRanges, fold: p.fold}
	case 's':
		return &reNode{op: opClass, cls: reSpaceRanges, fold: p.fold}
	case 'd':
		return &reNode{op: opClass, cls: reDigitRanges, fold: p.fold}
	case 'W':
		return &reNode{op: opClass, cls: reWordRanges, neg: true, fold: p.fold}
	case 'S':
		return &reNode{op: opClass, cls: reSpaceRanges, neg: true, fold: p.fold}
	case 'D':
		return &reNode{op: opClass, cls: reDigitRanges, neg: true, fold: p.fold}
	case 'b':
		return &reNode{op: opWordB}
	case 'B':
		return &reNode{op: opWordNB}
	case 'A':
		return &reNode{op: opBol}
	case 'Z':
		return &reNode{op: opEol}
	case 'n':
		return &reNode{op: opLit, r: '\n', fold: p.fold}
	case 't':
		return &reNode{op: opLit, r: '\t', fold: p.fold}
	case 'r':
		return &reNode{op: opLit, r: '\r', fold: p.fold}
	case 'f':
		return &reNode{op: opLit, r: '\f', fold: p.fold}
	case 'v':
		return &reNode{op: opLit, r: '\v', fold: p.fold}
	case 'u':
		if r, ok := p.readHex(4); ok {
			return &reNode{op: opLit, r: r, fold: p.fold}
		}
		return &reNode{op: opLit, r: 'u', fold: p.fold}
	case 'x':
		if r, ok := p.readHex(2); ok {
			return &reNode{op: opLit, r: r, fold: p.fold}
		}
		return &reNode{op: opLit, r: 'x', fold: p.fold}
	default:
		return &reNode{op: opLit, r: e, fold: p.fold}
	}
}

// readHex consumes n hex digits (Python's \uXXXX / \xXX escapes).
func (p *reParser) readHex(n int) (rune, bool) {
	if p.i+n > len(p.src) {
		return 0, false
	}
	var r rune
	for k := 0; k < n; k++ {
		c := p.src[p.i+k]
		switch {
		case c >= '0' && c <= '9':
			r = r*16 + (c - '0')
		case c >= 'a' && c <= 'f':
			r = r*16 + (c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			r = r*16 + (c - 'A' + 10)
		default:
			return 0, false
		}
	}
	p.i += n
	return r, true
}

// nodeWidth is the fixed character width of a node (lookbehind only).
func nodeWidth(n *reNode) int {
	switch n.op {
	case opLit, opAny, opClass:
		return 1
	case opCat:
		w := 0
		for _, s := range n.subs {
			w += nodeWidth(s)
		}
		return w
	case opGroup:
		return nodeWidth(n.subs[0])
	case opRep:
		if n.min != n.max {
			panic("structidx: variable-width lookbehind")
		}
		return n.min * nodeWidth(n.subs[0])
	case opAlt:
		w := nodeWidth(n.subs[0])
		for _, s := range n.subs[1:] {
			if nodeWidth(s) != w {
				panic("structidx: variable-width lookbehind alt")
			}
		}
		return w
	default:
		return 0
	}
}

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
