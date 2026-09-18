// pyre_parse.go: the pyre pattern parser — Python-regex AST construction.

package structidx

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
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
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
				// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
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
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
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
				// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
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
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
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
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
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
			// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
			panic("structidx: variable-width lookbehind")
		}
		return n.min * nodeWidth(n.subs[0])
	case opAlt:
		w := nodeWidth(n.subs[0])
		for _, s := range n.subs[1:] {
			if nodeWidth(s) != w {
				// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
				panic("structidx: variable-width lookbehind alt")
			}
		}
		return w
	default:
		return 0
	}
}
