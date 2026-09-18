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
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: constant pattern compiled at init, the regexp.MustCompile contract
		panic("structidx: unparsed regex tail: " + pattern)
	}
	return &pyre{root: root, fold: p.fold, multi: p.multi, nGrp: p.nGrp}
}
