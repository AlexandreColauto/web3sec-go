package harness

import (
	"math"
	"sort"
	"strings"
	"unicode/utf8"
)

// intParse is the outcome of reading a bound value the way the twin's
// click does.
type intParse int

const (
	intOK intParse = iota
	intNotAnInt
	// intOverflowPositive is a POSITIVE Python int too wide for int64:
	// click accepts it (bignums), so the invocation STATED a bound this
	// parse cannot hold. It is not an error and not "unstated" (r31 F2).
	intOverflowPositive
	// intOverflowNegative is a NEGATIVE value too wide for int64. Its
	// sign is what decides it: every negative bound is < 1, which the
	// twin's VerifierFlags raises for — so this arm is degenerate in the
	// same way `--loop-bound -1` is, whatever the magnitude.
	intOverflowNegative
)

// parseClickInt reads a value the way click's type=int does, which is
// Python's int(str): surrounding whitespace is ignored, an optional +/-
// sign is allowed, ASCII underscores are allowed ONLY between digits, and
// any Unicode decimal digit (category Nd — int("٤٢") == 42, while "²" is
// a digit to str.isdigit() but NOT to int()) counts as its value, decoded
// by decimalDigit's block table (the twin's own Nd data). A value that is
// not an integer at all is intNotAnInt: click raises a UsageError for it,
// so the run is impossible rather than unbounded.
//
// The range arm is int64-wide on purpose (r31 F2): Python's int has no
// limit, so the only honest boundary is OUR storage. A value in
// [MinInt64, MaxInt64] is returned EXACTLY — MaxInt64 is a legal stated
// bound, not an overflow, and the r28 guard at 1<<62 wrongly collapsed
// both MaxInt64 and 2^62+1 into "no bound was stated". A positive value
// wider than int64 is intOverflowPositive, which the caller turns into the
// saturating BoundCapped (a stated bound, rendered as a lower bound); a
// negative one is intOverflowNegative, which is degenerate like every
// other value below 1. A negative magnitude of exactly 2^63 is MinInt64,
// which is representable and lands in the n < 1 degenerate arm.
func parseClickInt(raw string) (int, intParse) {
	s := strings.TrimSpace(raw) // int() strips whitespace, "\n4" included
	if s == "" {
		return 0, intNotAnInt
	}
	neg := false
	i := 0
	if s[0] == '+' || s[0] == '-' {
		neg = s[0] == '-'
		i = 1
	}
	// Magnitude accumulates in uint64 so a legal MinInt64 (|value| ==
	// 2^63) is representable while 2^63+1 is not.
	limit := uint64(math.MaxInt64)
	if neg {
		limit = uint64(math.MaxInt64) + 1
	}
	n, digits, underscore, overflow := uint64(0), 0, false, false
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '_' {
			// Python: an underscore must sit between digits, so "_4",
			// "4_" and "4__0" are not integers at all.
			if digits == 0 || underscore {
				return 0, intNotAnInt
			}
			underscore = true
			i += size
			continue
		}
		d, isDigit := decimalDigit(r)
		if !isDigit {
			return 0, intNotAnInt
		}
		underscore = false
		digits++
		if !overflow {
			if n > (limit-uint64(d))/10 {
				overflow = true
			} else {
				n = n*10 + uint64(d)
			}
		}
		i += size
	}
	if underscore || digits == 0 {
		return 0, intNotAnInt
	}
	if overflow {
		if neg {
			return 0, intOverflowNegative
		}
		return 0, intOverflowPositive
	}
	if neg {
		if n == limit {
			return math.MinInt64, intOK // -2^63 fits int64 exactly
		}
		return -int(n), intOK
	}
	return int(n), intOK
}

// ndBlockStarts is the start — the ZERO — of every Unicode Nd (decimal
// digit) block the twin's Python accepts, sorted ascending. parseClickInt
// decodes a digit by locating the block that CONTAINS it, so every entry
// here is the first of ten consecutive code points.
//
// The table is DERIVED, not guessed: it is every code point whose category
// is Nd and whose int(chr(cp)) is 0, printed by the twin's own interpreter
// (read-only), whose unicodedata is the authority for what click's
// type=int accepts:
//
//	/home/xand/Projects/miniprover/.venv/bin/python -c '
//	  import unicodedata
//	  cps=[cp for cp in range(0x110000)
//	       if unicodedata.category(chr(cp))=="Nd"]
//	  print(len(cps), [hex(cp) for cp in cps if int(chr(cp))==0])'
//	-> 760 [0x30, 0x660, …, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC,
//	        0x1D7F6, …, 0x1FBF0]        (76 blocks)
//
// 760 code points over 76 blocks, so every block is exactly ten long and
// every code point of a block decodes to (cp - start) == int(chr(cp)).
// NOTE the five ADJACENT pairs (0x116D0/0x116DA and the four mathematical
// blocks 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6 — r30 P1-2): a
// decoder that walks DOWN to the first non-digit (the r29 implementation)
// walks out of the block it was given and into the PREVIOUS one, decoding
// all 36 later code points as 9. Locating the containing block is what
// makes adjacency harmless.
//
// This is deliberately the TWIN's data and not Go's: Go 1.26 ships Unicode
// 15.0.0, whose 680 Nd code points are a strict SUBSET of the twin's 760
// (the twin adds the 0x10D40, 0x116D0, 0x116DA, 0x11BF0, 0x16130, 0x16D70,
// 0x1CCF0 and 0x1E5F1 blocks, which click's int() accepts and which
// therefore must decode). A rune this table does not cover is UNPARSEABLE
// (decimalDigit returns false) — the UsageError direction — never a digit,
// so a Go Unicode version that ever grows past the twin's data fails
// closed instead of inventing a value.
var ndBlockStarts = []rune{
	0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6,
	0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6,
	0xD66, 0xDE6, 0xE50, 0xED0, 0xF20, 0x1040,
	0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80,
	0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620,
	0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0,
	0xFF10, 0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0,
	0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
	0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950,
	0x11BF0, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16130,
	0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE,
	0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0,
	0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
}

// decimalDigit maps a Unicode decimal digit to 0-9 the way Python's int()
// does. ndBlockStarts IS the definition of "decimal digit" here — not
// unicode.IsDigit, whose Nd set is Go's Unicode version rather than the
// twin's — so a rune outside the table is unparseable and lands in
// parseClickInt's intNotAnInt (click's "'…' is not a valid integer"), while
// a digit in an ADJACENT block still decodes from its own block.
func decimalDigit(r rune) (int, bool) {
	i := sort.Search(len(ndBlockStarts), func(i int) bool {
		return ndBlockStarts[i] > r
	}) - 1
	if i < 0 {
		return 0, false
	}
	d := int(r - ndBlockStarts[i])
	if d < 0 || d > 9 {
		return 0, false
	}
	return d, true
}
