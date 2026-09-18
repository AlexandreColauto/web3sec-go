package validation

import (
	"math"
	"math/big"
)

// pythonRound rounds x to n decimal places (n >= 0) with CPython
// round(x, n) semantics: decimal round-half-even applied to the EXACT
// binary value of x, then correctly rounded back to float64.
//
// It does not scale in binary (x*10**n in float introduces a second
// rounding that can flip an exact .5 boundary); the exact-rational
// algorithm was verified against CPython 3.14 over 1.5M structured and
// random probes (docs/RoundingAudit.md, risk R3). The sign of the input
// is preserved on zero results (CPython: round(-1e-20, 2) == -0.0).
//
// n=0 matches CPython round(x) as a value (CPython returns an int;
// webv2 never calls with n=0). Non-finite input panics: every webv2
// call site is finite by construction (ratios of counts, bounded sums).
func PyRound(x float64, n int) float64 { return pythonRound(x, n) }

func pythonRound(x float64, n int) float64 {
	if n < 0 {
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: documented unsupported input, unreachable from webv2 call sites
		panic("pythonRound: negative ndigits unsupported (unused in webv2)")
	}
	if math.IsNaN(x) || math.IsInf(x, 0) {
		// aislop-ignore-next-line ai-slop/go-library-panic — deliberate: documented unsupported input, unreachable from webv2 call sites
		panic("pythonRound: non-finite input (webv2 call sites are finite by construction)")
	}
	bits := math.Float64bits(x)
	neg := bits>>63 == 1
	exp := int(bits >> 52 & 0x7ff)
	m := big.NewInt(int64(bits & (1<<52 - 1)))
	e := -1074
	if exp != 0 {
		m.Add(m, big.NewInt(1<<52))
		e = exp - 1075
	}
	if m.Sign() == 0 {
		if neg {
			return math.Copysign(0, -1)
		}
		return 0
	}
	// scaled := x * 10^n exactly, as m * 5^n * 2^(e+n).
	for i := 0; i < n; i++ {
		m.Mul(m, big.NewInt(5))
		e++
	}
	r := roundHalfEvenInt(m, e)
	f := scaledToFloat64(r, n)
	if neg {
		f = math.Copysign(f, -1)
	}
	return f
}

// roundHalfEvenInt rounds m * 2^e (m > 0) to the nearest integer, ties to even.
func roundHalfEvenInt(m *big.Int, e int) *big.Int {
	if e >= 0 {
		return new(big.Int).Lsh(m, uint(e))
	}
	den := new(big.Int).Lsh(big.NewInt(1), uint(-e))
	q, rem := new(big.Int).QuoRem(m, den, new(big.Int))
	switch new(big.Int).Lsh(rem, 1).Cmp(den) {
	case 1:
		q.Add(q, big.NewInt(1))
	case 0:
		if q.Bit(0) == 1 {
			q.Add(q, big.NewInt(1))
		}
	}
	return q
}

// scaledToFloat64 returns the correctly rounded float64 of r / 10^n.
// The 128-bit intermediate clears the double-rounding danger bound for
// 53-bit results (P >= p + 2 suffices; 128 is far beyond).
func scaledToFloat64(r *big.Int, n int) float64 {
	res := new(big.Float).SetPrec(128).SetInt(r)
	if n > 0 {
		res.Quo(res, new(big.Float).SetInt64(pow10[n]))
	}
	f, _ := res.Float64()
	return f
}

var pow10 = [7]int64{1, 10, 100, 1000, 10000, 100000, 1000000}

// PythonRound is the exported alias of pythonRound for call sites outside
// this package (webv2 uses round(x, 3) in invariants.coverage and elsewhere).
// Additive only: same CPython semantics, same panic contract.
func PythonRound(x float64, n int) float64 { return pythonRound(x, n) }
