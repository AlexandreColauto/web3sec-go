// Package wilson computes Wilson score intervals — the ONLY interval the
// framework may print for "X of Y" evidence counts (G4 discipline: a raw
// ratio without an interval is a claim the suite cannot support). Pure
// math, no storage, no model. z is fixed at 1.959963984540054 (two-sided
// 95%); a second confidence level is a future flag, not a second constant.
package wilson

import (
	"fmt"
	"math"
)

const z95 = 1.959963984540054

// Interval returns the Wilson score interval for k successes in n trials.
// Degenerate inputs (n<=0, k<0, k>n) return (0, 0) — callers must check
// n>0 before rendering; Format does exactly that.
func Interval(k, n int) (float64, float64) {
	if n <= 0 || k < 0 || k > n {
		return 0, 0
	}
	p := float64(k) / float64(n)
	z2 := z95 * z95
	den := 1 + z2/float64(n)
	center := p + z2/(2*float64(n))
	spread := z95 * math.Sqrt(p*(1-p)/float64(n)+z2/(4*float64(n)*float64(n)))
	lo, hi := (center-spread)/den, (center+spread)/den
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// Format renders the framework's canonical interval line, e.g.
// "recall: 2/2 (95% CI 34.2–100.0%)". noun is the metric name.
func Format(k, n int, noun string) string {
	if n <= 0 || k < 0 || k > n {
		return fmt.Sprintf("%s: %d/%d (95%% CI n/a)", noun, k, n)
	}
	lo, hi := Interval(k, n)
	return fmt.Sprintf("%s: %d/%d (95%% CI %.1f–%.1f%%)", noun, k, n,
		math.Round(lo*1000)/10, math.Round(hi*1000)/10)
}
