// DEPRECATED — DO NOT BUILD ON THIS PACKAGE (framework-plan-v1.6 Part 4 cut).
//
// Part 4 cuts the statistical-eval surface, and this package is part of it.
// It stays in the tree only until its twelve importers are cut with it:
// deleting it today would be a refactor of internal/evalscore,
// internal/planner/autotune.go, internal/risk/calibration.go and
// internal/backtest — not a cleanup. internal/audit/part4_guard_test.go fails
// if any file outside that importer list imports it; adding yourself to the
// list is not the fix, cutting the dependency is.
//
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
		pctOf(lo), pctOf(hi))
}

// pctOf renders one interval bound the way Format does: tenths of a
// percent, half away from zero (math.Round).
func pctOf(x float64) float64 {
	return math.Round(x*1000) / 10
}

// UpperPct renders only the interval's upper bound in Format's style
// ("8.8") — for call sites that cite the upper bound alone (the G17
// tactic-batting-average auto-deprioritization reason line). The bound
// still comes from Interval: one math source, no second implementation.
func UpperPct(k, n int) string {
	if n <= 0 || k < 0 || k > n {
		return "n/a"
	}
	_, hi := Interval(k, n)
	return fmt.Sprintf("%.1f", pctOf(hi))
}
