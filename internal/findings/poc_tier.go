package findings

// Two-tier fork evidence (framework-plan-v1.6 §2.2). EXISTENCE is the cheap
// tier: the state break on a pinned fork, at any magnitude, under
// non-optimized conditions. MAXIMIZED is the maximization loop's output.
// Severity's provisional pass consumes EXISTENCE; its final pass requires
// MAXIMIZED. The tier is a property of the EVIDENCE, never of the class —
// the same class can be decidable on a local harness for one hypothesis and
// need real protocol state for the next.

import (
	"fmt"

	"websec/internal/validation"
)

// The tier literals (the schema's enum values), named once: the law and the
// readers must agree on the spelling.
const (
	pocTierExistence = "existence"
	pocTierMaximized = "maximized"
)

// PocTiers are the declared tiers, weakest first.
var PocTiers = []string{pocTierExistence, pocTierMaximized}

// PocTierOf returns the strongest tier present on a finding's evidence, or
// "none" when no evidence item carries a tier.
func PocTierOf(f validation.Value) string {
	out := "none"
	for _, tier := range PocTiers {
		if HasPocTier(f, tier) {
			out = tier
		}
	}
	return out
}

// HasPocTier reports whether any evidence item carries this tier.
func HasPocTier(f validation.Value, tier string) bool {
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "poc_tier") == tier {
			return true
		}
	}
	return false
}

// MaximizedEvidence returns the first MAXIMIZED evidence item.
func MaximizedEvidence(f validation.Value) (validation.Value, bool) {
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "poc_tier") == pocTierMaximized {
			return e, true
		}
	}
	return validation.VNull(), false
}

// ValidatePocTierOrder is the §2.2 ordering law, in the WRITE path so every
// caller obeys it — mint, the ladder, and Phase 5's maximization loop alike.
// MAXIMIZED requires an EXISTENCE tier first, but only where the hypothesis is
// fork-dependent: a fork-independent hypothesis has no fork to break, and
// demanding one would make it unmintable.
func ValidatePocTierOrder(f validation.Value, tier string) error {
	if tier != pocTierMaximized {
		return nil
	}
	if !ForkDependent(f) {
		return nil
	}
	if !HasPocTier(f, pocTierExistence) {
		return fmt.Errorf("a maximized PoC requires an existence-tier PoC " +
			"first (v1.6 §2.2): mint the state break, then maximize it")
	}
	return nil
}
