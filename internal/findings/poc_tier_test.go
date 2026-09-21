package findings

import (
	"testing"

	"websec/internal/validation"
)

func TestPocTierOfReportsTheHighestTierPresent(t *testing.T) {
	f := validation.VObj(
		validation.KV{K: "evidence", V: validation.VArr(
			validation.VObj(validation.KV{K: "evidence_id", V: validation.VStr("EV-1")},
				validation.KV{K: "poc_tier", V: validation.VStr("existence")}),
			validation.VObj(validation.KV{K: "evidence_id", V: validation.VStr("EV-2")},
				validation.KV{K: "poc_tier", V: validation.VStr("maximized")}),
		)})
	if got := PocTierOf(f); got != "maximized" {
		t.Fatalf("PocTierOf = %q, want maximized", got)
	}
	if !HasPocTier(f, "existence") {
		t.Fatal("HasPocTier(existence) = false, want true")
	}
	if _, ok := MaximizedEvidence(f); !ok {
		t.Fatal("MaximizedEvidence = false, want true")
	}
}

func TestPocTierOfIsNoneWithoutTieredEvidence(t *testing.T) {
	f := validation.VObj(validation.KV{K: "evidence", V: validation.VArr(
		validation.VObj(validation.KV{K: "evidence_id", V: validation.VStr("EV-1")}))})
	if got := PocTierOf(f); got != "none" {
		t.Fatalf("PocTierOf = %q, want none", got)
	}
	if _, ok := MaximizedEvidence(f); ok {
		t.Fatal("MaximizedEvidence = true on untiered evidence")
	}
}

// TestForkDependentDefaultsToDependent pins the §2.2 default: absent is
// unknown is dependent, because a missing value must never defund the
// evidence that would correct it.
func TestForkDependentDefaultsToDependent(t *testing.T) {
	if ForkDependent(validation.VObj(
		validation.KV{K: "fork_dependence", V: validation.VStr("none")})) {
		t.Fatal("fork_dependence=none must not be fork-dependent")
	}
	for _, v := range []string{"external-protocol-state", "real-price-feed",
		"real-balances-liquidity", "proxy-implementation"} {
		if !ForkDependent(validation.VObj(
			validation.KV{K: "fork_dependence", V: validation.VStr(v)})) {
			t.Fatalf("fork_dependence=%s must be fork-dependent", v)
		}
	}
	if !ForkDependent(validation.VObj()) {
		t.Fatal("an absent fork_dependence must default to dependent")
	}
}

// TestValidatePocTierOrderIsConditionalOnForkDependence is the Task 6/Task 8
// compatibility law: a fork-independent hypothesis has no fork to break, so it
// may be maximized without an existence tier; a fork-dependent one may not.
func TestValidatePocTierOrderIsConditionalOnForkDependence(t *testing.T) {
	dependent := validation.VObj(
		validation.KV{K: "fork_dependence", V: validation.VStr("real-price-feed")},
		validation.KV{K: "evidence", V: validation.VArr()})
	if err := ValidatePocTierOrder(dependent, "maximized"); err == nil {
		t.Fatal("fork-dependent maximized mint without existence must be refused")
	}
	independent := validation.VObj(
		validation.KV{K: "fork_dependence", V: validation.VStr("none")},
		validation.KV{K: "evidence", V: validation.VArr()})
	if err := ValidatePocTierOrder(independent, "maximized"); err != nil {
		t.Fatalf("fork-independent maximized mint refused: %v", err)
	}
	if err := ValidatePocTierOrder(dependent, "existence"); err != nil {
		t.Fatalf("existence tier must always be allowed: %v", err)
	}
}
