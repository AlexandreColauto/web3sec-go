// assumptions_test.go: Task 4 (G10 table rendering) — the briefing
// assumption-table block (ChainAssumptions + the BuildBrief key).
//
// TDD: written BEFORE the hookup; must FAIL (undefined ChainAssumptions)
// until briefing.go renders it.
package briefing

import (
	"path/filepath"
	"testing"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

// assumptionModel is a schema-valid model with one declared chain and one
// untouched-by-entry chain on a shared BRIDGES hop.
func assumptionModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("nn")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("chains", validation.VArr(
			validation.VStr("mainnet"), validation.VStr("arbitrum"))),
		kv("chain_assumptions", validation.VArr(validation.VObj(
			kv("chain", validation.VStr("mainnet")),
			kv("finality", validation.VStr("probabilistic")),
			kv("confirmation_depth", validation.VInt(12)),
			kv("messenger", validation.VStr("canonical")),
			kv("separator", validation.VStr("chainid")),
		))),
		kv("relations", validation.VArr(validation.VObj(
			kv("from", validation.VStr("mainnet-vault")),
			kv("rel", validation.VStr("BRIDGES")),
			kv("to", validation.VStr("arbitrum-inbox")),
		))),
	)
}

// TestChainAssumptionsAbsentForLegacy pins the presence gate: a chains-only
// legacy model (no assumptions, no BRIDGES-touch gaps) renders NOTHING —
// no lines and no brief key.
func TestChainAssumptionsAbsentForLegacy(t *testing.T) {
	c := newCamp(t, "Legacy Program")
	model := validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("nn")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("chains", validation.VArr(validation.VStr("mainnet"))),
		kv("relations", validation.VArr()),
	)
	if _, err := protocolgraph.SaveModel(c, model, filepath.Join(
		c.ArtifactsDir, "protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	if got := ChainAssumptions(c); len(got) != 0 {
		t.Fatalf("legacy chains-only model must render no lines, got %q", got)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasKey(b, "chain_assumption_lines") {
		t.Fatal("legacy brief must not carry chain_assumption_lines")
	}
}

// TestChainAssumptionsRendersRowsAndGap pins the exact row lines plus the
// verbatim gap line, at both the function and the BuildBrief key.
func TestChainAssumptionsRendersRowsAndGap(t *testing.T) {
	c := newCamp(t, "Assumed Program")
	if _, err := protocolgraph.SaveModel(c, assumptionModel(), filepath.Join(
		c.ArtifactsDir, "protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"- mainnet: finality=probabilistic confirmations=12 messenger=canonical separator=chainid",
		"- arbitrum: finality=declared: none confirmations=declared: none messenger=declared: none separator=declared: none",
		"- ASSUMPTION GAP mainnet-vault->arbitrum-inbox arbitrum: missing-assumptions",
	}
	got := ChainAssumptions(c)
	if len(got) != len(want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	al := objAt(b, "chain_assumption_lines")
	if al.Kind != validation.Arr || len(al.A) != len(want) {
		t.Fatalf("chain_assumption_lines = %v, want %d lines", al, len(want))
	}
	for i := range want {
		if al.A[i].Kind != validation.Str || al.A[i].S != want[i] {
			t.Errorf("key line %d = %v, want %q", i, al.A[i], want[i])
		}
	}
}

// TestChainAssumptionsAbsentWithoutModel pins no model file ⇒ no lines.
func TestChainAssumptionsAbsentWithoutModel(t *testing.T) {
	c := newCamp(t, "Modeless Program")
	if got := ChainAssumptions(c); len(got) != 0 {
		t.Fatalf("no model must render no lines, got %q", got)
	}
}
