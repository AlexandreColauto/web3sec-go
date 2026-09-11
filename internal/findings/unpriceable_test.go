// unpriceable_test.go ports the findings-layer slices of
// tests/test_unpriceable_impact.py (round-7 D3): the NAMED DECISION that no
// USD figure is defensible, read back from finding state and accepted by the
// economic-class E7 clause. The CLI flag surface, the `gate --dry-run`
// wording and report.py's rendering are other tasks — PORT-NOTE below.
package findings

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

const (
	unpCeiling = "capacity basis: the sink is an address[255] test constant — " +
		"no live liquidity bounds it"
	unpDeficitTail = "no evidence of type ['balance-delta', 'manual'] at " +
		"level >= E7 and no unpriceable decision recorded (`webv2 impact " +
		"<campaign> <finding> --unpriceable --ceiling '<capacity basis>' " +
		"--reason <why no figure is defensible> --actor <you>`)"
)

// unpFinding is an economic-class finding with the given economic_impact
// block (nil = the block is absent).
func unpFinding(impact validation.Value) validation.Value {
	f := classFinding("oracle-manipulation")
	if impact.Kind == validation.Obj {
		f.O = append(f.O, kv("economic_impact", impact))
	}
	return f
}

// TestUnpriceableDecisionReadsOnlyAnExplicitFalseWithACeiling is
// test_bare_priceable_false_without_a_ceiling_is_not_a_decision plus the
// absent/true cases: economic_impact.priceable ABSENT means priceable, and a
// bare flag without the ceiling basis is not a decision.
func TestUnpriceableDecisionReadsOnlyAnExplicitFalseWithACeiling(t *testing.T) {
	cases := []struct {
		name   string
		impact validation.Value
		want   bool
	}{
		{"absent-block", validation.VNull(), false},
		{"empty-block", validation.VObj(), false},
		{"priceable-true", validation.VObj(
			kv("priceable", validation.VBool(true))), false},
		{"bare-false", validation.VObj(
			kv("priceable", validation.VBool(false))), false},
		{"false-null-ceiling", validation.VObj(
			kv("priceable", validation.VBool(false)),
			kv("ceiling", validation.VNull())), false},
		{"false-blank-ceiling", validation.VObj(
			kv("priceable", validation.VBool(false)),
			kv("ceiling", validation.VStr("   "))), false},
		{"false-and-ceiling", validation.VObj(
			kv("priceable", validation.VBool(false)),
			kv("ceiling", validation.VStr(unpCeiling))), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UnpriceableDecision(unpFinding(tc.impact))
			if (got != nil) != tc.want {
				t.Fatalf("decision = %v; want present=%v", got, tc.want)
			}
			if got == nil {
				return
			}
			// the reader returns exactly {priceable: false, ceiling: ...}
			// in that key order, and the ceiling verbatim.
			if d := validation.DumpIndented(*got); d !=
				"{\n  \"priceable\": false,\n  \"ceiling\": \""+unpCeiling+
					"\"\n}" {
				t.Errorf("decision = %s", d)
			}
		})
	}
}

// TestBarePriceableFalseLeavesTheE7ClauseUnmet is the negative half of the
// same Python test: a hand-set flag is not a decision, so the clause stays
// unmet and the deficit still names E7.
func TestBarePriceableFalseLeavesTheE7ClauseUnmet(t *testing.T) {
	f := unpFinding(validation.VObj(kv("priceable", validation.VBool(false))))
	if d := UnpriceableDecision(f); d != nil {
		t.Fatalf("bare flag read as a decision: %s", validation.DumpIndented(*d))
	}
	deficit := EvidenceDeficit(f, "CONFIRMED", nil)
	if deficit == nil || !strings.Contains(*deficit, "E7") {
		t.Fatalf("deficit = %v; want E7", deficit)
	}
}

// TestDeficitNamesTheUnpriceableOption is
// test_deficit_names_the_unpriceable_option, byte-exact: the gate message
// must teach the sanctioned alternative, not just say "no evidence" — that
// silence is what pushed operators into fake numbers.
func TestDeficitNamesTheUnpriceableOption(t *testing.T) {
	f := unpFinding(validation.VNull())
	deficit := EvidenceDeficit(f, "CONFIRMED", nil)
	if deficit == nil {
		t.Fatal("economic-class finding without evidence has no deficit")
	}
	want := "no evidence of type ['foundry-test', 'fuzz', 'unit-test'] at " +
		"level >= E4; no evidence of type ['balance-delta', 'differential', " +
		"'fork-test', 'historical-analog', 'manual', 'trace'] at level >= E5; " +
		unpDeficitTail
	if *deficit != want {
		t.Errorf("deficit =\n  %q\nwant\n  %q", *deficit, want)
	}
	// the other clauses' messages stay untouched (no relaxation, no drift)
	if strings.Count(*deficit, "--unpriceable") != 1 {
		t.Errorf("the option is named once, for the E7 clause only: %q",
			*deficit)
	}
}

// TestClauseMetAcceptsTheNamedDecision is
// test_economic_clause_satisfied_by_named_decision at the clause level: the
// economic-class E7 clause is satisfied by the recorded decision, and by
// nothing else — the decision never satisfies the other two clauses.
func TestClauseMetAcceptsTheNamedDecision(t *testing.T) {
	clauses := GateRequirements("CONFIRMED", "oracle-manipulation", nil)
	if len(clauses) != 3 || clauses[2].Decision != "unpriceable" {
		t.Fatalf("economic gate = %+v; want a decision-carrying E7 clause",
			clauses)
	}
	if clauses[0].Decision != "" || clauses[1].Decision != "" {
		t.Errorf("only the E7 clause may name a decision: %+v", clauses)
	}
	econ := clauses[2]
	bare := unpFinding(validation.VObj(kv("priceable", validation.VBool(false))))
	if ClauseMet(bare, econ) {
		t.Error("bare priceable=false satisfied the E7 clause")
	}
	decided := unpFinding(validation.VObj(
		kv("priceable", validation.VBool(false)),
		kv("ceiling", validation.VStr(unpCeiling)),
	))
	if !ClauseMet(decided, econ) {
		t.Error("named decision did not satisfy the E7 clause")
	}
	// no blanket relaxation: the decision does not stand in for E4/E5
	for i, cl := range clauses[:2] {
		if ClauseMet(decided, cl) {
			t.Errorf("decision satisfied clause %d (%+v)", i, cl)
		}
	}
	// an evidence item still satisfies the clause the ordinary way
	withE7 := validation.VObj(
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")))),
		kv("evidence", validation.VArr(ev("E7", "manual"))),
	)
	if !ClauseMet(withE7, econ) {
		t.Error("E7 manual evidence no longer satisfies the clause")
	}
}

// TestDeficitCampaignSlotNeverRendersEmpty pins the E7 repair hint against a
// campaign in hand with no id: the campaign slot must read the documented
// metavariable (what NameCampaign leaves for an empty id) or the real id,
// never an empty hole between two spaces.
func TestDeficitCampaignSlotNeverRendersEmpty(t *testing.T) {
	cases := []struct {
		name     string
		campaign *state.Campaign
		want     string
	}{
		{"no campaign at all", nil, campaignPlaceholder},
		{"a campaign with no id", &state.Campaign{}, campaignPlaceholder},
		{"a named campaign", &state.Campaign{CampaignID: "C-abc123"},
			"C-abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := unpFinding(validation.VNull())
			d := EvidenceDeficit(f, "CONFIRMED", tc.campaign)
			if d == nil {
				t.Fatal("economic-class finding without evidence has no " +
					"deficit")
			}
			slot := "`webv2 impact " + tc.want + " <finding> --unpriceable"
			if !strings.Contains(*d, slot) {
				t.Errorf("the hint does not name the campaign slot %q: %q",
					slot, *d)
			}
			if strings.Contains(*d, "impact  ") {
				t.Errorf("the campaign slot is an empty hole: %q", *d)
			}
		})
	}
}
