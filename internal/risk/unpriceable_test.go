// unpriceable_test.go ports tests/test_unpriceable_impact.py at the risk
// layer: the NAMED DECISION that no USD figure is defensible (round-7 D3).
// The CLI flag surface (`impact --unpriceable`, its exit codes and stderr)
// and report.py's rendering are other tasks — PORT-NOTE in the comments.
package risk

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	unpCeiling = "capacity basis: the sink is an address[255] test constant — " +
		"no live liquidity bounds it"
	unpReason = "the sink is a test fixture, so any USD figure would be " +
		"invented precision, not a measurement"
	unpActor = "operator"
)

// TestRecordUnpriceableRecordsStateAndEvent is
// test_unpriceable_records_state_and_event at the API layer: the decision is
// state (priceable false + the ceiling basis) plus exactly one
// finding.unpriceable event carrying finding/ceiling/reason/actor.
func TestRecordUnpriceableRecordsStateAndEvent(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	out, err := RecordUnpriceable(c, fid, unpCeiling, unpReason, unpActor)
	if err != nil {
		t.Fatal(err)
	}
	imp := validation.ObjAt(out, "economic_impact")
	if p := validation.ObjAt(imp, "priceable"); p.Kind != validation.Bool || p.B {
		t.Errorf("priceable = %v; want False", p)
	}
	if got := validation.ObjStr(imp, "ceiling"); got != unpCeiling {
		t.Errorf("ceiling = %q", got)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var logged int
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "finding.unpriceable" {
			continue
		}
		logged++
		// CanonCompact sorts keys: actor, ceiling, finding, reason.
		want := `{"actor":"` + unpActor + `","ceiling":` +
			validation.CanonCompact(validation.VStr(unpCeiling)) +
			`,"finding":"` + fid + `","reason":` +
			validation.CanonCompact(validation.VStr(unpReason)) + `}`
		if got := validation.CanonCompact(validation.ObjAt(e, "data")); got != want {
			t.Errorf("log data = %s\nwant %s", got, want)
		}
	}
	if logged != 1 {
		t.Errorf("finding.unpriceable events = %d; want 1", logged)
	}
}

// TestRecordUnpriceableRequiresEachNamedInput is
// test_unpriceable_requires_each_named_flag at the API layer: the decision is
// refused unless the ceiling, a written reason (>=10 chars) and the actor are
// all present — the point is the audit trail, not the bypass. (The CLI's
// exit-2 mapping for the same three cases is T14's.)
func TestRecordUnpriceableRequiresEachNamedInput(t *testing.T) {
	cases := []struct {
		name                   string
		ceiling, reason, actor string
		want                   string
	}{
		{"ceiling", "", unpReason, unpActor,
			"an unpriceable decision must state the capacity basis it was " +
				"made against (--ceiling)"},
		{"ceiling-blank", "   ", unpReason, unpActor,
			"an unpriceable decision must state the capacity basis it was " +
				"made against (--ceiling)"},
		{"reason", unpCeiling, "too short", unpActor,
			"an unpriceable decision needs a written reason (>=10 chars): " +
				"the point is the audit trail, not the bypass"},
		{"actor", unpCeiling, unpReason, "",
			"an unpriceable decision must name its actor (who decided this)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := riskCamp(t)
			fid := ingest(t, c)
			_, err := RecordUnpriceable(c, fid, tc.ceiling, tc.reason, tc.actor)
			if err == nil {
				t.Fatal("want an error")
			}
			if err.Error() != tc.want {
				t.Errorf("err = %q\nwant %q", err.Error(), tc.want)
			}
			// nothing was recorded by the rejected call
			f, err := loadFinding(t, c, fid)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := fieldAt(validation.ObjAt(f, "economic_impact"), "priceable"); ok {
				t.Error("priceable recorded by a rejected call")
			}
			evs, err := c.Events()
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range evs {
				if validation.ObjStr(e, "type") == "finding.unpriceable" {
					t.Error("finding.unpriceable logged by a rejected call")
				}
			}
		})
	}
}

// TestPricedImpactReversesTheDecision is
// test_priced_impact_reverses_the_decision: the latest decision wins — a
// priced record flips priceable back to true, drops the ceiling and logs
// reversed_unpriceable, while both events stay on the record.
func TestPricedImpactReversesTheDecision(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	if _, err := RecordUnpriceable(c, fid, unpCeiling, unpReason,
		unpActor); err != nil {
		t.Fatal(err)
	}
	out, err := RecordEconomicImpact(c, fid, validation.VFloat(1234.5),
		validation.VNull(), validation.VNull())
	if err != nil {
		t.Fatal(err)
	}
	imp := validation.ObjAt(out, "economic_impact")
	if p := validation.ObjAt(imp, "priceable"); p.Kind != validation.Bool || !p.B {
		t.Errorf("priceable = %v; want True", p)
	}
	if got := validation.DumpIndented(validation.ObjAt(imp, "extractable_usd")); got != "1234.5" {
		t.Errorf("extractable_usd = %s", got)
	}
	if _, ok := fieldAt(imp, "ceiling"); ok {
		t.Errorf("ceiling must be dropped: %s", validation.DumpIndented(imp))
	}
	if d := unpriceableOf(t, c, fid); d != nil {
		t.Errorf("unpriceable decision still readable: %s",
			validation.DumpIndented(*d))
	}
	// the reversal is on the log, and the decision event is still there
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var reversed, decision bool
	for _, e := range evs {
		if validation.ObjStr(e, "ref") != fid {
			continue
		}
		switch validation.ObjStr(e, "type") {
		case "finding.unpriceable":
			decision = true
		case "finding.impact_recorded":
			if d := validation.ObjAt(e, "data"); validation.ObjAt(d, "reversed_unpriceable").Kind ==
				validation.Bool {
				reversed = true
			}
		}
	}
	if !decision || !reversed {
		t.Errorf("decision=%v reversed=%v; want both on the log", decision,
			reversed)
	}
}

// TestPricedImpactBehaviourUnchanged is
// test_priced_impact_behaviour_unchanged: a finding that never carried the
// decision is written exactly as before — no priceable key, no ceiling key,
// no reversal flag.
func TestPricedImpactBehaviourUnchanged(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	out, err := RecordEconomicImpact(c, fid, validation.VInt(1000),
		validation.VInt(5000), validation.VInt(100))
	if err != nil {
		t.Fatal(err)
	}
	imp := validation.ObjAt(out, "economic_impact")
	if got := validation.DumpIndented(imp); got !=
		"{\n  \"extractable_usd\": 1000.0,\n  \"max_loss_usd\": 5000.0\n}" {
		t.Errorf("impact = %s", got)
	}
	if got := validation.DumpIndented(validation.ObjAt(validation.ObjAt(out, "attacker"),
		"required_capital_usd")); got != "100.0" {
		t.Errorf("required_capital_usd = %s", got)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if validation.ObjStr(e, "ref") != fid {
			continue
		}
		switch validation.ObjStr(e, "type") {
		case "finding.unpriceable":
			t.Error("finding.unpriceable logged by the priced path")
		case "finding.impact_recorded":
			if got := validation.CanonCompact(validation.ObjAt(e, "data")); got !=
				`{"extractable_usd":1000,"max_loss_usd":5000}` {
				t.Errorf("log data = %s; no reversal flag expected", got)
			}
		}
	}
}

// loadFinding is findings.load_finding (the reader the audit surface uses).
func loadFinding(t *testing.T, c *state.Campaign,
	fid string) (validation.Value, error) {
	t.Helper()
	return findings.LoadFinding(c, fid)
}

// unpriceableOf reads findings.UnpriceableDecision through the same loader
// the audit surface uses.
func unpriceableOf(t *testing.T, c *state.Campaign,
	fid string) *validation.Value {
	t.Helper()
	f, err := loadFinding(t, c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return findings.UnpriceableDecision(f)
}

// TestUnpriceableDecisionIsNilAfterReversal pins the reader's contract on the
// reversed projection: priceable true (or absent) is not a decision.
func TestUnpriceableDecisionIsNilAfterReversal(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := riskCamp(t)
	fid := ingest(t, c)
	if got := unpriceableOf(t, c, fid); got != nil {
		t.Fatalf("bare finding has a decision: %s", validation.DumpIndented(*got))
	}
	if _, err := RecordUnpriceable(c, fid, unpCeiling, unpReason,
		unpActor); err != nil {
		t.Fatal(err)
	}
	d := unpriceableOf(t, c, fid)
	if d == nil {
		t.Fatal("decision not readable after record")
	}
	if got := validation.ObjStr(*d, "ceiling"); got != unpCeiling {
		t.Errorf("decision ceiling = %q", got)
	}
	if p := validation.ObjAt(*d, "priceable"); p.Kind != validation.Bool || p.B {
		t.Errorf("decision priceable = %v", p)
	}
}
