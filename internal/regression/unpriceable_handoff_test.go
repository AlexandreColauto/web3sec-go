// unpriceable_handoff_test.go: the write path's half of the handoff's
// UNPRICEABLE escape (the schema's half lives in
// internal/validation/unpriceable_handoff_schema_test.go).
//
// The handoff could only carry a strictly positive extractable_usd, so a
// control target whose CONFIRMED finding has no honest figure — T-7e2781f96e25
// / F-cfff3ebc0250, whose 10b fork spike REFUSED the number because no attack
// was run (c5ba1048, docs/gates/v16-P1-10b-fork-spike.md) — could only be
// closed by fabricating one. The escape mirrors risk.RecordUnpriceable: a
// NAMED DECISION that stands in for the missing measurement, with the ceiling
// basis it was made against, a written reason and a named actor, because "a
// bare flag is not a decision" (internal/findings/levels.go).
package regression

import (
	"fmt"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

const (
	unpSource  = "10b fork spike (refusal), docs/gates/v16-P1-10b-fork-spike.md"
	unpCeiling = "capacity basis: no attack was run, so no loss was measured"
	unpReason  = "the 10b spike refused the figure: the target's own suite is stale"
)

// unpSpec is the unpriceable decision's spec builder, with each of the three
// requirements a named argument so a test can blank exactly one.
func unpSpec(tid, fid, ceiling, reason, actor string) HandoffSpec {
	return HandoffSpec{
		TargetID: tid, FindingID: fid, Source: unpSource, Unpriceable: true,
		Ceiling: ceiling, Reason: reason, RecordedBy: actor,
	}
}

// unpCampaign is the shared fixture: a control target with its control block
// recorded and one CONFIRMED finding on it.
func unpCampaign(t *testing.T, id string) (*state.Campaign, string, string) {
	t.Helper()
	c := regressionCampaign(t, id)
	tid := controlTarget(t, c)
	recordControlForHandoff(t, c, tid)
	return c, tid, confirmedFinding(t, c)
}

// assertUnpriceableRefused asserts the EXACT refusal message: a refusal whose
// wording drifts is a refusal the operator cannot act on, and the message is
// the only thing standing between the escape and a silent bypass.
func assertUnpriceableRefused(t *testing.T, c *state.Campaign, spec HandoffSpec, want string) {
	t.Helper()
	_, err := RecordHandoff(c, spec)
	if err == nil {
		t.Fatalf("unpriceable handoff (ceiling=%q reason=%q actor=%q) was accepted",
			spec.Ceiling, spec.Reason, spec.RecordedBy)
	}
	if err.Error() != want {
		t.Fatalf("err = %q, want %q", err.Error(), want)
	}
}

// TestRecordHandoffRefusesUnpriceableWithABlankCeiling: the capacity basis is
// the decision's evidence — blank (or whitespace-only) is a bare flag.
func TestRecordHandoffRefusesUnpriceableWithABlankCeiling(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp1")
	for _, blank := range []string{"", "   "} {
		assertUnpriceableRefused(t, c, unpSpec(tid, fid, blank, unpReason, "operator"),
			"an unpriceable handoff must state the capacity basis it was made "+
				"against (--ceiling)")
	}
}

// TestRecordHandoffRefusesUnpriceableWithAShortReason: the point is the audit
// trail, not the bypass, so the reason must be written.
func TestRecordHandoffRefusesUnpriceableWithAShortReason(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp2")
	for _, short := range []string{"too short", "   "} {
		assertUnpriceableRefused(t, c, unpSpec(tid, fid, unpCeiling, short, "operator"),
			"an unpriceable handoff needs a written reason (>=10 chars): "+
				"the point is the audit trail, not the bypass")
	}
}

// TestRecordHandoffRefusesUnpriceableWithoutAnActor: the decision is
// attributed — an unattributed decision is nobody's.
func TestRecordHandoffRefusesUnpriceableWithoutAnActor(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp3")
	for _, nobody := range []string{"", "   "} {
		assertUnpriceableRefused(t, c, unpSpec(tid, fid, unpCeiling, unpReason, nobody),
			"an unpriceable handoff must name its actor (who decided this): "+
				"pass --actor")
	}
}

// TestRecordHandoffRefusesUnpriceableWithAFigure: the escape is not a way to
// keep a number as well — the schema's `false` subschema refuses the pair, and
// the write path refuses it with a message naming the figure.
func TestRecordHandoffRefusesUnpriceableWithAFigure(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp4")
	spec := unpSpec(tid, fid, unpCeiling, unpReason, "operator")
	spec.ExtractableUSD = 900000
	assertUnpriceableRefused(t, c, spec,
		"an unpriceable handoff must not carry extractable_usd (got 900000): "+
			"the escape records why no figure exists, not a figure")
}

// TestRecordHandoffAcceptsAnUnpriceableDecision is the escape working: the
// decision lands with all three requirements, the figure is ABSENT (not a
// zero), and the bytes on disk re-validate against the schema.
func TestRecordHandoffAcceptsAnUnpriceableDecision(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp5")
	doc, err := RecordHandoff(c, unpSpec(tid, fid, unpCeiling, unpReason, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	ho := validation.ObjAt(doc, "handoff")
	assertUnpriceableLeaves(t, ho)
	onDisk, err := validation.ReadJson(targetPath(c, tid))
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(onDisk, "regression_target", 1); err != nil {
		t.Fatalf("the written record does not validate: %v", err)
	}
	if got := validation.ObjStr(validation.ObjAt(onDisk, "handoff"), "reason"); got != unpReason {
		t.Fatalf("on-disk handoff.reason = %q, want %q", got, unpReason)
	}
	assertUnpriceableHandoffEvent(t, c, tid, fid)
}

// assertUnpriceableLeaves pins the decision's three leaves on the record, and
// the figure's ABSENCE — not a zero, which would read as a measurement.
func assertUnpriceableLeaves(t *testing.T, ho validation.Value) {
	t.Helper()
	if got := validation.ObjAt(ho, "priceable"); got.Kind != validation.Bool || got.B {
		t.Fatalf("handoff.priceable = %v, want the explicit false", got)
	}
	if got := validation.ObjStr(ho, "ceiling"); got != unpCeiling {
		t.Fatalf("handoff.ceiling = %q, want %q", got, unpCeiling)
	}
	if got := validation.ObjStr(ho, "reason"); got != unpReason {
		t.Fatalf("handoff.reason = %q, want %q", got, unpReason)
	}
	// The attribution is part of the decision, and the schema requires it in
	// the `false` branch (the audit reconciles it against the ledger's actor).
	if got := validation.ObjStr(ho, "recorded_by"); got != "operator" {
		t.Fatalf("handoff.recorded_by = %q, want the deciding actor", got)
	}
	if validation.HasKey(ho, "extractable_usd") {
		t.Fatal("an unpriceable handoff must not carry extractable_usd")
	}
}

// assertUnpriceableHandoffEvent pins the ledger half: exactly one
// regression.control.handoff event, carrying the decision's basis, the ACTOR
// who decided and NO extractable_usd key — the ledger must not hold a zero the
// projection does not, and a decision the log cannot attribute is one the
// audit cannot reconcile. RecordHandoff logs one event, not two.
func assertUnpriceableHandoffEvent(t *testing.T, c *state.Campaign, tid, fid string) {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	logged := 0
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "regression.control.handoff" {
			continue
		}
		logged++
		want := `{"actor":"operator","ceiling":` +
			validation.CanonCompact(validation.VStr(unpCeiling)) +
			`,"finding_id":"` + fid + `","priceable":false,"reason":` +
			validation.CanonCompact(validation.VStr(unpReason)) + `,"source":` +
			validation.CanonCompact(validation.VStr(unpSource)) +
			`,"target_id":"` + tid + `"}`
		if got := validation.CanonCompact(validation.ObjAt(e, "data")); got != want {
			t.Errorf("log data = %s\nwant %s", got, want)
		}
	}
	if logged != 1 {
		t.Errorf("regression.control.handoff events = %d; want 1", logged)
	}
}

// TestRecordHandoffPriceableEventPayload pins the PRICEABLE event's bytes, and
// pins that they did not move: the escape added an actor to the unpriceable
// payload only, so the priced form still logs exactly
// {target_id, finding_id, extractable_usd, source} — no actor, no priceable
// key, no decision leaves. (This is D8d: only the unpriceable payload was
// pinned before.)
func TestRecordHandoffPriceableEventPayload(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp7")
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	logged := 0
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "regression.control.handoff" {
			continue
		}
		logged++
		want := `{"extractable_usd":900000.0,"finding_id":"` + fid +
			`","source":"reproduction on the pre-patch commit","target_id":"` + tid + `"}`
		if got := validation.CanonCompact(validation.ObjAt(e, "data")); got != want {
			t.Errorf("log data = %s\nwant %s", got, want)
		}
	}
	if logged != 1 {
		t.Errorf("regression.control.handoff events = %d; want 1", logged)
	}
}

// TestRecordHandoffKeepsThePriceableRefusals pins the priceable path's two
// messages byte-for-byte: the escape must not have moved them, and a priceable
// record must still carry the figure and no decision.
func TestRecordHandoffKeepsThePriceableRefusals(t *testing.T) {
	c, tid, fid := unpCampaign(t, "C-reghandoffunp6")
	for _, usd := range []float64{0, -1} {
		spec := HandoffSpec{TargetID: tid, FindingID: fid, ExtractableUSD: usd, Source: "s"}
		err := checkHandoff(c, spec)
		want := fmt.Sprintf("handoff extractable_usd must be positive (got %v)", usd)
		if err == nil || err.Error() != want {
			t.Fatalf("usd=%v: err = %v, want %q", usd, err, want)
		}
	}
	err := checkHandoff(c, HandoffSpec{TargetID: tid, FindingID: fid, ExtractableUSD: 900000})
	want := "the handoff needs --source: how the extractable figure was derived"
	if err == nil || err.Error() != want {
		t.Fatalf("no source: err = %v, want %q", err, want)
	}
	doc, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	ho := validation.ObjAt(doc, "handoff")
	if got := validation.ObjAt(ho, "extractable_usd").F; got != 900000 {
		t.Fatalf("handoff.extractable_usd = %v, want 900000", got)
	}
	if validation.HasKey(ho, "priceable") {
		t.Fatal("a priceable handoff must not carry a priceable key")
	}
}
