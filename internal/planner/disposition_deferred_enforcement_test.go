package planner

// disposition_deferred_enforcement_test.go — morph pass-2 §6.1/§7.1: the
// deferred-consequence gate's structural trigger. The FIX-5 triggers are both
// lexical (the asserter anchor, the failure-consequence vocabulary), so the
// morph pass-1 miss — an enforcement-timing row closed Safe with "the truth
// of the prev state root is asserted downstream by finalizeBatch" — passed
// both untouched. A high-risk row on the enforcement-timing axis now owes the
// pricing whatever its reason says.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ptr is the *string helper this file's fixtures use.
func ptr(s string) *string { return &s }

// enforcementRow is the row these tests close: the recorded surface's
// tier-0/gap-4 assertion-strength row (testdata/probe_surface.json,
// 81dfad6492 — axis enforcement-timing, consumer commitBatch, asserter
// finalizeBatch) re-emitted under the morph pass-1 row id. The whole object
// is kept, not the six fields the gate reads: resolveAnchor resolves the
// row's legal anchor enum through `probe`, `concept_keys` and the contract
// line fields, so a hand-rolled row would trip the anchor rule before the
// trigger under test.
func enforcementRow(t *testing.T) validation.Value {
	t.Helper()
	surface, _ := maSurface(t)
	for _, r := range listOf(*surface, "rows") {
		if validation.ObjStr(r, "row_id") != "81dfad6492" {
			continue
		}
		row := deepCopy(t, r)
		row.O = validation.SetOrAppend(row.O, "row_id",
			validation.VStr("34589e8588"))
		return row
	}
	t.Fatalf("fixture row 81dfad6492 is gone")
	return validation.VNull()
}

// enforcementFixture is the campaign + plan + priority the tests close
// against: the enforcement row ALONE as the campaign's surface (so no other
// fixture row can answer for it), and the recorded plan extended with one
// open priority citing it — the construction disposition_test.go uses for
// its extra rows, changing only the row object.
func enforcementFixture(t *testing.T, row validation.Value) (*state.Campaign,
	validation.Value, string) {
	t.Helper()
	_, index := maSurface(t)
	surface := validation.VObj(kv("rows", validation.VArr(row)))
	withProbes(t, probeEnv{surface: &surface, index: index})
	camp := newCampaign(t, "dc-enforcement")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(
		append(listOf(plan, "priorities"),
			probePriorityVal("Q-100", "open", "", "34589e8588"))...))
	return camp, plan, "Q-100"
}

// A high-risk enforcement-timing row closed as answered WITHOUT the asserter
// anchor and with a clean (non-vocabulary) reason — the exact morph pass-1
// shape: "asserted downstream by finalizeBatch" — must still be refused until
// the interim window is priced (morph review §6.1: late enforcement is the
// freeze primitive, not protection).
func TestEnforcementTimingRowPricedWithoutWords(t *testing.T) {
	camp, plan, prioID := enforcementFixture(t, enforcementRow(t))
	reason := "the check is asserted downstream by finalizeBatch:508, any bad " +
		"value is caught before corruption"
	anchor := "concept" // the row's legal non-asserter anchor
	_, err := MarkAnswered(camp, plan, prioID, "answered", AnsweredOpts{
		Reason: &reason, Anchor: &anchor})
	if err == nil {
		t.Fatal("enforcement-timing row closed unpriced — the gate must refuse")
	}
	if !strings.Contains(err.Error(), "enforcement-timing") {
		t.Fatalf("refusal must name the axis trigger, got: %v", err)
	}
	// The refusal must offer both pricing exits.
	for _, want := range []string{"--finding", "--interim"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not offer %s: %v", want, err)
		}
	}
}

// The pricing exits stay open: an --interim statement citing a row symbol
// passes, and the logged override passes (and records
// probe.dismissal_overridden) — the FIX-5 contract, unchanged for the new
// trigger.
func TestEnforcementTimingRowPricingExits(t *testing.T) {
	// The closure reason names a row symbol: on a high-risk row the
	// dismissal gate's v3 citation rule (which runs AFTER this one) refuses
	// prose that names nothing from the row, and a test that tripped it
	// would not be testing the deferred gate at all.
	reason := "commitBatch already checks it elsewhere"
	camp, plan, prioID := enforcementFixture(t, enforcementRow(t))
	interim := "commitBatch persists prev_state_root that finalizeBatch can " +
		"never chain from — finalization halts forever"
	if _, err := MarkAnswered(camp, plan, prioID, "answered", AnsweredOpts{
		Reason: ptr(reason), Anchor: ptr("concept"),
		Interim: &interim}); err != nil {
		t.Fatalf("--interim pricing must pass the gate: %v", err)
	}
	camp2, plan2, prio2 := enforcementFixture(t, enforcementRow(t))
	over := "lens already answered in liveness mode on the sibling row"
	logged := false
	if _, err := MarkAnswered(camp2, plan2, prio2, "answered", AnsweredOpts{
		Reason: ptr(reason), Anchor: ptr("concept"),
		OverrideDismissal: true, OverrideReason: &over,
		OverrideLogged: &logged}); err != nil {
		t.Fatalf("logged override must pass the gate: %v", err)
	}
	if !logged {
		t.Fatal("override did not record probe.dismissal_overridden")
	}
}
