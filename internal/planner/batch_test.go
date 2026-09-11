package planner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// batchPlanFiles pins the campaign_plan.json bytes so a refusal test can
// prove zero mutations by byte comparison.
func batchPlanFiles(t *testing.T, camp *state.Campaign,
	plan validation.Value) string {
	t.Helper()
	if _, err := SavePlan(camp, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// batchEventsOfType returns the logged events of one type.
func batchEventsOfType(t *testing.T, camp *state.Campaign,
	typ string) []validation.Value {
	t.Helper()
	evts, err := camp.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var out []validation.Value
	for _, e := range evts {
		if objStr(e, "type") == typ {
			out = append(out, e)
		}
	}
	return out
}

// batchStatusOf reads one priority's status out of a plan.
func batchStatusOf(t *testing.T, plan validation.Value,
	pid string) string {
	t.Helper()
	for _, p := range listOf(plan, "priorities") {
		if objStr(p, "id") == pid {
			return objStr(p, "status")
		}
	}
	t.Fatalf("priority %s not in plan", pid)
	return ""
}

// TestMarkAnsweredBatchAllValid pins the 3-row happy path: every row marked,
// the shared reason riding the rows that carry none, and one
// plan.priority_status event per row in the exact single-mark shape.
func TestMarkAnsweredBatchAllValid(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-batch-ok")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))

	anchor := "consumer"
	own := "checked by hand, the operator attests Q-002"
	got, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: "Q-001", Outcome: "answered", Opts: AnsweredOpts{}},
		{PriorityID: "Q-002", Outcome: "answered",
			Opts: AnsweredOpts{Reason: &own}},
		{PriorityID: "Q-005", Outcome: "answered",
			Opts: AnsweredOpts{
				Reason: strPtr("checked commitBatch by hand, the " +
					"equality holds"),
				Anchor: &anchor,
			}},
	}, "batch review of the queue")
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	for _, pid := range []string{"Q-001", "Q-002", "Q-005"} {
		if s := batchStatusOf(t, got, pid); s != "answered" {
			t.Errorf("%s status = %q, want answered", pid, s)
		}
	}
	// the shared reason rides the rows that carry none; a row's own
	// reason wins.
	if r := objStr(probePriority(t, got, "Q-001"),
		"closed_reason"); r != "batch review of the queue" {
		t.Errorf("Q-001 closed_reason = %q", r)
	}
	if r := objStr(probePriority(t, got, "Q-002"),
		"closed_reason"); r != own {
		t.Errorf("Q-002 closed_reason = %q, want the row's own reason", r)
	}
	q5 := probePriority(t, got, "Q-005")
	if r := objStr(q5, "closed_ref"); r != "Rollup.sol#L45" {
		t.Errorf("Q-005 closed_ref = %q, want Rollup.sol#L45", r)
	}

	// one plan.priority_status per row, in row order, each in the exact
	// single-mark event shape (status/reason/ref/actor + anchor record).
	evts := batchEventsOfType(t, camp, "plan.priority_status")
	if len(evts) != 3 {
		t.Fatalf("plan.priority_status events = %d, want 3", len(evts))
	}
	for i, pid := range []string{"Q-001", "Q-002", "Q-005"} {
		if r := objStr(evts[i], "ref"); r != pid {
			t.Errorf("event %d ref = %q, want %q", i, r, pid)
		}
	}
	if got := objStr(objAt(evts[0], "data"), "reason"); got !=
		"batch review of the queue" {
		t.Errorf("row 1 event reason = %q", got)
	}
	if got := objStr(objAt(evts[1], "data"), "reason"); got != own {
		t.Errorf("row 2 event reason = %q, want the row's own reason", got)
	}
	if got := objStr(objAt(evts[2], "data"), "ref"); got !=
		"Rollup.sol#L45" {
		t.Errorf("row 3 event ref = %q, want Rollup.sol#L45", got)
	}
	anchorRec := objAt(objAt(evts[2], "data"), "anchor")
	if objStr(anchorRec, "field") != "consumer" {
		t.Errorf("row 3 event anchor = %v, want the consumer record",
			validation.CanonCompact(anchorRec))
	}

	// the batch events ARE the single-mark events: closing Q-001 alone
	// with the same options yields byte-identical data + ref rows.
	single := newCampaign(t, "ma-batch-single-shape")
	singlePlan, err := MarkAnswered(single, deepCopy(t, plan), "Q-001",
		"answered", AnsweredOpts{Reason: strPtr("batch review of the queue")})
	_ = singlePlan
	if err != nil {
		t.Fatalf("single mark: %v", err)
	}
	singleEvts := batchEventsOfType(t, single, "plan.priority_status")
	if len(singleEvts) != 1 {
		t.Fatalf("single events = %d, want 1", len(singleEvts))
	}
	requireJSON(t, "batch row 1 event data == single-mark event data",
		objAt(evts[0], "data"), objAt(singleEvts[0], "data"))
	requireJSON(t, "batch row 1 event ref == single-mark event ref",
		objAt(evts[0], "ref"), objAt(singleEvts[0], "ref"))
}

// TestMarkAnsweredBatchRefusalIsAtomic pins the all-or-nothing law: the
// mid-batch gate failure names the first bad row, leaves the plan file
// byte-identical, and logs zero events.
func TestMarkAnsweredBatchRefusalIsAtomic(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-batch-refuse")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	before := batchPlanFiles(t, camp, plan)

	anchor := "consumer"
	_, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: "Q-001", Outcome: "answered", Opts: AnsweredOpts{}},
		{PriorityID: "Q-005", Outcome: "answered",
			Opts: AnsweredOpts{
				Reason: strPtr("liveness-only, the owner can revert"),
				Anchor: &anchor,
			}},
		{PriorityID: "Q-002", Outcome: "answered", Opts: AnsweredOpts{}},
	}, "batch review of the queue")
	if err == nil {
		t.Fatal("a batch with a dismissive mid row must be refused")
	}
	if got := err.Error(); !strings.HasPrefix(got,
		"answered: row 2 (Q-005):") ||
		!strings.Contains(got, "dismissal vocabulary") {
		t.Fatalf("refusal must name the first bad row: %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatal("refused batch mutated the plan file")
	}
	if evts := batchEventsOfType(t, camp,
		"plan.priority_status"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d plan.priority_status events",
			len(evts))
	}
	if evts := batchEventsOfType(t, camp,
		"probe.dismissal_overridden"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d override events", len(evts))
	}
}

// TestMarkAnsweredBatchOverrideDryRun pins that a refused batch logs no
// override event either: the pre-flight gate validates the override without
// recording it, so a later row's failure still leaves zero mutations.
func TestMarkAnsweredBatchOverrideDryRun(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-batch-override-dry")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	before := batchPlanFiles(t, camp, plan)

	anchor := "consumer"
	_, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: "Q-005", Outcome: "answered",
			Opts: AnsweredOpts{
				Reason: strPtr("liveness-only, the owner can revert"),
				Anchor: &anchor, OverrideDismissal: true,
				OverrideReason: strPtr("the owner confirmed the " +
					"intended behavior in the spec"),
			}},
		{PriorityID: "Q-999", Outcome: "answered", Opts: AnsweredOpts{}},
	}, "batch review of the queue")
	if err == nil {
		t.Fatal("a batch with an unknown trailing row must be refused")
	}
	if got := err.Error(); !strings.HasPrefix(got,
		"answered: row 2 (Q-999):") {
		t.Fatalf("refusal must name the unknown row: %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatal("refused batch mutated the plan file")
	}
	if evts := batchEventsOfType(t, camp,
		"probe.dismissal_overridden"); len(evts) != 0 {
		t.Fatalf("pre-flight must not record the override: %d events",
			len(evts))
	}
	if evts := batchEventsOfType(t, camp,
		"plan.priority_status"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d plan.priority_status events",
			len(evts))
	}
}

// TestMarkAnsweredBatchEmpty pins the empty batch refusal.
func TestMarkAnsweredBatchEmpty(t *testing.T) {
	camp := newCampaign(t, "ma-batch-empty")
	_, err := MarkAnsweredBatch(camp, maPlan(t, "plan_probe_rows.json"),
		nil, "batch review of the queue")
	if err == nil {
		t.Fatal("an empty batch must be an error")
	}
}

// TestMarkAnsweredBatchUnknownRow pins the unknown-row failure naming.
func TestMarkAnsweredBatchUnknownRow(t *testing.T) {
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-batch-unknown")
	_, err := MarkAnsweredBatch(camp, maPlan(t, "plan_probe_rows.json"),
		[]AnsweredRow{
			{PriorityID: "Q-001", Outcome: "answered",
				Opts: AnsweredOpts{}},
			{PriorityID: "Q-999", Outcome: "answered",
				Opts: AnsweredOpts{}},
		}, "batch review of the queue")
	if err == nil {
		t.Fatal("a batch with an unknown row must be refused")
	}
	if got := err.Error(); !strings.HasPrefix(got,
		"answered: row 2 (Q-999):") ||
		!strings.Contains(got, "no priority 'Q-999'") {
		t.Fatalf("refusal must name the unknown row: %q", got)
	}
}

// TestMarkAnsweredBatchOverrideHappyPath pins that N override rows yield N
// probe.dismissal_overridden events: each high-risk row closed on dismissal
// vocabulary with an explicit override records its own override event plus
// its own plan.priority_status event.
func TestMarkAnsweredBatchOverrideHappyPath(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-batch-override-ok")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))

	anchor := "consumer"
	mkOpts := func() AnsweredOpts {
		return AnsweredOpts{
			Reason: strPtr("liveness-only, the owner can revert"),
			Anchor: &anchor, OverrideDismissal: true,
			OverrideReason: strPtr("the owner confirmed the " +
				"intended behavior in the spec"),
		}
	}
	got, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: "Q-005", Outcome: "answered", Opts: mkOpts()},
		{PriorityID: "Q-006", Outcome: "answered", Opts: mkOpts()},
	}, "batch review of the queue")
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	for _, pid := range []string{"Q-005", "Q-006"} {
		if s := batchStatusOf(t, got, pid); s != "answered" {
			t.Errorf("%s status = %q, want answered", pid, s)
		}
	}
	overrides := batchEventsOfType(t, camp, "probe.dismissal_overridden")
	if len(overrides) != 2 {
		t.Fatalf("probe.dismissal_overridden events = %d, want 2",
			len(overrides))
	}
	for i, pid := range []string{"Q-005", "Q-006"} {
		if r := objStr(overrides[i], "ref"); r != pid {
			t.Errorf("override event %d ref = %q, want %q", i, r, pid)
		}
	}
	if evts := batchEventsOfType(t, camp,
		"plan.priority_status"); len(evts) != 2 {
		t.Fatalf("plan.priority_status events = %d, want 2", len(evts))
	}
}

// TestMarkAnsweredBatchAnchorOnNonProbeRow pins that a batch --anchor on a
// non-probe row is refused naming the row: the shared anchor cannot name a
// field on a priority that is not a probe disposition.
func TestMarkAnsweredBatchAnchorOnNonProbeRow(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "ma-batch-anchor-nonprobe")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	before := batchPlanFiles(t, camp, plan)

	anchor := "consumer"
	_, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: "Q-001", Outcome: "answered",
			Opts: AnsweredOpts{Anchor: &anchor}},
	}, "batch review of the queue")
	if err == nil {
		t.Fatal("a batch anchoring a non-probe row must be refused")
	}
	if got := err.Error(); !strings.HasPrefix(got,
		"answered: row 1 (Q-001):") ||
		!strings.Contains(got, "not a probe row") {
		t.Fatalf("refusal must name the non-probe row: %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatal("refused batch mutated the plan file")
	}
	if evts := batchEventsOfType(t, camp,
		"plan.priority_status"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d plan.priority_status events",
			len(evts))
	}
}
