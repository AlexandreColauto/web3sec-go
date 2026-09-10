package briefing

// disposition_test.go — IMPROVEMENTS B4: the brief's disposition_review
// block. Presence-gated (the additive convention): the key exists only when
// something is flagged, one entry per high-risk dismissal.

import (
	"path/filepath"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// drSeam installs a planner probes seam serving the given surface and
// restores the default on cleanup.
func drSeam(t *testing.T, surface *validation.Value) {
	t.Helper()
	planner.SetProbes(planner.ProbesAPI{
		CampaignSurface: func(c *state.Campaign) (*validation.Value, error) {
			return surface, nil
		},
	})
	t.Cleanup(func() { planner.SetProbes(planner.ProbesAPI{}) })
}

// drWritePlan loads the recorded probe-row plan, closes one priority with
// the given reason, and writes it as the campaign's plan.
func drWritePlan(t *testing.T, camp *state.Campaign,
	priorityID, reason string) {
	t.Helper()
	plan, err := validation.ReadJson("../planner/testdata/plan_probe_rows.json")
	if err != nil {
		t.Fatal(err)
	}
	prios := objAt(plan, "priorities")
	for i := range prios.A {
		if objStr(prios.A[i], "id") == priorityID {
			prios.A[i].O = validation.SetOrAppend(prios.A[i].O, "status",
				validation.VStr("answered"))
			prios.A[i].O = validation.SetOrAppend(prios.A[i].O, "closed_reason",
				validation.VStr(reason))
		}
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
}

func TestBriefDispositionReviewFlagged(t *testing.T) {
	camp := newCamp(t, "Disposition Program")
	surface, err := validation.ReadJson(
		"../planner/testdata/probe_surface.json")
	if err != nil {
		t.Fatal(err)
	}
	drSeam(t, &surface)
	drWritePlan(t, camp, "Q-005", "liveness-only, the owner can revert")

	b := build(t, camp, false)

	rev := objAt(b, "disposition_review")
	if rev.Kind != validation.Arr || len(rev.A) != 1 {
		t.Fatalf("disposition_review = %v, want exactly 1 entry", rev)
	}
	f := rev.A[0]
	if got := objStr(f, "priority"); got != "Q-005" {
		t.Errorf("priority = %q, want Q-005", got)
	}
	if got := objStr(f, "row_id"); got != "81dfad6492" {
		t.Errorf("row_id = %q, want 81dfad6492", got)
	}
	if got := objAt(f, "tier").I; got != 0 {
		t.Errorf("tier = %d, want 0", got)
	}
	if got := objAt(f, "assertion_gap").I; got != 4 {
		t.Errorf("assertion_gap = %d, want 4", got)
	}
	if got := objStr(f, "reason"); got != "liveness-only, the owner can revert" {
		t.Errorf("reason = %q", got)
	}
	phrases := objAt(f, "phrases")
	if phrases.Kind != validation.Arr || len(phrases.A) != 2 ||
		phrases.A[0].S != "liveness-only" || phrases.A[1].S != "owner can revert" {
		t.Errorf("phrases = %v, want [liveness-only owner can revert]", phrases)
	}
}

// TestBriefDispositionReviewEmpty pins the absence arm (the additive
// convention): with nothing flagged the key is absent entirely, so a clean
// campaign's brief bytes are unchanged and the print layer renders nothing.
func TestBriefDispositionReviewEmpty(t *testing.T) {
	camp := newCamp(t, "Disposition Clean")
	surface, err := validation.ReadJson(
		"../planner/testdata/probe_surface.json")
	if err != nil {
		t.Fatal(err)
	}
	drSeam(t, &surface)
	drWritePlan(t, camp, "Q-005", "checked it thoroughly by hand")

	b := build(t, camp, false)

	if got := objAt(b, "disposition_review"); got.Kind != validation.Null {
		t.Fatalf("clean campaign: disposition_review = %v, want absent", got)
	}

	// and with no plan at all there is nothing to scan: absent as well
	camp2 := newCamp(t, "Disposition Bare")
	drSeam(t, &surface)
	b2 := build(t, camp2, false)
	if got := objAt(b2, "disposition_review"); got.Kind != validation.Null {
		t.Fatalf("no-plan campaign: disposition_review = %v, want absent", got)
	}
}
