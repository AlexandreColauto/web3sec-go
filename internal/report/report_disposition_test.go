package report

// report_disposition_test.go — IMPROVEMENTS B4: the Disposition review
// section. Presence-gated (the additive convention): it renders only when a
// high-risk row was dismissed with dismissal vocabulary or a gate override
// was recorded — a clean campaign gains no bytes.

import (
	"path/filepath"
	"strings"
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
			prios.A[i].O = setOrAppend(prios.A[i].O, "status",
				validation.VStr("answered"))
			prios.A[i].O = setOrAppend(prios.A[i].O, "closed_reason",
				validation.VStr(reason))
		}
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
}

// drLogOverride records one probe.dismissal_overridden event.
func drLogOverride(t *testing.T, camp *state.Campaign,
	why, actor string) {
	t.Helper()
	ref := "Q-005"
	data := validation.VObj(
		kv("row_id", validation.VStr("81dfad6492")),
		kv("tier", validation.VInt(0)),
		kv("assertion_gap", validation.VInt(4)),
		kv("actor", validation.VStr(actor)),
		kv("phrases", validation.VArr(validation.VStr("liveness-only"))),
		kv("override_reason", validation.VStr(why)),
		kv("closed_reason", validation.VStr("liveness-only")),
	)
	if _, err := camp.Log("probe.dismissal_overridden", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

func TestReportDispositionReview(t *testing.T) {
	camp := clusterCamp(t)
	surface, err := validation.ReadJson(
		"../planner/testdata/probe_surface.json")
	if err != nil {
		t.Fatal(err)
	}
	drSeam(t, &surface)
	drWritePlan(t, camp, "Q-005", "liveness-only, the owner can revert")
	drLogOverride(t, camp,
		"the owner confirmed the intended behavior in the spec", "operator")

	text := mustGenerate(t, camp)

	if !strings.Contains(text, "## Disposition review") {
		t.Fatalf("missing the Disposition review section:\n%s", text)
	}
	wantFlag := "- `Q-005` (row 81dfad6492, tier 0, gap 4): " +
		"liveness-only, the owner can revert — dismissal vocabulary: " +
		"liveness-only, owner can revert"
	if !strings.Contains(text, wantFlag) {
		t.Fatalf("missing the flag line:\n%s", text)
	}
	wantOverride := "- OVERRIDDEN `Q-005` (row 81dfad6492) by operator: " +
		"the owner confirmed the intended behavior in the spec"
	if !strings.Contains(text, wantOverride) {
		t.Fatalf("missing the override line:\n%s", text)
	}
}

// TestReportDispositionReviewAbsence pins the additive convention: with no
// plan at all (and no override events) the section does not render.
func TestReportDispositionReviewAbsence(t *testing.T) {
	camp := clusterCamp(t)
	surface, err := validation.ReadJson(
		"../planner/testdata/probe_surface.json")
	if err != nil {
		t.Fatal(err)
	}
	drSeam(t, &surface)
	// a plan with a CLEAN closure: nothing flagged, nothing overridden
	drWritePlan(t, camp, "Q-005", "checked it thoroughly by hand")

	text := mustGenerate(t, camp)
	if strings.Contains(text, "Disposition review") {
		t.Fatalf("clean campaign must not render the section:\n%s", text)
	}
}

// TestReportDispositionReviewOverridesOnly pins the other half of the
// presence gate: an override event alone (no v1 flags) still renders the
// section.
func TestReportDispositionReviewOverridesOnly(t *testing.T) {
	camp := clusterCamp(t)
	surface, err := validation.ReadJson(
		"../planner/testdata/probe_surface.json")
	if err != nil {
		t.Fatal(err)
	}
	drSeam(t, &surface)
	// no plan at all: the flag scan has nothing to read
	drLogOverride(t, camp, "operator overrode the gate", "operator")

	text := mustGenerate(t, camp)
	if !strings.Contains(text, "## Disposition review") {
		t.Fatalf("override event alone must render the section:\n%s", text)
	}
	if !strings.Contains(text,
		"- OVERRIDDEN `Q-005` (row 81dfad6492) by operator: "+
			"operator overrode the gate") {
		t.Fatalf("missing the override line:\n%s", text)
	}
}
