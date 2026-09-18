// lens_yield_test.go — Task 22 (G13): the briefing economics block
// carries lens_yield if and only if lens data exists (presence-gated:
// no key at all, never an empty one).
package briefing

import (
	"path/filepath"
	"testing"

	"websec/internal/costs"
	"websec/internal/validation"
)

func TestBriefEconomicsLensYieldPresence(t *testing.T) {
	camp := newCamp(t, "Lens Program")
	traj := "code"
	if _, err := costs.RecordCost(camp, costs.RecordOpts{Kind: "model",
		AmountUSD: 30, Trajectory: &traj, Actor: "op",
		Lens: "L-01"}); err != nil {
		t.Fatal(err)
	}
	lenses := validation.VArr(validation.VObj(
		kv("id", validation.VStr("L-01")),
		kv("lens", validation.VStr("liveness")),
		kv("surface", validation.VStr("protocol")),
		kv("question", validation.VStr("lens q?")),
		kv("status", validation.VStr("open"))))
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(camp.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question",
				validation.VStr("is the sweep guarded? (fixture)")),
			kv("status", validation.VStr("open")),
			kv("probe", validation.VObj(
				kv("row_id", validation.VStr("r1")),
				kv("probe_id", validation.VStr("p")),
				kv("axis", validation.VStr("liveness"))))))),
		kv("lenses", lenses))
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
	surface := validation.VObj(
		kv("rows", validation.VArr(validation.VObj(
			kv("row_id", validation.VStr("r1")),
			kv("lens", validation.VStr("L-01"))))))
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"probe_surface.json"), surface, ""); err != nil {
		t.Fatal(err)
	}
	b := build(t, camp, false)
	econ := validation.ObjAt(b, "economics")
	ly := validation.ObjAt(econ, "lens_yield")
	if ly.Kind != validation.Arr || len(ly.A) != 1 {
		t.Fatalf("lens_yield = %s, want 1 row",
			validation.DumpIndented(ly))
	}
	if got := validation.ObjStr(ly.A[0], "lens"); got != "L-01" {
		t.Errorf("lens = %q, want L-01", got)
	}
	if got := floatOf(validation.ObjAt(ly.A[0], "cost_usd")); got != 30 {
		t.Errorf("cost_usd = %v, want 30", got)
	}
	// The per-confirmed quotients ride totals (null here: no findings).
	totals := validation.ObjAt(econ, "totals")
	for _, k := range []string{"cost_per_critic_confirmed_usd",
		"cost_per_evidence_confirmed_usd"} {
		if v := validation.ObjAt(totals, k); v.Kind != validation.Null {
			t.Errorf("totals.%s = %s, want null (no findings)", k,
				validation.DumpIndented(v))
		}
	}
}

func TestBriefEconomicsLensYieldAbsent(t *testing.T) {
	camp := newCamp(t, "No Lens Program")
	b := build(t, camp, false)
	econ := validation.ObjAt(b, "economics")
	for _, kv := range econ.O {
		if kv.K == "lens_yield" {
			t.Fatalf("fresh campaign economics carries lens_yield: %s",
				validation.DumpIndented(econ))
		}
	}
}
