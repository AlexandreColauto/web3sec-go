// lens_yield_test.go — Task 22 (G13): the Results lens-yield table
// renders if and only if lens data exists (presence-gated: no header,
// no bytes otherwise), with pinned money to 2 decimals.
package report

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/costs"
	"websec/internal/validation"
)

func TestReportLensYieldTable(t *testing.T) {
	camp := clusterCamp(t)
	f1 := mk(t, camp, "d1", "deposit", "Empty-pool 1:1 mint via deposit")
	fid1 := validation.ObjStr(f1, "finding_id")
	traj := "code"
	if _, err := costs.RecordCost(camp, costs.RecordOpts{Kind: "model",
		AmountUSD: 30, Trajectory: &traj, Actor: "op",
		Lens: "L-01"}); err != nil {
		t.Fatal(err)
	}
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(camp.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("priorities", validation.VArr(validation.VObj(
			kv("id", validation.VStr("Q-001")),
			kv("question",
				validation.VStr("is the sweep guarded? (fixture)")),
			kv("status", validation.VStr("answered")),
			kv("closed_reason", validation.VStr("repro passes")),
			kv("closed_ref", validation.VStr(fid1)),
			kv("probe", validation.VObj(
				kv("row_id", validation.VStr("r1")),
				kv("probe_id", validation.VStr("p")),
				kv("axis", validation.VStr("liveness"))))))),
		kv("lenses", validation.VArr(validation.VObj(
			kv("id", validation.VStr("L-01")),
			kv("lens", validation.VStr("liveness")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr("lens q?")),
			kv("status", validation.VStr("open"))))))
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
	text := mustGenerate(t, camp)
	// The mk finding is critic-confirmed AND evidence-confirmed, so $30
	// over 1 lands on both quotients to 2 decimals.
	for _, want := range []string{
		"- **lens yield (advisory — never gates):**",
		"cost per critic-confirmed $30.00 / per evidence-confirmed $30.00",
		"  | lens | planned | confirmed | cost_usd |",
		"  | L-01 | 1 | 1 | $30.00 |",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q\n---\n%s", want, resultsSection(text))
		}
	}
}

func TestReportLensYieldAbsentIsByteSilent(t *testing.T) {
	camp := clusterCamp(t)
	text := mustGenerate(t, camp)
	for _, needle := range []string{"lens yield", "lens_yield",
		"| lens |", "cost per critic-confirmed"} {
		if strings.Contains(text, needle) {
			t.Fatalf("lens-less report renders %q\n---\n%s", needle,
				resultsSection(text))
		}
	}
}
