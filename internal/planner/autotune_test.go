// autotune_test.go (G17 tactic batting average): the planner gate is
// policy-gated OFF (flag off => zero queue change, byte law), demotes a
// genuinely dead lens's unstarted slots to park with the exact reason
// line, and holds the threshold edges (n=9 no; 0/20's real 16.1% no).
package planner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// atunePrio is one plan priority for the batting fixtures.
func atunePrio(id, status, rowID, ref string, risk float64) validation.Value {
	p := validation.VObj(
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr("probe the sweep ("+id+")")),
		kv("risk", validation.VFloat(risk)),
		kv("trajectories", validation.VArr(validation.VStr("A-code"))),
		kv("budget_class", validation.VStr("cheap")),
		kv("status", validation.VStr(status)),
	)
	if rowID != "" {
		p.O = append(p.O, kv("probe", validation.VObj(
			kv("row_id", validation.VStr(rowID)),
			kv("probe_id", validation.VStr("p")),
			kv("axis", validation.VStr("liveness")))))
	}
	if ref != "" {
		p.O = append(p.O, kv("closed_ref", validation.VStr(ref)))
	}
	return p
}

// atuneLens is one plan lens entry (the stored-id rail: id rides the doc).
func atuneLens(id, family string) validation.Value {
	return validation.VObj(
		kv("id", validation.VStr(id)),
		kv("lens", validation.VStr(family)),
		kv("surface", validation.VStr("protocol")),
		kv("question", validation.VStr("lens q?")),
		kv("status", validation.VStr("open")),
	)
}

// atuneWritePlan writes artifacts/campaign_plan.json and returns the plan.
func atuneWritePlan(t *testing.T, c *state.Campaign,
	lenses []validation.Value, prios []validation.Value) validation.Value {
	t.Helper()
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("priorities", validation.VArr(prios...)),
		kv("lenses", validation.VArr(lenses...)),
	)
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
	return plan
}

// atuneWriteSurface writes artifacts/probe_surface.json rows.
func atuneWriteSurface(t *testing.T, c *state.Campaign,
	rowLens map[string]string) {
	t.Helper()
	rows := []validation.Value{}
	for rid, lens := range rowLens {
		rows = append(rows, validation.VObj(
			kv("row_id", validation.VStr(rid)),
			kv("lens", validation.VStr(lens)),
		))
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"),
		validation.VObj(kv("rows", validation.VArr(rows...))), ""); err != nil {
		t.Fatal(err)
	}
}

// atuneWriteFinding writes a billed confirmation: critic-confirmed with
// E4 evidence (the LensYield floor intersection — the costs T22 shape).
func atuneWriteFinding(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	f := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")),
		kv("verification", validation.VObj(
			kv("critic_verdict", validation.VStr("confirmed")))),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("unguarded sweep")))),
		kv("evidence", validation.VArr(validation.VObj(
			kv("evidence_id", validation.VStr("EV-atune-1")),
			kv("level", validation.VStr("E4")),
			kv("type", validation.VStr("foundry-test"))))),
		kv("economic_impact", validation.VObj(
			kv("extractable_usd", validation.VFloat(1000)))),
	)
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(c.FindingsDir, fid+".json"),
		f, ""); err != nil {
		t.Fatal(err)
	}
}

// atuneWritePolicy writes a minimal bounty policy carrying the flag.
func atuneWritePolicy(t *testing.T, c *state.Campaign, on bool) {
	t.Helper()
	flag := "false"
	if on {
		flag = "true"
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "bounty_policy.json"),
		[]byte(`{"auto_tune": `+flag+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// atuneQueueOf indexes queue rows by priority id.
func atuneQueueOf(t *testing.T, q []validation.Value) map[string]validation.Value {
	t.Helper()
	out := map[string]validation.Value{}
	for _, row := range q {
		out[objStr(row, "priority_id")] = row
	}
	return out
}

// atuneTwoLensFixture builds the delegation's fixture: L-01 goes 0/40
// (trips: 95% CI upper 8.8%), L-02 goes 5/12 (upper 68.0%, never parks).
// All open rows are risk 0.9/cheap (L-01) and 0.5/cheap (L-02).
func atuneTwoLensFixture(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	surface := map[string]string{}
	prios := []validation.Value{}
	for i := 1; i <= 40; i++ {
		rid := fmt.Sprintf("rA-%03d", i)
		qid := fmt.Sprintf("Q-A-%03d", i)
		surface[rid] = "L-01"
		prios = append(prios, atunePrio(qid, "open", rid, "", 0.9))
	}
	for i := 1; i <= 12; i++ {
		rid := fmt.Sprintf("rB-%03d", i)
		qid := fmt.Sprintf("Q-B-%03d", i)
		surface[rid] = "L-02"
		if i <= 5 {
			fid := fmt.Sprintf("F-atune%06d", i)
			atuneWriteFinding(t, c, fid)
			prios = append(prios, atunePrio(qid, "answered", rid, fid,
				0.5))
			continue
		}
		prios = append(prios, atunePrio(qid, "open", rid, "", 0.5))
	}
	atuneWriteSurface(t, c, surface)
	return atuneWritePlan(t, c,
		[]validation.Value{atuneLens("L-01", "liveness"),
			atuneLens("L-02", "incentive-inversion")}, prios)
}

// TestAutoTuneFlagOffByteLaw is the byte law: without the flag (absent
// file, or explicit false) the queue is exactly the standing
// (slot, -risk) order with no reason keys anywhere.
func TestAutoTuneFlagOffByteLaw(t *testing.T) {
	c := newCampaign(t, "atune-off")
	plan := atuneTwoLensFixture(t, c)
	off, err := WorkQueue(c, plan, validation.VObj(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 47 {
		t.Fatalf("queue rows = %d, want 47 (40 L-01 + 7 L-02 open)",
			len(off))
	}
	for _, row := range off {
		if hasKey(row, "reason") {
			t.Fatalf("flag-off row %s carries a reason key",
				objStr(row, "priority_id"))
		}
	}
	byID := atuneQueueOf(t, off)
	if got := objStr(byID["Q-A-001"], "slot"); got != "now" {
		t.Errorf("flag-off Q-A-001 slot = %q, want now", got)
	}
	if got := objStr(byID["Q-B-006"], "slot"); got != "batch" {
		t.Errorf("flag-off Q-B-006 slot = %q, want batch", got)
	}
	// Explicit false is byte-identical to absent (T11-style defaulting).
	atuneWritePolicy(t, c, false)
	off2, err := WorkQueue(c, plan, validation.VObj(), false)
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, "auto_tune:false == absent", validation.VArr(off2...),
		validation.VArr(off...))
}

// TestAutoTuneDemotesDeadLens pins the two-lens fixture with the flag on:
// L-01's 40 unstarted slots park with the exact reason line; L-02 keeps
// its standing slots with no reason; the order is L-02 batch block first
// (parked-last), then the parked L-01 block in priority order.
func TestAutoTuneDemotesDeadLens(t *testing.T) {
	c := newCampaign(t, "atune-on")
	plan := atuneTwoLensFixture(t, c)
	atuneWritePolicy(t, c, true)
	q, err := WorkQueue(c, plan, validation.VObj(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 47 {
		t.Fatalf("queue rows = %d, want 47", len(q))
	}
	const reason = "- lens L-01: auto-deprioritized " +
		"(0/40 confirmed, 95% CI upper 8.8%)"
	byID := atuneQueueOf(t, q)
	for i := 1; i <= 40; i++ {
		qid := fmt.Sprintf("Q-A-%03d", i)
		row, ok := byID[qid]
		if !ok {
			t.Fatalf("%s missing from the queue", qid)
		}
		if got := objStr(row, "slot"); got != "park" {
			t.Errorf("%s slot = %q, want park", qid, got)
		}
		if got := objStr(row, "reason"); got != reason {
			t.Errorf("%s reason = %q, want %q", qid, got, reason)
		}
	}
	for i := 6; i <= 12; i++ {
		qid := fmt.Sprintf("Q-B-%03d", i)
		row, ok := byID[qid]
		if !ok {
			t.Fatalf("%s missing from the queue", qid)
		}
		if got := objStr(row, "slot"); got != "batch" {
			t.Errorf("%s slot = %q, want batch (5/12 never parks)", qid,
				got)
		}
		if hasKey(row, "reason") {
			t.Errorf("%s carries a reason key without demotion", qid)
		}
	}
	// Order: the 7 L-02 batch rows lead (priority order), then the 40
	// parked L-01 rows (priority order) — L-id then parked-last.
	for i, want := range []string{"Q-B-006", "Q-B-007", "Q-B-008",
		"Q-B-009", "Q-B-010", "Q-B-011", "Q-B-012"} {
		if got := objStr(q[i], "priority_id"); got != want {
			t.Fatalf("queue[%d] = %q, want %q", i, got, want)
		}
	}
	for i := 0; i < 40; i++ {
		want := fmt.Sprintf("Q-A-%03d", i+1)
		if got := objStr(q[7+i], "priority_id"); got != want {
			t.Fatalf("queue[%d] = %q, want %q", 7+i, got, want)
		}
	}
}

// TestAutoTuneThresholdEdges pins the gate's two edges with the flag on:
// 0/9 never demotes (below the n>=10 depth floor) and 0/20 never demotes
// (95% CI upper 16.1% >= 0.10 — the brief's case, real math, no fake).
func TestAutoTuneThresholdEdges(t *testing.T) {
	for _, n := range []int{9, 20} {
		c := newCampaign(t, fmt.Sprintf("atune-edge-%d", n))
		surface := map[string]string{}
		prios := []validation.Value{}
		for i := 1; i <= n; i++ {
			rid := fmt.Sprintf("rE-%03d", i)
			qid := fmt.Sprintf("Q-E-%03d", i)
			surface[rid] = "L-01"
			prios = append(prios, atunePrio(qid, "open", rid, "", 0.9))
		}
		atuneWriteSurface(t, c, surface)
		plan := atuneWritePlan(t, c,
			[]validation.Value{atuneLens("L-01", "liveness")}, prios)
		atuneWritePolicy(t, c, true)
		q, err := WorkQueue(c, plan, validation.VObj(), false)
		if err != nil {
			t.Fatal(err)
		}
		if len(q) != n {
			t.Fatalf("n=%d: queue rows = %d, want %d", n, len(q), n)
		}
		for _, row := range q {
			if got := objStr(row, "slot"); got != "now" {
				t.Errorf("n=%d: %s slot = %q, want now (no demote)",
					n, objStr(row, "priority_id"), got)
			}
			if hasKey(row, "reason") {
				t.Errorf("n=%d: %s carries a reason key without demotion",
					n, objStr(row, "priority_id"))
			}
		}
	}
}

// TestSeedLensesIDsStoredAndStable pins the rail choice: lens ids are
// STORED in the plan doc (additive — the schema already requires id), the
// derivation is deterministic by plan-order (LensIDs index), and a replan
// under a different model changes nothing.
func TestSeedLensesIDsStoredAndStable(t *testing.T) {
	modelA := jsonValue(t, `{"state_machines":[{"id":"sm-a"}]}`)
	added, plan := SeedLenses(validation.VObj(), modelA)
	if len(added) != 4 {
		t.Fatalf("seed added %d entries, want 4", len(added))
	}
	wantIDs := []string{"L-01", "L-02", "L-03", "L-04"}
	lenses := listOf(plan, "lenses")
	for i, want := range wantIDs {
		if got := objStr(lenses[i], "id"); got != want {
			t.Fatalf("lens[%d].id = %q, want %q (plan-order)", i, got,
				want)
		}
	}
	for i, want := range LensIDs {
		if got := objStr(lenses[i], "lens"); got != want {
			t.Fatalf("lens[%d].lens = %q, want %q", i, got, want)
		}
	}
	modelB := jsonValue(t, `{"state_machines":[{"id":"sm-b"}],
		"actors":[{"id":"mallory"}]}`)
	again, plan2 := SeedLenses(plan, modelB)
	if len(again) != 0 {
		t.Fatalf("replan added %d entries, want 0", len(again))
	}
	requireJSON(t, "replan ids stable", plan2, plan)
}
