// costs_lens_test.go — Task 22 (G13 cost attribution, advisory-only).
//
// The arithmetic fixture pins the two per-confirmed quotients, the
// per-lens yield rows (ordering, unattributed-last, unknown-lens
// billing), the denominator-zero nulls, and the presence gate.
package costs

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// writeLensFinding writes a finding file directly: status CONFIRMED,
// critic verdict + evidence under the test's control.
func writeLensFinding(t *testing.T, dir, fid, critic string,
	levels []string) {
	t.Helper()
	ev := []validation.Value{}
	for i, lv := range levels {
		ev = append(ev, validation.VObj(
			validation.KV{K: "evidence_id",
				V: validation.VStr("EV-lens-1")},
			validation.KV{K: "level", V: validation.VStr(lv)},
			validation.KV{K: "type", V: validation.VStr("foundry-test")},
		))
		_ = i
	}
	f := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(fid)},
		validation.KV{K: "created_at",
			V: validation.VStr("2026-01-01T00:00:00+00:00")},
		validation.KV{K: "status", V: validation.VStr("CONFIRMED")},
		validation.KV{K: "trajectory", V: validation.VStr("code")},
		validation.KV{K: "verification", V: validation.VObj(
			validation.KV{K: "critic_verdict",
				V: validation.VStr(critic)})},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class",
				V: validation.VStr("access-control")},
			validation.KV{K: "description",
				V: validation.VStr("unguarded sweep")})},
		validation.KV{K: "evidence", V: validation.VArr(ev...)},
		validation.KV{K: "economic_impact", V: validation.VObj(
			validation.KV{K: "extractable_usd",
				V: validation.VFloat(1000)})},
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir, fid+".json"), f,
		""); err != nil {
		t.Fatal(err)
	}
}

// writeLensPlan writes artifacts/campaign_plan.json with the given lens
// ids and priorities; writeLensSurface writes probe_surface.json rows.
func writeLensPlan(t *testing.T, dir string, lensIDs []string,
	prios []validation.Value) {
	t.Helper()
	lenses := []validation.Value{}
	for _, id := range lensIDs {
		lenses = append(lenses, validation.VObj(
			validation.KV{K: "id", V: validation.VStr(id)},
			validation.KV{K: "lens", V: validation.VStr("liveness")},
			validation.KV{K: "surface", V: validation.VStr("protocol")},
			validation.KV{K: "question", V: validation.VStr("lens q?")},
			validation.KV{K: "status", V: validation.VStr("open")},
		))
	}
	plan := validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr("C-lens")},
		validation.KV{K: "created_at",
			V: validation.VStr("2026-01-01T00:00:00+00:00")},
		validation.KV{K: "priorities", V: validation.VArr(prios...)},
		validation.KV{K: "lenses", V: validation.VArr(lenses...)},
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
}

func writeLensSurface(t *testing.T, dir string,
	rowLens map[string]string) {
	t.Helper()
	rows := []validation.Value{}
	for rid, lens := range rowLens {
		rows = append(rows, validation.VObj(
			validation.KV{K: "row_id", V: validation.VStr(rid)},
			validation.KV{K: "lens", V: validation.VStr(lens)},
		))
	}
	surface := validation.VObj(
		validation.KV{K: "rows", V: validation.VArr(rows...)},
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir,
		"probe_surface.json"), surface, ""); err != nil {
		t.Fatal(err)
	}
}

func lensPrio(id, status, rowID, ref string) validation.Value {
	p := validation.VObj(
		validation.KV{K: "id", V: validation.VStr(id)},
		validation.KV{K: "question",
			V: validation.VStr("is the sweep guarded? (fixture)")},
		validation.KV{K: "status", V: validation.VStr(status)},
	)
	if rowID != "" {
		p.O = append(p.O, validation.KV{K: "probe", V: validation.VObj(
			validation.KV{K: "row_id", V: validation.VStr(rowID)},
			validation.KV{K: "probe_id", V: validation.VStr("p")},
			validation.KV{K: "axis", V: validation.VStr("liveness")},
		)})
	}
	if ref != "" {
		p.O = append(p.O,
			validation.KV{K: "closed_ref", V: validation.VStr(ref)})
	}
	return p
}

// lensCamp arithmetic fixture:
//
//	costs: 30 @ L-01, 30 @ L-02, 10 @ L-09 (unknown to the plan), 40 bare
//	  => total 110
//	findings: F-1 critic-confirmed + E4 (both bars), F-2 critic-confirmed
//	  evidence-less (critic bar only)
//	  => criticN 2, evidenceN 1 => 55.00 / 110.00
//	plan lenses L-01, L-02, L-03; surface r1->L-01, r2->L-02
//	priorities: Q-001 probe r1 answered ref F-1 (L-01 confirmed),
//	  Q-002 probe r2 open, Q-003 bare open (unattributed planned)
func TestYieldReportPerConfirmedQuotients(t *testing.T) {
	c := camp(t)
	writeLensFinding(t, c.FindingsDir, "F-lens000001", "confirmed",
		[]string{"E4"})
	writeLensFinding(t, c.FindingsDir, "F-lens000002", "confirmed", nil)
	traj := "code"
	for _, row := range []struct {
		kind string
		amt  float64
		lens string
	}{
		{"model", 30, "L-01"},
		{"compute", 30, "L-02"},
		{"model", 10, "L-09"},
		{"human-review", 40, ""},
	} {
		if _, err := RecordCost(c, RecordOpts{Kind: row.kind,
			AmountUSD: row.amt, Trajectory: &traj, Actor: "op",
			Lens: row.lens}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := YieldReport(c)
	if err != nil {
		t.Fatal(err)
	}
	totals := objAt(rep, "totals")
	if got := floatField(totals, "total_cost_usd"); got != 110 {
		t.Errorf("total_cost_usd = %v, want 110", got)
	}
	if got := objAt(totals,
		"cost_per_critic_confirmed_usd"); got.Kind != validation.Flt ||
		got.F != 55 {
		t.Errorf("cost_per_critic_confirmed_usd = %s, want 55",
			validation.DumpIndented(got))
	}
	if got := objAt(totals,
		"cost_per_evidence_confirmed_usd"); got.Kind != validation.Flt ||
		got.F != 110 {
		t.Errorf("cost_per_evidence_confirmed_usd = %s, want 110",
			validation.DumpIndented(got))
	}
}

func TestYieldReportPerConfirmedNullWhenDenominatorZero(t *testing.T) {
	c := camp(t)
	traj := "code"
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 25,
		Trajectory: &traj, Actor: "op"}); err != nil {
		t.Fatal(err)
	}
	// A finding the critic disproved with no evidence: neither bar.
	writeLensFinding(t, c.FindingsDir, "F-lens000009", "disproved", nil)
	rep, err := YieldReport(c)
	if err != nil {
		t.Fatal(err)
	}
	totals := objAt(rep, "totals")
	for _, k := range []string{"cost_per_critic_confirmed_usd",
		"cost_per_evidence_confirmed_usd"} {
		if v := objAt(totals, k); v.Kind != validation.Null {
			t.Errorf("%s = %s, want null (never inf, never div-by-zero)",
				k, validation.DumpIndented(v))
		}
	}
	// Empty campaign: int-0 total, null quotients.
	c2 := camp(t)
	rep2, err := YieldReport(c2)
	if err != nil {
		t.Fatal(err)
	}
	totals2 := objAt(rep2, "totals")
	if v := objAt(totals2, "total_cost_usd"); v.Kind != validation.Int ||
		v.I != 0 {
		t.Errorf("empty total_cost_usd = %s, want int 0",
			validation.DumpIndented(v))
	}
	for _, k := range []string{"cost_per_critic_confirmed_usd",
		"cost_per_evidence_confirmed_usd"} {
		if v := objAt(totals2, k); v.Kind != validation.Null {
			t.Errorf("empty %s = %s, want null", k,
				validation.DumpIndented(v))
		}
	}
}

func TestRecordCostLensRidesRowOnlyWhenKnown(t *testing.T) {
	c := camp(t)
	e, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 5,
		Actor: "op", Lens: "L-01"})
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(e, "lens"); got != "L-01" {
		t.Errorf("lens = %q, want L-01", got)
	}
	e2, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 5,
		Actor: "op"})
	if err != nil {
		t.Fatal(err)
	}
	if hasKey(e2, "lens") {
		t.Errorf("lens-less row carries a lens key: %s",
			validation.DumpIndented(e2))
	}
	rows, err := LoadCosts(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if objStr(rows[0], "lens") != "L-01" {
		t.Errorf("row[0].lens = %q, want L-01", objStr(rows[0], "lens"))
	}
	if hasKey(rows[1], "lens") {
		t.Errorf("row[1] carries a lens key after reload: %s",
			validation.DumpIndented(rows[1]))
	}
}

func TestLensYieldArithmeticAndOrdering(t *testing.T) {
	c := camp(t)
	writeLensFinding(t, c.FindingsDir, "F-lens000001", "confirmed",
		[]string{"E4"})
	writeLensFinding(t, c.FindingsDir, "F-lens000002", "confirmed", nil)
	traj := "code"
	for _, row := range []struct {
		kind string
		amt  float64
		lens string
	}{
		{"model", 30, "L-01"},
		{"compute", 30, "L-02"},
		{"model", 10, "L-09"},
		{"human-review", 40, ""},
	} {
		if _, err := RecordCost(c, RecordOpts{Kind: row.kind,
			AmountUSD: row.amt, Trajectory: &traj, Actor: "op",
			Lens: row.lens}); err != nil {
			t.Fatal(err)
		}
	}
	writeLensPlan(t, c.ArtifactsDir, []string{"L-01", "L-02", "L-03"},
		[]validation.Value{
			lensPrio("Q-001", "answered", "r1", "F-lens000001"),
			lensPrio("Q-002", "open", "r2", ""),
			lensPrio("Q-003", "open", "", ""),
		})
	writeLensSurface(t, c.ArtifactsDir,
		map[string]string{"r1": "L-01", "r2": "L-02"})
	ly, err := LensYield(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ly) != 4 {
		t.Fatalf("rows = %d, want 4 (L-01 L-02 L-03 unattributed)",
			len(ly))
	}
	gotIDs := []string{}
	for _, r := range ly {
		gotIDs = append(gotIDs, objStr(r, "lens"))
	}
	wantIDs := []string{"L-01", "L-02", "L-03", "unattributed"}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("order = %v, want %v (sorted L-id, unattributed last)",
				gotIDs, wantIDs)
		}
	}
	byID := map[string]validation.Value{}
	for _, r := range ly {
		byID[objStr(r, "lens")] = r
	}
	// L-01: Q-001 planned via r1, confirmed via its answered F-1 ref,
	// $30 spend.
	if v := intField(byID["L-01"], "n_planned"); v != 1 {
		t.Errorf("L-01 n_planned = %d, want 1", v)
	}
	if v := intField(byID["L-01"], "n_confirmed"); v != 1 {
		t.Errorf("L-01 n_confirmed = %d, want 1", v)
	}
	if v := floatField(byID["L-01"], "cost_usd"); v != 30 {
		t.Errorf("L-01 cost_usd = %v, want 30", v)
	}
	// L-02: Q-002 planned, still open, $30 spend.
	if v := intField(byID["L-02"], "n_planned"); v != 1 {
		t.Errorf("L-02 n_planned = %d, want 1", v)
	}
	if v := intField(byID["L-02"], "n_confirmed"); v != 0 {
		t.Errorf("L-02 n_confirmed = %d, want 0", v)
	}
	// L-03: no priorities, no spend — the partial-data zeros.
	if v := intField(byID["L-03"], "n_planned"); v != 0 {
		t.Errorf("L-03 n_planned = %d, want 0", v)
	}
	if v := floatField(byID["L-03"], "cost_usd"); v != 0 {
		t.Errorf("L-03 cost_usd = %v, want 0", v)
	}
	// unattributed: the bare $40 + the $10 on unknown L-09 (a lens the
	// plan does not know bills here, never dropped). Q-003 has no lens.
	un := byID["unattributed"]
	if v := floatField(un, "cost_usd"); v != 50 {
		t.Errorf("unattributed cost_usd = %v, want 50", v)
	}
	if v := intField(un, "n_planned"); v != 1 {
		t.Errorf("unattributed n_planned = %d, want 1 (Q-003)", v)
	}
	// Invariant: per-lens spend + unattributed == campaign total.
	sum := 0.0
	for _, r := range ly {
		sum += floatField(r, "cost_usd")
	}
	rep, err := YieldReport(c)
	if err != nil {
		t.Fatal(err)
	}
	if total := floatField(objAt(rep, "totals"),
		"total_cost_usd"); sum != total {
		t.Errorf("lens cost sum %v != total %v", sum, total)
	}
}

func TestLensYieldPresenceGate(t *testing.T) {
	// Empty campaign: no costs, no plan => nil, renderers emit nothing.
	c := camp(t)
	ly, err := LensYield(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ly) != 0 {
		t.Fatalf("empty campaign rows = %d, want 0", len(ly))
	}
	// Costs without lens and no plan: still nothing (no lens data on
	// either side).
	traj := "code"
	if _, err := RecordCost(c, RecordOpts{Kind: "model", AmountUSD: 5,
		Trajectory: &traj, Actor: "op"}); err != nil {
		t.Fatal(err)
	}
	ly, err = LensYield(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(ly) != 0 {
		t.Fatalf("lens-less rows only: rows = %d, want 0", len(ly))
	}
	// Plan lens data alone renders the table with zeros.
	c2 := camp(t)
	writeLensPlan(t, c2.ArtifactsDir, []string{"L-01"}, nil)
	ly, err = LensYield(c2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ly) != 1 || objStr(ly[0], "lens") != "L-01" {
		t.Fatalf("plan-only rows = %s, want [L-01]",
			validation.DumpIndented(validation.VArr(ly...)))
	}
	if v := floatField(ly[0], "cost_usd"); v != 0 {
		t.Errorf("plan-only L-01 cost_usd = %v, want 0", v)
	}
}

func hasKey(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}
