package metrics

// Port of tests/test_metrics.py: tiny synthetic campaigns pin the precision
// math on 2-confirm/1-disprove, critic recall + false rejection on a 2-case
// linked campaign, the benchmark 2x2, training-export exclusion both ways,
// dead-end/avg-tier math, and the all-None empty campaign. CONFIRMED statuses
// are written directly (save_finding validates shape, not gates) because the
// CONFIRMED transition gate needs a full repro/memory-check/critic bundle
// metrics must not depend on.

import (
	"path/filepath"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func newCamp(t *testing.T, name string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hypo() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr(
			"User can withdraw more than deposited via rounding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("precision-rounding")),
			kv("description", validation.VStr(
				"share calculation rounds in the attacker's favor")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))))
}

// makeFinding ingests a hypothesis, optionally adds low-tier evidence +
// assumptions, then forces the terminal status directly (shape-validated,
// gates bypassed — metrics reads files, not the transition API).
func makeFinding(t *testing.T, camp *state.Campaign, status, tier string,
	assumptions []validation.Value, eid string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(camp, hypo(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if tier != "E0" {
		if _, err := findings.AddEvidence(camp, fid, validation.VObj(
			kv("evidence_id", validation.VStr(eid)),
			kv("level", validation.VStr(tier)),
			kv("type", validation.VStr("static-analysis")),
			kv("description", validation.VStr(
				"callgraph: withdraw() has no access modifier")))); err != nil {
			t.Fatal(err)
		}
	}
	if assumptions != nil {
		if _, err := findings.SetAssumptions(camp, fid, assumptions, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = setKey(doc.O, "status", validation.VStr(status))
	if err := findings.SaveFinding(camp, &doc); err != nil {
		t.Fatal(err)
	}
	return fid
}

func setKey(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

func assumption(aid string, blocking bool, status string) validation.Value {
	return validation.VObj(
		kv("id", validation.VStr(aid)),
		kv("type", validation.VStr("reachability")),
		kv("claim", validation.VStr("proposition "+aid+" holds on the target")),
		kv("status", validation.VStr(status)),
		kv("model_belief", validation.VFloat(0.7)),
		kv("blocking", validation.VBool(blocking)))
}

func linkSidecar(t *testing.T, camp *state.Campaign, caseIDs []string) {
	t.Helper()
	ids := make([]validation.Value, 0, len(caseIDs))
	for _, id := range caseIDs {
		ids = append(ids, validation.VStr(id))
	}
	if err := validation.WriteJson(filepath.Join(camp.Dir, "eval_link.json"),
		validation.VObj(kv("eval_case_id", validation.VArr(ids...))), ""); err != nil {
		t.Fatal(err)
	}
}

// StubStore is the test double for the eval-store seam.
type StubStore struct{ Cases map[string]validation.Value }

func (s StubStore) LoadCase(caseID string) (validation.Value, error) {
	c, ok := s.Cases[caseID]
	if !ok {
		return validation.VNull(), errNoCase(caseID)
	}
	return c, nil
}

type errNoCase string

func (e errNoCase) Error() string { return "no such case " + string(e) }

func devCase(caseID, outcome string) validation.Value {
	return validation.VObj(
		kv("case_id", validation.VStr(caseID)),
		kv("partition", validation.VStr("dev")),
		kv("gold", validation.VObj(kv("outcome", validation.VStr(outcome)))))
}

func stubBoth(t *testing.T, cases map[string]validation.Value) {
	t.Helper()
	SetEvalStore(StubStore{Cases: cases})
	t.Cleanup(func() { SetEvalStore(nil) })
}

func num(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Flt:
		return v.F, true
	case validation.Int:
		return float64(v.I), true
	}
	return 0, false
}

func wantNum(t *testing.T, v validation.Value, want float64) {
	t.Helper()
	got, ok := num(v)
	if !ok || got != want {
		t.Fatalf("got %v want %v", v, want)
	}
}

// ---------------------------------------------------------------------------
// campaign_metrics: precision

func TestMetricsPrecisionTwoConfirmOneDisprove(t *testing.T) {
	camp := newCamp(t, "test-program")
	makeFinding(t, camp, "CONFIRMED", "E0", nil, "EV-1")
	makeFinding(t, camp, "CONFIRMED", "E0", nil, "EV-1")
	makeFinding(t, camp, "DISPROVED", "E0", nil, "EV-1")
	m := CampaignMetrics(camp)
	if got := objAt(m, "confirmations").I; got != 2 {
		t.Fatalf("confirmations = %d", got)
	}
	if got := objAt(m, "disprovals").I; got != 1 {
		t.Fatalf("disprovals = %d", got)
	}
	wantNum(t, objAt(m, "confirmation_precision"), 2.0/3.0)
	if got := objAt(m, "findings_total").I; got != 3 {
		t.Fatalf("findings_total = %d", got)
	}
	if got := objAt(m, "critic_recall"); got.Kind != validation.Null {
		t.Fatalf("critic_recall = %v", got)
	}
	if got := objAt(m, "false_rejection_rate"); got.Kind != validation.Null {
		t.Fatalf("false_rejection_rate = %v", got)
	}
}

// ---------------------------------------------------------------------------
// campaign_metrics: critic recall + false rejection, 2 cases

func TestMetricsCriticRecallAndFalseRejection(t *testing.T) {
	camp := newCamp(t, "test-program")
	caseOK := "CASE-" + repeat("a", 12)
	caseBad := "CASE-" + repeat("b", 12)
	stubBoth(t, map[string]validation.Value{
		caseOK:  devCase(caseOK, "confirmed-not-exploitable"),
		caseBad: devCase(caseBad, "confirmed-exploitable")})
	linkSidecar(t, camp, []string{caseOK, caseBad})
	fidOK := makeFinding(t, camp, "DISPROVED", "E0", nil, "EV-1")
	if _, err := trajectory.RecordOutcome(camp, fidOK, "disproved",
		trajectory.OutcomeOpts{FinalStatus: "DISPROVED",
			FinalEvidenceTier: "E0", CaseID: &caseOK}); err != nil {
		t.Fatal(err)
	}
	fidBad := makeFinding(t, camp, "DISPROVED", "E0", nil, "EV-1")
	if _, err := trajectory.RecordOutcome(camp, fidBad, "disproved",
		trajectory.OutcomeOpts{FinalStatus: "DISPROVED",
			FinalEvidenceTier: "E0", CaseID: &caseBad}); err != nil {
		t.Fatal(err)
	}
	m := CampaignMetrics(camp)
	wantNum(t, objAt(m, "critic_recall"), 1.0)
	wantNum(t, objAt(m, "false_rejection_rate"), 1.0)
}

// ---------------------------------------------------------------------------
// benchmark_report 2x2

func linkedCampaign(t *testing.T, caseID, status string) *state.Campaign {
	t.Helper()
	camp := newCamp(t, "bench")
	makeFinding(t, camp, status, "E0", nil, "EV-1")
	linkSidecar(t, camp, []string{caseID})
	return camp
}

func TestMetricsBenchmark2x2Math(t *testing.T) {
	tpCase, fnCase := "CASE-"+repeat("1", 12), "CASE-"+repeat("2", 12)
	tnCase, fpCase := "CASE-"+repeat("3", 12), "CASE-"+repeat("4", 12)
	stubBoth(t, map[string]validation.Value{
		tpCase: devCase(tpCase, "confirmed-exploitable"),
		fnCase: devCase(fnCase, "confirmed-exploitable"),
		tnCase: devCase(tnCase, "confirmed-not-exploitable"),
		fpCase: devCase(fpCase, "confirmed-not-exploitable")})
	camps := []*state.Campaign{
		linkedCampaign(t, tpCase, "CONFIRMED"),
		linkedCampaign(t, fnCase, "DISPROVED"),
		linkedCampaign(t, tnCase, "DISPROVED"),
		linkedCampaign(t, fpCase, "CONFIRMED"),
	}
	rep := BenchmarkReport([]string{tpCase, fnCase, tnCase, fpCase}, camps)
	if rep := rep; objAt(rep, "tp").I != 1 || objAt(rep, "fp").I != 1 ||
		objAt(rep, "tn").I != 1 || objAt(rep, "fn").I != 1 {
		t.Fatalf("2x2 = %v", rep)
	}
	wantNum(t, objAt(rep, "precision"), 0.5)
	wantNum(t, objAt(rep, "recall"), 0.5)
	wantNum(t, objAt(rep, "f1"), 0.5)
	byID := map[string]validation.Value{}
	for _, c := range objAt(rep, "cases").A {
		byID[objStr(c, "case_id")] = c
	}
	for _, tc := range []struct {
		id   string
		want bool
	}{{tpCase, true}, {fnCase, false}, {tnCase, true}, {fpCase, false}} {
		match := objAt(byID[tc.id], "match")
		if match.Kind != validation.Bool || match.B != tc.want {
			t.Fatalf("case %s match = %v want %v", tc.id, match, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// training_export exclusion both ways

func TestMetricsTrainingExportExcludesHeldOutByDefault(t *testing.T) {
	dev, held := "CASE-"+repeat("d", 12), "CASE-"+repeat("e", 12)
	stubBoth(t, map[string]validation.Value{
		dev: devCase(dev, "confirmed-exploitable"),
		held: validation.VObj(
			kv("case_id", validation.VStr(held)),
			kv("partition", validation.VStr("held-out")),
			kv("gold", validation.VObj(
				kv("outcome", validation.VStr("confirmed-exploitable")))))})
	cDev := newCamp(t, "exp")
	makeFinding(t, cDev, "CONFIRMED", "E0", nil, "EV-1")
	linkSidecar(t, cDev, []string{dev})
	cHeld := newCamp(t, "exp")
	makeFinding(t, cHeld, "CONFIRMED", "E0", nil, "EV-1")
	linkSidecar(t, cHeld, []string{held})

	rows := TrainingExport([]*state.Campaign{cDev, cHeld}, false)
	if len(rows) != 1 || objStr(rows[0], "case_id") != dev {
		t.Fatalf("rows = %v", rows)
	}
	if got := objAt(rows[0], "labels"); validation.CanonCompact(got) !=
		`{"human":false}` {
		t.Fatalf("labels = %s", validation.CanonCompact(got))
	}
	if got := objStr(rows[0], "outcome"); got != "confirmed-exploitable" {
		t.Fatalf("outcome = %q", got)
	}
	if got := objAt(rows[0], "excluded"); got.Kind != validation.Bool || got.B {
		t.Fatalf("excluded = %v", got)
	}

	rowsAll := TrainingExport([]*state.Campaign{cDev, cHeld}, true)
	if len(rowsAll) != 2 {
		t.Fatalf("rows_all = %d", len(rowsAll))
	}
	var heldRow validation.Value
	for _, r := range rowsAll {
		if objStr(r, "case_id") == held {
			heldRow = r
		}
	}
	if got := objAt(heldRow, "excluded"); got.Kind != validation.Bool || !got.B {
		t.Fatalf("held excluded = %v", got)
	}
	if got := objStr(heldRow, "exclude_reason"); got !=
		"held-out case — leakage" {
		t.Fatalf("exclude_reason = %q", got)
	}
}

// ---------------------------------------------------------------------------
// dead-end / avg-tier / assumption efficiency

func TestMetricsDeadEndAvgTierAndAssumptions(t *testing.T) {
	camp := newCamp(t, "test-program")
	makeFinding(t, camp, "DISPROVED", "E0", nil, "EV-1") // dead end
	makeFinding(t, camp, "DISPROVED", "E0", nil, "EV-1") // dead end
	fid := makeFinding(t, camp, "CONFIRMED", "E2", []validation.Value{
		assumption("A1", true, "UNKNOWN"),
		assumption("A2", true, "UNKNOWN"),
		assumption("A3", false, "UNKNOWN")}, "EV-9")
	// resolved only through the transition API (store provenance: EV-9)
	if _, err := findings.AssumptionTransition(camp, fid, "A1", "SUPPORTED",
		[]string{"EV-9"}, ""); err != nil {
		t.Fatal(err)
	}
	m := CampaignMetrics(camp)
	wantNum(t, objAt(m, "dead_end_rate"), 2.0/3.0)
	wantNum(t, objAt(m, "avg_evidence_tier"), (0+0+2)/3.0)
	hist := objAt(m, "evidence_tier_histogram")
	if got := objAt(hist, "E0").I; got != 2 {
		t.Fatalf("E0 = %d", got)
	}
	if got := objAt(hist, "E2").I; got != 1 {
		t.Fatalf("E2 = %d", got)
	}
	// 2 blocking created, 1 resolved (non-blocking A3 ignored)
	wantNum(t, objAt(m, "assumption_efficiency"), 0.5)
}

// ---------------------------------------------------------------------------
// empty campaign: all None, no exceptions

func TestMetricsEmptyCampaignAllNone(t *testing.T) {
	camp := newCamp(t, "test-program")
	m := CampaignMetrics(camp)
	if got := objAt(m, "findings_total").I; got != 0 {
		t.Fatalf("findings_total = %d", got)
	}
	for _, key := range []string{"confirmation_precision", "duplicate_rate",
		"dead_end_rate", "avg_evidence_tier", "critic_recall",
		"false_rejection_rate", "assumption_efficiency"} {
		if got := objAt(m, key); got.Kind != validation.Null {
			t.Fatalf("%s = %v", key, got)
		}
	}
	if got := objAt(m, "notes"); got.Kind != validation.Arr {
		t.Fatalf("notes = %v", got)
	}
	rep := BenchmarkReport(nil, nil)
	if objAt(rep, "tp").I != 0 || objAt(rep, "fp").I != 0 ||
		objAt(rep, "tn").I != 0 || objAt(rep, "fn").I != 0 {
		t.Fatalf("2x2 = %v", rep)
	}
	if objAt(rep, "precision").Kind != validation.Null ||
		objAt(rep, "recall").Kind != validation.Null {
		t.Fatalf("precision/recall = %v", rep)
	}
	if objAt(rep, "f1").Kind != validation.Null {
		t.Fatalf("f1 = %v", objAt(rep, "f1"))
	}
	if rows := TrainingExport([]*state.Campaign{camp}, false); len(rows) != 0 {
		t.Fatalf("rows = %v", rows)
	}
}

// ---- helpers -------------------------------------------------------------

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
