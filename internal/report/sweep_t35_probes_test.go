package report

// T35 testmap re-triage: tests/test_probes_cli.py's report rows — the
// "Mechanical candidate surface" section renders the rows and their
// dispositions, and marks a surface stale once the index moves.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const (
	rpProbeCID     = "C-probecli01"
	rpProbeRanking = "../probes/testdata/probes/ranking"
)

var rpProbeClasses = []string{"logic-error", "access-control",
	"oracle-manipulation", "reentrancy"}

// rpProbeModel is test_probes_cli.PLAN_MODEL.
func rpProbeModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("probe-cli")),
		kv("name", validation.VStr("Probe CLI")),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Rollup")),
			kv("path", validation.VStr("Rollup.sol")),
			kv("role", validation.VStr("core")),
			kv("in_scope", validation.VBool(true)),
			kv("entry_points", validation.VArr(validation.VStr("commitBatch"),
				validation.VStr("finalizeBatch")))))),
		kv("state_machines", validation.VArr(validation.VObj(
			kv("name", validation.VStr("rollup-lifecycle")),
			kv("transitions", validation.VArr(validation.VStr("commit"),
				validation.VStr("challenge"),
				validation.VStr("finalize")))))),
		kv("actors", validation.VArr(validation.VObj(
			kv("id", validation.VStr("active_staker")),
			kv("kind", validation.VStr("ROLE")),
			kv("trust", validation.VStr("semi-trusted"))))))
}

// rpProbeSetup is _setup.
func rpProbeSetup(t *testing.T) (*state.Campaign, validation.Value,
	validation.Value) {
	t.Helper()
	probes.Wire()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	installMemorySeams(t)
	c, err := state.Init(root, "Probe CLI", state.InitOpts{
		CampaignID: rpProbeCID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, rpProbeRanking,
		structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	surface, err := probes.BuildSurface(idx, validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatal(err)
	}
	plan, err := planner.DefaultPlanFromModel(c, rpProbeModel())
	if err != nil {
		t.Fatal(err)
	}
	prios := listAt(plan, "priorities")
	for i, cls := range rpProbeClasses {
		if i >= len(prios) {
			break
		}
		prios[i].O = rpSet(prios[i].O, "bug_class", validation.VStr(cls))
	}
	plan.O = rpSet(plan.O, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := probes.EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit rows: %v", err)
	}
	return c, idx, surface
}

// rpProbePriority is _probe_priority.
func rpProbePriority(t *testing.T, c *state.Campaign,
	rowID string) validation.Value {
	t.Helper()
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range listAt(plan, "priorities") {
		prov := objAt(p, "probe")
		if prov.Kind == validation.Obj && objStr(prov, "row_id") != "" &&
			(rowID == "" || objStr(prov, "row_id") == rowID) {
			return p
		}
	}
	t.Fatal("no probe priority emitted")
	return validation.VNull()
}

func TestReportRendersTheMechanicalCandidateSurface(t *testing.T) {
	c, _, surface := rpProbeSetup(t)
	rows := listAt(surface, "rows")
	if len(rows) == 0 {
		t.Fatal("surface has no rows")
	}
	row := rows[0]
	pid := objStr(rpProbePriority(t, c, objStr(row, "row_id")), "id")
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	reason := "the asserter is not authoritative for batch:index in commitBatch"
	anchor := "asserter"
	// FIX-5: an asserter-anchored tier-0 closure prices the interim window —
	// the statement cites the row's own surface entry
	interim := "until finalizeBatch asserts batch:index, commitBatch " +
		"accepts a stale root"
	plan, err = planner.MarkAnswered(c, plan, pid, "not-applicable",
		planner.AnsweredOpts{Reason: &reason, Anchor: &anchor,
			Interim: &interim, Actor: "pytest"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	text := rpText(t, c)
	for _, want := range []string{"## Mechanical candidate surface",
		objStr(row, "row_id"), "assertion-strength", "enforcement-timing",
		"L-03", "Rollup.sol#L45", "Rollup.sol#L66", "not-applicable",
		"the asserter is not authoritative"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, tailLines(text, 40))
		}
	}
	if strings.Contains(text, "STALE") {
		t.Errorf("a fresh surface must not read STALE:\n%s",
			tailLines(text, 40))
	}
}

func TestReportMarksAStaleSurface(t *testing.T) {
	c, idx, _ := rpProbeSetup(t)
	rpBumpIndexLine(t, c, idx)
	text := rpText(t, c)
	if !strings.Contains(text, "## Mechanical candidate surface") {
		t.Fatalf("report lacks the surface section:\n%s", tailLines(text, 40))
	}
	if !strings.Contains(text, "STALE") {
		t.Fatalf("report does not mark the surface stale:\n%s",
			tailLines(text, 40))
	}
}

// rpBumpIndexLine is t29BumpIndexLine: move the first node's line by one.
func rpBumpIndexLine(t *testing.T, c *state.Campaign, idx validation.Value) {
	t.Helper()
	moved := idx
	nodes := listAt(moved, "nodes")
	if len(nodes) == 0 {
		t.Fatal("index has no nodes")
	}
	n := nodes[0]
	n.O = rpSet(n.O, "line", validation.VInt(intAt(n, "line")+1))
	nodes[0] = n
	moved.O = rpSet(moved.O, "nodes", validation.VArr(nodes...))
	if err := validation.WriteJson(
		filepath.Join(c.ArtifactsDir, "structural_index.json"), moved, ""); err != nil {
		t.Fatal(err)
	}
}
