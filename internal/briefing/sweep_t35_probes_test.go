package briefing

// T35 testmap re-triage: tests/test_probes_cli.py's brief/next_actions rows —
// open probe rows lead the action list in probe rank order, and the attention
// lead does not suppress the phase-guidance fallback.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const (
	t35ProbeCID     = "C-probecli01"
	t35ProbeRanking = "../probes/testdata/probes/ranking"
)

var t35ProbeClasses = []string{"logic-error", "access-control",
	"oracle-manipulation", "reentrancy"}

// t35ProbeModel is test_probes_cli.PLAN_MODEL.
func t35ProbeModel() validation.Value {
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

// t35ProbePlan is _plan.
func t35ProbePlan(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	plan, err := planner.DefaultPlanFromModel(c, t35ProbeModel())
	if err != nil {
		t.Fatal(err)
	}
	prios := listAt(plan, "priorities")
	for i, cls := range t35ProbeClasses {
		if i >= len(prios) {
			break
		}
		prios[i].O = bfSet(prios[i].O, "bug_class", validation.VStr(cls))
	}
	plan.O = bfSet(plan.O, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

// t35ProbeSetup is _setup.
func t35ProbeSetup(t *testing.T, withPlan bool) (*state.Campaign,
	validation.Value, validation.Value) {
	t.Helper()
	probes.Wire()
	c, err := state.Init(t.TempDir(), "Probe CLI", state.InitOpts{
		CampaignID: t35ProbeCID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t35ProbeRanking,
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
	if withPlan {
		t35ProbePlan(t, c)
	}
	return c, idx, surface
}

// t35ProbeEmit is _emit.
func t35ProbeEmit(t *testing.T, c *state.Campaign, surface,
	idx validation.Value) {
	t.Helper()
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probes.EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit rows: %v", err)
	}
}

func TestBriefFeedsOpenProbeRowsAheadOfGenericItems(t *testing.T) {
	c, idx, surface := t35ProbeSetup(t, true)
	t35ProbeEmit(t, c, surface, idx)
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ps := objAt(b, "probe_surface")
	if objInt(ps, "rows") != 10 || objInt(ps, "open") != 10 ||
		objBool(ps, "stale") {
		t.Fatalf("probe_surface = %v, want 10/10 not stale", ps)
	}
	rows := listAt(surface, "rows")
	sorted := append([]validation.Value{}, rows...)
	// expected = sorted(rows, key=PB.rank_key)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if probes.RankKeyOf(sorted[j]).Less(probes.RankKeyOf(sorted[i])) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	openRows := listAt(ps, "open_rows")
	if len(openRows) != len(sorted) {
		t.Fatalf("open_rows = %d, want %d", len(openRows), len(sorted))
	}
	for i := range sorted {
		if objStr(openRows[i], "row_id") != objStr(sorted[i], "row_id") {
			t.Fatalf("open_rows[%d] = %q, want %q", i,
				objStr(openRows[i], "row_id"), objStr(sorted[i], "row_id"))
		}
	}
	actions := strListOf(objAt(b, "next_actions"))
	probeActions := []string{}
	for _, a := range actions {
		if strings.HasPrefix(a, "work probe row ") ||
			strings.HasPrefix(a, "emit probe row ") {
			probeActions = append(probeActions, a)
		}
	}
	if len(probeActions) != 10 {
		t.Fatalf("probe actions = %d, want 10: %v", len(probeActions), actions)
	}
	first := indexOfString(actions, probeActions[0])
	for i, a := range probeActions {
		if indexOfString(actions, a) != first+i {
			t.Fatalf("probe actions are not one contiguous block: %v", actions)
		}
	}
	for i, r := range sorted {
		found := -1
		for j, a := range probeActions {
			if strings.Contains(a, objStr(r, "row_id")) {
				found = j
			}
		}
		if found != i {
			t.Fatalf("row %s ranks at %d, want %d", objStr(r, "row_id"),
				found, i)
		}
	}
	generic := []string{}
	for _, a := range actions {
		if strings.HasPrefix(a, "work probe row ") ||
			strings.HasPrefix(a, "emit probe row ") ||
			strings.HasPrefix(a, "divergence gate open") {
			continue
		}
		generic = append(generic, a)
	}
	if len(generic) == 0 {
		t.Fatal("the campaign says nothing else to do")
	}
	if indexOfString(actions, generic[0]) <=
		indexOfString(actions, probeActions[len(probeActions)-1]) {
		t.Fatalf("generic items do not follow the probe rows: %v", actions)
	}
}

// indexOfString is Python's list.index for a unique element.
func indexOfString(items []string, needle string) int {
	for i, s := range items {
		if s == needle {
			return i
		}
	}
	return -1
}

func TestNextActionsRanksProbeRowsByTheProbeRankKey(t *testing.T) {
	row := func(rid string, tier, gap, sibs int64, name string) validation.Value {
		return validation.VObj(
			kv("row_id", validation.VStr(rid)),
			kv("priority_id", validation.VStr("Q-001")),
			kv("probe", validation.VStr("assertion-strength")),
			kv("axis", validation.VStr("enforcement-timing")),
			kv("lens", validation.VStr("L-03")),
			kv("tier", validation.VInt(tier)),
			kv("assertion_gap", validation.VInt(gap)),
			kv("siblings", validation.VInt(sibs)),
			kv("name", validation.VStr(name)),
			kv("why", validation.VStr("row "+rid+" is a candidate")))
	}
	probeSurface := validation.VObj(
		kv("rows", validation.VInt(4)),
		kv("dispositioned", validation.VInt(0)),
		kv("open", validation.VInt(4)),
		kv("stale", validation.VBool(false)),
		kv("index_sha", validation.VStr("x")),
		kv("current_index_sha", validation.VStr("x")),
		kv("open_rows", validation.VArr(
			row("cccccccccc", 1, 4, 1, "z"),
			row("aaaaaaaaaa", 0, 4, 2, "b"),
			row("bbbbbbbbbb", 0, 4, 1, "c"),
			row("dddddddddd", 0, 3, 1, "a"))))
	findings := validation.VObj(
		kv("materializable_chains", validation.VArr()),
		kv("memory_recall_pending", validation.VArr()),
		kv("structurally_unreachable", validation.VArr()),
		kv("gate_deficits", validation.VArr(validation.VObj(
			kv("finding_id", validation.VStr("F-1")),
			kv("status", validation.VStr("POSSIBLE")),
			kv("level", validation.VStr("E3")),
			kv("deficit", validation.VStr("needs E5"))))))
	brief := validation.VObj(
		kv("campaign", validation.VObj(
			kv("closed", validation.VBool(false)),
			kv("campaign_id", validation.VStr(t35ProbeCID)))),
		kv("criticality", validation.VNull()),
		kv("divergence", validation.VNull()),
		kv("integrity", validation.VObj(kv("ok", validation.VBool(true)))),
		kv("economics", validation.VObj(
			kv("budget", validation.VObj(
				kv("status", validation.VStr("within")))))),
		kv("findings", findings),
		kv("independent_verification_queue", validation.VArr()),
		kv("bounty", validation.VObj(kv("evaluated", validation.VArr()))),
		kv("pending_memory", validation.VArr()),
		kv("terminals", validation.VArr()),
		kv("probe_surface", probeSurface))
	actions, err := NextActions(brief, nil)
	if err != nil {
		t.Fatal(err)
	}
	probeIDs := []string{}
	for _, a := range actions {
		if !strings.HasPrefix(a, "work probe row ") &&
			!strings.HasPrefix(a, "emit probe row ") {
			continue
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(a, "work probe row "),
			"emit probe row ")
		probeIDs = append(probeIDs, strings.SplitN(rest, " ", 2)[0])
	}
	want := []string{"bbbbbbbbbb", "aaaaaaaaaa", "dddddddddd", "cccccccccc"}
	if strings.Join(probeIDs, ",") != strings.Join(want, ",") {
		t.Fatalf("probe order = %v, want %v", probeIDs, want)
	}
	if !strings.Contains(actions[len(actions)-1], "needs E5") {
		t.Fatalf("generic items do not follow the probe rows: %v", actions)
	}
}

func TestAGrandfatheredBriefDoesNotGainPhaseGuidance(t *testing.T) {
	c := newCamp(t, "Probe CLI")
	t35ProbePlan(t, c)
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(b, "probe_surface"); v.Kind != validation.Null {
		t.Fatalf("grandfather: probe_surface = %v, want null", v)
	}
	actions := strListOf(objAt(b, "next_actions"))
	ranked := listAt(objAt(b, "attention"), "ranked")
	if len(ranked) == 0 {
		t.Fatal("no attention lead")
	}
	if actions[0] != objStr(ranked[0], "action") {
		t.Fatalf("actions[0] = %q, want the attention lead %q", actions[0],
			objStr(ranked[0], "action"))
	}
	if len(actions) != 4 {
		t.Fatalf("len(actions) = %d, want 4: %v", len(actions), actions)
	}
	divLines := 0
	for _, a := range actions {
		if strings.HasPrefix(a, "divergence gate open — L-") {
			divLines++
		}
		if strings.HasPrefix(a, "orchestrator.") {
			t.Fatalf("phase guidance leaked into a grandfathered brief: %v",
				actions)
		}
	}
	if divLines != 3 {
		t.Fatalf("divergence lines = %d, want 3: %v", divLines, actions)
	}
	empty, err := state.Init(t.TempDir(), "Probe CLI", state.InitOpts{
		CampaignID: t35ProbeCID})
	if err != nil {
		t.Fatal(err)
	}
	eb, err := BuildBrief(empty, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := orchestrator.NextActions(empty)
	if err != nil {
		t.Fatal(err)
	}
	got := strListOf(objAt(eb, "next_actions"))
	if strings.Join(got, "\x00") != strings.Join(strListOf(want), "\x00") {
		t.Fatalf("empty brief actions = %v, want orchestrator.NextActions = %v",
			got, strListOf(want))
	}
}

func TestAttentionDebtDoesNotSuppressThePhaseGuidanceFallback(t *testing.T) {
	c, _, _ := t35ProbeSetup(t, true)
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(b, "probe_surface").Kind == validation.Null {
		t.Fatal("probe_surface must be present")
	}
	actions := strListOf(objAt(b, "next_actions"))
	ranked := listAt(objAt(b, "attention"), "ranked")
	if len(ranked) == 0 {
		t.Fatal("no attention lead")
	}
	lead := objStr(ranked[0], "action")
	count := 0
	for _, a := range actions {
		if a == lead {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("attention lead appears %d times, want 1: %v", count, actions)
	}
	divLines := 0
	phase := []string{}
	for _, a := range actions {
		if strings.HasPrefix(a, "divergence gate open — ") {
			divLines++
		}
		if strings.HasPrefix(a, "orchestrator.") {
			phase = append(phase, a)
		}
	}
	if divLines != 3 {
		t.Fatalf("divergence lines = %d, want 3: %v", divLines, actions)
	}
	if len(phase) == 0 {
		t.Fatalf("phase-guidance fallback did not survive: %v", actions)
	}
}
