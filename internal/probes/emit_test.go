// emit_test.go: 1:1 ports of tests/test_probe_emit.py (A3: probe rows become
// plan obligations, and lens closure depends on them).
package probes

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/completion"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// emitRanking is RANKING (tests/fixtures/structural/probes/ranking).
var emitRanking = filepath.Join("testdata", "probes", "ranking")

// emitSurfaceRows is _SURFACE_ROWS: the surface rows cached by _emit_ready so
// the disposition helper can cite anchors.
var emitSurfaceRows []validation.Value

// emitPlanModel is PLAN_MODEL.
func emitPlanModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("probe-emit")),
		kv("name", validation.VStr("Probe Emit")),
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
				validation.VStr("challenge"), validation.VStr("finalize")))))),
		kv("actors", validation.VArr(validation.VObj(
			kv("id", validation.VStr("active_staker")),
			kv("kind", validation.VStr("ROLE")),
			kv("trust", validation.VStr("semi-trusted"))))),
	)
}

// emitCampaign is _campaign.
func emitCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Probe Emit",
		state.InitOpts{CampaignID: "C-emit1234"})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return c
}

// emitModel is _model().
func emitModel(t *testing.T) validation.Value {
	t.Helper()
	m, err := validation.ReadJson(filepath.Join(emitRanking, "model.json"))
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	return m
}

// emitDeepCopy is copy.deepcopy over a validation.Value. The round trip
// through canonical JSON also normalises key order, which every consumer of
// these rows (row_shape_sha, row_question, emit_rows) is order-insensitive to.
func emitDeepCopy(t *testing.T, v validation.Value) validation.Value {
	t.Helper()
	out, err := validation.ParseOrdered([]byte(validation.CanonCompact(v)))
	if err != nil {
		t.Fatalf("deep copy: %v", err)
	}
	return out
}

// emitSurface is _surface.
func emitSurface(t *testing.T, c *state.Campaign, root string,
	model *validation.Value) (validation.Value, validation.Value) {
	t.Helper()
	m := emitModel(t)
	if model != nil {
		m = *model
	}
	idx, err := structidx.IndexSnapshot(c, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatalf("index_snapshot: %v", err)
	}
	surface, err := BuildSurface(idx, m, 12, 40, 3, "")
	if err != nil {
		t.Fatalf("build_surface: %v", err)
	}
	return idx, surface
}

// emitPlan is _plan: four lenses seeded and four distinct bug classes named.
func emitPlan(t *testing.T, c *state.Campaign,
	model *validation.Value) validation.Value {
	t.Helper()
	m := emitPlanModel()
	if model != nil {
		m = *model
	}
	plan, err := planner.DefaultPlanFromModel(c, m)
	if err != nil {
		t.Fatalf("default_plan_from_model: %v", err)
	}
	classes := []string{"logic-error", "access-control", "oracle-manipulation",
		"reentrancy"}
	prios := vList(plan, "priorities")
	for i, cls := range classes {
		if i >= len(prios) {
			break
		}
		vSet(&prios[i], "bug_class", validation.VStr(cls))
	}
	return plan
}

// emitPlanPath is campaign.artifacts_dir / "campaign_plan.json".
func emitPlanPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "campaign_plan.json")
}

// emitReload re-reads the saved plan (the living document emit_rows /
// mark_answered rewrote in place).
func emitReload(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatalf("load_plan_readonly: %v", err)
	}
	return plan
}

// emitReady is _emit_ready.
func emitReady(t *testing.T) (*state.Campaign, validation.Value,
	validation.Value, validation.Value) {
	t.Helper()
	c := emitCampaign(t)
	idx, surface := emitSurface(t, c, emitRanking, nil)
	plan := emitPlan(t, c, nil)
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatalf("save_index: %v", err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatalf("write probe_surface: %v", err)
	}
	emitSurfaceRows = vObjList(surface, "rows")
	return c, idx, surface, plan
}

// emitAnswerAll is _answer_all.
func emitAnswerAll(t *testing.T, c *state.Campaign,
	plan validation.Value) validation.Value {
	t.Helper()
	reason := "fixture closure with a written reason"
	ref := "Rollup.sol#L45"
	prios := vList(plan, "priorities")
	for i := range prios {
		vSet(&prios[i], "status", validation.VStr("answered"))
		vSet(&prios[i], "closed_reason", validation.VStr(reason))
		vSet(&prios[i], "closed_ref", validation.VStr(ref))
		vSet(&prios[i], "closed_by", validation.VStr("pytest"))
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatalf("save_plan: %v", err)
	}
	return plan
}

// reconOnRecord puts both FIX-8 recon stamps on record for one campaign.
// The real verbs are off-limits here for two test-local reasons: the real
// prescreen/sinks would rebuild this campaign's fixture index from the
// shared sink tree (EnsureFreshIndex), and — in packages structidx wires —
// importing them is an import cycle in test. So the prescreen artifact is
// seeded as a fixture file and the sinks stamp rides the REAL
// state.StampRecon write path; the end-to-end real-verb version of this
// setup lives in internal/cli (cmd_recon_gate_test.go).
func reconOnRecord(t *testing.T, c *state.Campaign) {
	t.Helper()
	prescreen := validation.VObj(
		kv("snapshot_id", validation.VStr("S-0123456789abcdef")))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"archetype_prescreen.json"), prescreen, ""); err != nil {
		t.Fatalf("seed prescreen artifact: %v", err)
	}
	if err := c.StampRecon("sinks", "src"); err != nil {
		t.Fatalf("stamp sinks: %v", err)
	}
}

// emitCloseLenses is _close_lenses.
func emitCloseLenses(t *testing.T, c *state.Campaign,
	plan validation.Value) validation.Value {
	t.Helper()
	reconOnRecord(t, c)
	for _, l := range vObjList(plan, "lenses") {
		reason := vStr(l, "lens") + " resolved for the fixture tree"
		ref := "Rollup.sol#L45"
		fams := vStrList(l, "families")
		if fams == nil {
			fams = []string{}
		}
		updated, err := planner.MarkLens(c, plan, vStr(l, "id"), "answered",
			planner.LensOpts{Reason: &reason, Ref: &ref, Actor: "pytest",
				FamiliesChecked: &fams})
		if err != nil {
			t.Fatalf("mark_lens %s: %v", vStr(l, "id"), err)
		}
		plan = updated
	}
	return plan
}

// emitIsProbe is `if not p.get("probe")`.
func emitIsProbe(p validation.Value) bool {
	prov := vGet(p, "probe")
	return prov.Kind == validation.Obj && len(prov.O) > 0
}

// emitInterimFor is the morph §6.1/§7.1 pricing for a fixture row: every row
// on the enforcement-timing axis owes an interim statement citing its own
// surface entry, so a test whose subject is some OTHER rule prices the window
// here and keeps its target. The statement names the row's consumer, which is
// always one of its symbols.
func emitInterimFor(t *testing.T, surface validation.Value,
	rowID string) *string {
	t.Helper()
	for _, r := range vObjList(surface, "rows") {
		if vStr(r, "row_id") != rowID {
			continue
		}
		consumer := vStr(r, "consumer")
		if consumer == "" {
			return nil
		}
		s := "until the deferred assertion runs, " + consumer +
			" keeps acting on the unverified value"
		return &s
	}
	t.Fatalf("no surface row %q to price the interim window", rowID)
	return nil
}

// emitAnswerProbeRows is _answer_probe_rows.
func emitAnswerProbeRows(t *testing.T, c *state.Campaign, plan validation.Value,
	idx *validation.Value) validation.Value {
	t.Helper()
	for _, p := range vList(plan, "priorities") {
		if !emitIsProbe(p) {
			continue
		}
		rid := vStr(vGet(p, "probe"), "row_id")
		var row validation.Value
		found := false
		for _, r := range emitSurfaceRows {
			if vStr(r, "row_id") == rid {
				row, found = r, true
				break
			}
		}
		var spec *probeSpec
		if found {
			spec = probesTable[vStr(row, "probe")]
		}
		anchor := ""
		hasAnchor := false
		if spec != nil && len(spec.anchors) > 0 {
			anchor, hasAnchor = spec.anchors[0], true
		}
		ref := "Rollup.sol#L45"
		if hasAnchor {
			got, err := AnchorRef(row, anchor, idx)
			if err != nil {
				t.Fatalf("anchor_ref: %v", err)
			}
			ref = got
		}
		reason := "row " + rid + " checked at " + ref
		opts := planner.AnsweredOpts{Reason: &reason, Ref: &ref,
			Actor: "pytest"}
		if hasAnchor {
			opts.Anchor = &anchor
		}
		// morph §6.1/§7.1: every fixture row sits on the enforcement-timing
		// axis, so each high-risk closure owes the interim pricing; it cites
		// the row's own consumer (the v3 citation rule).
		if consumer := vStr(row, "consumer"); consumer != "" {
			interim := "until the deferred assertion runs, " + consumer +
				" keeps acting on the unverified value"
			opts.Interim = &interim
		}
		updated, err := planner.MarkAnswered(c, plan, vStr(p, "id"),
			"answered", opts)
		if err != nil {
			t.Fatalf("mark_answered %s: %v", vStr(p, "id"), err)
		}
		plan = updated
	}
	return plan
}

// emitClosedWithRows is _closed_with_rows.
func emitClosedWithRows(t *testing.T) (*state.Campaign, validation.Value,
	validation.Value, validation.Value) {
	t.Helper()
	c, idx, surface, plan := emitReady(t)
	if _, err := EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	plan = emitReload(t, c)
	plan = emitAnswerProbeRows(t, c, plan, &idx)
	plan = emitCloseLenses(t, c, plan)
	plan = emitAnswerAll(t, c, plan)
	return c, idx, surface, plan
}

// emitProbePriority is `next(p for p in plan["priorities"] if p.get("probe"))`,
// or the priority whose probe row_id is rowID when rowID != "".
func emitProbePriority(t *testing.T, plan validation.Value,
	rowID string) validation.Value {
	t.Helper()
	for _, p := range vList(plan, "priorities") {
		if !emitIsProbe(p) {
			continue
		}
		if rowID == "" || vStr(vGet(p, "probe"), "row_id") == rowID {
			return p
		}
	}
	t.Fatalf("no probe priority (row_id=%q)", rowID)
	return validation.VNull()
}

// emitProbeIDs is [p["id"] for p in plan["priorities"] if p.get("probe")].
func emitProbeIDs(plan validation.Value) []string {
	out := []string{}
	for _, p := range vList(plan, "priorities") {
		if emitIsProbe(p) {
			out = append(out, vStr(p, "id"))
		}
	}
	return out
}

// emitPriorityByID is next(x for x in plan["priorities"] if x["id"] == id).
func emitPriorityByID(t *testing.T, plan validation.Value,
	id string) validation.Value {
	t.Helper()
	for _, p := range vList(plan, "priorities") {
		if vStr(p, "id") == id {
			return p
		}
	}
	t.Fatalf("no priority %q", id)
	return validation.VNull()
}

// emitMissingBySubject is next(m for m in div["missing"] if m["subject"] == s).
func emitMissingBySubject(t *testing.T, div validation.Value,
	subject string) validation.Value {
	t.Helper()
	for _, m := range vObjList(div, "missing") {
		if vStr(m, "subject") == subject {
			return m
		}
	}
	t.Fatalf("no missing entry for %q: %s", subject,
		validation.CanonCompact(vGet(div, "missing")))
	return validation.VNull()
}

// emitSurfaceSha is PB.index_sha(idx) as a pointer for DivergenceOpts.
func emitSurfaceSha(idx validation.Value) string { return IndexSha(idx) }

// ---- pure seams -----------------------------------------------------------

func TestRegisteredAxesCoversEveryProbeAndItsLens(t *testing.T) {
	axes := RegisteredAxes()
	want := map[string]struct{}{}
	for _, spec := range probesTable {
		want[spec.axis] = struct{}{}
	}
	if len(axes) != len(want) {
		t.Errorf("registered_axes has %d axes, want %d", len(axes), len(want))
	}
	for ax := range want {
		if _, ok := axes[ax]; !ok {
			t.Errorf("registered_axes missing axis %q", ax)
		}
	}
	for pid, spec := range probesTable {
		got, ok := axes[spec.axis]
		if !ok {
			t.Errorf("registered_axes missing axis %q for probe %q", spec.axis, pid)
			continue
		}
		wantMeta := AxisMeta{Axis: spec.axis, Probe: pid, Lens: spec.lens}
		if got != wantMeta {
			t.Errorf("registered_axes[%q] = %+v, want %+v", spec.axis, got, wantMeta)
		}
	}
	// Python asserts list(axes) == sorted(axes); Go's RegisteredAxes returns a
	// map, which has no observable iteration order, so the port asserts the
	// keys are sorted instead.
	keys := sortedKeys(axes)
	if !sort.StringsAreSorted(keys) {
		t.Errorf("registered_axes keys are not sorted: %v", keys)
	}
}

func TestRowShapeShaTracksTheAnchorTupleNotTheRowID(t *testing.T) {
	c := emitCampaign(t)
	_, surface := emitSurface(t, c, emitRanking, nil)
	row := vObjList(surface, "rows")[0]
	if got := len(RowShapeSha(row)); got != 16 {
		t.Errorf("len(row_shape_sha(row)) = %d, want 16", got)
	}
	if RowShapeSha(row) != RowShapeSha(emitDeepCopy(t, row)) {
		t.Errorf("row_shape_sha is not stable across a copy")
	}
	moved := emitDeepCopy(t, row)
	vSet(&moved, "asserter_line", validation.VInt(int64(vInt(row,
		"asserter_line")+1)))
	if RowIDFor(moved) != RowIDFor(row) {
		t.Errorf("row_id is line-stable: got %q, want %q", RowIDFor(moved),
			RowIDFor(row))
	}
	if RowShapeSha(moved) == RowShapeSha(row) {
		t.Errorf("row_shape_sha did not change when asserter_line moved")
	}
	renamed := emitDeepCopy(t, row)
	vSet(&renamed, "consumer", validation.VStr("somewhereElse"))
	if RowShapeSha(renamed) == RowShapeSha(row) {
		t.Errorf("row_shape_sha did not change when consumer was renamed")
	}
	classy := emitDeepCopy(t, row)
	vSet(&classy, "own_class", validation.VInt(1))
	if RowShapeSha(classy) == RowShapeSha(row) {
		t.Errorf("row_shape_sha did not change when own_class changed")
	}
}

func TestProbeRiskMapsRankOntoTheExistingBandVocabulary(t *testing.T) {
	row := func(tier, gap int) validation.Value {
		return validation.VObj(
			kv("probe", validation.VStr("assertion-strength")),
			kv("tier", validation.VInt(int64(tier))),
			kv("assertion_gap", validation.VInt(int64(gap))))
	}
	band, risk := ProbeRisk(row(0, 3))
	if band != "high" || risk != 0.9 {
		t.Errorf("probe_risk(tier=0, gap=3) = (%q, %v), want (\"high\", 0.9)",
			band, risk)
	}
	if band, _ := ProbeRisk(row(0, 4)); band != "high" {
		t.Errorf("probe_risk(tier=0, gap=4) band = %q, want \"high\"", band)
	}
	if band, _ := ProbeRisk(row(0, 2)); band != "medium" {
		t.Errorf("probe_risk(tier=0, gap=2) band = %q, want \"medium\"", band)
	}
	if band, _ := ProbeRisk(row(1, 3)); band != "medium" {
		t.Errorf("probe_risk(tier=1, gap=3) band = %q, want \"medium\"", band)
	}
	if band, _ := ProbeRisk(row(1, 1)); band != "low" {
		t.Errorf("probe_risk(tier=1, gap=1) band = %q, want \"low\"", band)
	}
	if band, _ := ProbeRisk(row(2, 0)); band != "low" {
		t.Errorf("probe_risk(tier=2, gap=0) band = %q, want \"low\"", band)
	}
	_, low := ProbeRisk(row(2, 0))
	_, med := ProbeRisk(row(0, 2))
	_, high := ProbeRisk(row(0, 3))
	if !(low < med && med < high) {
		t.Errorf("probe_risk ordering: low=%v med=%v high=%v, want low < med < high",
			low, med, high)
	}
}

func TestRowQuestionIsDeterministicAndNamesFileLineAnchors(t *testing.T) {
	c := emitCampaign(t)
	idx, surface := emitSurface(t, c, emitRanking, nil)
	row := vObjList(surface, "rows")[0]
	q, err := RowQuestion(row, &idx)
	if err != nil {
		t.Fatalf("row_question: %v", err)
	}
	q2, err := RowQuestion(emitDeepCopy(t, row), &idx)
	if err != nil {
		t.Fatalf("row_question (copy): %v", err)
	}
	if q != q2 {
		t.Errorf("row_question is not deterministic:\n%q\n%q", q, q2)
	}
	if why := vStr(row, "why"); !strings.Contains(q, why) {
		t.Errorf("row_question %q does not contain the row's why %q", q, why)
	}
	if !strings.Contains(q, "Rollup.sol#L45") ||
		!strings.Contains(q, "Rollup.sol#L66") {
		t.Errorf("row_question %q does not name both file#L anchors", q)
	}
	if strings.ContainsAny(q, "{}") {
		t.Errorf("row_question %q has an unrendered template slot", q)
	}
	noIdx, err := RowQuestion(row, nil)
	if err != nil {
		t.Fatalf("row_question(nil index): %v", err)
	}
	if !strings.Contains(noIdx, "Rollup#L45") {
		t.Errorf("row_question without an index = %q, want it to contain "+
			"\"Rollup#L45\"", noIdx)
	}
}

// ---- emit -----------------------------------------------------------------

func TestEmitCreatesOnePriorityPerRowWithProbeProvenance(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	before := len(vList(plan, "priorities"))
	res, err := EmitRows(c, plan, surface, &idx)
	if err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	if got := len(vStrList(res, "created")); got != len(vObjList(surface,
		"rows")) || got != 10 {
		t.Errorf("created = %d, want len(rows) = %d = 10", got,
			len(vObjList(surface, "rows")))
	}
	plan = emitReload(t, c)
	if got := len(vList(plan, "priorities")); got != before+10 {
		t.Errorf("len(plan.priorities) = %d, want %d", got, before+10)
	}
	row := vObjList(surface, "rows")[0]
	p := emitProbePriority(t, plan, vStr(row, "row_id"))
	want := validation.VObj(
		kv("row_id", vGet(row, "row_id")),
		kv("probe_id", validation.VStr("assertion-strength")),
		kv("axis", validation.VStr("enforcement-timing")),
		kv("surface_sha", vGet(surface, "index_sha")),
		kv("shape_sha", validation.VStr(RowShapeSha(row))),
		kv("risk_band", validation.VStr("high")))
	if got := validation.CanonCompact(vGet(p, "probe")); got !=
		validation.CanonCompact(want) {
		t.Errorf("p.probe = %s, want %s", got, validation.CanonCompact(want))
	}
	if got := vStrList(p, "trajectories"); len(got) != 1 ||
		got[0] != "lifecycle" {
		t.Errorf("p.trajectories = %v, want [\"lifecycle\"]", got)
	}
	if got := vStr(p, "status"); got != "open" {
		t.Errorf("p.status = %q, want \"open\"", got)
	}
	if got := vGet(p, "risk"); got.Kind != validation.Flt || got.F != 0.9 {
		t.Errorf("p.risk = %s, want 0.9", validation.CanonCompact(got))
	}
	question := vStr(p, "question")
	if why := vStr(row, "why"); !strings.HasPrefix(question, why) {
		t.Errorf("p.question = %q, want it to start with %q", question, why)
	}
	if !strings.Contains(question, "Rollup.sol#L45") {
		t.Errorf("p.question = %q, want it to name Rollup.sol#L45", question)
	}
	onDisk, err := validation.ReadJson(emitPlanPath(c))
	if err != nil {
		t.Fatalf("read campaign_plan.json: %v", err)
	}
	if err := validation.Validate(onDisk, "campaign_plan", 1); err != nil {
		t.Errorf("campaign_plan.json does not validate: %v", err)
	}
}

func TestEmitTwiceCreatesNoDuplicates(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	first, err := EmitRows(c, plan, surface, &idx)
	if err != nil {
		t.Fatalf("first emit_rows: %v", err)
	}
	afterFirst, err := validation.ReadJson(emitPlanPath(c))
	if err != nil {
		t.Fatalf("read campaign_plan.json: %v", err)
	}
	second, err := EmitRows(c, plan, surface, &idx)
	if err != nil {
		t.Fatalf("second emit_rows: %v", err)
	}
	if got := vStrList(second, "created"); len(got) != 0 {
		t.Errorf("second created = %v, want []", got)
	}
	gotUpdated := append([]string(nil), vStrList(second, "updated")...)
	wantUpdated := append([]string(nil), vStrList(first, "created")...)
	sort.Strings(gotUpdated)
	sort.Strings(wantUpdated)
	if strings.Join(gotUpdated, ",") != strings.Join(wantUpdated, ",") {
		t.Errorf("second updated = %v, want sorted %v", gotUpdated, wantUpdated)
	}
	plan = emitReload(t, c)
	ids := []string{}
	for _, p := range vList(plan, "priorities") {
		if emitIsProbe(p) {
			ids = append(ids, vStr(vGet(p, "probe"), "row_id"))
		}
	}
	uniq := map[string]struct{}{}
	for _, id := range ids {
		uniq[id] = struct{}{}
	}
	if len(ids) != len(uniq) || len(ids) != 10 {
		t.Errorf("probe row_ids: %d total, %d unique, want 10/10", len(ids),
			len(uniq))
	}
	afterSecond, err := validation.ReadJson(emitPlanPath(c))
	if err != nil {
		t.Fatalf("re-read campaign_plan.json: %v", err)
	}
	if validation.CanonCompact(afterSecond) != validation.CanonCompact(afterFirst) {
		t.Errorf("an unchanged re-emit is a no-op, but the plan changed")
	}
}

func TestEmitCreatesOnePriorityPerRowEvenIfARowRepeats(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	doubled := emitDeepCopy(t, surface)
	rows := vList(doubled, "rows")
	rows = append(rows, emitDeepCopy(t, rows[0]))
	vSet(&doubled, "rows", validation.VArr(rows...))
	res, err := EmitRows(c, plan, doubled, &idx)
	if err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	if got := len(vStrList(res, "created")); got != len(vObjList(surface,
		"rows")) || got != 10 {
		t.Errorf("created = %d, want len(rows) = %d = 10", got,
			len(vObjList(surface, "rows")))
	}
	plan = emitReload(t, c)
	ids := []string{}
	for _, p := range vList(plan, "priorities") {
		if emitIsProbe(p) {
			ids = append(ids, vStr(vGet(p, "probe"), "row_id"))
		}
	}
	uniq := map[string]struct{}{}
	for _, id := range ids {
		uniq[id] = struct{}{}
	}
	if len(ids) != len(uniq) || len(ids) != 10 {
		t.Errorf("probe row_ids: %d total, %d unique, want 10/10", len(ids),
			len(uniq))
	}
}

func TestReemitDoesNotClobberAnsweredUnlessTheShapeChanged(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	if _, err := EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	plan = emitReload(t, c)
	first := emitProbePriority(t, plan, "")
	pid := vStr(first, "id")
	// v3: a tier-0 closure has to quote the row's own code. morph
	// §6.1/§7.1: the enforcement-timing row also owes the interim pricing;
	// the re-emit rule is what this test exercises.
	reason := "checked the anchor pair by hand: commitBatch reads the slots it writes"
	ref := "Rollup.sol#L45"
	anchor := "consumer"
	plan, err := planner.MarkAnswered(c, plan, pid, "answered",
		planner.AnsweredOpts{Reason: &reason, Ref: &ref, Actor: "pytest",
			Anchor: &anchor,
			Interim: emitInterimFor(t, surface, vStr(vGet(first, "probe"),
				"row_id"))})
	if err != nil {
		t.Fatalf("mark_answered: %v", err)
	}
	if _, err := EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("re-emit: %v", err)
	}
	plan = emitReload(t, c)
	p := emitPriorityByID(t, plan, pid)
	if got := vStr(p, "status"); got != "answered" {
		t.Errorf("p.status = %q, want \"answered\"", got)
	}
	if got := vStr(p, "closed_reason"); !strings.Contains(got, "commitBatch") {
		t.Errorf("p.closed_reason = %q, want the cited fixture reason",
			got)
	}
	if got := vStr(p, "closed_ref"); got != "Rollup.sol#L45" {
		t.Errorf("p.closed_ref = %q, want \"Rollup.sol#L45\"", got)
	}
	if got, want := vStr(vGet(p, "probe"), "surface_sha"),
		vStr(surface, "index_sha"); got != want {
		t.Errorf("p.probe.surface_sha = %q, want %q", got, want)
	}

	moved := emitDeepCopy(t, surface)
	row := validation.VNull()
	for _, r := range vObjList(moved, "rows") {
		if vStr(r, "row_id") == vStr(vGet(p, "probe"), "row_id") {
			row = r
			break
		}
	}
	if row.Kind != validation.Obj {
		t.Fatalf("no row with row_id %q in the moved surface",
			vStr(vGet(p, "probe"), "row_id"))
	}
	vSet(&row, "asserter_line", validation.VInt(int64(vInt(row,
		"asserter_line")+1)))
	res, err := EmitRows(c, plan, moved, &idx)
	if err != nil {
		t.Fatalf("emit_rows (moved): %v", err)
	}
	if got := vStrList(res, "reopened"); len(got) != 1 || got[0] != pid {
		t.Errorf("reopened = %v, want [%q]", got, pid)
	}
	plan = emitReload(t, c)
	p = emitPriorityByID(t, plan, pid)
	if got := vStr(p, "status"); got != "open" {
		t.Errorf("p.status = %q, want \"open\"", got)
	}
	for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
		"closed_by"} {
		if vHas(p, k) {
			t.Errorf("p still has %q after the reopen", k)
		}
	}
	if got, want := vStr(vGet(p, "probe"), "shape_sha"), RowShapeSha(row); got !=
		want {
		t.Errorf("p.probe.shape_sha = %q, want %q", got, want)
	}
	question, err := RowQuestion(row, &idx)
	if err != nil {
		t.Fatalf("row_question: %v", err)
	}
	if got := vStr(p, "question"); got != question {
		t.Errorf("p.question = %q, want %q", got, question)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	found := false
	for _, e := range events {
		if vStr(e, "type") == "probes.reopen" &&
			vStr(e, "ref") == pid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no probes.reopen event with ref %q", pid)
	}
}

func TestPlanSchemaAcceptsProbeProvenanceAndRejectsDrift(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	if _, err := EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	plan = emitReload(t, c)
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	bad := emitDeepCopy(t, plan)
	prios := vList(bad, "priorities")
	found := false
	for i := range prios {
		prov := vGet(prios[i], "probe")
		if prov.Kind != validation.Obj || len(prov.O) == 0 {
			continue
		}
		provCopy := copyObj(prov)
		vSet(&provCopy, "bogus", validation.VInt(1))
		vSet(&prios[i], "probe", provCopy)
		found = true
		break
	}
	if !found {
		t.Fatalf("no probe priority to corrupt")
	}
	err := validation.Validate(bad, "campaign_plan", 1)
	if err == nil {
		t.Fatalf("validate accepted a probe provenance with a bogus key")
	}
	if _, ok := err.(*validation.SchemaError); !ok {
		t.Errorf("validate error = %T (%v), want *validation.SchemaError", err,
			err)
	}
}

// ---- the divergence clause ------------------------------------------------

func TestStaleSurfaceLeavesTheLensOpen(t *testing.T) {
	_, idx, surface, plan := emitClosedWithRows(t)
	sha := emitSurfaceSha(idx)
	fresh := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &surface, CurrentIndexSha: &sha})
	if !vBool(fresh, "closed") {
		t.Fatalf("fresh surface: closed = false, missing = %s",
			validation.CanonCompact(vGet(fresh, "missing")))
	}
	staleSha := strings.Repeat("0", 64)
	stale := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &surface, CurrentIndexSha: &staleSha})
	if vBool(stale, "closed") {
		t.Errorf("stale surface: closed = true, want false")
	}
	entry := emitMissingBySubject(t, stale, "L-03")
	what := vStr(entry, "what")
	if !strings.Contains(what, "stale") {
		t.Errorf("L-03 entry %q does not mention \"stale\"", what)
	}
	if !strings.Contains(what, "webv2 probes C-emit1234 run --emit") {
		t.Errorf("L-03 entry %q does not name the fix command", what)
	}
}

func TestANewSurfaceRowReopensAClosedLens(t *testing.T) {
	c, idx, surface, plan := emitClosedWithRows(t)
	grown := emitDeepCopy(t, surface)
	newRow := emitDeepCopy(t, vObjList(surface, "rows")[0])
	vSet(&newRow, "row_id", validation.VStr("deadbeef00"))
	vSet(&newRow, "consumer", validation.VStr("revertBatch"))
	vSet(&newRow, "consumer_line", validation.VInt(83))
	vSet(&newRow, "asserter", validation.VStr("auditRevert"))
	vSet(&newRow, "asserter_line", validation.VInt(113))
	vSet(&newRow, "rank", validation.VInt(10))
	rows := vList(grown, "rows")
	rows = append(rows, newRow)
	vSet(&grown, "rows", validation.VArr(rows...))
	sha := emitSurfaceSha(idx)
	div := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &grown, CurrentIndexSha: &sha})
	if vBool(div, "closed") {
		t.Errorf("grown surface: closed = true, want false")
	}
	entry := emitMissingBySubject(t, div, "L-03")
	what := vStr(entry, "what")
	if !strings.Contains(what, "deadbeef00") ||
		!strings.Contains(what, "not emitted") {
		t.Errorf("L-03 entry %q does not name deadbeef00 as not emitted", what)
	}
	res, err := EmitRows(c, plan, grown, &idx)
	if err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	if got := len(vStrList(res, "created")); got != 1 {
		t.Errorf("created = %d, want 1", got)
	}
	plan = emitReload(t, c)
	div = planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &grown, CurrentIndexSha: &sha})
	if vBool(div, "closed") {
		t.Errorf("after emitting the new row: closed = true, want false")
	}
	entry = emitMissingBySubject(t, div, "L-03")
	if what := vStr(entry, "what"); !strings.Contains(what, "deadbeef00: open") {
		t.Errorf("L-03 entry %q does not name \"deadbeef00: open\"", what)
	}
}

func TestARegisteredAxisAbsentFromTheSurfaceIsOneMissingEntry(t *testing.T) {
	_, idx, surface, plan := emitClosedWithRows(t)
	trimmed := emitDeepCopy(t, surface)
	axes := []validation.Value{}
	for _, a := range vObjList(trimmed, "axes") {
		if vStr(a, "probe") != "sequential-cursor" {
			axes = append(axes, a)
		}
	}
	vSet(&trimmed, "axes", validation.VArr(axes...))
	sha := emitSurfaceSha(idx)
	div := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &trimmed, CurrentIndexSha: &sha})
	entries := []validation.Value{}
	for _, m := range vObjList(div, "missing") {
		if vStr(m, "subject") == "liveness" {
			entries = append(entries, m)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("liveness missing entries = %d, want 1: %s", len(entries),
			validation.CanonCompact(vGet(div, "missing")))
	}
	what := vStr(entries[0], "what")
	if !strings.Contains(what, "no surface") {
		t.Errorf("liveness entry %q does not say \"no surface\"", what)
	}
	if !strings.Contains(what, "webv2 probes C-emit1234 run --emit") {
		t.Errorf("liveness entry %q does not name the fix command", what)
	}
	// no surface artifact at all is the grandfather case: no new blocker
	grandfathered := planner.DivergenceStatus(plan, planner.DivergenceOpts{})
	for _, m := range vObjList(grandfathered, "missing") {
		if vStr(m, "subject") == "liveness" {
			t.Errorf("grandfathered plan gained a liveness blocker: %q",
				vStr(m, "what"))
		}
	}
	if !vBool(grandfathered, "closed") {
		t.Errorf("grandfathered plan: closed = false, missing = %s",
			validation.CanonCompact(vGet(grandfathered, "missing")))
	}
}

func TestGrandfatheredCampaignWithoutASurfaceClosesAsBefore(t *testing.T) {
	c := emitCampaign(t)
	plan := emitPlan(t, c, nil)
	plan = emitCloseLenses(t, c, plan)
	plan = emitAnswerAll(t, c, plan)
	if div := planner.DivergenceStatus(plan, planner.DivergenceOpts{}); !vBool(
		div, "closed") {
		t.Errorf("divergence_status: closed = false, missing = %s",
			validation.CanonCompact(vGet(div, "missing")))
	}
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		t.Fatalf("divergence_status_for: %v", err)
	}
	if !vBool(div, "closed") {
		t.Errorf("divergence_status_for: closed = false, missing = %s",
			validation.CanonCompact(vGet(div, "missing")))
	}
	proof, err := completion.ProofStatus(c, "discovery")
	if err != nil {
		t.Fatalf("proof_status: %v", err)
	}
	if !vBool(proof, "done") {
		t.Errorf("discovery proof: done = false, missing = %s",
			validation.CanonCompact(vGet(proof, "missing")))
	}
}

func TestDivergenceStatusForReadsTheCampaignSurfaceAndIndex(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatalf("save_index: %v", err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatalf("write probe_surface: %v", err)
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatalf("save_plan: %v", err)
	}
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		t.Fatalf("divergence_status_for: %v", err)
	}
	if vBool(div, "closed") {
		t.Errorf("closed = true, want false")
	}
	found := false
	for _, m := range vObjList(div, "missing") {
		if vStr(m, "subject") == "L-03" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("missing has no L-03 entry: %s",
			validation.CanonCompact(vGet(div, "missing")))
	}
}

func TestCompletionDiscoveryDependsOnDispositionedRows(t *testing.T) {
	c := emitCampaign(t)
	idx, surface := emitSurface(t, c, emitRanking, nil)
	emitSurfaceRows = vObjList(surface, "rows")
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatalf("save_index: %v", err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatalf("write probe_surface: %v", err)
	}
	plan := emitPlan(t, c, nil)
	plan = emitCloseLenses(t, c, plan)
	plan = emitAnswerAll(t, c, plan)
	proof, err := completion.ProofStatus(c, "discovery")
	if err != nil {
		t.Fatalf("proof_status: %v", err)
	}
	if vBool(proof, "done") {
		t.Errorf("rows on the surface but not in the plan must block")
	}
	if !emitAnyMissingContains(proof, "not emitted") {
		t.Errorf("missing does not mention \"not emitted\": %s",
			validation.CanonCompact(vGet(proof, "missing")))
	}

	if _, err := EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	plan = emitReload(t, c)
	proof, err = completion.ProofStatus(c, "discovery")
	if err != nil {
		t.Fatalf("proof_status: %v", err)
	}
	if vBool(proof, "done") {
		t.Errorf("emitted but undispositioned rows must block")
	}
	if !emitAnyMissingContains(proof, "not dispositioned") {
		t.Errorf("missing does not mention \"not dispositioned\": %s",
			validation.CanonCompact(vGet(proof, "missing")))
	}

	plan = emitAnswerProbeRows(t, c, plan, &idx)
	proof, err = completion.ProofStatus(c, "discovery")
	if err != nil {
		t.Fatalf("proof_status: %v", err)
	}
	if !vBool(proof, "done") {
		t.Errorf("discovery proof: done = false, missing = %s",
			validation.CanonCompact(vGet(proof, "missing")))
	}
}

// emitAnyMissingContains is any(pattern in m for m in proof["missing"]).
func emitAnyMissingContains(proof validation.Value, pattern string) bool {
	for _, m := range vList(proof, "missing") {
		if strings.Contains(validation.PyStr(m), pattern) {
			return true
		}
	}
	return false
}

func TestBlindAxisNeedsABlankAttestationToClose(t *testing.T) {
	c := emitCampaign(t)
	idx, surface := emitSurface(t, c,
		filepath.Join("testdata", "probes", "assertion_strength", "clean"), nil)
	emitSurfaceRows = vObjList(surface, "rows")
	plan := emitPlan(t, c, nil)
	plan = emitCloseLenses(t, c, plan)
	plan = emitAnswerAll(t, c, plan)
	axis := validation.VNull()
	for _, a := range vObjList(surface, "axes") {
		if vStr(a, "probe") == "assertion-strength" {
			axis = a
			break
		}
	}
	if axis.Kind != validation.Obj {
		t.Fatalf("no assertion-strength axis in the surface")
	}
	if got := vStr(axis, "status"); got != "blind" {
		t.Fatalf("axis.status = %q, want \"blind\"", got)
	}
	sha := emitSurfaceSha(idx)
	div := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &surface, CurrentIndexSha: &sha})
	if vBool(div, "closed") {
		t.Errorf("blind axis: closed = true, want false")
	}
	entry := emitMissingBySubject(t, div, "L-03")
	// Python passes blanks=None here, so the blocker must render the
	// "webv2 probes blank ..." instruction (not the "cites ''" rejection).
	if what := vStr(entry, "what"); !strings.Contains(what, "webv2 probes blank") {
		t.Errorf("L-03 entry does not name the blank command:\n got: %q\nwant: "+
			"a string containing \"webv2 probes blank\" (Python: "+
			"\"assertion-strength saw 4 sites and rejected every one of them "+
			"(5 blind keys published) — close it with `webv2 probes blank "+
			"--axis L-03 --anchor-blind <key> --reason R --actor A`\")", what)
	}
	blind := vObjList(axis, "blind")
	if len(blind) == 0 {
		t.Fatalf("blind axis published no blind keys")
	}
	key := vStr(blind[0], "key")
	blanks := map[string]validation.Value{
		"enforcement-timing": validation.VObj(
			kv("anchor_blind", validation.VStr(key)),
			kv("reason", validation.VStr("the near keys were audited")),
			kv("actor", validation.VStr("pytest"))),
	}
	div = planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &surface, CurrentIndexSha: &sha, Blanks: blanks})
	if !vBool(div, "closed") {
		t.Errorf("attested blind axis: closed = false, missing = %s",
			validation.CanonCompact(vGet(div, "missing")))
	}
}

// ---- fix round 1: the three review findings -------------------------------

func TestRowShapeShaTracksTheSiblingSetAndStrandedEntry(t *testing.T) {
	c := emitCampaign(t)
	_, surface := emitSurface(t, c, emitRanking, nil)
	row := vObjList(surface, "rows")[0]
	base := RowShapeSha(row)

	gained := emitDeepCopy(t, row)
	sibs := vList(gained, "siblings")
	sibs = append(sibs, validation.VObj(
		kv("contract", validation.VStr("Rollup")),
		kv("line", validation.VInt(900))))
	vSet(&gained, "siblings", validation.VArr(sibs...))
	if RowIDFor(gained) != RowIDFor(row) {
		t.Errorf("row_id is line-stable and ignores the sibling set: got %q, "+
			"want %q", RowIDFor(gained), RowIDFor(row))
	}
	if RowShapeSha(gained) == base {
		t.Errorf("row_shape_sha did not change when a sibling was gained")
	}

	lost := emitDeepCopy(t, row)
	vSet(&lost, "siblings", validation.VArr())
	if RowShapeSha(lost) == base {
		t.Errorf("row_shape_sha did not change when every sibling was lost")
	}

	stranded := emitDeepCopy(t, row)
	vSet(&stranded, "stranded_entry", validation.VArr(
		validation.VStr("withdrawBatch")))
	if RowShapeSha(stranded) == base {
		t.Errorf("row_shape_sha did not change when an entry was stranded")
	}
	if RowShapeSha(stranded) == RowShapeSha(gained) {
		t.Errorf("stranded and gained rows share a shape_sha")
	}
}

func TestASiblingGainReopensADispositionedRow(t *testing.T) {
	c, idx, surface, plan := emitReady(t)
	if _, err := EmitRows(c, plan, surface, &idx); err != nil {
		t.Fatalf("emit_rows: %v", err)
	}
	plan = emitReload(t, c)
	plan = emitAnswerProbeRows(t, c, plan, &idx)
	p := emitProbePriority(t, plan, "")
	if got := vStr(p, "status"); got != "answered" {
		t.Fatalf("p.status = %q, want \"answered\"", got)
	}
	rid := vStr(vGet(p, "probe"), "row_id")
	pid := vStr(p, "id")

	grown := emitDeepCopy(t, surface)
	grow := validation.VNull()
	for _, r := range vObjList(grown, "rows") {
		if vStr(r, "row_id") == rid {
			grow = r
			break
		}
	}
	if grow.Kind != validation.Obj {
		t.Fatalf("no row %q in the grown surface", rid)
	}
	sibs := vList(grow, "siblings")
	sibs = append(sibs, validation.VObj(
		kv("contract", validation.VStr("Rollup")),
		kv("line", validation.VInt(900))))
	vSet(&grow, "siblings", validation.VArr(sibs...))
	res, err := EmitRows(c, plan, grown, &idx)
	if err != nil {
		t.Fatalf("emit_rows (grown): %v", err)
	}
	if got := vStrList(res, "reopened"); len(got) != 1 || got[0] != pid {
		t.Fatalf("reopened = %v, want [%q]", got, pid)
	}
	plan = emitReload(t, c)
	p = emitPriorityByID(t, plan, pid)
	if got := vStr(p, "status"); got != "open" {
		t.Errorf("p.status = %q, want \"open\"", got)
	}
	for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
		"closed_by"} {
		if vHas(p, k) {
			t.Errorf("p still has %q after the reopen", k)
		}
	}
	if got, want := vStr(vGet(p, "probe"), "shape_sha"), RowShapeSha(grow); got !=
		want {
		t.Errorf("p.probe.shape_sha = %q, want %q", got, want)
	}

	// losing a sibling is the same class of change: re-disposition, then shrink.
	// morph §6.1/§7.1: the enforcement-timing row owes the interim pricing too.
	reason := "re-checked the collapsed site by hand: commitBatch is the consumer"
	ref := "Rollup.sol#L45"
	anchor := "consumer"
	plan, err = planner.MarkAnswered(c, plan, pid, "answered",
		planner.AnsweredOpts{Reason: &reason, Ref: &ref, Actor: "pytest",
			Anchor:  &anchor,
			Interim: emitInterimFor(t, surface, rid)})
	if err != nil {
		t.Fatalf("mark_answered: %v", err)
	}
	shrunk := emitDeepCopy(t, surface)
	res, err = EmitRows(c, plan, shrunk, &idx)
	if err != nil {
		t.Fatalf("emit_rows (shrunk): %v", err)
	}
	if got := vStrList(res, "reopened"); len(got) != 1 || got[0] != pid {
		t.Errorf("reopened = %v, want [%q]", got, pid)
	}
}

func TestADeprioritizedRowDischargesItsAxisButBlockedDoesNot(t *testing.T) {
	c, idx, surface, plan := emitClosedWithRows(t)
	probeIDs := emitProbeIDs(plan)
	if len(probeIDs) < 2 {
		t.Fatalf("need two probe priorities, got %d", len(probeIDs))
	}
	parked, stuck := probeIDs[0], probeIDs[1]

	reason := "commitBatch ranks below the target's real attack surface"
	ref := "Rollup.sol#L45"
	anchor := "consumer"
	// morph §6.1/§7.1: `deprioritized` is a disposition, so the
	// enforcement-timing row owes the interim pricing; the axis-discharge
	// rule is what this arm exercises.
	parkedRow := emitPriorityByID(t, plan, parked)
	var err error
	plan, err = planner.MarkAnswered(c, plan, parked, "deprioritized",
		planner.AnsweredOpts{Reason: &reason, Ref: &ref, Actor: "pytest",
			Anchor: &anchor,
			Interim: emitInterimFor(t, surface, vStr(vGet(parkedRow,
				"probe"), "row_id"))})
	if err != nil {
		t.Fatalf("mark_answered (deprioritized): %v", err)
	}
	sha := emitSurfaceSha(idx)
	div := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &surface, CurrentIndexSha: &sha})
	if !vBool(div, "closed") {
		t.Errorf("deprioritized row: closed = false, missing = %s",
			validation.CanonCompact(vGet(div, "missing")))
	}

	blockedReason := "waiting on the oracle's mainnet address"
	blockedRef := "Rollup.sol#L49"
	plan, err = planner.MarkAnswered(c, plan, stuck, "blocked",
		planner.AnsweredOpts{Reason: &blockedReason, Ref: &blockedRef,
			Actor: "pytest"})
	if err != nil {
		t.Fatalf("mark_answered (blocked): %v", err)
	}
	div = planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &surface, CurrentIndexSha: &sha})
	if vBool(div, "closed") {
		t.Errorf("blocked row: closed = true, want false")
	}
	entry := emitMissingBySubject(t, div, "L-03")
	what := vStr(entry, "what")
	if !strings.Contains(what, stuck+" (") {
		t.Errorf("L-03 entry %q does not name %q", what, stuck)
	}
	if !strings.Contains(what, ": blocked)") {
		t.Errorf("L-03 entry %q does not say \": blocked)\"", what)
	}
}

func TestAMovedAnchorWithoutAReemitLeavesTheLensOpen(t *testing.T) {
	c, idx, surface, plan := emitClosedWithRows(t)
	moved := emitDeepCopy(t, surface)
	rows := vList(moved, "rows")
	row := rows[0]
	p := emitProbePriority(t, plan, vStr(row, "row_id"))
	stored := vStr(vGet(p, "probe"), "shape_sha")
	vSet(&row, "asserter_line", validation.VInt(int64(vInt(row,
		"asserter_line")+1)))
	rows[0] = row
	vSet(&moved, "rows", validation.VArr(rows...))
	if RowIDFor(row) != vStr(vGet(p, "probe"), "row_id") {
		t.Errorf("row_id is line-stable: got %q, want %q", RowIDFor(row),
			vStr(vGet(p, "probe"), "row_id"))
	}
	if RowShapeSha(row) == stored {
		t.Errorf("row_shape_sha did not change after the anchor moved")
	}

	sha := emitSurfaceSha(idx)
	div := planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &moved, CurrentIndexSha: &sha})
	if vBool(div, "closed") {
		t.Errorf("moved anchor without a re-emit: closed = true, want false")
	}
	entry := emitMissingBySubject(t, div, "L-03")
	what := vStr(entry, "what")
	if !strings.Contains(what, vStr(p, "id")) {
		t.Errorf("L-03 entry %q does not name %q", what, vStr(p, "id"))
	}
	if !strings.Contains(what, "webv2 probes C-emit1234 run --emit") {
		t.Errorf("L-03 entry %q does not name the fix command", what)
	}

	// re-emitting refreshes the stamp and reopens the row; re-dispositioning
	// against the new anchors closes the axis again (not a deadlock)
	res, err := EmitRows(c, plan, moved, &idx)
	if err != nil {
		t.Fatalf("emit_rows (moved): %v", err)
	}
	if got := vStrList(res, "reopened"); len(got) != 1 ||
		got[0] != vStr(p, "id") {
		t.Fatalf("reopened = %v, want [%q]", got, vStr(p, "id"))
	}
	plan = emitReload(t, c)
	emitSurfaceRows = vObjList(moved, "rows")
	// the disposition re-derives its anchor from the campaign's surface, which
	// `probes run` would have rewritten with the moved rows
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"), moved, "probe_surface"); err != nil {
		t.Fatalf("write probe_surface: %v", err)
	}
	plan = emitAnswerProbeRows(t, c, plan, &idx)
	div = planner.DivergenceStatus(plan, planner.DivergenceOpts{
		Surface: &moved, CurrentIndexSha: &sha})
	if !vBool(div, "closed") {
		t.Errorf("re-dispositioned axis: closed = false, missing = %s",
			validation.CanonCompact(vGet(div, "missing")))
	}
}
