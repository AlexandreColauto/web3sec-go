package cli

// T29 cmd_probes tests: port of web3sec-final/tests/test_probes_cli.py
// (A4/A6, the operator surface for the mechanical candidate plane).
//
// Python -> Go map used throughout:
//   _run(*argv)                  -> run(t, argv...)
//   Campaign.init(ws, P, cid=C)  -> state.Init(ws, P, state.InitOpts{CampaignID: C})
//   SI.index_snapshot(camp, R)   -> structidx.IndexSnapshot(c, R, structidx.DefaultBackend)
//   SI.save_index(camp, idx)     -> structidx.SaveIndex(c, idx)
//   PB.build_surface(idx, None)  -> probes.BuildSurface(idx, VNull(), 12, 40, 3, "")
//   write_json(..., "probe_surface") -> validation.WriteJson(path, surface, "probe_surface")
//   validate(doc, "x")           -> validation.Validate(doc, "x", 1)
//   camp.state() / camp._save(st)-> c.State() / t29SaveState(t, c, st)
//   camp.log(...)                -> c.Log(type, ref, data)
//
// Only probes-command output is asserted (the ROOT usage text differs from
// Python's); the probes subparser's own argparse text is pinned byte-exactly
// in cmd_probes.go.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/audit"
	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const (
	t29CID     = "C-probecli01"
	t29Ranking = "../probes/testdata/probes/ranking"
	t29Blind   = "../probes/testdata/probes/assertion_strength/clean"
)

// t29Classes is CLASSES.
var t29Classes = []string{"logic-error", "access-control",
	"oracle-manipulation", "reentrancy"}

// t29Model is PLAN_MODEL.
func t29Model() validation.Value {
	return validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("probe-cli")},
		validation.KV{K: "name", V: validation.VStr("Probe CLI")},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Rollup")},
			validation.KV{K: "path", V: validation.VStr("Rollup.sol")},
			validation.KV{K: "role", V: validation.VStr("core")},
			validation.KV{K: "in_scope", V: validation.VBool(true)},
			validation.KV{K: "entry_points", V: validation.VArr(
				validation.VStr("commitBatch"),
				validation.VStr("finalizeBatch"))},
		))},
		validation.KV{K: "state_machines", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("rollup-lifecycle")},
			validation.KV{K: "transitions", V: validation.VArr(
				validation.VStr("commit"), validation.VStr("challenge"),
				validation.VStr("finalize"))},
		))},
		validation.KV{K: "actors", V: validation.VArr(validation.VObj(
			validation.KV{K: "id", V: validation.VStr("active_staker")},
			validation.KV{K: "kind", V: validation.VStr("ROLE")},
			validation.KV{K: "trust", V: validation.VStr("semi-trusted")},
		))},
	)
}

// t29Set is setOrAppend.
func t29Set(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
}

// t29Del is Python's `del d[k]`.
func t29Del(v *validation.Value, key string) {
	out := make([]validation.KV, 0, len(v.O))
	for _, kv := range v.O {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	v.O = out
}

// t29Has is Python's `k in d`.
func t29Has(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// t29List is d.get(key) as a list (nil when absent/not a list).
func t29List(v validation.Value, key string) []validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}

// t29ObjList is d.get(key) filtered to objects.
func t29ObjList(v validation.Value, key string) []validation.Value {
	out := []validation.Value{}
	for _, it := range t29List(v, key) {
		if it.Kind == validation.Obj {
			out = append(out, it)
		}
	}
	return out
}

// t29StrList is list(d.get(key) or []).
func t29StrList(v validation.Value, key string) []string {
	out := []string{}
	for _, it := range t29List(v, key) {
		out = append(out, scalarStr(it))
	}
	return out
}

// t29DeepCopy is copy.deepcopy for the ordered Value.
func t29DeepCopy(v validation.Value) validation.Value {
	out := v
	if len(v.A) > 0 {
		out.A = make([]validation.Value, len(v.A))
		for i := range v.A {
			out.A[i] = t29DeepCopy(v.A[i])
		}
	}
	if len(v.O) > 0 {
		out.O = make([]validation.KV, len(v.O))
		for i, kv := range v.O {
			out.O[i] = validation.KV{K: kv.K, V: t29DeepCopy(kv.V)}
		}
	}
	return out
}

// t29Plan is _plan: default_plan_from_model + the four bug classes, saved.
func t29Plan(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	plan, err := planner.DefaultPlanFromModel(c, t29Model())
	if err != nil {
		t.Fatal(err)
	}
	prios := t29List(plan, "priorities")
	for i, cls := range t29Classes {
		if i >= len(prios) {
			break
		}
		p := prios[i]
		t29Set(&p, "bug_class", validation.VStr(cls))
		prios[i] = p
	}
	t29Set(&plan, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

// t29Setup is _setup: workspace + campaign + saved index + saved surface
// (+ plan).
func t29Setup(t *testing.T, root string, withPlan bool) (string,
	*state.Campaign, validation.Value, validation.Value) {
	t.Helper()
	probes.Wire() // a sibling test may have reset the planner seam
	audit.Setup() // idempotent; makes the audit section registry order-free
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, root, structidx.DefaultBackend)
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
	if err := validation.WriteJson(
		filepath.Join(c.ArtifactsDir, "probe_surface.json"), surface,
		"probe_surface"); err != nil {
		t.Fatal(err)
	}
	if withPlan {
		t29Plan(t, c)
	}
	return ws, c, idx, surface
}

// t29Emit is _emit.
func t29Emit(t *testing.T, ws string) string {
	t.Helper()
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run", "--emit")
	if code != 0 {
		t.Fatalf("probes run --emit exit %d: out=%q err=%q", code, out, errS)
	}
	return out
}

// t29Row is _row.
func t29Row(t *testing.T, surface validation.Value, rowID string) validation.Value {
	t.Helper()
	for _, r := range t29ObjList(surface, "rows") {
		if rowID == "" || validation.ObjStr(r, "row_id") == rowID {
			return r
		}
	}
	t.Fatalf("no surface row %q", rowID)
	return validation.VNull()
}

// t29PlanJSON reads artifacts/campaign_plan.json.
func t29PlanJSON(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	plan, err := validation.ReadJson(
		filepath.Join(c.ArtifactsDir, "campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// t29ProbePriority is _probe_priority.
func t29ProbePriority(t *testing.T, c *state.Campaign, rowID string) validation.Value {
	t.Helper()
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		prov := validation.ObjAt(p, "probe")
		if prov.Kind != validation.Obj || validation.ObjStr(prov, "row_id") == "" {
			continue
		}
		if rowID == "" || validation.ObjStr(prov, "row_id") == rowID {
			return p
		}
	}
	t.Fatal("no probe priority emitted")
	return validation.VNull()
}

// t29ProbePriorities is [p for p in plan["priorities"] if p.get("probe")].
func t29ProbePriorities(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	out := []validation.Value{}
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjAt(p, "probe").Kind == validation.Obj {
			out = append(out, p)
		}
	}
	return out
}

// t29LensProbe is divergence_status_for(camp, plan)["lenses"] -> the lens
// entry whose `lens` is name, and its `probe` counts dict.
func t29LensProbe(t *testing.T, c *state.Campaign, plan validation.Value,
	lens string) validation.Value {
	t.Helper()
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range t29ObjList(div, "lenses") {
		if validation.ObjStr(e, "lens") == lens {
			return validation.ObjAt(e, "probe")
		}
	}
	t.Fatalf("no lens entry %q in divergence_status_for: %s", lens,
		validation.DumpIndented(div))
	return validation.VNull()
}

// t29Divergence is divergence_status_for(camp, plan).
func t29Divergence(t *testing.T, c *state.Campaign,
	plan validation.Value) validation.Value {
	t.Helper()
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	return div
}

// t29SaveState is campaign._save(st): bump updated_at and re-write.
func t29SaveState(t *testing.T, c *state.Campaign, st validation.Value) {
	t.Helper()
	t29Set(&st, "updated_at", validation.VStr(state.NowIso()))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
}

// t29CloseEverything is _close_everything: close every lens and every
// priority so the ONLY thing left open is the probe clause.
// reconOnRecord puts both FIX-8 recon stamps on record for one campaign.
// The real verbs would rebuild this campaign's fixture index from the shared
// sink tree (EnsureFreshIndex), so the prescreen artifact is seeded as a
// fixture file and the sinks stamp rides the REAL state.StampRecon write
// path; the end-to-end real-verb version lives in cmd_recon_gate_test.go.
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

func t29CloseEverything(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	reconOnRecord(t, c)
	plan := t29PlanJSON(t, c)
	for _, lens := range t29ObjList(plan, "lenses") {
		reason := validation.ObjStr(lens, "lens") + " resolved for the fixture tree"
		ref := "Rollup.sol#L45"
		fams := t29StrList(lens, "families")
		next, err := planner.MarkLens(c, plan, validation.ObjStr(lens, "id"), "answered",
			planner.LensOpts{Reason: &reason, Ref: &ref, Actor: "pytest",
				FamiliesChecked: &fams})
		if err != nil {
			t.Fatal(err)
		}
		plan = next
	}
	for _, p := range t29ObjList(plan, "priorities") {
		reason := "fixture closure with a written reason"
		ref := "Rollup.sol#L45"
		next, err := planner.MarkAnswered(c, plan, validation.ObjStr(p, "id"),
			"answered", planner.AnsweredOpts{Reason: &reason, Ref: &ref,
				Actor: "pytest"})
		if err != nil {
			t.Fatal(err)
		}
		plan = next
	}
	return t29PlanJSON(t, c)
}

// t29AuditSection is AUDIT.audit_campaign(camp)["sections"]["probe_surface"].
func t29AuditSection(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	report, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(validation.ObjAt(report, "sections"), "probe_surface")
}

// t29Problems is sec["problems"].
func t29Problems(sec validation.Value) []string { return t29StrList(sec, "problems") }

// t29HasProblem reports whether any problem contains needle.
func t29HasProblem(sec validation.Value, needle string) bool {
	for _, p := range t29Problems(sec) {
		if strings.Contains(p, needle) {
			return true
		}
	}
	return false
}

// t29L01Tree is _l01_tree.
func t29L01Tree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "l01")
	copyTree(t, "../probes/testdata/probes/cursor/buggy",
		filepath.Join(root, "cursor"))
	copyTree(t, "../probes/testdata/probes/accumulator/buggy",
		filepath.Join(root, "acc"))
	return root
}

// t29SharedLens is _shared_lens.
func t29SharedLens(t *testing.T) (string, *state.Campaign, validation.Value,
	validation.Value) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "tree")
	copyTree(t, "../probes/testdata/probes/accumulator/blind",
		filepath.Join(root, "acc"))
	copyTree(t, "../probes/testdata/probes/short_circuit/clean",
		filepath.Join(root, "guard"))
	return t29Setup(t, root, true)
}

// t29JSONDoc parses a CLI --json document into map[string]any.
func t29JSONDoc(t *testing.T, doc string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(doc), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, doc)
	}
	return out
}

// t29SurfacePath is the surface artifact path.
func t29SurfacePath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "probe_surface.json")
}

// t29IndexPath is the structural index artifact path.
func t29IndexPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "structural_index.json")
}

// t29WriteSurface writes the surface artifact (no schema name, like the
// Python test's write_json for hand edits).
func t29WriteSurface(t *testing.T, c *state.Campaign, surface validation.Value) {
	t.Helper()
	if err := validation.WriteJson(t29SurfacePath(c), surface,
		"probe_surface"); err != nil {
		t.Fatal(err)
	}
}

// t29BumpIndexLine is the "the index artifact moves" edit.
func t29BumpIndexLine(t *testing.T, c *state.Campaign, idx validation.Value) {
	t.Helper()
	moved := t29DeepCopy(idx)
	nodes := t29List(moved, "nodes")
	if len(nodes) == 0 {
		t.Fatal("index has no nodes")
	}
	n := nodes[0]
	t29Set(&n, "line", validation.VInt(objInt(n, "line")+1))
	nodes[0] = n
	t29Set(&moved, "nodes", validation.VArr(nodes...))
	if err := validation.WriteJson(t29IndexPath(c), moved, ""); err != nil {
		t.Fatal(err)
	}
}

// t29BlankKeyOf is next(a for a in surface["axes"] if a["probe"] == probe)
// ["blind"][0]["key"].
func t29BlankKeyOf(t *testing.T, surface validation.Value,
	probe string) (validation.Value, string) {
	t.Helper()
	for _, a := range t29ObjList(surface, "axes") {
		if validation.ObjStr(a, "probe") != probe {
			continue
		}
		blind := t29ObjList(a, "blind")
		if len(blind) == 0 {
			t.Fatalf("axis %s published no blind keys", probe)
		}
		return a, validation.ObjStr(blind[0], "key")
	}
	t.Fatalf("no axis for probe %s", probe)
	return validation.VNull(), ""
}

// t29AxisByProbe is next(a for a in surface["axes"] if a["probe"] == probe).
func t29AxisByProbe(t *testing.T, surface validation.Value,
	probe string) validation.Value {
	t.Helper()
	a, _ := t29BlankKeyOf(t, surface, probe)
	return a
}

// t29AxisByAxis is next(a for a in surface["axes"] if a["axis"] == name).
func t29AxisByAxis(t *testing.T, surface validation.Value,
	name string) validation.Value {
	t.Helper()
	for _, a := range t29ObjList(surface, "axes") {
		if validation.ObjStr(a, "axis") == name {
			return a
		}
	}
	t.Fatalf("no axis named %q", name)
	return validation.VNull()
}

// t29StateBlanks is camp.state()["probe_blanks"].
func t29StateBlanks(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return t29ObjList(st, "probe_blanks")
}

// ---- probes run -----------------------------------------------------------

func TestProbesRunWritesTheSurfaceAndReportsEveryAxis(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	surface, err := probes.CampaignSurface(c)
	if err != nil {
		t.Fatal(err)
	}
	if surface == nil {
		t.Fatal("no surface written")
	}
	if validation.ObjStr(*surface, "index_sha") != probes.IndexSha(idx) {
		t.Fatalf("index_sha = %q, want %q", validation.ObjStr(*surface, "index_sha"),
			probes.IndexSha(idx))
	}
	if got := len(t29ObjList(*surface, "rows")); got != 10 {
		t.Fatalf("rows = %d, want 10", got)
	}
	for _, a := range t29ObjList(*surface, "axes") {
		if !strings.Contains(out, validation.ObjStr(a, "probe")) {
			t.Errorf("run output does not report axis probe %q: %q",
				validation.ObjStr(a, "probe"), out)
		}
	}
	if !strings.Contains(out, "10 rows") && !strings.Contains(out, "rows=10") {
		t.Fatalf("run output does not report the row count: %q", out)
	}
}

func TestProbesRunWithoutAnIndexNamesTheRebuildCommand(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	if _, err := state.Init(ws, "Probe CLI",
		state.InitOpts{CampaignID: t29CID}); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "webv2 index") {
		t.Fatalf("err = %q", errS)
	}
	if !strings.Contains(errS, "webv2 index "+t29CID) {
		t.Fatalf("err = %q", errS)
	}
}

func TestProbesRunEmitMintsPrioritiesAndIsIdempotent(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	out := t29Emit(t, ws)
	if !strings.Contains(out, "created 10") &&
		!strings.Contains(out, "10 created") {
		t.Fatalf("emit output = %q", out)
	}
	plan := t29PlanJSON(t, c)
	probePrios := []validation.Value{}
	for _, p := range t29ObjList(plan, "priorities") {
		if validation.ObjAt(p, "probe").Kind == validation.Obj {
			probePrios = append(probePrios, p)
		}
	}
	if len(probePrios) != 10 {
		t.Fatalf("probe priorities = %d, want 10", len(probePrios))
	}
	for _, p := range probePrios {
		if validation.ObjStr(p, "status") != "open" {
			t.Errorf("status = %q, want open", validation.ObjStr(p, "status"))
		}
		if validation.ObjStr(validation.ObjAt(p, "probe"), "surface_sha") !=
			validation.ObjStr(surface, "index_sha") {
			t.Errorf("probe.surface_sha = %q, want %q",
				validation.ObjStr(validation.ObjAt(p, "probe"), "surface_sha"),
				validation.ObjStr(surface, "index_sha"))
		}
	}
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		t.Fatalf("plan invalid: %v", err)
	}
	out = t29Emit(t, ws)
	if !strings.Contains(out, "created 0") &&
		!strings.Contains(out, "0 created") {
		t.Fatalf("re-emit output = %q", out)
	}
	if got := len(t29ProbePriorities(t, c)); got != 10 {
		t.Fatalf("probe priorities after re-emit = %d, want 10", got)
	}
}

func TestProbesRunEmitWithoutAPlanFailsLoudly(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, false)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run", "--emit")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "webv2 plan "+t29CID) {
		t.Fatalf("err = %q", errS)
	}
}

func TestProbesRunPerAxisQuotaIsHonoured(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run",
		"--per-axis", "2", "--total", "40")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	surface, err := probes.CampaignSurface(c)
	if err != nil || surface == nil {
		t.Fatalf("surface = %v, %v", surface, err)
	}
	if got := len(t29ObjList(*surface, "rows")); got != 2 {
		t.Fatalf("rows = %d, want 2", got)
	}
	if got := objInt(*surface, "per_axis"); got != 2 {
		t.Fatalf("per_axis = %d, want 2", got)
	}
}

func TestProbesRunRejectsAQuotaThatObligesNothing(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range [][2]string{{"--per-axis", "0"}, {"--per-axis", "-1"},
		{"--total", "0"}} {
		flag, value := tc[0], tc[1]
		code, out, errS := run(t, "--root", ws, "probes", t29CID, "run",
			flag, value)
		if code != 2 {
			t.Errorf("%s %s: exit %d, want 2 (out=%q err=%q)", flag, value,
				code, out, errS)
			continue
		}
		if !strings.Contains(errS, flag) || !strings.Contains(errS, ">= 1") {
			t.Errorf("%s %s: err = %q", flag, value, errS)
		}
	}
	if _, err := os.Stat(t29SurfacePath(c)); err == nil {
		t.Fatal("a rejected knob must not write a surface")
	}
}

// t29SeedSurface campaign + saved index + a surface artifact built with the
// given quotas, the starting point of every repair test.
func t29SeedSurface(t *testing.T, perAxis, total int) (string,
	*state.Campaign, validation.Value) {
	t.Helper()
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	surface, err := probes.BuildSurface(idx, validation.VNull(), perAxis,
		total, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	t29WriteSurface(t, c, surface)
	return ws, c, surface
}

// TestProbesRunAdoptsRecordedQuotas pins the repair rule per flag: an explicit
// flag wins, an unset one adopts the quota the existing surface records, and
// the output names both the effective numbers and their source. The canonical
// ranking fixture yields only 10 candidate rows, so the emitted row count is
// 10 under both the adopted 30/70 and the compiled-in 12/40: it cannot
// discriminate adoption here. The recorded per_axis/total and the provenance
// line are what do.
func TestProbesRunAdoptsRecordedQuotas(t *testing.T) {
	cases := []struct {
		name          string
		recordedPer   int
		recordedTotal int
		noArtifact    bool
		perAsString   bool
		args          []string
		withPlan      bool
		wantPer       int
		wantTotal     int
		wantSource    string
	}{
		{"no flags adopt the recorded pair", 30, 70, false, false, nil, false,
			30, 70, "recorded in probe_surface.json"},
		{"a tighter recorded pair still wins", 2, 5, false, false, nil, false,
			2, 5, "recorded in probe_surface.json"},
		{"an explicit per-axis wins and total falls back", 30, 70, false,
			false, []string{"--per-axis", "2"}, false, 2, 70,
			"--per-axis passed on the command line; --total recorded in " +
				"probe_surface.json"},
		{"an explicit total wins and per-axis falls back", 30, 70, false,
			false, []string{"--total", "5"}, false, 30, 5,
			"--per-axis recorded in probe_surface.json; --total passed on " +
				"the command line"},
		{"an explicit pair wins over the record", 30, 70, false, false,
			[]string{"--per-axis", "2", "--total", "5"}, false, 2, 5,
			"passed on the command line"},
		{"an explicit default per-axis still wins", 30, 70, false, false,
			[]string{"--per-axis", "12"}, false, 12, 70,
			"--per-axis passed on the command line; --total recorded in " +
				"probe_surface.json"},
		{"--emit adopts the recorded pair too", 2, 5, false, false,
			[]string{"--emit"}, true, 2, 5,
			"recorded in probe_surface.json"},
		{"one flag without an artifact keeps the other default", 12, 40, true,
			false, []string{"--total", "5"}, false, 12, 5,
			"--per-axis defaults; --total passed on the command line"},
		{"an artifact without a usable per-axis names itself", 30, 70, false,
			true, nil, false, 12, 70,
			"--per-axis default (probe_surface.json records no integer); " +
				"--total recorded in probe_surface.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, c, seed := t29SeedSurface(t, tc.recordedPer, tc.recordedTotal)
			if tc.noArtifact {
				if err := os.Remove(t29SurfacePath(c)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.perAsString {
				bad := t29DeepCopy(seed)
				t29Set(&bad, "per_axis", validation.VStr("thirty"))
				body := validation.DumpIndented(bad) + "\n"
				if err := os.WriteFile(t29SurfacePath(c), []byte(body),
					0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.withPlan {
				t29Plan(t, c)
			}
			args := append([]string{"--root", ws, "probes", t29CID, "run"},
				tc.args...)
			code, out, errS := run(t, args...)
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			got, err := probes.CampaignSurface(c)
			if err != nil || got == nil {
				t.Fatalf("surface = %v, %v", got, err)
			}
			if v := objInt(*got, "per_axis"); v != int64(tc.wantPer) {
				t.Errorf("per_axis = %d, want %d", v, tc.wantPer)
			}
			if v := objInt(*got, "total"); v != int64(tc.wantTotal) {
				t.Errorf("total = %d, want %d", v, tc.wantTotal)
			}
			flat := strings.Join(strings.Fields(out), " ")
			want := fmt.Sprintf("quotas: --per-axis %d --total %d (%s)",
				tc.wantPer, tc.wantTotal, tc.wantSource)
			if !strings.Contains(flat, want) {
				t.Errorf("output missing %q: %q", want, flat)
			}
			if tc.withPlan && !strings.Contains(flat, "emit: created") {
				t.Errorf("--emit did not run off the repaired surface: %q",
					flat)
			}
		})
	}
}

// TestProbesRunWithoutASurfaceUsesTheDefaults pins the fallback: with no
// artifact to repair, the compiled-in 12/40 still build the surface and the
// provenance line says so.
func TestProbesRunWithoutASurfaceUsesTheDefaults(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	got, err := probes.CampaignSurface(c)
	if err != nil || got == nil {
		t.Fatalf("surface = %v, %v", got, err)
	}
	if v := objInt(*got, "per_axis"); v != 12 {
		t.Errorf("per_axis = %d, want 12", v)
	}
	if v := objInt(*got, "total"); v != 40 {
		t.Errorf("total = %d, want 40", v)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "quotas: --per-axis 12 --total 40 (defaults)") {
		t.Errorf("output does not name the default provenance: %q", flat)
	}
}

// TestProbesRunRejectsAnInvalidRecordedQuota pins the loud path: a knob the
// artifact records as an integer that ValidateKnobs refuses must fail naming
// the artifact and the value, and must write nothing.
func TestProbesRunRejectsAnInvalidRecordedQuota(t *testing.T) {
	cases := []struct{ key, flag string }{
		{"per_axis", "--per-axis"},
		{"total", "--total"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			ws, c, seed := t29SeedSurface(t, 12, 40)
			bad := t29DeepCopy(seed)
			t29Set(&bad, tc.key, validation.VInt(0))
			path := t29SurfacePath(c)
			before := validation.DumpIndented(bad) + "\n"
			if err := os.WriteFile(path, []byte(before), 0o644); err != nil {
				t.Fatal(err)
			}
			code, out, errS := run(t, "--root", ws, "probes", t29CID, "run")
			if code != 2 {
				t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
			}
			if !strings.Contains(errS, "probe_surface.json") {
				t.Errorf("err does not name the artifact: %q", errS)
			}
			if !strings.Contains(errS, tc.flag+" 0") {
				t.Errorf("err does not name the recorded value: %q", errS)
			}
			if strings.Contains(out, "probe surface:") {
				t.Errorf("a rejected record must print no surface line: %q",
					out)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != before {
				t.Errorf("a rejected record must write nothing: %q", after)
			}
		})
	}
}

// TestProbesRunRepairsAroundACorruptSurfaceArtifact pins the remedy path: an
// artifact the run cannot parse names the artifact and the way out (delete or
// repair it, or pass the quotas explicitly) with the probes exit code 2, and
// leaves the bytes as they were.
func TestProbesRunRepairsAroundACorruptSurfaceArtifact(t *testing.T) {
	cases := []struct{ name, body string }{
		{"truncated json", `{"campaign_id": "` + t29CID + `"`},
		{"empty file", ""},
		{"json array", `[]`},
		{"json string", `"x"`},
		{"json null", `null`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, c, _ := t29SeedSurface(t, 30, 70)
			path := t29SurfacePath(c)
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			code, out, errS := run(t, "--root", ws, "probes", t29CID, "run")
			if code != 2 {
				t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
			}
			if !strings.Contains(errS, "probe_surface.json") {
				t.Errorf("err does not name the artifact: %q", errS)
			}
			if !strings.Contains(errS, "--per-axis") ||
				!strings.Contains(errS, "--total") {
				t.Errorf("err does not offer the explicit-flag way out: %q",
					errS)
			}
			if strings.Contains(out, "probe surface:") {
				t.Errorf("a corrupt artifact must print no surface line: %q",
					out)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != tc.body {
				t.Errorf("a corrupt artifact must be left for the operator "+
					"to delete or repair: %q", after)
			}
		})
	}
}

// TestProbesRunPerAxisZeroOnTheCommandLineStillFails is the regression pin for
// the gate: an explicit --per-axis 0 keeps its existing message even when the
// artifact records a valid quota, and the artifact is left untouched.
func TestProbesRunPerAxisZeroOnTheCommandLineStillFails(t *testing.T) {
	ws, c, _ := t29SeedSurface(t, 30, 70)
	path := t29SurfacePath(c)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run",
		"--per-axis", "0")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "--per-axis must be >= 1, got 0") {
		t.Errorf("err = %q", errS)
	}
	if strings.Contains(out, "probe surface:") {
		t.Errorf("a rejected knob must print no surface line: %q", out)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("a rejected knob must leave the artifact untouched")
	}
}

// TestProbesRunHelpStatesTheRepairRule pins the documentation half: --help
// states the adoption rule, wrapped in the file's 80-column voice.
func TestProbesRunHelpStatesTheRepairRule(t *testing.T) {
	code, out, errS := run(t, "probes", t29CID, "run", "--help")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "quotas: a quota flag the run was not given "+
		"adopts the value already recorded in probe_surface.json (else the "+
		"default)") {
		t.Fatalf("help does not state the adoption rule: %q", flat)
	}
	if !strings.Contains(flat, "so a bare run repairs the surface the "+
		"campaign has instead of shrinking it") {
		t.Fatalf("help does not say what the rule is for: %q", flat)
	}
	for _, line := range strings.Split(out, "\n") {
		if utf8.RuneCountInString(line) > 80 {
			t.Errorf("help line exceeds 80 columns: %q", line)
		}
	}
}

func TestProbesRunAndListSurfaceTheFloorOverrunWarning(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run", "--total", "2")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{"warning: floor reserve 3",
		"exceeds --total 2", "Raise --total to >= 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("run output missing %q: %q", want, out)
		}
	}
	surface, err := probes.CampaignSurface(c)
	if err != nil || surface == nil {
		t.Fatalf("surface = %v, %v", surface, err)
	}
	warnings := t29ObjList(*surface, "warnings")
	if len(warnings) == 0 || validation.ObjStr(warnings[0], "kind") !=
		"floor-reserve-exceeds-total" {
		t.Fatalf("warnings = %s", validation.DumpIndented(*surface))
	}
	if err := validation.Validate(*surface, "probe_surface", 1); err != nil {
		t.Fatalf("surface invalid: %v", err)
	}
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "warning: floor reserve 3") {
		t.Fatalf("list output missing the warning: %q", out)
	}
	// A bare re-run repairs the surface it has and would adopt the recorded
	// --total 2 (and its warning) back, so the winning ceiling is explicit.
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "run",
		"--total", "40")
	if code != 0 {
		t.Fatalf("re-run exit %d: out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out, "warning:") {
		t.Fatalf("a ceiling that can win is silent: %q", out)
	}
}

// ---- probes list ----------------------------------------------------------

// TestProbesListCapsConsoleRows (Task 7a): a surface longer than
// consoleRowCap floods a terminal, so the console table prints the first
// consoleRowCap rows and exactly one pointer line; `--json` stays complete
// (the full table is the machine-readable answer, not the card dump).
func TestProbesListCapsConsoleRows(t *testing.T) {
	const want = 45
	ws, c, _, surface := t29Setup(t, t29Ranking, false)
	rows := t29ObjList(surface, "rows")
	if len(rows) == 0 {
		t.Fatal("fixture surface has no rows to clone")
	}
	cloned := make([]validation.Value, 0, want)
	ids := make([]string, 0, want)
	for i := 0; i < want; i++ {
		row := t29DeepCopy(rows[0])
		id := fmt.Sprintf("aaaaaaaa%02x", i+1)
		t29Set(&row, "row_id", validation.VStr(id))
		t29Set(&row, "rank", validation.VInt(int64(i+1)))
		cloned = append(cloned, row)
		ids = append(ids, id)
	}
	t29Set(&surface, "rows", validation.VArr(cloned...))
	if err := validation.WriteJson(t29SurfacePath(c), surface,
		"probe_surface"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	if got := strings.Count(out, " rank "); got != consoleRowCap {
		t.Fatalf("console row lines = %d, want %d:\n%s", got, consoleRowCap,
			out)
	}
	if !strings.Contains(out, ids[consoleRowCap-1]) {
		t.Fatalf("row %d missing from the console table:\n%s", consoleRowCap,
			out)
	}
	if strings.Contains(out, ids[consoleRowCap]) {
		t.Fatalf("row %d printed past the cap:\n%s", consoleRowCap+1, out)
	}
	if !strings.Contains(out,
		"  … +5 more rows — use --json for the full table\n") {
		t.Fatalf("missing the overflow pointer:\n%s", out)
	}
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list", "--json")
	if code != 0 {
		t.Fatalf("list --json exit %d: %q", code, errS)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	got, ok := doc["surface_rows"].([]any)
	if !ok || len(got) != want {
		t.Fatalf("--json surface_rows = %d, want %d (--json must stay "+
			"complete)", len(got), want)
	}
}

func TestLensProbeClosureMessageCarriesTheCounts(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	plan := t29PlanJSON(t, c)
	probe := t29LensProbe(t, c, plan, "enforcement-timing")
	if objInt(probe, "rows") != 10 || objInt(probe, "emitted") != 10 ||
		objInt(probe, "tail") != 0 {
		t.Fatalf("rows/emitted/tail = %d/%d/%d, want 10/10/0",
			objInt(probe, "rows"), objInt(probe, "emitted"),
			objInt(probe, "tail"))
	}
	if objInt(probe, "dispositioned") != 0 || objInt(probe, "open") != 10 {
		t.Fatalf("dispositioned/open = %d/%d, want 0/10",
			objInt(probe, "dispositioned"), objInt(probe, "open"))
	}
	if objInt(probe, "blind") != 4 || objInt(probe, "blind_attested") != 0 {
		t.Fatalf("blind/blind_attested = %d/%d, want 4/0",
			objInt(probe, "blind"), objInt(probe, "blind_attested"))
	}
	if objBool(probe, "closed") {
		t.Fatal("closed = true, want false")
	}
	wantOpen := "L-03 open — 0/10 rows dispositioned, 0 in tail, 4 blind keys " +
		"disclosed"
	if got := validation.ObjStr(probe, "message"); got != wantOpen {
		t.Fatalf("message = %q, want %q", got, wantOpen)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, wantOpen) {
		t.Fatalf("list output missing %q: %q", wantOpen, out)
	}
	last := ""
	for _, row := range t29ObjList(surface, "rows") {
		p := t29ProbePriority(t, c, validation.ObjStr(row, "row_id"))
		code, out, errS = run(t, "--root", ws, "answered", t29CID,
			validation.ObjStr(p, "id"), "answered", "--anchor", "consumer",
			"--reason", "the batch:index join is anchored elsewhere",
			"--actor", "pytest")
		if code != 0 {
			t.Fatalf("answered exit %d: out=%q err=%q", code, out, errS)
		}
		last = out
	}
	wantClosed := "L-03 closed — 10/10 rows dispositioned, 0 in tail, " +
		"4 blind keys disclosed"
	if !strings.Contains(last, wantClosed) {
		t.Fatalf("last disposition output missing %q: %q", wantClosed, last)
	}
	plan = t29PlanJSON(t, c)
	probe = t29LensProbe(t, c, plan, "enforcement-timing")
	if !objBool(probe, "closed") || objInt(probe, "dispositioned") != 10 {
		t.Fatalf("closed/dispositioned = %v/%d, want true/10",
			objBool(probe, "closed"), objInt(probe, "dispositioned"))
	}
	if objInt(probe, "open") != 0 {
		t.Fatalf("open = %d, want 0", objInt(probe, "open"))
	}
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, wantClosed) {
		t.Fatalf("list output missing %q: %q", wantClosed, out)
	}
}

func TestAShrunkenQuotaCannotCloseALensOnItsTail(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	t29Plan(t, c)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "run", "--emit",
		"--per-axis", "2", "--total", "40")
	if code != 0 {
		t.Fatalf("run exit %d: out=%q err=%q", code, out, errS)
	}
	surface, err := probes.CampaignSurface(c)
	if err != nil || surface == nil {
		t.Fatalf("surface = %v, %v", surface, err)
	}
	rows := t29ObjList(*surface, "rows")
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for _, row := range rows {
		p := t29ProbePriority(t, c, validation.ObjStr(row, "row_id"))
		code, out, errS = run(t, "--root", ws, "answered", t29CID,
			validation.ObjStr(p, "id"), "answered", "--anchor", "consumer",
			"--reason", "the batch:index join is anchored elsewhere",
			"--actor", "pytest")
		if code != 0 {
			t.Fatalf("answered exit %d: out=%q err=%q", code, out, errS)
		}
	}
	plan := t29PlanJSON(t, c)
	probe := t29LensProbe(t, c, plan, "enforcement-timing")
	if objInt(probe, "rows") != 10 || objInt(probe, "emitted") != 2 ||
		objInt(probe, "tail") != 8 {
		t.Fatalf("rows/emitted/tail = %d/%d/%d, want 10/2/8",
			objInt(probe, "rows"), objInt(probe, "emitted"),
			objInt(probe, "tail"))
	}
	if objInt(probe, "dispositioned") != 2 {
		t.Fatalf("dispositioned = %d, want 2", objInt(probe, "dispositioned"))
	}
	if !objBool(probe, "closed") {
		t.Fatal("closed = false, want true")
	}
	want := "L-03 closed — 2/10 rows dispositioned, 8 in tail, 4 blind keys " +
		"disclosed"
	if got := validation.ObjStr(probe, "message"); got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

func TestProbesListShowsRowsAnchorsAndDispositions(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	row := t29Row(t, surface, "")
	prio := t29ProbePriority(t, c, validation.ObjStr(row, "row_id"))
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list")
	if code != 0 {
		t.Fatalf("list exit %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{validation.ObjStr(row, "row_id"), validation.ObjStr(prio, "id"),
		"Rollup.sol#L45", "enforcement-timing", "L-03",
		"(0 dispositioned, 10 open)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q: %q", want, out)
		}
	}
}

func TestProbesListJSONIsMachineReadableAndTracksStaleness(t *testing.T) {
	ws, c, idx, surface := t29Setup(t, t29Ranking, true)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list", "--json")
	if code != 0 {
		t.Fatalf("list --json exit %d: out=%q err=%q", code, out, errS)
	}
	doc := t29JSONDoc(t, out)
	if doc["rows"] != float64(10) || doc["open"] != float64(10) ||
		doc["dispositioned"] != float64(0) {
		t.Fatalf("rows/open/dispositioned = %v/%v/%v, want 10/10/0",
			doc["rows"], doc["open"], doc["dispositioned"])
	}
	if doc["stale"] != false {
		t.Fatalf("stale = %v, want false", doc["stale"])
	}
	if doc["index_sha"] != validation.ObjStr(surface, "index_sha") {
		t.Fatalf("index_sha = %v, want %q", doc["index_sha"],
			validation.ObjStr(surface, "index_sha"))
	}
	gotRows := map[string]bool{}
	for _, r := range doc["surface_rows"].([]any) {
		gotRows[r.(map[string]any)["row_id"].(string)] = true
	}
	wantRows := map[string]bool{}
	for _, r := range t29ObjList(surface, "rows") {
		wantRows[validation.ObjStr(r, "row_id")] = true
	}
	if len(gotRows) != len(wantRows) {
		t.Fatalf("surface_rows = %d ids, want %d", len(gotRows), len(wantRows))
	}
	for id := range wantRows {
		if !gotRows[id] {
			t.Errorf("surface_rows missing %q", id)
		}
	}
	// the index artifact moves: the stored surface is now stale
	t29BumpIndexLine(t, c, idx)
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list", "--json")
	if code != 0 {
		t.Fatalf("list --json exit %d: out=%q err=%q", code, out, errS)
	}
	if t29JSONDoc(t, out)["stale"] != true {
		t.Fatalf("stale = %v, want true", t29JSONDoc(t, out)["stale"])
	}
}

func TestProbesListAxisFilterAcceptsLensAndAxisName(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29Ranking, true)
	for _, selector := range []string{"L-03", "enforcement-timing"} {
		code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
			"--axis", selector)
		if code != 0 {
			t.Fatalf("--axis %s exit %d: out=%q err=%q", selector, code, out,
				errS)
		}
		if !strings.Contains(out, "enforcement-timing") {
			t.Errorf("--axis %s: %q", selector, out)
		}
		if strings.Contains(strings.Split(out, "\n")[0], "liveness") {
			t.Errorf("--axis %s leaks the first line: %q", selector, out)
		}
	}
	code, _, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--axis", "L-99")
	if code != 2 {
		t.Fatalf("--axis L-99 exit %d, want 2", code)
	}
	if !strings.Contains(errS, "L-99") {
		t.Fatalf("err = %q", errS)
	}
	if !strings.Contains(errS, "enforcement-timing") {
		t.Fatalf("the error names the valid axes: %q", errS)
	}
}

func TestProbesListAllShowsBlindKeysAndEmptyAxes(t *testing.T) {
	ws, _, _, surface := t29Setup(t, t29Blind, true)
	axis := t29AxisByProbe(t, surface, "assertion-strength")
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list", "--all")
	if code != 0 {
		t.Fatalf("list --all exit %d: out=%q err=%q", code, out, errS)
	}
	blind := t29ObjList(axis, "blind")
	if len(blind) == 0 {
		t.Fatalf("axis published no blind keys: %s",
			validation.DumpIndented(axis))
	}
	if !strings.Contains(out, validation.ObjStr(blind[0], "key")) {
		t.Errorf("list --all missing blind key %q: %q",
			validation.ObjStr(blind[0], "key"), out)
	}
	if !strings.Contains(out, "blind") {
		t.Errorf("list --all missing 'blind': %q", out)
	}
}

func TestProbesListWithoutASurfaceFailsLoudly(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	if _, err := state.Init(ws, "Probe CLI",
		state.InitOpts{CampaignID: t29CID}); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "webv2 probes "+t29CID+" run") {
		t.Fatalf("err = %q", errS)
	}
}

// ---- dispositions name the field they claim is safe -----------------------

func TestAnsweredOnAProbeRowRequiresAnAnchor(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	pid := validation.ObjStr(t29ProbePriority(t, c, ""), "id")
	code, _, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"not-applicable", "--reason", "the asserter is not authoritative for "+
			"this concept")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	for _, want := range []string{"--anchor", "consumer", "asserter", "concept"} {
		if !strings.Contains(errS, want) {
			t.Errorf("err missing %q: %q", want, errS)
		}
	}
}

func TestAnsweredRejectsAnAnchorTheProbeNeverProduced(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	pid := validation.ObjStr(t29ProbePriority(t, c, ""), "id")
	// `custody` belongs to custody-primitive, not to this assertion-strength row
	code, _, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"not-applicable", "--anchor", "custody",
		"--reason", "wrong probe's anchor enum")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "custody") {
		t.Fatalf("err = %q", errS)
	}
	code, _, _ = run(t, "--root", ws, "answered", t29CID, pid,
		"not-applicable", "--anchor", "nonsense",
		"--reason", "not an anchor at all")
	if code != 2 {
		t.Fatalf("nonsense anchor exit %d, want 2", code)
	}
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjStr(p, "id") == pid && validation.ObjStr(p, "status") != "open" {
			t.Fatalf("status = %q, want open", validation.ObjStr(p, "status"))
		}
	}
}

func TestAnsweredRecordsTheRowsRealAnchorValue(t *testing.T) {
	ws, c, idx, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	row := t29Row(t, surface, "")
	pid := validation.ObjStr(t29ProbePriority(t, c, validation.ObjStr(row, "row_id")), "id")
	code, out, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"not-applicable", "--anchor", "asserter",
		"--reason", "the asserter is not authoritative for batch:index here",
		// FIX-5: an asserter-anchored tier-0 closure prices the interim
		// window — the statement cites the row's own surface entry
		"--interim", "until finalizeBatch asserts batch:index, commitBatch "+
			"accepts a stale root")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	var p validation.Value
	for _, x := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjStr(x, "id") == pid {
			p = x
		}
	}
	if validation.ObjStr(p, "status") != "not-applicable" {
		t.Fatalf("status = %q", validation.ObjStr(p, "status"))
	}
	anchor := validation.ObjAt(validation.ObjAt(p, "probe"), "anchor")
	wantValue, err := probes.RowAnchorValue(row, "asserter")
	if err != nil {
		t.Fatal(err)
	}
	wantRef, err := probes.AnchorRef(row, "asserter", &idx)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(anchor, "field") != "asserter" {
		t.Fatalf("anchor.field = %q", validation.ObjStr(anchor, "field"))
	}
	if validation.CanonCompact(validation.ObjAt(anchor, "value")) !=
		validation.CanonCompact(wantValue) {
		t.Fatalf("anchor.value = %s, want %s",
			validation.CanonCompact(validation.ObjAt(anchor, "value")),
			validation.CanonCompact(wantValue))
	}
	if validation.ObjStr(anchor, "ref") != wantRef {
		t.Fatalf("anchor.ref = %q, want %q", validation.ObjStr(anchor, "ref"), wantRef)
	}
	if validation.ObjStr(p, "closed_ref") != wantRef {
		t.Fatalf("closed_ref = %q, want %q", validation.ObjStr(p, "closed_ref"), wantRef)
	}
	plan := t29PlanJSON(t, c)
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		t.Fatalf("plan invalid: %v", err)
	}
}

func TestAnsweredRejectsARefThatIsNotTheAnchorItClaims(t *testing.T) {
	ws, c, idx, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	row := t29Row(t, surface, "")
	pid := validation.ObjStr(t29ProbePriority(t, c, validation.ObjStr(row, "row_id")), "id")
	// a well-formed ref that is neither this anchor's citation nor a
	// refutation: the message must name the citation the anchor expects
	code, _, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"answered", "--anchor", "consumer",
		"--ref", "Rollup.sol#L99",
		"--reason", "cites something else entirely about commitBatch")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	wantRef, err := probes.AnchorRef(row, "consumer", &idx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errS, wantRef) {
		t.Fatalf("err = %q, want it to name %q", errS, wantRef)
	}
}

// TestAnsweredRejectsACitationThatDoesNotExist is v3's converse duty: a ref
// naming a record that was never written is refused as fabricated, and the
// message says which id failed to resolve (the anchor rule would answer the
// narrower "that is not the anchor it claims").
func TestAnsweredRejectsACitationThatDoesNotExist(t *testing.T) {
	ws, c, idx, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	row := t29Row(t, surface, "")
	pid := validation.ObjStr(t29ProbePriority(t, c, validation.ObjStr(row, "row_id")), "id")
	code, _, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"answered", "--anchor", "consumer", "--ref", "F-000000000000",
		"--reason", "cites something else entirely about commitBatch")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	for _, want := range []string{"F-000000000000", "which does not exist"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("err = %q, want it to name %q", errS, want)
		}
	}
	// a finding that DOES exist is still not the anchor it claims: the anchor
	// rule keeps its own, narrower refusal
	fid := validation.ObjStr(t15Finding(t, c, "a real finding", "logic-error"), "finding_id")
	code, _, errS = run(t, "--root", ws, "answered", t29CID, pid,
		"answered", "--anchor", "consumer", "--ref", fid,
		"--reason", "cites something else entirely about commitBatch")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	wantRef, err := probes.AnchorRef(row, "consumer", &idx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errS, "must be the anchor it claims") ||
		!strings.Contains(errS, wantRef) {
		t.Fatalf("err = %q, want the anchor refusal naming %q", errS, wantRef)
	}
}

func TestAnsweredRejectsAProbeRowTheSurfaceNoLongerCarries(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	pid := validation.ObjStr(t29ProbePriority(t, c, ""), "id")
	if err := os.Remove(t29SurfacePath(c)); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"not-applicable", "--anchor", "asserter",
		"--reason", "the asserter is not authoritative")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "surface") || !strings.Contains(errS, "--emit") {
		t.Fatalf("err = %q", errS)
	}
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjStr(p, "id") == pid && validation.ObjStr(p, "status") != "open" {
			t.Fatalf("status = %q, want open", validation.ObjStr(p, "status"))
		}
	}
}

func TestADirectLibraryClosureOfAProbeRowMustNameItsAnchor(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	pid := validation.ObjStr(t29ProbePriority(t, c, ""), "id")
	plan := t29PlanJSON(t, c)
	reason := "prose closure with no anchor at all"
	ref := "F-000000000001"
	_, err := planner.MarkAnswered(c, plan, pid, "answered",
		planner.AnsweredOpts{Reason: &reason, Ref: &ref, Actor: "ingest"})
	if err == nil {
		t.Fatal("MarkAnswered accepted an anchorless probe closure")
	}
	msg := err.Error()
	for _, want := range []string{"consumer", "asserter", "concept"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error missing %q: %q", want, msg)
		}
	}
	// the row is untouched: no status flip, no closure provenance
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjStr(p, "id") != pid {
			continue
		}
		if validation.ObjStr(p, "status") != "open" {
			t.Fatalf("status = %q, want open", validation.ObjStr(p, "status"))
		}
		if t29Has(p, "closed_ref") || t29Has(p, "closed_reason") {
			t.Fatalf("closure provenance stamped: %s",
				validation.DumpIndented(p))
		}
		if t29Has(validation.ObjAt(p, "probe"), "anchor") {
			t.Fatalf("probe.anchor stamped: %s", validation.DumpIndented(p))
		}
	}
}

func TestIngestCannotCloseAProbeRowWithoutAnAnchor(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	pid := validation.ObjStr(t29ProbePriority(t, c, ""), "id")
	payload, err := validation.ParseOrdered([]byte(`{"title":"A library ` +
		`caller closes a probe row","root_cause":{"class":"logic-error",` +
		`"description":"the closure is prose only, no anchor"},` +
		`"affected":[{"path":"Rollup.sol","contract":"Rollup",` +
		`"function":"finalizeBatch"}],"attacker":{"profile":"arbitrary EOA",` +
		`"capabilities":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = orchestrator.New(c).Ingest(payload,
		orchestrator.IngestOpts{AnswersPriority: pid})
	if err == nil {
		t.Fatal("Ingest closed a probe row with no anchor")
	}
	if !strings.Contains(err.Error(), "consumer") {
		t.Fatalf("err = %q", err.Error())
	}
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjStr(p, "id") == pid && validation.ObjStr(p, "status") != "open" {
			t.Fatalf("status = %q, want open", validation.ObjStr(p, "status"))
		}
	}
}

func TestAnsweredStillWorksForNonProbePriorities(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	pid := ""
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjAt(p, "probe").Kind != validation.Obj {
			pid = validation.ObjStr(p, "id")
			break
		}
	}
	if pid == "" {
		t.Fatal("no non-probe priority in the fixture plan")
	}
	code, out, errS := run(t, "--root", ws, "answered", t29CID, pid,
		"deprioritized", "--reason", "ranked below the real attack surface",
		"--ref", "Rollup.sol#L45")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	for _, p := range t29ObjList(t29PlanJSON(t, c), "priorities") {
		if validation.ObjStr(p, "id") != pid {
			continue
		}
		if validation.ObjStr(p, "status") != "deprioritized" ||
			validation.ObjStr(p, "closed_ref") != "Rollup.sol#L45" {
			t.Fatalf("status/closed_ref = %q/%q", validation.ObjStr(p, "status"),
				validation.ObjStr(p, "closed_ref"))
		}
	}
}

// ---- blank attestations ---------------------------------------------------

func TestBlankAttestationClosesABlindAxis(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Blind, true)
	axis := t29AxisByProbe(t, surface, "assertion-strength")
	if validation.ObjStr(axis, "status") != "blind" {
		t.Fatalf("axis status = %q, want blind", validation.ObjStr(axis, "status"))
	}
	blind := t29ObjList(axis, "blind")
	key := validation.ObjStr(blind[0], "key")
	plan := t29CloseEverything(t, c)
	div := t29Divergence(t, c, plan)
	if objBool(div, "closed") {
		t.Fatalf("closed = true, want false: %s", validation.DumpIndented(div))
	}
	found := false
	for _, m := range t29ObjList(div, "missing") {
		if validation.ObjStr(m, "subject") == "L-03" {
			found = true
			if !strings.Contains(validation.ObjStr(m, "what"), "webv2 probes blank") {
				t.Errorf("missing.what = %q", validation.ObjStr(m, "what"))
			}
		}
		if validation.ObjStr(m, "subject") == "L-01" {
			t.Errorf("unexpected L-01 missing entry: %s",
				validation.DumpIndented(m))
		}
	}
	if !found {
		t.Fatalf("no missing entry for L-03: %s", validation.DumpIndented(div))
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", key,
		"--reason", "every published near key was audited by hand",
		"--actor", "pytest")
	if code != 0 {
		t.Fatalf("blank exit %d: out=%q err=%q", code, out, errS)
	}
	saved := t29StateBlanks(t, c)
	if len(saved) != 1 {
		t.Fatalf("probe_blanks = %s", validation.DumpIndented(validation.VArr(saved...)))
	}
	if validation.ObjStr(saved[0], "axis") != "L-03" ||
		validation.ObjStr(saved[0], "anchor_blind") != key {
		t.Fatalf("saved = %s", validation.DumpIndented(saved[0]))
	}
	if validation.ObjStr(saved[0], "actor") != "pytest" || validation.ObjStr(saved[0], "at") == "" {
		t.Fatalf("actor/at = %q/%q", validation.ObjStr(saved[0], "actor"),
			validation.ObjStr(saved[0], "at"))
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, e := range events {
		if validation.ObjStr(e, "type") == "probes.blank" && validation.ObjStr(e, "ref") == "L-03" {
			seen = true
		}
	}
	if !seen {
		t.Error("no probes.blank event with ref L-03")
	}
	// the persisted attestation is what divergence_status_for reads
	blanks, err := probes.CampaignBlanks(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(blanks) != 1 {
		t.Fatalf("campaign_blanks = %v", blanks)
	}
	if got := validation.CanonCompact(blanks["enforcement-timing"]); got !=
		validation.CanonCompact(saved[0]) {
		t.Fatalf("campaign_blanks = %s, want %s", got,
			validation.CanonCompact(saved[0]))
	}
	div = t29Divergence(t, c, plan)
	if !objBool(div, "closed") {
		t.Fatalf("closed = false: %s", validation.DumpIndented(div))
	}
}

func TestBlankAttestationRequiresABlindAxis(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	axis := t29AxisByAxis(t, surface, "enforcement-timing")
	if validation.ObjStr(axis, "status") != "emitted" || objInt(axis, "rows") <= 0 {
		t.Fatalf("axis = %s", validation.DumpIndented(axis))
	}
	key := validation.ObjStr(t29ObjList(axis, "blind")[0], "key")
	code, _, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", key,
		"--reason", "a written reason of legal length",
		"--actor", "pytest")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "blind") || !strings.Contains(errS, "emitted") {
		t.Fatalf("err = %q", errS)
	}
	if got := t29StateBlanks(t, c); len(got) != 0 {
		t.Fatalf("probe_blanks = %s", validation.DumpIndented(validation.VArr(got...)))
	}
	_, err := probes.SetBlank(c, "L-03", key,
		"a written reason of legal length", "pytest")
	if err == nil || !strings.Contains(err.Error(), "blind") {
		t.Fatalf("SetBlank err = %v", err)
	}
	if got := t29StateBlanks(t, c); len(got) != 0 {
		t.Fatalf("probe_blanks = %s", validation.DumpIndented(validation.VArr(got...)))
	}
}

func TestBlankRejectsAKeyTheProbeNeverPublished(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Blind, true)
	axis := t29AxisByProbe(t, surface, "assertion-strength")
	code, _, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", "not-a-blind-key",
		"--reason", "cites a key nobody published", "--actor", "pytest")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "not-a-blind-key") {
		t.Fatalf("err = %q", errS)
	}
	if !strings.Contains(errS, validation.ObjStr(t29ObjList(axis, "blind")[0], "key")) {
		t.Fatalf("the error lists the real keys: %q", errS)
	}
	if got := t29StateBlanks(t, c); len(got) != 0 {
		t.Fatalf("probe_blanks = %s", validation.DumpIndented(validation.VArr(got...)))
	}
}

func TestBlankRequiresAWrittenReasonAndAnActor(t *testing.T) {
	ws, _, _, surface := t29Setup(t, t29Blind, true)
	axis := t29AxisByProbe(t, surface, "assertion-strength")
	key := validation.ObjStr(t29ObjList(axis, "blind")[0], "key")
	code, _, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", key,
		"--reason", "short", "--actor", "pytest")
	if code != 2 || !strings.Contains(errS, "reason") {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	code, _, errS = run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", key,
		"--reason", "a written reason of legal length")
	if code != 2 || !strings.Contains(errS, "actor") {
		t.Fatalf("exit %d err=%q", code, errS)
	}
}

func TestBlankRejectsAnUnregisteredAxisAndAMissingSurface(t *testing.T) {
	ws, _, _, surface := t29Setup(t, t29Blind, true)
	key := validation.ObjStr(t29ObjList(t29AxisByProbe(t, surface, "assertion-strength"),
		"blind")[0], "key")
	code, _, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-99", "--anchor-blind", key,
		"--reason", "no such axis at all", "--actor", "pytest")
	if code != 2 || !strings.Contains(errS, "L-99") {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	bare := t.TempDir()
	if _, err := state.Init(bare, "Probe CLI",
		state.InitOpts{CampaignID: t29CID}); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "--root", bare, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", key,
		"--reason", "there is no surface here", "--actor", "pytest")
	if code != 2 || !strings.Contains(errS, "webv2 probes "+t29CID+" run") {
		t.Fatalf("exit %d err=%q", code, errS)
	}
}

// ---- audit ----------------------------------------------------------------

func TestAuditDetectsProbeRowDriftInBothDirections(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	sec := t29AuditSection(t, c)
	if !objBool(sec, "ok") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
	// (a) a plan row the current surface does not carry
	plan := t29PlanJSON(t, c)
	ghost := t29DeepCopy(t29ProbePriority(t, c, ""))
	t29Set(&ghost, "id", validation.VStr("Q-900"))
	prov := validation.ObjAt(ghost, "probe")
	t29Set(&prov, "row_id", validation.VStr("deadbeef00"))
	t29Set(&ghost, "probe", prov)
	prios := t29List(plan, "priorities")
	prios = append(prios, ghost)
	t29Set(&plan, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	sec = t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true after a ghost plan row")
	}
	if !t29HasProblem(sec, "deadbeef00") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
	// (b) a surface row that was never emitted as a priority
	dropped := validation.ObjStr(t29Row(t, surface, ""), "row_id")
	plan = t29PlanJSON(t, c)
	kept := []validation.Value{}
	for _, p := range t29ObjList(plan, "priorities") {
		if validation.ObjStr(validation.ObjAt(p, "probe"), "row_id") == dropped {
			continue
		}
		kept = append(kept, p)
	}
	t29Set(&plan, "priorities", validation.VArr(kept...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	sec = t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true after a dropped surface row")
	}
	if !t29HasProblem(sec, dropped) {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
}

func TestAuditReDerivesRowsAndCatchesAHandEditedAnchor(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	sec := t29AuditSection(t, c)
	if !objBool(sec, "ok") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
	if objInt(sec, "rederived_rows") != 10 ||
		len(t29ObjList(surface, "rows")) != 10 {
		t.Fatalf("rederived_rows = %d, rows = %d", objInt(sec, "rederived_rows"),
			len(t29ObjList(surface, "rows")))
	}
	stored, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	rows := t29List(stored, "rows")
	edited := rows[0]
	if validation.ObjStr(edited, "row_id") != validation.ObjStr(t29Row(t, surface, ""), "row_id") {
		t.Fatalf("edited row_id = %q", validation.ObjStr(edited, "row_id"))
	}
	t29Set(&edited, "consumer_line", validation.VInt(99999))
	rows[0] = edited
	t29Set(&stored, "rows", validation.VArr(rows...))
	t29WriteSurface(t, c, stored)
	sec = t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true after a hand-edited anchor")
	}
	found := false
	for _, p := range t29Problems(sec) {
		if strings.Contains(p, "does not re-derive") &&
			strings.Contains(p, validation.ObjStr(edited, "row_id")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
	// the disposition stamp is re-derived too: a priority closed against a
	// shape the tree no longer produces is not a disposition
	t29WriteSurface(t, c, surface)
	plan := t29PlanJSON(t, c)
	prios := t29List(plan, "priorities")
	victim := validation.VNull()
	for i, p := range prios {
		if validation.ObjAt(p, "probe").Kind == validation.Obj {
			victim = p
			prov := validation.ObjAt(p, "probe")
			t29Set(&prov, "shape_sha", validation.VStr(strings.Repeat("0", 16)))
			t29Set(&p, "probe", prov)
			prios[i] = p
			break
		}
	}
	if victim.Kind != validation.Obj {
		t.Fatal("no probe priority")
	}
	t29Set(&plan, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	sec = t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true after a stale shape stamp")
	}
	found = false
	for _, p := range t29Problems(sec) {
		if strings.Contains(p, "dispositioned probe row") &&
			strings.Contains(p, validation.ObjStr(victim, "id")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
}

func TestAuditFlagsSurfaceRowsThatWereNeverEmitted(t *testing.T) {
	// surface written, no --emit
	_, c, _, _ := t29Setup(t, t29Ranking, true)
	if got := t29ProbePriorities(t, c); len(got) != 0 {
		t.Fatalf("probe priorities = %d, want 0", len(got))
	}
	sec := t29AuditSection(t, c)
	if objInt(sec, "checked") != 10 {
		t.Fatalf("checked = %d, want 10: %s", objInt(sec, "checked"),
			validation.DumpIndented(sec))
	}
	if objBool(sec, "ok") {
		t.Fatal("ok = true, want false")
	}
	if !t29HasProblem(sec, "webv2 probes "+t29CID+" run --emit") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
}

func TestAuditFlagsABlankAttestationForAnAxisThatIsNotBlind(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	axis := t29AxisByAxis(t, surface, "enforcement-timing")
	key := validation.ObjStr(t29ObjList(axis, "blind")[0], "key")
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	t29Set(&st, "probe_blanks", validation.VArr(validation.VObj(
		validation.KV{K: "axis", V: validation.VStr("L-03")},
		validation.KV{K: "anchor_blind", V: validation.VStr(key)},
		validation.KV{K: "reason", V: validation.VStr("attested against a non-blind axis")},
		validation.KV{K: "actor", V: validation.VStr("pytest")},
		validation.KV{K: "at", V: validation.VStr("2026-01-01T00:00:00+00:00")},
	)))
	t29SaveState(t, c, st)
	ref := "L-03"
	data := validation.VObj(
		validation.KV{K: "axis", V: validation.VStr("enforcement-timing")},
		validation.KV{K: "probe", V: validation.VStr("assertion-strength")},
		validation.KV{K: "anchor_blind", V: validation.VStr(key)},
		validation.KV{K: "actor", V: validation.VStr("pytest")},
		validation.KV{K: "reason", V: validation.VStr("attested against a non-blind axis")},
		validation.KV{K: "replaced", V: validation.VBool(false)},
	)
	if _, err := c.Log("probes.blank", &ref, &data); err != nil {
		t.Fatal(err)
	}
	sec := t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true, want false")
	}
	if !t29HasProblem(sec, "not blind") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
}

func TestAuditDetectsAStaleSurfaceAndAHandEditedAttestation(t *testing.T) {
	ws, c, idx, surface := t29Setup(t, t29Blind, true)
	axis := t29AxisByProbe(t, surface, "assertion-strength")
	key := validation.ObjStr(t29ObjList(axis, "blind")[0], "key")
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-03", "--anchor-blind", key,
		"--reason", "every near key was audited", "--actor", "pytest")
	if code != 0 {
		t.Fatalf("blank exit %d: out=%q err=%q", code, out, errS)
	}
	sec := t29AuditSection(t, c)
	if !objBool(sec, "ok") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	blanks := t29ObjList(st, "probe_blanks")
	b0 := blanks[0]
	t29Set(&b0, "anchor_blind", validation.VStr("hand-edited-key"))
	blanks[0] = b0
	t29Set(&st, "probe_blanks", validation.VArr(blanks...))
	t29SaveState(t, c, st)
	sec = t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true after a hand-edited attestation")
	}
	if !t29HasProblem(sec, "hand-edited-key") &&
		!t29HasProblem(sec, "probes.blank") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
	st, err = c.State()
	if err != nil {
		t.Fatal(err)
	}
	blanks = t29ObjList(st, "probe_blanks")
	b0 = blanks[0]
	t29Set(&b0, "anchor_blind", validation.VStr(key))
	blanks[0] = b0
	t29Set(&st, "probe_blanks", validation.VArr(blanks...))
	t29SaveState(t, c, st)
	t29BumpIndexLine(t, c, idx)
	sec = t29AuditSection(t, c)
	if objBool(sec, "ok") {
		t.Fatal("ok = true after the index moved")
	}
	if !t29HasProblem(sec, "stale") {
		t.Fatalf("problems = %v", t29Problems(sec))
	}
}

// t29GhostPriority appends a plan priority citing a probe row the surface does
// not carry (the plan-priority-orphan condition).
func t29GhostPriority(t *testing.T, c *state.Campaign) {
	t.Helper()
	plan := t29PlanJSON(t, c)
	ghost := t29DeepCopy(t29ProbePriority(t, c, ""))
	t29Set(&ghost, "id", validation.VStr("Q-900"))
	prov := validation.ObjAt(ghost, "probe")
	t29Set(&prov, "row_id", validation.VStr("deadbeef00"))
	t29Set(&ghost, "probe", prov)
	prios := t29List(plan, "priorities")
	prios = append(prios, ghost)
	t29Set(&plan, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
}

// TestAuditHintNamesTheRecordedQuotasWhenTheSurfaceDrifts pins the repair
// information: a drifted surface that records 30/70 prints the quotas a bare
// re-run adopts, and no problem carries the <campaign> placeholder.
func TestAuditHintNamesTheRecordedQuotasWhenTheSurfaceDrifts(t *testing.T) {
	ws, c, idx, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	stored, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	t29Set(&stored, "per_axis", validation.VInt(30))
	t29Set(&stored, "total", validation.VInt(70))
	t29WriteSurface(t, c, stored)
	t29BumpIndexLine(t, c, idx)
	got := t29Problems(t29AuditSection(t, c))
	if len(got) != 1 {
		t.Fatalf("problems = %d, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "--per-axis 30 --total 70") {
		t.Errorf("hint does not name the recorded quotas: %q", got[0])
	}
	if !strings.Contains(got[0], "rebuilds with the surface's recorded") {
		t.Errorf("hint does not say what the numbers are for: %q", got[0])
	}
	if !strings.Contains(got[0], t29CID) {
		t.Errorf("hint does not name the campaign id: %q", got[0])
	}
	for _, p := range got {
		if strings.Contains(p, "<campaign>") {
			t.Errorf("problem carries the literal placeholder: %q", p)
		}
	}
}

// TestAuditHintStaysPlainWithoutRecordedQuotas pins the other half: an
// artifact recording neither knob keeps the plain hint and grows no clause.
func TestAuditHintStaysPlainWithoutRecordedQuotas(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	stored, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	t29Del(&stored, "per_axis")
	t29Del(&stored, "total")
	// raw write: the probe_surface schema requires both knobs, but an artifact
	// from an older build may record neither, which is the case under test.
	if err := os.WriteFile(t29SurfacePath(c),
		[]byte(validation.DumpIndented(stored)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t29GhostPriority(t, c)
	got := t29Problems(t29AuditSection(t, c))
	if len(got) != 1 {
		t.Fatalf("problems = %d, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "`webv2 probes "+t29CID+" run --emit`") {
		t.Errorf("hint is not the plain, copy-pasteable command: %q", got[0])
	}
	if strings.Contains(got[0], "rebuilds with") {
		t.Errorf("hint grew a quota clause from an artifact with none: %q",
			got[0])
	}
}

// TestAuditHintOmitsARecordedKnobTheCLIWouldRefuse pins the audit hint against
// the run's own validation: a surface recording a knob below 1 must not be
// quoted in a repair command the CLI exits 2 on.
func TestAuditHintOmitsARecordedKnobTheCLIWouldRefuse(t *testing.T) {
	cases := []struct {
		name       string
		perAxis    int
		total      int
		wantQuoted string
		wantGone   string
	}{
		{"the invalid per-axis is left out", 0, 70,
			"recorded --total 70", "--per-axis"},
		{"neither knob is usable drops the clause", 0, 0,
			"", "rebuilds with"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws, c, idx, _ := t29Setup(t, t29Ranking, true)
			t29Emit(t, ws)
			stored, err := validation.ReadJson(t29SurfacePath(c))
			if err != nil {
				t.Fatal(err)
			}
			t29Set(&stored, "per_axis", validation.VInt(int64(tc.perAxis)))
			t29Set(&stored, "total", validation.VInt(int64(tc.total)))
			// raw write: the probe_surface schema requires knobs >= 1, but an
			// artifact from a broken build is exactly the case under audit.
			if err := os.WriteFile(t29SurfacePath(c),
				[]byte(validation.DumpIndented(stored)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			t29BumpIndexLine(t, c, idx)
			got := t29Problems(t29AuditSection(t, c))
			if len(got) != 1 {
				t.Fatalf("problems = %d, want 1: %v", len(got), got)
			}
			if tc.wantQuoted != "" && !strings.Contains(got[0], tc.wantQuoted) {
				t.Errorf("hint does not quote the usable knob: %q", got[0])
			}
			if strings.Contains(got[0], tc.wantGone) {
				t.Errorf("hint quotes %q, which the CLI refuses: %q",
					tc.wantGone, got[0])
			}
		})
	}
}

// TestAuditPlanOrphanHintNamesTheCampaignID pins the placeholder fix on the
// one hint that never used the real campaign id.
func TestAuditPlanOrphanHintNamesTheCampaignID(t *testing.T) {
	ws, c, _, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	t29GhostPriority(t, c)
	got := t29Problems(t29AuditSection(t, c))
	if len(got) != 1 {
		t.Fatalf("problems = %d, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "`webv2 probes "+t29CID+" run --emit`") {
		t.Errorf("orphan hint does not name the campaign id: %q", got[0])
	}
	if strings.Contains(got[0], "<campaign>") {
		t.Errorf("orphan hint still carries the placeholder: %q", got[0])
	}
	if !strings.Contains(got[0], "rebuilds with the surface's recorded") {
		t.Errorf("orphan hint does not name the recorded quotas: %q", got[0])
	}
}

// TestAuditProblemListIsPinnedForADriftedSurface pins the whole list (count,
// order and text) so a hint edit cannot silently move the problem set.
func TestAuditProblemListIsPinnedForADriftedSurface(t *testing.T) {
	ws, c, idx, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	stored, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	t29Set(&stored, "per_axis", validation.VInt(30))
	t29Set(&stored, "total", validation.VInt(70))
	t29WriteSurface(t, c, stored)
	t29GhostPriority(t, c)
	t29BumpIndexLine(t, c, idx)
	current := probes.CampaignIndexSha(c)
	if current == nil {
		t.Fatal("no current index sha")
	}
	quota := "(rebuilds with the surface's recorded --per-axis 30 --total 70)"
	want := []string{
		fmt.Sprintf("probe surface is stale: built against index_sha %s, "+
			"current index is %s — every row anchor describes the old tree; "+
			"re-run `webv2 probes %s run --emit` %s",
			validation.ObjStr(stored, "index_sha"), *current, t29CID, quota),
		fmt.Sprintf("plan priority Q-900 cites probe row 'deadbeef00', which "+
			"the current surface does not carry — the surface was rebuilt "+
			"without it; re-run `webv2 probes %s run --emit` %s", t29CID,
			quota),
	}
	got := t29Problems(t29AuditSection(t, c))
	if len(got) != len(want) {
		t.Fatalf("problems = %d, want %d:\n%s", len(got), len(want),
			strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("problem[%d]:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// TestAuditProblemListIsPinnedForAHandEditedAttestation pins a hint-free
// fixture exactly: this task must not move a problem it does not touch.
func TestAuditProblemListIsPinnedForAHandEditedAttestation(t *testing.T) {
	_, c, _, _ := t29Setup(t, t29Blind, true)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	t29Set(&st, "probe_blanks", validation.VArr(validation.VObj(
		validation.KV{K: "axis", V: validation.VStr("L-03")},
		validation.KV{K: "probe_axis", V: validation.VStr("assertion-strength")},
		validation.KV{K: "anchor_blind", V: validation.VStr("ghost-key")},
		validation.KV{K: "reason", V: validation.VStr("a written reason")},
		validation.KV{K: "actor", V: validation.VStr("pytest")},
		validation.KV{K: "at", V: validation.VStr("2026-01-01T00:00:00+00:00")},
	)))
	t29SaveState(t, c, st)
	want := []string{"blank attestation for 'L-03' cites 'ghost-key' with " +
		"no probes.blank event — the attestation was hand-edited"}
	got := t29Problems(t29AuditSection(t, c))
	if len(got) != len(want) {
		t.Fatalf("problems = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("problem[%d]:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// t29BlankForAnAxisTheSurfaceLacks persists a blank attestation citing a probe
// axis (ghost-axis) and its matching probes.blank event, on a surface that
// carries no such axis — the "surface carries no such axis" condition.
func t29BlankForAnAxisTheSurfaceLacks(t *testing.T, c *state.Campaign) {
	t.Helper()
	const key = "ghost-key"
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	t29Set(&st, "probe_blanks", validation.VArr(validation.VObj(
		validation.KV{K: "axis", V: validation.VStr("L-03")},
		validation.KV{K: "probe_axis", V: validation.VStr("ghost-axis")},
		validation.KV{K: "anchor_blind", V: validation.VStr(key)},
		validation.KV{K: "reason", V: validation.VStr("a written reason")},
		validation.KV{K: "actor", V: validation.VStr("pytest")},
		validation.KV{K: "at", V: validation.VStr("2026-01-01T00:00:00+00:00")},
	)))
	t29SaveState(t, c, st)
	ref := "L-03"
	data := validation.VObj(
		validation.KV{K: "axis", V: validation.VStr("assertion-strength")},
		validation.KV{K: "probe_axis", V: validation.VStr("ghost-axis")},
		validation.KV{K: "anchor_blind", V: validation.VStr(key)},
		validation.KV{K: "actor", V: validation.VStr("pytest")},
		validation.KV{K: "reason", V: validation.VStr("a written reason")},
		validation.KV{K: "replaced", V: validation.VBool(false)},
	)
	if _, err := c.Log("probes.blank", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// t29NoSuchAxisProblem returns the one "surface carries no such axis" problem.
func t29NoSuchAxisProblem(t *testing.T, c *state.Campaign) string {
	t.Helper()
	for _, p := range t29Problems(t29AuditSection(t, c)) {
		if strings.Contains(p, "the surface carries no such axis") {
			return p
		}
	}
	t.Fatalf("no \"carries no such axis\" problem: %v",
		t29Problems(t29AuditSection(t, c)))
	return ""
}

// TestAuditNoSuchAxisHintNamesTheRecordedQuotas covers the sixth repair hint:
// the condition co-occurs with a recorded-quota artifact, and a bare run
// adopts those quotas, so this hint carries the same note as the --emit sites.
func TestAuditNoSuchAxisHintNamesTheRecordedQuotas(t *testing.T) {
	_, c, _, _ := t29Setup(t, t29Blind, true)
	stored, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	t29Set(&stored, "per_axis", validation.VInt(30))
	t29Set(&stored, "total", validation.VInt(70))
	t29WriteSurface(t, c, stored)
	t29BlankForAnAxisTheSurfaceLacks(t, c)
	got := t29NoSuchAxisProblem(t, c)
	if !strings.Contains(got, "`webv2 probes "+t29CID+" run`") {
		t.Errorf("hint is not the bare repair command: %q", got)
	}
	if !strings.Contains(got, "--per-axis 30 --total 70") {
		t.Errorf("hint does not name the recorded quotas: %q", got)
	}
	if !strings.Contains(got, "rebuilds with the surface's recorded") {
		t.Errorf("hint does not say what the numbers are for: %q", got)
	}
}

// TestAuditNoSuchAxisHintStaysPlainWithoutRecordedQuotas is the other half: an
// artifact recording neither knob renders the plain form, with no new clause.
func TestAuditNoSuchAxisHintStaysPlainWithoutRecordedQuotas(t *testing.T) {
	_, c, _, _ := t29Setup(t, t29Blind, true)
	stored, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	t29Del(&stored, "per_axis")
	t29Del(&stored, "total")
	// raw write: the probe_surface schema requires both knobs, but an artifact
	// from an older build may record neither, which is the case under test.
	if err := os.WriteFile(t29SurfacePath(c),
		[]byte(validation.DumpIndented(stored)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t29BlankForAnAxisTheSurfaceLacks(t, c)
	got := t29NoSuchAxisProblem(t, c)
	if !strings.Contains(got, "`webv2 probes "+t29CID+" run`") {
		t.Errorf("hint is not the plain, copy-pasteable command: %q", got)
	}
	if strings.Contains(got, "rebuilds with") {
		t.Errorf("hint grew a quota clause from an artifact with none: %q", got)
	}
}

// ---- A6: the anchor help, and a lens that carries several probes -----------

func TestAnchorHelpIsDerivedFromTheRegistry(t *testing.T) {
	code, out, _ := run(t, "answered", "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	flat := strings.Join(strings.Fields(out), " ")
	parts := strings.SplitN(flat, "(anchors:", 2)
	if len(parts) != 2 {
		t.Fatalf("help has no (anchors: ...): %q", flat)
	}
	enum := strings.SplitN(parts[1], ")", 2)[0]
	got := []string{}
	for _, a := range strings.Split(enum, ",") {
		got = append(got, strings.TrimSpace(a))
	}
	want := probes.AnchorEnum()
	if len(got) != len(want) {
		t.Fatalf("anchor enum = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("anchor enum = %v, want %v", got, want)
		}
	}
	if !strings.Contains(enum, "base") {
		t.Fatal("the anchor the A4 review found missing is absent")
	}
}

func TestProbesListAxisFilterByLensShowsEveryProbeOnIt(t *testing.T) {
	ws, _, _, _ := t29Setup(t, t29L01Tree(t), true)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "list",
		"--axis", "L-01", "--all")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{"accumulator-skew", "liveness",
		"guard-short-circuit"} {
		if !strings.Contains(out, want) {
			t.Errorf("list --axis L-01 missing %q: %q", want, out)
		}
	}
	if strings.Contains(out, "enforcement-timing") {
		t.Errorf("list --axis L-01 leaks enforcement-timing: %q", out)
	}
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "list",
		"--axis", "accumulator-skew")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "accumulator-skew") {
		t.Errorf("list --axis accumulator-skew: %q", out)
	}
	if strings.Contains(out, "liveness") {
		t.Errorf("list --axis accumulator-skew leaks liveness: %q", out)
	}
}

func TestBlankAxisHelpAdvertisesTheLensSpelling(t *testing.T) {
	code, out, errS := run(t, "probes", t29CID, "blank", "--help")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "L-0n") {
		t.Fatalf("help = %q", flat)
	}
	if !strings.Contains(flat, "resolved by the cited") {
		t.Fatalf("help = %q", flat)
	}
}

func TestBlankLensSpellingResolvesToTheAxisThatPublishedTheKey(t *testing.T) {
	ws, c, _, surface := t29SharedLens(t)
	acc := t29AxisByProbe(t, surface, "accumulator-basis-skew")
	guard := t29AxisByProbe(t, surface, "short-circuitable-guard")
	if validation.ObjStr(acc, "status") != "blind" || validation.ObjStr(guard, "status") != "blind" {
		t.Fatalf("acc/guard status = %q/%q", validation.ObjStr(acc, "status"),
			validation.ObjStr(guard, "status"))
	}
	accKey := validation.ObjStr(t29ObjList(acc, "blind")[0], "key")
	guardKey := validation.ObjStr(t29ObjList(guard, "blind")[0], "key")
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-01", "--anchor-blind", accKey,
		"--reason", "the companion write is elsewhere",
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("blank exit %d: out=%q err=%q", code, out, errS)
	}
	if got := t29BlankPairs(t, c); !t29SamePairs(got, [][2]string{
		{"L-01", "accumulator-skew"}}) {
		t.Fatalf("saved = %v", got)
	}
	// the probe-axis spelling keeps working (no resolution needed)
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "guard-short-circuit", "--anchor-blind", guardKey,
		"--reason", "the conjunction has no sentinel", "--actor", "operator")
	if code != 0 {
		t.Fatalf("blank exit %d: out=%q err=%q", code, out, errS)
	}
	if got := t29BlankPairs(t, c); !t29SamePairs(got, [][2]string{
		{"L-01", "accumulator-skew"}, {"L-01", "guard-short-circuit"}}) {
		t.Fatalf("saved = %v", got)
	}
	// no match: fail naming the real blind keys the lens's axes published
	code, _, errS = run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-01", "--anchor-blind", "not-a-blind-key",
		"--reason", "cites a key nobody published", "--actor", "operator")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, accKey) || !strings.Contains(errS, guardKey) {
		t.Fatalf("err = %q", errS)
	}
	if got := t29BlankPairs(t, c); len(got) != 2 {
		t.Fatalf("nothing may be recorded: %v", got)
	}
	// ambiguous: two axes on the lens publish the same key -> fail loudly
	clash := t29DeepCopy(surface)
	clashAxes := t29List(clash, "axes")
	for i, axis := range clashAxes {
		if validation.ObjStr(axis, "probe") != "short-circuitable-guard" {
			continue
		}
		blind := t29List(axis, "blind")
		b0 := blind[0]
		t29Set(&b0, "key", validation.VStr(accKey))
		blind[0] = b0
		t29Set(&axis, "blind", validation.VArr(blind...))
		clashAxes[i] = axis
	}
	t29Set(&clash, "axes", validation.VArr(clashAxes...))
	t29WriteSurface(t, c, clash)
	code, _, errS = run(t, "--root", ws, "probes", t29CID, "blank",
		"--axis", "L-01", "--anchor-blind", accKey,
		"--reason", "two axes publish this exact key", "--actor", "operator")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "accumulator-skew") ||
		!strings.Contains(errS, "guard-short-circuit") {
		t.Fatalf("err = %q", errS)
	}
	if got := t29BlankPairs(t, c); len(got) != 2 {
		t.Fatalf("nothing may be recorded: %v", got)
	}
}

// t29BlankPairs is [(e["axis"], e["probe_axis"]) for e in state["probe_blanks"]].
func t29BlankPairs(t *testing.T, c *state.Campaign) [][2]string {
	t.Helper()
	out := [][2]string{}
	for _, e := range t29StateBlanks(t, c) {
		out = append(out, [2]string{validation.ObjStr(e, "axis"), validation.ObjStr(e, "probe_axis")})
	}
	return out
}

// t29SamePairs compares two (axis, probe_axis) lists in order.
func t29SamePairs(got [][2]string, want [][2]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Wave J Task 8 / J-recovery: `probes --flag=value` parity
// ---------------------------------------------------------------------------

// TestProbesFlagEqualsFormIsTheSpaceForm pins the argparse `--flag=value`
// spelling on every probes value flag. `probes` is a scripting surface; the
// rest of the CLI already routes value flags through the shared splitFlag
// splitter, so an operator's script must not have to special-case this verb.
//
// The assertion is byte-equality against the space form, not "it parsed":
// the two spellings are the same command line, so stdout, stderr and the exit
// code must be identical byte for byte.
func TestProbesFlagEqualsFormIsTheSpaceForm(t *testing.T) {
	probes.Wire()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, t29Ranking, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := structidx.SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}

	// same(t, space, eq) runs both spellings and requires byte-identical
	// output on both streams and the same exit code.
	same := func(t *testing.T, wantCode int, space, eq []string) {
		t.Helper()
		sc, so, se := run(t, space...)
		ec, eo, ee := run(t, eq...)
		if sc != wantCode || ec != wantCode {
			t.Fatalf("exit: space %d / equals %d, want %d\nspace: %q%q\nequals: %q%q",
				sc, ec, wantCode, so, se, eo, ee)
		}
		if so != eo {
			t.Errorf("stdout differs\n space: %q\nequals: %q", so, eo)
		}
		if se != ee {
			t.Errorf("stderr differs\n space: %q\nequals: %q", se, ee)
		}
	}

	// run: both value flags.
	same(t, 0, []string{"--root", ws, "probes", t29CID, "run",
		"--per-axis", "2", "--total", "40"},
		[]string{"--root", ws, "probes", t29CID, "run",
			"--per-axis=2", "--total=40"})
	surface, err := probes.CampaignSurface(c)
	if err != nil || surface == nil {
		t.Fatalf("surface = %v, %v", surface, err)
	}
	if got := objInt(*surface, "per_axis"); got != 2 {
		t.Fatalf("per_axis = %d, want 2 — the = value was not consumed", got)
	}
	if got := objInt(*surface, "total"); got != 40 {
		t.Fatalf("total = %d, want 40", got)
	}

	// list: --axis, and the flag-only forms still work beside it.
	same(t, 0, []string{"--root", ws, "probes", t29CID, "list", "--axis", "L-01"},
		[]string{"--root", ws, "probes", t29CID, "list", "--axis=L-01"})
	same(t, 0, []string{"--root", ws, "probes", t29CID, "list", "--all", "--json"},
		[]string{"--root", ws, "probes", t29CID, "list", "--all", "--json"})

	// blank: a missing-arguments error must be identical through both
	// spellings (the = form reaches the same parser with the same value).
	same(t, 2, []string{"--root", ws, "probes", t29CID, "blank",
		"--axis", "L-01"},
		[]string{"--root", ws, "probes", t29CID, "blank", "--axis=L-01"})

	// A rejected value keeps its exact message through the = form.
	same(t, 2, []string{"--root", ws, "probes", t29CID, "run",
		"--per-axis", "0", "--total", "40"},
		[]string{"--root", ws, "probes", t29CID, "run",
			"--per-axis=0", "--total=40"})
	// ...and a non-integer is argparse's invalid-int error, not "unrecognized".
	same(t, 2, []string{"--root", ws, "probes", t29CID, "run",
		"--per-axis", "x", "--total", "40"},
		[]string{"--root", ws, "probes", t29CID, "run",
			"--per-axis=x", "--total=40"})
}
