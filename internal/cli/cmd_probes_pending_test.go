package cli

// cmd_probes_pending_test.go — B10(b): the drain view (`probes <c> pending`)
// and the probe-row batch route (`answered <c> --rows ROWID,ROWID …`).
//
// The fixture is the ranking surface (10 assertion-strength rows, all tier 0/1
// with assertion_gap 4) emitted into the plan as Q-005..Q-014. Two helpers
// shape it: t30Setup emits it, t30SetRowTierGap rewrites one row's
// tier/assertion_gap so the batch route has rows the anti-dismissal rule does
// not cover (the real surface has none).
import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// t30Setup is the B10(b) fixture: the ranking surface, emitted.
func t30Setup(t *testing.T) (string, *state.Campaign, validation.Value) {
	t.Helper()
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	return ws, c, surface
}

// t30Rows is the surface's rows in artifact order.
func t30Rows(t *testing.T, surface validation.Value) []validation.Value {
	t.Helper()
	rows := t29ObjList(surface, "rows")
	if len(rows) == 0 {
		t.Fatal("the fixture emitted no surface rows")
	}
	return rows
}

// t30RowID is rows[i]'s id.
func t30RowID(t *testing.T, rows []validation.Value, i int) string {
	t.Helper()
	return validation.ObjStr(rows[i], "row_id")
}

// t30SetRowTierGap rewrites one surface row's tier/assertion_gap in the
// artifact (raw write: this is a fixture edit, not a surface the probes built).
func t30SetRowTierGap(t *testing.T, c *state.Campaign, rowID string,
	tier, gap int64) {
	t.Helper()
	path := t29SurfacePath(c)
	surface, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := t29ObjList(surface, "rows")
	found := false
	for i, r := range rows {
		if validation.ObjStr(r, "row_id") != rowID {
			continue
		}
		t29Set(&r, "tier", validation.VInt(tier))
		t29Set(&r, "assertion_gap", validation.VInt(gap))
		rows[i] = r
		found = true
	}
	if !found {
		t.Fatalf("no surface row %s", rowID)
	}
	t29Set(&surface, "rows", validation.VArr(rows...))
	if err := validation.WriteJson(path, surface, ""); err != nil {
		t.Fatal(err)
	}
}

// t30PendingHeader is the console header the drain view prints for a
// non-empty worklist.
const t30PendingHeader = "probe surface: 10 rows, 10 pending (cap 20; " +
	"--max N or --json for the full list)\n"

// t30PendingLines is the pinned drain view of the ranking fixture: tier
// ascending, then assertion_gap descending, then convergence descending, then
// rank — the fixture's own order, because all ten rows share gap 4 and
// converge with nothing (no protocol model artifact, no priority naming
// Rollup).
const t30PendingLines = `81dfad6492 | tier 0 | gap 4 | enforcement-timing | assertion-strength | Rollup#commitBatch:45 | 0 converging stores -> webv2 answered C-probecli01 Q-005 answered --reason "<why this row is safe>" --anchor consumer
66c7d14d35 | tier 0 | gap 4 | enforcement-timing | assertion-strength | Rollup#dropMessage:49 | 0 converging stores -> webv2 answered C-probecli01 Q-006 answered --reason "<why this row is safe>" --anchor consumer
b6fe31cdf7 | tier 0 | gap 4 | enforcement-timing | assertion-strength | Rollup#getActiveStakers:61 | 0 converging stores -> webv2 answered C-probecli01 Q-007 answered --reason "<why this row is safe>" --anchor consumer
63904ecbc1 | tier 0 | gap 4 | enforcement-timing | assertion-strength | Rollup#proveState:53 | 0 converging stores -> webv2 answered C-probecli01 Q-008 answered --reason "<why this row is safe>" --anchor consumer
46ebc2a5a1 | tier 0 | gap 4 | enforcement-timing | assertion-strength | Rollup#replayMessage:57 | 0 converging stores -> webv2 answered C-probecli01 Q-009 answered --reason "<why this row is safe>" --anchor consumer
748abbf715 | tier 0 | gap 4 | enforcement-timing | assertion-strength | MockRollup#setLastFinalizedBatchIndex:15 | 0 converging stores -> webv2 answered C-probecli01 Q-010 answered --reason "<why this row is safe>" --anchor consumer
d549f9e66a | tier 1 | gap 4 | enforcement-timing | assertion-strength | Rollup#challengeState:73 | 0 converging stores -> webv2 answered C-probecli01 Q-011 answered --reason "<why this row is safe>" --anchor consumer
d6e1821dc6 | tier 1 | gap 4 | enforcement-timing | assertion-strength | Rollup#importGenesisBatch:79 | 0 converging stores -> webv2 answered C-probecli01 Q-012 answered --reason "<why this row is safe>" --anchor consumer
dd489a9a69 | tier 1 | gap 4 | enforcement-timing | assertion-strength | Rollup#revertBatch:83 | 0 converging stores -> webv2 answered C-probecli01 Q-013 answered --reason "<why this row is safe>" --anchor consumer
954d79770b | tier 1 | gap 4 | enforcement-timing | assertion-strength | Rollup#updateWithdrawLock:87 | 0 converging stores -> webv2 answered C-probecli01 Q-014 answered --reason "<why this row is safe>" --anchor consumer
`

// TestProbesPendingPinsTheRankedDrainLines pins the whole console view: the
// header, the rank order and the exact `answered` shape each row's own data
// implies (campaign, the emitted priority, the row's own anchor field).
func TestProbesPendingPinsTheRankedDrainLines(t *testing.T) {
	ws, _, _ := t30Setup(t)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t30PendingHeader+t30PendingLines {
		t.Fatalf("stdout = %q, want %q", out, t30PendingHeader+t30PendingLines)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestProbesPendingRanksGapDescending closes the mutation the round-2 review
// proved survives the suite: every fixture row shares gap 4, so flipping the
// middle rank key (cmd_probes_pending.go "a.gap > b.gap") kept everything
// green. Three SAME-tier rows get three distinct gaps (9/4/1); the view is
// read as an id permutation against the untouched byte pin — any rank-key
// change other than gap-descending changes the permutation, including a
// tie-break shift the naive pairwise index check would sleep through.
func TestProbesPendingRanksGapDescending(t *testing.T) {
	ws, c, _ := t30Setup(t)
	t30SetRowTierGap(t, c, "81dfad6492", 0, 1) // fixture FIRST row: sinks
	t30SetRowTierGap(t, c, "66c7d14d35", 0, 4) // mid tier-0 row
	t30SetRowTierGap(t, c, "b6fe31cdf7", 0, 9) // fixture third: rises to top
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	// gap 9 first; the four untouched gap-4 rows keep their relative rank
	// order; the demoted gap-1 row trails the whole tier-0 group.
	want := []string{"b6fe31cdf7", "66c7d14d35",
		"63904ecbc1", "46ebc2a5a1", "748abbf715", "81dfad6492",
		"d549f9e66a", "d6e1821dc6", "dd489a9a69", "954d79770b"}
	var got []string
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n")[1:] {
		if i := strings.Index(l, " | "); i > 0 {
			got = append(got, l[:i])
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("pending order = %v, want %v (gap-desc within tier)", got, want)
	}
}

// TestProbesPendingCapPointerAndMax pins the console cap: the default cap is
// 20, --max N selects N lines, and a truncated list points at --json.
func TestProbesPendingCapPointerAndMax(t *testing.T) {
	ws, _, _ := t30Setup(t)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending",
		"--max", "3")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "probe surface: 10 rows, 10 pending (cap 3; --max N or --json " +
		"for the full list)\n" +
		strings.Join(strings.Split(t30PendingLines, "\n")[:3], "\n") + "\n" +
		"  … +7 more pending rows — use --max N or --json for the full list\n"
	if out != want {
		t.Fatalf("--max 3 stdout = %q, want %q", out, want)
	}
	// A cap above the list prints every line and no pointer (the header
	// reports the effective cap).
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "pending",
		"--max", "40")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want = "probe surface: 10 rows, 10 pending (cap 40; --max N or --json " +
		"for the full list)\n" + t30PendingLines
	if out != want {
		t.Fatalf("--max 40 stdout = %q", out)
	}
	// argparse's other spelling (CLI-wide: `--flag=V` == `--flag V`).
	code, out, errS = run(t, "--root", ws, "probes", t29CID, "pending",
		"--max=2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "probe surface: 10 rows, 10 pending (cap 2; ") ||
		!strings.Contains(out, "+8 more pending rows") {
		t.Fatalf("--max=2 stdout = %q", out)
	}
}

// TestProbesPendingAllDispositionedIsOneLine pins the empty worklist: the
// drain is done, and the view says so in one line (the ABSENT case of the
// whole row table).
func TestProbesPendingAllDispositionedIsOneLine(t *testing.T) {
	ws, c, surface := t30Setup(t)
	for _, row := range t30Rows(t, surface) {
		rid := validation.ObjStr(row, "row_id")
		pid := t30PriorityFor(t, c, rid)
		reason := validation.ObjStr(row, "consumer") + " enforces the check itself"
		code, _, errS := run(t, "--root", ws, "answered", t29CID, pid,
			"answered", "--reason", reason, "--anchor", "consumer",
			"--interim", cliInterimFor(row),
			"--actor", "op")
		if code != 0 {
			t.Fatalf("draining %s (%s) exit %d: %q", rid, pid, code, errS)
		}
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "probe surface: 10 rows, 0 pending — all dispositioned\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// t30PriorityFor is the priority the plan emitted for a surface row (read
// through the same seam the pending view uses).
func t30PriorityFor(t *testing.T, c *state.Campaign, rowID string) string {
	t.Helper()
	surface, err := validation.ReadJson(t29SurfacePath(c))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	disp := probes.RowDispositions(&plan, surface)
	pid := validation.ObjStr(validation.ObjAt(disp, rowID), "priority_id")
	if pid == "" {
		t.Fatalf("row %s was never emitted", rowID)
	}
	return pid
}

// t30JSONPending is the parsed `pending --json` document.
func t30JSONPending(t *testing.T, ws string) map[string]any {
	t.Helper()
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending",
		"--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	return t29JSONDoc(t, out)
}

// t30JSONRows is doc["pending_rows"].
func t30JSONRows(t *testing.T, doc map[string]any) []map[string]any {
	t.Helper()
	raw, ok := doc["pending_rows"].([]any)
	if !ok {
		t.Fatalf("pending_rows is %T", doc["pending_rows"])
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("pending_rows entry is %T", r)
		}
		out = append(out, m)
	}
	return out
}

// TestProbesPendingJSONIsFullAndUncapped pins the machine view: --max does not
// cap it, and every row carries its own anchor, citation and command.
func TestProbesPendingJSONIsFullAndUncapped(t *testing.T) {
	ws, _, _ := t30Setup(t)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending",
		"--json", "--max", "2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	doc := t29JSONDoc(t, out)
	if got := int(doc["pending"].(float64)); got != 10 {
		t.Fatalf("pending = %d, want 10", got)
	}
	if got := int(doc["cap"].(float64)); got != 2 {
		t.Fatalf("cap = %d, want 2", got)
	}
	rows := t30JSONRows(t, doc)
	if len(rows) != 10 {
		t.Fatalf("pending_rows = %d, want 10 (--json is never capped)",
			len(rows))
	}
	first := rows[0]
	for k, want := range map[string]any{
		"row_id":            "81dfad6492",
		"probe":             "assertion-strength",
		"axis":              "enforcement-timing",
		"tier":              float64(0),
		"assertion_gap":     float64(4),
		"cite":              "Rollup#commitBatch:45",
		"anchor":            "consumer",
		"anchor_ref":        "Rollup.sol#L45",
		"priority_id":       "Q-005",
		"status":            "open",
		"stale":             false,
		"converging_stores": float64(0),
		"command": "webv2 answered C-probecli01 Q-005 answered --reason " +
			"\"<why this row is safe>\" --anchor consumer",
	} {
		if got := first[k]; got != want {
			t.Errorf("pending_rows[0][%s] = %#v, want %#v", k, got, want)
		}
	}
	if !strings.Contains(first["why"].(string), "commitBatch#45") {
		t.Errorf("why = %q, want the row's own why text",
			first["why"])
	}
}

// TestProbesPendingConvergenceCountsEveryStore pins the B7 half: the join is
// internal/anchorlink's, and a row's count is the union of the stores that
// name its anchors — plan only is 2, plan + a filed finding is 3.
func TestProbesPendingConvergenceCountsEveryStore(t *testing.T) {
	ws, c, _ := t30Setup(t)
	t30WriteModel(t, c)
	t30AddPlanPriority(t, c, "Q-900", "Rollup")
	doc := t30JSONPending(t, ws)
	first := t30JSONRows(t, doc)[0]
	if got := first["converging_stores"]; got != float64(2) {
		t.Fatalf("converging_stores = %#v, want 2 (surface + plan)", got)
	}
	if names := first["converging_names"].([]any); len(names) != 2 ||
		names[0] != "plan" || names[1] != "surface" {
		t.Fatalf("converging_names = %#v, want [plan surface]", names)
	}
	// The stronger lead sorts first: same tier and gap, higher convergence.
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	lines := strings.Split(out, "\n")
	if !strings.Contains(lines[1], "| 2 converging stores -> ") {
		t.Fatalf("first row is not the converging one: %q", lines[1])
	}
	// A filed finding that pins the same path is the third store.
	t30WriteFinding(t, c, "F-000000000001", "Rollup.sol")
	doc = t30JSONPending(t, ws)
	first = t30JSONRows(t, doc)[0]
	if got := first["converging_stores"]; got != float64(3) {
		t.Fatalf("converging_stores = %#v, want 3 (surface + plan + findings)",
			got)
	}
	if keys := first["converging_keys"].([]any); len(keys) == 0 {
		t.Fatalf("converging_keys = %#v, want the canonical keys", keys)
	}
}

// TestProbesPendingStaleRowIsPendingAndFlagged pins the stale case: a row
// whose recorded shape moved is undispositioned again (the plan's shape_sha no
// longer matches), and the header says how many.
func TestProbesPendingStaleRowIsPendingAndFlagged(t *testing.T) {
	ws, c, surface := t30Setup(t)
	rid := t30RowID(t, t30Rows(t, surface), 0)
	t30BumpRowLine(t, c, rid, 99)
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "probe surface: 10 rows, 10 pending (1 stale; cap 20; --max N " +
		"or --json for the full list)\n"
	if !strings.HasPrefix(out, want) {
		t.Fatalf("stdout = %q, want prefix %q", out, want)
	}
	if !strings.Contains(out, rid+" | tier 0 | gap 4 | enforcement-timing | "+
		"assertion-strength | Rollup#commitBatch:99 | ") {
		t.Fatalf("stale row line = %q", out)
	}
	doc := t30JSONPending(t, ws)
	for _, row := range t30JSONRows(t, doc) {
		if row["row_id"] == rid && row["stale"] != true {
			t.Fatalf("stale flag = %#v, want true", row["stale"])
		}
	}
}

// t30BumpRowLine rewrites one surface row's consumer_line (a shape field, so
// the plan's recorded shape_sha stops matching).
func t30BumpRowLine(t *testing.T, c *state.Campaign, rowID string, line int64) {
	t.Helper()
	path := t29SurfacePath(c)
	surface, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := t29ObjList(surface, "rows")
	for i, r := range rows {
		if validation.ObjStr(r, "row_id") != rowID {
			continue
		}
		t29Set(&r, "consumer_line", validation.VInt(line))
		rows[i] = r
	}
	t29Set(&surface, "rows", validation.VArr(rows...))
	if err := validation.WriteJson(path, surface, ""); err != nil {
		t.Fatal(err)
	}
}

// t30WriteModel writes the protocol model artifact the B7 seam indexes.
func t30WriteModel(t *testing.T, c *state.Campaign) {
	t.Helper()
	model := validation.VObj(
		validation.KV{K: "protocol_id", V: validation.VStr("probe-cli")},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Rollup")},
			validation.KV{K: "path", V: validation.VStr("Rollup.sol")}))},
		validation.KV{K: "state_machines", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("rollup-lifecycle")}))})
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), model, ""); err != nil {
		t.Fatal(err)
	}
}

// t30AddPlanPriority appends one plan priority naming a model contract, which
// is what makes the plan store converge with the surface rows.
func t30AddPlanPriority(t *testing.T, c *state.Campaign, id, component string) {
	t.Helper()
	path := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	plan, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	prios := t29ObjList(plan, "priorities")
	prios = append(prios, validation.VObj(
		validation.KV{K: "id", V: validation.VStr(id)},
		validation.KV{K: "components", V: validation.StrArr([]string{component})},
		validation.KV{K: "status", V: validation.VStr("open")}))
	t29Set(&plan, "priorities", validation.VArr(prios...))
	if err := validation.WriteJson(path, plan, ""); err != nil {
		t.Fatal(err)
	}
}

// t30WriteFinding files the minimal finding the anchor join needs: an id and
// an affected[] path that pins the model path by full path.
func t30WriteFinding(t *testing.T, c *state.Campaign, id, path string) {
	t.Helper()
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	finding := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(id)},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr(path)},
			validation.KV{K: "function", V: validation.VStr("commitBatch")}))})
	if err := validation.WriteJson(filepath.Join(c.FindingsDir, id+".json"),
		finding, ""); err != nil {
		t.Fatal(err)
	}
}

// ---- the probe-row batch route (`answered --rows`) -------------------------

// t30AnsweredRows runs the batch route with the house flags.
func t30AnsweredRows(t *testing.T, ws, rows, status, reason string,
	extra ...string) (int, string, string) {
	t.Helper()
	args := []string{"--root", ws, "answered", t29CID, "--rows", rows,
		status, "--reason-all", reason, "--anchor", "consumer",
		"--actor", "op"}
	args = append(args, extra...)
	return run(t, args...)
}

// TestAnsweredRowsBatchDischargesProbeRows pins the happy path: two rows the
// anti-dismissal rule does not cover, one status, --reason-all riding both,
// and the closure's own provenance on each priority.
func TestAnsweredRowsBatchDischargesProbeRows(t *testing.T) {
	ws, c, surface := t30Setup(t)
	rows := t30Rows(t, surface)
	r1, r2 := t30RowID(t, rows, 0), t30RowID(t, rows, 1)
	t30SetRowTierGap(t, c, r1, 2, 0)
	t30SetRowTierGap(t, c, r2, 2, 0)
	code, out, errS := t30AnsweredRows(t, ws, r1+","+r2, "answered",
		"the queue was read and both rows are covered")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "Q-005: status -> answered (ref: Rollup.sol#L45) [anchor consumer]\n" +
		"Q-006: status -> answered (ref: Rollup.sol#L49) [anchor consumer]\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	plan := t29PlanJSON(t, c)
	prios := validation.VArr(t29List(plan, "priorities")...)
	for _, pid := range []string{"Q-005", "Q-006"} {
		p, ok := t14FindByID(prios, pid)
		if !ok {
			t.Fatalf("no priority %s", pid)
		}
		if got := validation.ObjStr(p, "status"); got != "answered" {
			t.Errorf("%s status = %q", pid, got)
		}
		probe := validation.ObjAt(p, "probe")
		if got := validation.ObjStr(validation.ObjAt(probe, "anchor"),
			"field"); got != "consumer" {
			t.Errorf("%s anchor = %q, want consumer", pid, got)
		}
	}
}

// TestAnsweredRowsReasonAllRefusedForHighRiskRows pins the B10(b) rule: the
// bulk route is legal only when EVERY named row is tier>0 and
// assertion_gap<3, the refusal names each offending row with its reason, and
// nothing is written.
func TestAnsweredRowsReasonAllRefusedForHighRiskRows(t *testing.T) {
	ws, c, surface := t30Setup(t)
	rows := t30Rows(t, surface)
	r1, r2 := t30RowID(t, rows, 0), t30RowID(t, rows, 1)
	t30SetRowTierGap(t, c, r2, 2, 0)
	before := batchPlanBytes(t, ws, t29CID)
	code, out, errS := t30AnsweredRows(t, ws, r1+","+r2, "answered",
		"a batch close over one high-risk row")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want nothing", out)
	}
	want := "answered: --reason-all is refused for 1 of 2 rows — the bulk " +
		"route is legal only when EVERY named row is tier>0 and " +
		"assertion_gap<3 (a tier-0 or gap>=3 row is discharged one-per-call, " +
		"with a reason that cites its own code):\n" +
		"  " + r1 + " (Q-005): tier 0, gap 4\n" +
		"`webv2 probes " + t29CID + " pending` prints the exact per-row " +
		"command.\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	if after := batchPlanBytes(t, ws, t29CID); after != before {
		t.Fatal("a refused batch must leave the plan untouched")
	}
}

// TestAnsweredRowsReasonAllRefusedForGapThree pins the second half of the
// rule: a tier>0 row is still covered when its assertion_gap is 3 or more.
func TestAnsweredRowsReasonAllRefusedForGapThree(t *testing.T) {
	ws, c, surface := t30Setup(t)
	r1 := t30RowID(t, t30Rows(t, surface), 0)
	t30SetRowTierGap(t, c, r1, 1, 3)
	code, _, errS := t30AnsweredRows(t, ws, r1, "answered", "one row only")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, r1+" (Q-005): tier 1, gap 3") {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestAnsweredRowsTierZeroStillWorksOnePerCall pins the other half of the
// bootstrap rule: the per-row path keeps working on a tier-0 row, with its own
// --anchor and a reason citing the row's own code, byte-for-byte.
func TestAnsweredRowsTierZeroStillWorksOnePerCall(t *testing.T) {
	ws, _, surface := t30Setup(t)
	// morph §6.1/§7.1: the tier-0 row sits on the enforcement-timing axis, so
	// the per-row path owes the interim pricing; the bootstrap rule is the
	// gate this arm is about.
	row := t30Rows(t, surface)[0]
	code, out, errS := run(t, "--root", ws, "answered", t29CID, "Q-005",
		"answered", "--reason", "commitBatch enforces the check itself",
		"--anchor", "consumer", "--actor", "op",
		"--interim", cliInterimFor(row))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "Q-005: status -> answered (ref: Rollup.sol#L45) [anchor consumer]\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestAnsweredRowsReasonAllRuleIsStatusIndependent pins the spec-literal
// reading of the rule: it is a property of the BULK --reason-all route, so it
// bites whatever status rides it (a `blocked` row is not a discharge — A3 —
// but the operator who wants it on a tier-0 row uses the one-per-call form,
// which is never refused).
func TestAnsweredRowsReasonAllRuleIsStatusIndependent(t *testing.T) {
	ws, _, surface := t30Setup(t)
	r1 := t30RowID(t, t30Rows(t, surface), 0)
	code, _, errS := t30AnsweredRows(t, ws, r1, "blocked", "blocked upstream")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, r1+" (Q-005): tier 0, gap 4") {
		t.Fatalf("stderr = %q", errS)
	}
	// The one-per-call form is untouched: `blocked` is not a probe-row
	// disposition, so it needs no anchor and no dismissal proof.
	code, out, errS := run(t, "--root", ws, "answered", t29CID, "Q-005",
		"blocked", "--reason", "the exec that would settle it cannot run here",
		"--actor", "op")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "Q-005: status -> blocked\n" {
		t.Fatalf("stdout = %q", out)
	}
}

// TestProbesPendingWithoutAPlanIsStillAWorklist pins the tolerant half: a
// campaign that never ran `plan` has no dispositions, so every row is pending
// and its next command is the emit that creates the obligations.
func TestProbesPendingWithoutAPlanIsStillAWorklist(t *testing.T) {
	ws, _, _, surface := t29Setup(t, t29Ranking, false)
	rows := t30Rows(t, surface)
	if len(rows) != 10 {
		t.Fatalf("rows = %d, want 10", len(rows))
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 12 {
		t.Fatalf("stdout = %q, want a header + 10 rows + a trailing newline",
			out)
	}
	rid := t30RowID(t, rows, 0)
	want := rid + " | tier 0 | gap 4 | enforcement-timing | assertion-strength" +
		" | Rollup#commitBatch:45 | 0 converging stores -> webv2 probes " +
		t29CID + " run --emit"
	if lines[1] != want {
		t.Fatalf("row line = %q, want %q", lines[1], want)
	}
	doc := t30JSONPending(t, ws)
	first := t30JSONRows(t, doc)[0]
	if first["priority_id"] != "" || first["status"] != "" {
		t.Fatalf("row without a plan = %#v", first)
	}
}

// TestAnsweredRowsRefusalsAreNamedPerRow pins every refusal the route owns:
// an unknown row, a repeated row, the wrong reason flag for a multi-row batch,
// a priority positional alongside --rows, a missing anchor and an anchor the
// row's probe does not produce. Each is exit 2 and writes nothing.
func TestAnsweredRowsRefusalsAreNamedPerRow(t *testing.T) {
	ws, _, surface := t30Setup(t)
	rows := t30Rows(t, surface)
	r1, r2 := t30RowID(t, rows, 0), t30RowID(t, rows, 1)
	// r1 is made low-risk so the cases that ride --reason-all reach the gate
	// they are about: the anti-dismissal rule runs FIRST (it is the route's
	// own rule), and its refusal is pinned by its own test.
	c, err := state.Open(ws, t29CID)
	if err != nil {
		t.Fatal(err)
	}
	t30SetRowTierGap(t, c, r1, 2, 0)
	before := batchPlanBytes(t, ws, t29CID)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown row", []string{"--rows", "bogus1", "answered",
			"--reason-all", "x", "--anchor", "consumer"},
			"answered: row 1 (bogus1): not in the current surface — run " +
				"`webv2 probes " + t29CID + " run --emit`\n"},
		{"repeated row", []string{"--rows", r1 + "," + r1, "answered",
			"--reason-all", "x", "--anchor", "consumer"},
			"answered: --rows names row " + r1 + " twice — one status per " +
				"row, named once\n"},
		{"blank list", []string{"--rows", r1 + ",", "answered",
			"--reason-all", "x", "--anchor", "consumer"},
			"answered: --rows takes a comma-separated list of surface row " +
				"ids — got " + validation.PyReprStr(r1+",") + "\n"},
		{"--reason on a batch", []string{"--rows", r1 + "," + r2, "answered",
			"--reason", "x", "--anchor", "consumer"},
			"answered: closing 2 priorities needs --reason-all (why) — " +
				"--reason names a single closure, --reason-all rides every " +
				"row.\n"},
		{"priority positional", []string{"Q-001", "--rows", r1, "answered",
			"--reason-all", "x", "--anchor", "consumer"},
			"answered: --rows names the probe rows to discharge, so it " +
				"takes no priority positional (got 'Q-001'); drop the " +
				"priority and pass the row ids to --rows\n"},
		{"no anchor", []string{"--rows", r1, "answered", "--reason", "x"},
			"answered: row 1 (Q-005): priority Q-005 is probe row '" + r1 +
				"': 'answered' dispositions it, so the closure must name " +
				"the field it claims is safe — pass anchor=<field> (one of " +
				"consumer, asserter, concept)\n"},
		{"anchor not produced", []string{"--rows", r1, "answered",
			"--reason", "x", "--anchor", "actor"},
			"answered: row 1 (Q-005): anchor 'actor' is not produced by " +
				"probe 'assertion-strength'; allowed: ['consumer', " +
				"'asserter', 'concept']\n"},
		{"--reconcile on the rows route", []string{"--rows", r1, "answered",
			"--reason-all", "x", "--anchor", "consumer", "--reconcile",
			"R=V"},
			"answered: --reconcile reconciles the divergence rows of an " +
				"L-04 primitive-symmetry lens closure — 'Q-005' is a Q-* " +
				"priority, so there is nothing to reconcile: drop " +
				"--reconcile\n"},
	}
	for _, tc := range cases {
		code, out, errS := run(t, append([]string{"--root", ws, "answered",
			t29CID}, tc.args...)...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2 (%q)", tc.name, code, errS)
			continue
		}
		if out != "" {
			t.Errorf("%s: stdout = %q, want nothing", tc.name, out)
		}
		if errS != tc.want {
			t.Errorf("%s: stderr = %q, want %q", tc.name, errS, tc.want)
		}
	}
	if after := batchPlanBytes(t, ws, t29CID); after != before {
		t.Fatal("refused batches must leave the plan untouched")
	}
}

// TestAnsweredRowsNeedsASurfaceAndAnEmittedRow pins the two fixture gaps: a
// campaign with no surface refuses, and a row the plan never emitted names the
// emit that creates it.
func TestAnsweredRowsNeedsASurfaceAndAnEmittedRow(t *testing.T) {
	// no surface at all (the plan exists).
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	r1 := t30RowID(t, t30Rows(t, surface), 0)
	if err := os.Remove(t29SurfacePath(c)); err != nil {
		t.Fatal(err)
	}
	code, _, errS := t30AnsweredRows(t, ws, r1, "answered", "x")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want := "answered: no probe surface for " + t29CID + " — run `webv2 " +
		"probes " + t29CID + " run --emit` first\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	// surface present, row not emitted (no --emit ever ran).
	ws2, _, _, surface2 := t29Setup(t, t29Ranking, true)
	r2 := t30RowID(t, t30Rows(t, surface2), 0)
	code, _, errS = t30AnsweredRows(t, ws2, r2, "answered", "x")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want = "answered: row 1 (" + r2 + "): the plan does not carry this " +
		"row — run `webv2 probes " + t29CID + " run --emit`\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

// TestAnsweredRowsNoPlanKeepsTheExistingRefusal pins that the rows route rides
// the verb's existing missing-plan guard, byte for byte.
func TestAnsweredRowsNoPlanKeepsTheExistingRefusal(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "answered", cid, "--rows",
		"abc123", "answered", "--reason-all", "x", "--anchor", "consumer")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "no campaign plan loaded (webv2 plan "+cid+")\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestAnsweredRowsPositionalShapes pins the argparse layer of the new form:
// the missing positionals are named, and an invalid status keeps the verb's
// status enum message.
func TestAnsweredRowsPositionalShapes(t *testing.T) {
	code, _, errS := run(t, "answered", "--rows", "abc123")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "the following arguments are required: "+
		"campaign, status") {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "answered", t29CID, "--rows", "abc123")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "the following arguments are required: "+
		"status") {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "answered", t29CID, "--rows", "abc123", "bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "argument status: invalid choice: 'bogus' "+
		"(choose from 'open', 'assigned', 'answered', 'not-applicable', "+
		"'deprioritized', 'blocked')") {
		t.Fatalf("stderr = %q", errS)
	}
}

// ---- byte discipline ------------------------------------------------------

// TestProbesPendingLeavesTheExistingVerbBytesAlone pins the ABSENT case of the
// new subcommand: the verb's usage/choice error is unchanged (the new
// subcommand is deliberately not added to that pinned argparse choice list),
// and the verb's help text grows the new line.
func TestProbesPendingLeavesTheExistingVerbBytesAlone(t *testing.T) {
	code, out, errS := run(t, "probes", t29CID, "bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := t29ProbesUsage + "webv2 probes: error: argument probes_cmd: " +
		"invalid choice: 'bogus' (choose from 'run', 'list', 'blank')\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	code, out, errS = run(t, "probes", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "pending") ||
		!strings.Contains(out, "exact 'answered' command") {
		t.Fatalf("help does not advertise the subcommand: %q", out)
	}
}

// TestProbesPendingHelpAndUsage pins the new subparser's own argparse text and
// its refusals.
func TestProbesPendingHelpAndUsage(t *testing.T) {
	code, out, errS := run(t, "probes", t29CID, "pending", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t29ProbesPendingHelp || errS != "" {
		t.Fatalf("help = %q, stderr = %q", out, errS)
	}
	code, out, errS = run(t, "probes", t29CID, "pending", "--max", "0")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out=%q", code, out)
	}
	if errS != "probes pending: --max 0 prints nothing — pass --max N with "+
		"N >= 1, or --json for the full list\n" {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "probes", t29CID, "pending", "--max", "zz")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := t29ProbesPendingUsage + "webv2 probes campaign pending: error: " +
		"argument --max: invalid int value: 'zz'\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	code, _, errS = run(t, "probes", t29CID, "pending", "--max")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want = t29ProbesPendingUsage + "webv2 probes campaign pending: error: " +
		"argument --max: expected one argument\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	code, _, errS = run(t, "probes", t29CID, "pending", "--bogus")
	if code != 2 || !strings.Contains(errS, "unrecognized arguments: --bogus") {
		t.Fatalf("exit %d stderr=%q", code, errS)
	}
}

// TestProbesPendingNoSurfaceRefusal pins the cold-campaign refusal.
func TestProbesPendingNoSurfaceRefusal(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "probes", cid, "pending")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "probes: no probe surface for "+cid+" — run `webv2 probes "+
		cid+" run` first\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestProbesPendingUnreadablePlanRefuses pins the split the anchors verb also
// makes: a MISSING plan is a worklist of not-emitted rows, an UNREADABLE plan
// is a refusal — never a worklist of lies.
func TestProbesPendingUnreadablePlanRefuses(t *testing.T) {
	ws, c, _ := t30Setup(t)
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if err := os.WriteFile(planPath, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", ws, "probes", t29CID, "pending")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS, "probes pending: unreadable "+planPath) ||
		!strings.Contains(errS, "webv2 plan "+t29CID) {
		t.Fatalf("stderr = %q", errS)
	}
}
