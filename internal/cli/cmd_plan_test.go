package cli

// T14 cmd_plan tests: bootstrap, the read-only view (note on stderr, view on
// stdout), --rebuild, and the --json shape. Vectors captured from the live
// Python CLI (.scratch/t14/py3.json).

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestPlanBootstrapView(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestWrite(t, root, "model.json", t14TestModelJSON)
	if code, _, errS := run(t, "--root", root, "model", cid,
		root+"/model.json"); code != 0 {
		t.Fatalf("model exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "plan", cid)
	if code != 0 {
		t.Fatalf("plan exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "plan: 8 queued priorities\n") {
		t.Fatalf("stdout = %q", out[:60])
	}
	// the queue names each row by its priority id
	if !strings.Contains(out, "  [Q-001] Economic transform donation-attack: ") {
		t.Fatalf("missing priority row: %q", out)
	}
	// lens checklist, divergence gate and the reachability note are present
	for _, want := range []string{
		"  [ ] L-01 liveness (protocol): open\n",
		"  Divergence gate: OPEN — 0 distinct bug class(es) (min 4)\n",
		"  reachability: classes whose CONFIRMED floor is E5/E6 cannot " +
			"reach confirmation",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q", want)
		}
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPlanReadOnlyView(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	// the second bare call is the read-only view: same stdout, note on stderr
	code, out, errS := run(t, "--root", root, "plan", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "plan: 8 queued priorities\n") {
		t.Fatalf("stdout = %q", out[:60])
	}
	if errS != planNote {
		t.Fatalf("stderr = %q, want %q", errS, planNote)
	}
	if !strings.Contains(planNote, "add --rebuild to regenerate") {
		t.Fatalf("planNote = %q", planNote)
	}
}

func TestPlanRebuildIsQuiet(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "plan", cid, "--rebuild")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "plan: 8 queued priorities\n") {
		t.Fatalf("stdout = %q", out[:60])
	}
	if errS != "" {
		t.Fatalf("rebuild must not print the read-only note: %q", errS)
	}
}

func TestPlanJSON(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "plan", cid, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "\"read_only\": true") {
		t.Fatalf("json missing read_only: %q", out[:200])
	}
	for _, want := range []string{"\"work_queue\"", "\"lenses\"",
		"\"divergence\""} {
		if !strings.Contains(out, want) {
			t.Fatalf("json missing %s", want)
		}
	}
	// The seeded lenses appear in id order and the divergence gate is open
	// (test_plan_display_shows_lenses_and_gate).
	var doc struct {
		Lenses     []struct{ ID string } `json:"lenses"`
		Divergence struct {
			Closed bool `json:"closed"`
		} `json:"divergence"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("plan json: %v", err)
	}
	ids := make([]string, 0, len(doc.Lenses))
	for _, l := range doc.Lenses {
		ids = append(ids, l.ID)
	}
	if strings.Join(ids, ",") != "L-01,L-02,L-03,L-04" {
		t.Fatalf("lens ids = %v", ids)
	}
	if doc.Divergence.Closed {
		t.Fatal("divergence must be open on a seeded plan")
	}
	if errS != planNote {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPlanInvalidFile(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	plan := t14TestWrite(t, root, "plan.json",
		`{"campaign_id":"C-0000000000","created_at":"2026-09-10T00:00:00.000000+00:00",`+
			`"snapshot_id":"unpinned","strategy_note":"fixture","priorities":`+
			`[{"id":"Q-001","question":"q","risk":0.5,"status":"open",`+
			`"components":[],"invariant_ids":[],"required_context":[],`+
			`"trajectories":[],"recommended_stages":[],`+
			`"budget_class":"standard"}],"lenses":[]}`)
	code, out, errS := run(t, "--root", root, "plan", cid, plan)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "plan failed: campaign_plan validation failed at " +
		"priorities/0/question: 'q' is too short (+1 more errors)\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestPlanUnrecognizedFlag(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "plan", cid, "--file", "x")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(errS, "webv2: error: unrecognized arguments: "+
		"--file\n") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPlanHelp(t *testing.T) {
	code, out, errS := run(t, "plan", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14PlanHelp {
		t.Fatalf("help = %q, want %q", out, t14PlanHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// Port of tests/test_cli.py::test_plan_text_queue_shows_priority_ids: the text
// queue reads the row's real key. work_queue emits `priority_id`, so reading
// `priority` printed `[?]` on every line — the operator could not tell which
// Q-id to answer.
func TestPlanTextQueueShowsPriorityIDs(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "plan", cid)
	if code != 0 {
		t.Fatalf("plan exit %d: %q", code, errS)
	}
	plan, err := validation.ReadJson(filepath.Join(root, "campaigns", cid,
		"artifacts", "campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	prios := objAt(plan, "priorities")
	if prios.Kind != validation.Arr || len(prios.A) == 0 {
		t.Fatalf("the fixture plan must queue priorities: %+v", prios)
	}
	for _, p := range prios.A {
		if !strings.Contains(out, "["+objStr(p, "id")+"]") {
			t.Fatalf("stdout is missing [%s]: %q", objStr(p, "id"), out)
		}
	}
	if strings.Contains(out, "[?]") {
		t.Fatalf("the queue printed a placeholder id: %q", out)
	}
}
