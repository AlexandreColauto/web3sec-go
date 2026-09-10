package cli

// cmd_answered_disposition_test.go — IMPROVEMENTS B4 CLI: the override flag
// argparse surface, and the end-to-end gate flows (rejection, refutation
// backing via an exec record, and the --override-dismissal path with its
// audit event).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// dgSeedProbeCampaign seeds the CLI test campaign with the planner's
// recorded probe row (Q-005, tier 0, gap 4, anchor consumer ->
// Rollup.sol#L45) so the answered flow sees a real probe surface.
func dgSeedProbeCampaign(t *testing.T, root, cid string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	copies := [][2]string{
		{"../planner/testdata/probe_surface.json", "probe_surface.json"},
		{"../planner/testdata/structural_index.json", "structural_index.json"},
		{"../planner/testdata/plan_probe_rows.json", "campaign_plan.json"},
	}
	for _, cp := range copies {
		b, err := os.ReadFile(cp[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(c.ArtifactsDir, cp[1]),
			b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// dgWriteExecRecord puts one exec record on disk so an EXEC ref is
// refutation-backed.
func dgWriteExecRecord(t *testing.T, root, cid, execID string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exec_record.json"),
		[]byte(`{"exec_id":"`+execID+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// dgEventsOfType returns the logged events of one type.
func dgEventsOfType(t *testing.T, root, cid, typ string) []validation.Value {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var out []validation.Value
	for _, e := range evts {
		if objStr(e, "type") == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestAnsweredOverrideFlagArgparse(t *testing.T) {
	// a bare --override-reason (no value) is an argparse error, exit 2
	code, out, errS := run(t, "answered", "C-x", "Q-005", "answered",
		"--reason", "r", "--override-reason")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS,
		"argument --override-reason: expected one argument") {
		t.Fatalf("stderr = %q", errS)
	}
	// an unknown override-ish flag is still unrecognized
	code, _, errS = run(t, "answered", "C-x", "Q-005", "answered",
		"--reason", "r", "--override")
	if code != 2 || !strings.Contains(errS, "unrecognized arguments: --override") {
		t.Fatalf("exit %d stderr = %q", code, errS)
	}
}

func TestAnsweredDismissalGateRejects(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "liveness-only, the owner can revert",
		"--anchor", "consumer")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	for _, want := range []string{"dismissal vocabulary", "liveness-only",
		"owner can revert", "EXEC-", "INV-", "--override-dismissal"} {
		if !strings.Contains(errS, want) {
			t.Errorf("stderr missing %q:\n%s", want, errS)
		}
	}
	// the rejection must leave the plan untouched (still open)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range t14List(plan, "priorities").A {
		if objStr(p, "id") == "Q-005" && objStr(p, "status") != "open" {
			t.Fatalf("rejected closure changed the plan status to %q",
				objStr(p, "status"))
		}
	}
}

func TestAnsweredDismissalGateExecBacked(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	dgWriteExecRecord(t, root, cid, "EXEC-abcdef1234")
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "liveness-only, the owner can revert",
		"--anchor", "consumer", "--ref", "EXEC-abcdef1234")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "Q-005: status -> answered (ref: EXEC-abcdef1234) "+
		"[anchor consumer]\n" {
		t.Fatalf("stdout = %q", out)
	}
	// the audit trail: plan.priority_status carries the refutation ref
	evts := dgEventsOfType(t, root, cid, "plan.priority_status")
	if len(evts) != 1 {
		t.Fatalf("plan.priority_status events = %d, want 1", len(evts))
	}
	if got := objStr(objAt(evts[0], "data"), "ref"); got != "EXEC-abcdef1234" {
		t.Errorf("event ref = %q, want EXEC-abcdef1234", got)
	}
}

func TestAnsweredDismissalGateOverride(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)

	// override without a reason: refused
	code, _, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "liveness-only", "--anchor", "consumer",
		"--override-dismissal")
	if code != 2 || !strings.Contains(errS,
		"--override-dismissal needs --override-reason") {
		t.Fatalf("exit %d stderr = %q", code, errS)
	}

	// override with a reason: closes + logs the audit event
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "liveness-only", "--anchor", "consumer",
		"--override-dismissal", "--override-reason",
		"the owner confirmed the intended behavior in the spec",
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "Q-005: status -> answered (ref: Rollup.sol#L45) "+
		"[anchor consumer]\n" {
		t.Fatalf("stdout = %q", out)
	}
	evts := dgEventsOfType(t, root, cid, "probe.dismissal_overridden")
	if len(evts) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want 1", len(evts))
	}
	data := objAt(evts[0], "data")
	if got := objStr(data, "row_id"); got != "81dfad6492" {
		t.Errorf("row_id = %q", got)
	}
	if got := objStr(data, "actor"); got != "operator" {
		t.Errorf("actor = %q, want operator", got)
	}
	if got := objStr(data, "override_reason"); got !=
		"the owner confirmed the intended behavior in the spec" {
		t.Errorf("override_reason = %q", got)
	}
	if got := objStr(data, "closed_reason"); got != "liveness-only" {
		t.Errorf("closed_reason = %q", got)
	}
	// the = spelling parses identically
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	dgSeedProbeCampaign(t, root2, cid2)
	code, out, errS = run(t, "--root", root2, "answered", cid2, "Q-005",
		"answered", "--reason", "no profit", "--anchor", "consumer",
		"--override-dismissal",
		"--override-reason=owner confirmed the intended behavior in the spec")
	if code != 0 {
		t.Fatalf("= spelling exit %d: %q", code, errS)
	}
	if out != "Q-005: status -> answered (ref: Rollup.sol#L45) "+
		"[anchor consumer]\n" {
		t.Fatalf("= spelling stdout = %q", out)
	}
}
