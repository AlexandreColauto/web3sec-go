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

// dgSeedSentinelSurface rewrites the seeded probe surface's fixture row with
// Task 1's sentinel enrichment (own_form=sentinel, own_guard_text), so a CLI
// closing of Q-005 is a closing of a sentinel-guarded row.
func dgSeedSentinelSurface(t *testing.T, root, cid string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c.ArtifactsDir, "probe_surface.json")
	surface, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	rows := t14List(surface, "rows").A
	for i, r := range rows {
		if objStr(r, "row_id") != "81dfad6492" {
			continue
		}
		found = true
		r.O = validation.SetOrAppend(r.O, "own_form",
			validation.VStr("sentinel"))
		r.O = validation.SetOrAppend(r.O, "own_guard_text",
			validation.VStr("stateRoot != bytes32(0)"))
		rows[i] = r
	}
	if !found {
		t.Fatal("fixture row 81dfad6492 is gone")
	}
	if err := validation.WriteJson(p, surface, ""); err != nil {
		t.Fatal(err)
	}
}

// dgStoredPriority reads one priority back off the campaign's saved plan.
func dgStoredPriority(t *testing.T, root, cid, pid string) validation.Value {
	t.Helper()
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
		if objStr(p, "id") == pid {
			return p
		}
	}
	t.Fatalf("priority %s not in the stored plan", pid)
	return validation.VNull()
}

// TestAnsweredCLISentinelPassesFlag: the CLI refuses the closing disposition
// of a sentinel row without --passes (naming both exits), accepts it with
// the flag, and the refusal leaves the priority untouched.
func TestAnsweredCLISentinelPassesFlag(t *testing.T) {
	const reason = "commitBatch re-derives prev:state; the assertion is " +
		"checked at finalizeBatch"

	// (1) refusal: sentinel-guarded row, no --passes
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	dgSeedSentinelSurface(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", reason, "--anchor", "consumer")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	for _, want := range []string{"sentinel-guarded probe row 81dfad6492",
		"must name the value that passes", "--passes VALUE",
		"--override-dismissal", "--override-reason"} {
		if !strings.Contains(errS, want) {
			t.Errorf("stderr missing %q:\n%s", want, errS)
		}
	}
	// the refusal is a fixed sentence: both exits, named exactly
	wantRefusal := "answered failed: sentinel-guarded probe row 81dfad6492: " +
		"a closing disposition must name the value that passes its check " +
		"(--passes VALUE) — or override explicitly (--override-dismissal " +
		"--override-reason R)\n"
	if errS != wantRefusal {
		t.Errorf("stderr = %q\nwant %q", errS, wantRefusal)
	}
	// the refusal is a decision that did not happen: the priority is untouched
	p := dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "status"); got != "open" {
		t.Fatalf("refused closure changed the status to %q", got)
	}
	if objAt(p, "passes").Kind != validation.Null {
		t.Fatalf("refused closure recorded passes = %q", objStr(p, "passes"))
	}

	// (2) accept: the same closure with the value that passes the check
	passes := "any non-zero root; asserted at finalizeBatch"
	code, _, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", reason, "--anchor", "consumer",
		"--passes", passes)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	p = dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "status"); got != "answered" {
		t.Errorf("status = %q, want answered", got)
	}
	if got := objStr(p, "passes"); got != passes {
		t.Errorf("passes = %q, want %q", got, passes)
	}

	// (2b) FIX-C: a value that clears the length floor but is neither a row
	// citation nor a concrete literal is refused, both legal shapes named
	junk := "zzz"
	code, _, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", reason, "--anchor", "consumer",
		"--passes", junk)
	if code != 2 || !strings.Contains(errS,
		"is not a plausible value for the check") ||
		!strings.Contains(errS, "row's own surface entry") ||
		!strings.Contains(errS, "concrete literal") {
		t.Fatalf("junk --passes: exit %d stderr = %q", code, errS)
	}
	// negative control: the refusal is a decision that did not happen
	p = dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "passes"); got != passes {
		t.Fatalf("junk refusal changed passes to %q, want %q", got, passes)
	}
	// the literal shape rides the same flag through the CLI and is recorded
	passes = "0xdeadbeef"
	code, _, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", reason, "--anchor", "consumer",
		"--passes", passes)
	if code != 0 {
		t.Fatalf("literal --passes exit %d: %q", code, errS)
	}
	if got := objStr(dgStoredPriority(t, root, cid, "Q-005"), "passes"); got != passes {
		t.Errorf("passes = %q, want %q", got, passes)
	}

	// (3) negative control: the rule is row-scoped — with no own_form on the
	// surface row the very same closure needs no --passes.
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	dgSeedProbeCampaign(t, root2, cid2)
	// the guard: --passes followed by an option token is never a value
	code, _, errS = run(t, "--root", root2, "answered", cid2, "Q-005",
		"answered", "--reason", reason, "--anchor", "consumer",
		"--passes", "--actor")
	if code != 2 || !strings.Contains(errS,
		"argument --passes: expected one argument") {
		t.Fatalf("exit %d stderr = %q", code, errS)
	}
	code, _, errS = run(t, "--root", root2, "answered", cid2, "Q-005",
		"answered", "--reason", reason, "--anchor", "consumer")
	if code != 0 {
		t.Fatalf("row without own_form: exit %d: %q", code, errS)
	}
	if strings.Contains(errS, "must name the value that passes") {
		t.Fatalf("row-scoped rule fired without own_form: %q", errS)
	}
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
	// The override is announced before the status line: the operator must see
	// the decision land, not infer it from a log they never read.
	if want := "  dismissal overridden: Q-005 logged as " +
		"probe.dismissal_overridden (actor operator)\n" +
		"Q-005: status -> answered (ref: Rollup.sol#L45) " +
		"[anchor consumer]\n"; out != want {
		t.Fatalf("stdout = %q\nwant %q", out, want)
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
	if want := "  dismissal overridden: Q-005 logged as " +
		"probe.dismissal_overridden (actor cli)\n" +
		"Q-005: status -> answered (ref: Rollup.sol#L45) " +
		"[anchor consumer]\n"; out != want {
		t.Fatalf("= spelling stdout = %q\nwant %q", out, want)
	}
}

// TestAnsweredSentinelOverrideNeedsReason: the sentinel rule's escape hatch
// is the logged override, not a bare flag. A bare --override-dismissal on a
// sentinel-guarded row is refused with the priority untouched, and an
// override with a reason closes it, announces itself, and records exactly
// one probe.dismissal_overridden.
func TestAnsweredSentinelOverrideNeedsReason(t *testing.T) {
	// (1) bare override: refused, the priority is untouched
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	dgSeedSentinelSurface(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "liveness-only", "--anchor", "consumer",
		"--override-dismissal")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS,
		"--override-dismissal needs --override-reason") {
		t.Fatalf("stderr = %q, want the override-reason refusal", errS)
	}
	p := dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "status"); got != "open" {
		t.Fatalf("refused closure changed the status to %q", got)
	}
	if objAt(p, "passes").Kind != validation.Null {
		t.Fatalf("refused closure recorded passes = %q", objStr(p, "passes"))
	}

	// (2) override with a reason: closes, announces, one event
	code, out, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "liveness-only", "--anchor", "consumer",
		"--override-dismissal", "--override-reason",
		"the operator accepts the risk in writing for this run",
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if want := "  dismissal overridden: Q-005 logged as " +
		"probe.dismissal_overridden (actor operator)\n" +
		"Q-005: status -> answered (ref: Rollup.sol#L45) " +
		"[anchor consumer]\n"; out != want {
		t.Fatalf("stdout = %q\nwant %q", out, want)
	}
	evts := dgEventsOfType(t, root, cid, "probe.dismissal_overridden")
	if len(evts) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want 1", len(evts))
	}
	data := objAt(evts[0], "data")
	if got := objStr(data, "row_id"); got != "81dfad6492" {
		t.Errorf("row_id = %q", got)
	}
	if got := objAt(data, "tier").I; got != 0 {
		t.Errorf("tier = %d, want 0", got)
	}
	if got := objAt(data, "assertion_gap").I; got != 4 {
		t.Errorf("assertion_gap = %d, want 4", got)
	}
	if got := objStr(data, "actor"); got != "operator" {
		t.Errorf("actor = %q, want operator", got)
	}
	if got := objStr(data, "override_reason"); got !=
		"the operator accepts the risk in writing for this run" {
		t.Errorf("override_reason = %q", got)
	}
	if got := objStr(data, "closed_reason"); got != "liveness-only" {
		t.Errorf("closed_reason = %q", got)
	}
}

// dgSeedFinding writes one filed finding so a --finding ref resolves.
func dgSeedFinding(t *testing.T, root, cid, id string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.FindingsDir, id+".json"),
		[]byte(`{"finding_id":"`+id+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// dgSeedLowSurface rewrites the seeded probe surface's fixture row to
// tier 2 / gap 1 (not high-risk), so a CLI closing of Q-005 exercises the
// gate's negative control on the same anchor.
func dgSeedLowSurface(t *testing.T, root, cid string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c.ArtifactsDir, "probe_surface.json")
	surface, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	rows := t14List(surface, "rows").A
	for i, r := range rows {
		if objStr(r, "row_id") != "81dfad6492" {
			continue
		}
		found = true
		r.O = validation.SetOrAppend(r.O, "tier", validation.VInt(2))
		r.O = validation.SetOrAppend(r.O, "assertion_gap", validation.VInt(1))
		rows[i] = r
	}
	if !found {
		t.Fatal("fixture row 81dfad6492 is gone")
	}
	if err := validation.WriteJson(p, surface, ""); err != nil {
		t.Fatal(err)
	}
}

// TestAnsweredCLIDeferredConsequenceGate: a tier-0 row anchored on asserter
// must price the interim window — the CLI refuses without --interim or
// --finding, accepts a symbol-citing statement and a filed finding ref, and
// refuses ghost ids and prose that names nothing from the row.
func TestAnsweredCLIDeferredConsequenceGate(t *testing.T) {
	const reason = "commitBatch consumes prev:state before the assertion runs"

	// (1) refusal: asserter anchor, no pricing
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", reason, "--anchor", "asserter")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	for _, want := range []string{"anchors on asserter", "finalizeBatch",
		"commitBatch", "--finding F-<id>", "--interim STATEMENT",
		"--override-dismissal"} {
		if !strings.Contains(errS, want) {
			t.Errorf("stderr missing %q:\n%s", want, errS)
		}
	}
	// the refusal is a decision that did not happen
	p := dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "status"); got != "open" {
		t.Fatalf("refused closure changed the status to %q", got)
	}

	// (2) accept: the consequence priced in prose that cites the row's own
	// entry — recorded on the priority as its interim field
	interim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	code, out, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", reason, "--anchor", "asserter",
		"--interim", interim)
	if code != 0 {
		t.Fatalf("interim exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "Q-005: status -> answered") ||
		!strings.Contains(out, "[anchor asserter]") {
		t.Fatalf("interim stdout = %q", out)
	}
	p = dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "interim"); got != interim {
		t.Errorf("interim = %q, want %q", got, interim)
	}

	// (3) accept: the other exit — a filed finding id, recorded as
	// interim_finding
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	dgSeedProbeCampaign(t, root2, cid2)
	dgSeedFinding(t, root2, cid2, "F-1a2b3c4d5e6f")
	code, _, errS = run(t, "--root", root2, "answered", cid2, "Q-005",
		"answered", "--reason", reason, "--anchor", "asserter",
		"--finding", "F-1a2b3c4d5e6f")
	if code != 0 {
		t.Fatalf("finding exit %d: %q", code, errS)
	}
	p = dgStoredPriority(t, root2, cid2, "Q-005")
	if got := objStr(p, "interim_finding"); got != "F-1a2b3c4d5e6f" {
		t.Errorf("interim_finding = %q", got)
	}

	// (4) a ghost finding id is refused as fabricated
	root3 := mkroot(t)
	cid3 := initOne(t, root3)
	t14TestSeed(t, root3, cid3)
	dgSeedProbeCampaign(t, root3, cid3)
	code, _, errS = run(t, "--root", root3, "answered", cid3, "Q-005",
		"answered", "--reason", reason, "--anchor", "asserter",
		"--finding", "F-000000000000")
	if code != 2 || !strings.Contains(errS, "F-000000000000") ||
		!strings.Contains(errS, "does not exist") {
		t.Fatalf("ghost finding: exit %d stderr = %q", code, errS)
	}

	// (5) prose that names nothing from the row is refused — the citation
	// muscle applies to the interim statement too
	root4 := mkroot(t)
	cid4 := initOne(t, root4)
	t14TestSeed(t, root4, cid4)
	dgSeedProbeCampaign(t, root4, cid4)
	code, _, errS = run(t, "--root", root4, "answered", cid4, "Q-005",
		"answered", "--reason", reason, "--anchor", "asserter",
		"--interim", "we looked at it carefully and it holds")
	if code != 2 || !strings.Contains(errS, "names nothing from the "+
		"row's own surface entry") {
		t.Fatalf("uncited interim: exit %d stderr = %q", code, errS)
	}

	// (6) negative control: the rule is row-scoped — a low-risk row anchored
	// on asserter needs no pricing
	root5 := mkroot(t)
	cid5 := initOne(t, root5)
	t14TestSeed(t, root5, cid5)
	dgSeedProbeCampaign(t, root5, cid5)
	dgSeedLowSurface(t, root5, cid5)
	code, _, errS = run(t, "--root", root5, "answered", cid5, "Q-005",
		"answered", "--reason", reason, "--anchor", "asserter")
	if code != 0 {
		t.Fatalf("low-risk row: exit %d: %q", code, errS)
	}
	if strings.Contains(errS, "anchors on asserter") {
		t.Fatalf("row-scoped rule fired on a low-risk row: %q", errS)
	}
}

// TestAnsweredCLIDeferredFlagsArgparse: the FIX-5 flags parse like --passes —
// a bare flag is an argparse error, an option-shaped token is never a value,
// and the = spelling parses identically.
func TestAnsweredCLIDeferredFlagsArgparse(t *testing.T) {
	// a bare --interim / --finding is an argparse error, exit 2
	code, out, errS := run(t, "answered", "C-x", "Q-005", "answered",
		"--reason", "r", "--interim")
	if code != 2 || out != "" ||
		!strings.Contains(errS, "argument --interim: expected one argument") {
		t.Fatalf("bare --interim: exit %d stderr = %q", code, errS)
	}
	code, _, errS = run(t, "answered", "C-x", "Q-005", "answered",
		"--reason", "r", "--finding")
	if code != 2 ||
		!strings.Contains(errS, "argument --finding: expected one argument") {
		t.Fatalf("bare --finding: exit %d stderr = %q", code, errS)
	}
	// an option token after the flag is a missing value, never a value
	code, _, errS = run(t, "answered", "C-x", "Q-005", "answered",
		"--reason", "r", "--interim", "--actor")
	if code != 2 ||
		!strings.Contains(errS, "argument --interim: expected one argument") {
		t.Fatalf("option-shaped value: exit %d stderr = %q", code, errS)
	}
	// the = spelling parses identically (exercised end-to-end on a seeded
	// campaign so the value actually lands)
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	code, _, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason",
		"commitBatch consumes prev:state before the assertion runs",
		"--anchor", "asserter",
		"--interim=until finalizeBatch asserts prev:state, commitBatch "+
			"accepts a stale root")
	if code != 0 {
		t.Fatalf("= spelling exit %d: %q", code, errS)
	}
	p := dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "interim"); got != "until finalizeBatch asserts "+
		"prev:state, commitBatch accepts a stale root" {
		t.Errorf("interim = %q", got)
	}
}

// TestAnsweredCLIDeferredOverride: the deferred rule's escape hatch is the
// logged override, not a bare flag. A bare --override-dismissal on an
// asserter-anchored tier-0 row is refused; an override with a reason closes
// it and records exactly ONE probe.dismissal_overridden — even when the
// reason also carries dismissal vocabulary (the deferred arm defers to the
// dismissal gate, which runs after it with the same opts).
func TestAnsweredCLIDeferredOverride(t *testing.T) {
	// (1) bare override: refused, the priority is untouched
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason",
		"commitBatch consumes prev:state before the assertion runs",
		"--anchor", "asserter", "--override-dismissal")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS,
		"--override-dismissal needs --override-reason") {
		t.Fatalf("stderr = %q, want the override-reason refusal", errS)
	}
	p := dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "status"); got != "open" {
		t.Fatalf("refused closure changed the status to %q", got)
	}

	// (2) override with a reason: closes, announces, exactly one event —
	// with a clean reason AND with a dismissal-vocabulary reason (no double)
	for i, reason := range []string{
		"commitBatch consumes prev:state before the assertion runs",
		"liveness-only, the owner can revert",
	} {
		rroot := mkroot(t)
		rcid := initOne(t, rroot)
		t14TestSeed(t, rroot, rcid)
		dgSeedProbeCampaign(t, rroot, rcid)
		code, out, errS = run(t, "--root", rroot, "answered", rcid, "Q-005",
			"answered", "--reason", reason, "--anchor", "asserter",
			"--override-dismissal", "--override-reason",
			"the operator accepts the interim window in writing for this run",
			"--actor", "operator")
		if code != 0 {
			t.Fatalf("case %d: exit %d: %q", i, code, errS)
		}
		if want := "  dismissal overridden: Q-005 logged as " +
			"probe.dismissal_overridden (actor operator)\n"; !strings.
			Contains(out, want) {
			t.Fatalf("case %d: stdout = %q, want the override notice", i, out)
		}
		evts := dgEventsOfType(t, rroot, rcid, "probe.dismissal_overridden")
		if len(evts) != 1 {
			t.Fatalf("case %d: probe.dismissal_overridden events = %d, "+
				"want exactly 1", i, len(evts))
		}
		data := objAt(evts[0], "data")
		if got := objStr(data, "row_id"); got != "81dfad6492" {
			t.Errorf("case %d: row_id = %q", i, got)
		}
		if got := objStr(data, "actor"); got != "operator" {
			t.Errorf("case %d: actor = %q", i, got)
		}
		if got := objStr(data, "override_reason"); got !=
			"the operator accepts the interim window in writing for this run" {
			t.Errorf("case %d: override_reason = %q", i, got)
		}
	}
}

// TestAnsweredCLILowRiskOverrideLogged pins FIX-8 at the CLI: an explicit
// --override-dismissal with a justification on a NON-high-risk, non-sentinel
// probe row is logged (exactly one probe.dismissal_overridden, announced on
// stdout), and a bare one is refused — it used to exit 0 silently with no
// event and no notice.
func TestAnsweredCLILowRiskOverrideLogged(t *testing.T) {
	// (1) bare override: refused, the priority is untouched
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	dgSeedLowSurface(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "commitBatch re-derives the root itself",
		"--anchor", "consumer", "--override-dismissal")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS,
		"--override-dismissal needs --override-reason") {
		t.Fatalf("stderr = %q, want the override-reason refusal", errS)
	}
	p := dgStoredPriority(t, root, cid, "Q-005")
	if got := objStr(p, "status"); got != "open" {
		t.Fatalf("refused closure changed the status to %q", got)
	}

	// (2) override with a reason: closes, announces, one event
	code, out, errS = run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason", "commitBatch re-derives the root itself",
		"--anchor", "consumer", "--override-dismissal", "--override-reason",
		"the operator accepts the risk in writing for this run",
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "dismissal overridden: Q-005 logged as "+
		"probe.dismissal_overridden (actor operator)") {
		t.Fatalf("stdout = %q, want the override announcement", out)
	}
	evts := dgEventsOfType(t, root, cid, "probe.dismissal_overridden")
	if len(evts) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want 1", len(evts))
	}
	data := objAt(evts[0], "data")
	if got := objStr(data, "row_id"); got != "81dfad6492" {
		t.Errorf("row_id = %q", got)
	}
	if got := objAt(data, "tier").I; got != 2 {
		t.Errorf("tier = %d, want 2", got)
	}
	if got := objAt(data, "assertion_gap").I; got != 1 {
		t.Errorf("assertion_gap = %d, want 1", got)
	}
	if got := objStr(data, "actor"); got != "operator" {
		t.Errorf("actor = %q, want operator", got)
	}
	if got := objStr(data, "override_reason"); got !=
		"the operator accepts the risk in writing for this run" {
		t.Errorf("override_reason = %q", got)
	}
}

// TestAnsweredCLIFindingMustBeLive pins FIX-2 at the CLI: --finding is
// validated on EVERY closure — a ghost id and a terminal finding are refused
// even on a plain (non-probe) priority no disposition gate covers, and a
// live finding closes as before.
func TestAnsweredCLIFindingMustBeLive(t *testing.T) {
	seed := func(t *testing.T) (string, string) {
		root := mkroot(t)
		cid := initOne(t, root)
		t14TestSeed(t, root, cid)
		return root, cid
	}
	// (1) a ghost --finding: refused
	root, cid := seed(t)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason",
		"the drain-capable role is a single multisig, not reachable",
		"--ref", "F-1a2b3c4d5e6f", "--finding", "F-000000000000")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(errS, "F-000000000000") ||
		!strings.Contains(errS, "does not exist") {
		t.Fatalf("stderr = %q, want the ghost-finding refusal", errS)
	}

	// (2) a TERMINAL finding: refused
	root, cid = seed(t)
	dgSeedFinding(t, root, cid, "F-1a2b3c4d5e6f")
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.FindingsDir,
		"F-bbbbbbbbbbbb.json"),
		[]byte(`{"finding_id":"F-bbbbbbbbbbbb","status":"DISPROVED"}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason",
		"the drain-capable role is a single multisig, not reachable",
		"--ref", "F-1a2b3c4d5e6f", "--finding", "F-bbbbbbbbbbbb")
	if code != 2 || !strings.Contains(errS, "DISPROVED") {
		t.Fatalf("terminal --finding: exit %d stderr = %q", code, errS)
	}

	// (3) a live finding: closes as before
	root, cid = seed(t)
	dgSeedFinding(t, root, cid, "F-1a2b3c4d5e6f")
	code, out, errS = run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason",
		"the drain-capable role is a single multisig, not reachable",
		"--ref", "F-1a2b3c4d5e6f", "--finding", "F-1a2b3c4d5e6f")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "Q-001: status -> answered") {
		t.Fatalf("stdout = %q", out)
	}
	p := dgStoredPriority(t, root, cid, "Q-001")
	if got := objStr(p, "interim_finding"); got != "F-1a2b3c4d5e6f" {
		t.Errorf("interim_finding = %q", got)
	}
}
