package cli

// cmd_ladder tests — `ladder` (ord 53): argparse vectors, the full variant
// ladder lifecycle through the CLI (start -> add -> repro -> set-maximal ->
// explore -> complete -> report) and every captured failure vector.

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/maximization"
	"websec/internal/sandbox"
	"websec/internal/state"
)

var t23LADRe = regexp.MustCompile(`ladder (LAD-[0-9a-z]+) started`)
var t23RungRe = regexp.MustCompile(`rung (R-[0-9a-z]+) recorded`)

func TestLadderArgparse(t *testing.T) {
	t23WantHelp(t, []string{"ladder", "--help"}, t23LadderHelp)
	t23WantHelp(t, []string{"ladder", "C", "start", "--help"}, t23LadderHelp)
	t23WantArgparse(t, []string{"ladder"}, t23LadderUsage,
		"webv2 ladder: error: the following arguments are required: "+
			"campaign, action\n")
	t23WantArgparse(t, []string{"ladder", "C"}, t23LadderUsage,
		"webv2 ladder: error: the following arguments are required: action\n")
	t23WantArgparse(t, []string{"ladder", "C", "bogus"}, t23LadderUsage,
		"webv2 ladder: error: argument action: invalid choice: 'bogus' "+
			"(choose from 'start', 'show', 'explore', 'add', 'repro', "+
			"'disprove', 'set-maximal', 'complete', 'waive', 'reopen', "+
			"'report')\n")
	t23WantArgparse(t, []string{"ladder", "C", "start", "--capital", "abc"},
		t23LadderUsage,
		"webv2 ladder: error: argument --capital: invalid float value: "+
			"'abc'\n")
	t23WantArgparse(t, []string{"ladder", "C", "start", "F", "--ratio", "z"},
		t23LadderUsage,
		"webv2 ladder: error: argument --ratio: invalid float value: 'z'\n")
	t23WantArgparse(t, []string{"ladder", "C", "start", "F", "R", "ax",
		"one", "two"}, t14TopUsage,
		"webv2: error: unrecognized arguments: one two\n")
	t23WantArgparse(t, []string{"ladder", "C", "start", "F", "--name", "-x"},
		t23LadderUsage,
		"webv2 ladder: error: argument --name: expected one argument\n")
}

// t23StartLadder runs `ladder <cid> start <fid>` and returns the ladder id.
func t23StartLadder(t *testing.T, root, cid, fid string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "ladder", cid, "start", fid)
	if code != 0 {
		t.Fatalf("start exit %d: %q", code, errS)
	}
	want := "ladder "
	m := t23LADRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("start output %q", out)
	}
	if !strings.Contains(out, "started for "+fid+" (rung 0 = the finding's "+
		"current claim)\n") || !strings.HasPrefix(out, want) {
		t.Fatalf("start output %q", out)
	}
	return m[1]
}

// t23Exec registers one sandbox exec record for the repro step.
func t23Exec(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f := fid
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		FindingID: &f, ReportedBy: "test-harness", StdoutText: "PASS: test_x\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return objStr(rec, "exec_id")
}

func TestLadderStartAndShow(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-start")
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID, "show",
		fid)
	if code != 1 || out != "" {
		t.Fatalf("show before start: exit %d out %q err %q", code, out, errS)
	}
	want := fid + ": no ladder yet — `webv2 ladder " + c.CampaignID +
		" start " + fid + "`\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	ladID := t23StartLadder(t, root, c.CampaignID, fid)
	if again := t23StartLadder(t, root, c.CampaignID, fid); again != ladID {
		t.Fatalf("start not idempotent: %s vs %s", ladID, again)
	}
	code, out, errS = run(t, "--root", root, "ladder", c.CampaignID, "show",
		fid)
	if code != 0 {
		t.Fatalf("show exit %d: %q", code, errS)
	}
	lad, err := maximization.LoadLadder(c, fid)
	if err != nil || lad == nil {
		t.Fatalf("load ladder: %v", err)
	}
	if out != validation.DumpIndentedASCII(*lad)+"\n" {
		t.Fatalf("show stdout\n%q\nwant\n%q", out, validation.DumpIndentedASCII(*lad)+"\n")
	}
}

// TestLadderExploreNaturalAxisForm pins the FIXED-IN-GO behavior
// (python-twin-issues P3): `explore F <axis>` binds the positional to the
// axis. The reference bound it to the rung slot instead and failed with
// "unknown axis None", so the natural call was unusable as documented.
// The legacy `explore F <dummy-rung> <axis>` form keeps working.
func TestLadderExploreNaturalAxisForm(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-natural")
	t23StartLadder(t, root, c.CampaignID, fid)
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID,
		"explore", fid, "capital-minimization", "--note",
		"no capital reduction possible on this path")
	if code != 0 {
		t.Fatalf("natural form exit %d: %q", code, errS)
	}
	if want := "axis capital-minimization explored (1/5: " +
		"capital-minimization)\n"; out != want {
		t.Fatalf("natural form stdout %q, want %q", out, want)
	}
	code, out, errS = run(t, "--root", root, "ladder", c.CampaignID,
		"explore", fid, "-", "precondition-removal", "--note",
		"the precondition is structural and cannot be removed")
	if code != 0 {
		t.Fatalf("legacy form exit %d: %q", code, errS)
	}
	if want := "axis precondition-removal explored (2/5: " +
		"capital-minimization, precondition-removal)\n"; out != want {
		t.Fatalf("legacy form stdout %q, want %q", out, want)
	}
}

func TestLadderStartMissingFinding(t *testing.T) {
	c, root, _ := t23Campaign(t, "ladder-nofind")
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID, "start",
		"F-missing0001")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	if errS != "error: no finding 'F-missing0001' in "+c.CampaignID+"\n" {
		t.Fatalf("stderr %q", errS)
	}
}

// TestLadderFailures pins the `ladder <action> failed: <e>` handler (exit 2).
func TestLadderFailures(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-failures")
	t23StartLadder(t, root, c.CampaignID, fid)
	lad, err := maximization.LoadLadder(c, fid)
	if err != nil || lad == nil {
		t.Fatalf("load ladder: %v", err)
	}
	base := objStr(t14List(*lad, "variants").A[0], "rung_id")
	axes := "('capital-minimization', 'precondition-removal', " +
		"'role-conflation', 'ordering-permutation', 'cap-saturation')"
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"explore", fid, "-", "bogus", "--note",
			"a long enough note here"},
			"ladder explore failed: unknown axis 'bogus'; the axes are " +
				axes + "\n"},
		{[]string{"explore", fid, "--note", "a long enough note here"},
			"ladder explore failed: unknown axis None; the axes are " +
				axes + "\n"},
		{[]string{"add", fid, "--name", "dust"},
			"ladder add failed: a variant must name the axis (axes) it " +
				"exploits — that is what makes the search auditable\n"},
		{[]string{"add", fid, "--name", "dust", "--axes", "bogus"},
			"ladder add failed: unknown axis 'bogus'; the axes are " +
				axes + "\n"},
		{[]string{"repro", fid, "R-nope", "--exec", "EXEC-x"},
			"ladder repro failed: \"unknown rung 'R-nope'; rungs: ['" +
				base + "']\"\n"},
		{[]string{"set-maximal", fid},
			"ladder set-maximal failed: \"unknown rung None; rungs: ['" +
				base + "']\"\n"},
		{[]string{"complete", fid},
			"ladder complete failed: ladder not complete: unexplored axes " +
				"['capital-minimization', 'precondition-removal', " +
				"'role-conflation', " +
				"'ordering-permutation', 'cap-saturation'] — add a rung or " +
				"mark each with a written not-applicable note (webv2 ladder " +
				"explore)\n"},
	}
	for _, tc := range cases {
		args := append([]string{"--root", root, "ladder", c.CampaignID},
			tc.args...)
		code, out, errS := run(t, args...)
		if code != 2 || out != "" {
			t.Fatalf("%v: exit %d out %q err %q", tc.args, code, out, errS)
		}
		if errS != tc.want {
			t.Fatalf("%v: stderr\n%q\nwant\n%q", tc.args, errS, tc.want)
		}
	}
}

// TestLadderDisproveNeedsReason is the negative-knowledge gate.
func TestLadderDisproveNeedsReason(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-disprove")
	t23StartLadder(t, root, c.CampaignID, fid)
	lad, err := maximization.LoadLadder(c, fid)
	if err != nil || lad == nil {
		t.Fatalf("load ladder: %v", err)
	}
	rung := objStr(t14List(*lad, "variants").A[0], "rung_id")
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID,
		"disprove", fid, rung)
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	want := "ladder disprove failed: a disproof needs a written reason — " +
		"'didn't work' is not knowledge\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	code, out, errS = run(t, "--root", root, "ladder", c.CampaignID,
		"disprove", fid, rung, "--reason", "a sufficiently long reason")
	if code != 0 {
		t.Fatalf("disprove exit %d: %q", code, errS)
	}
	want = "rung " + rung + " (base) disproved — negative memory queued " +
		"(the next campaign starts smarter)\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

// TestLadderWaive covers the waiver's actor attribution.
func TestLadderWaive(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-waive")
	t23StartLadder(t, root, c.CampaignID, fid)
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID, "waive",
		fid, "--reason", "budget exhausted before the ladder closed")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	if errS != "ladder waive failed: a waiver needs a named actor\n" {
		t.Fatalf("stderr %q", errS)
	}
	code, out, errS = run(t, "--root", root, "ladder", c.CampaignID, "waive",
		fid, "--reason", "budget exhausted before the ladder closed",
		"--actor", "operator")
	if code != 0 {
		t.Fatalf("waive exit %d: %q", code, errS)
	}
	if out != "ladder for "+fid+" WAIVED (logged, actor operator)\n" {
		t.Fatalf("stdout %q", out)
	}
}

// TestLadderReopen (B2): the CLI path for `ladder reopen` — an open ladder
// is refused, a closed (waived) ladder reopens only with a written reason,
// and the success line is asserted.
func TestLadderReopen(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-reopen")
	ladID := t23StartLadder(t, root, c.CampaignID, fid)
	// an open ladder needs no reopening
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID,
		"reopen", fid, "--reason", "nope", "--actor", "op")
	if code != 2 || out != "" {
		t.Fatalf("open reopen exit %d out %q", code, out)
	}
	if errS != "ladder reopen failed: ladder is already open — nothing to "+
		"reopen\n" {
		t.Fatalf("stderr %q", errS)
	}
	// close it (waive), then reopen requires a written reason
	if code, _, errS = run(t, "--root", root, "ladder", c.CampaignID, "waive",
		fid, "--reason", "budget exhausted before the ladder closed",
		"--actor", "operator"); code != 0 {
		t.Fatalf("waive exit %d: %q", code, errS)
	}
	code, out, errS = run(t, "--root", root, "ladder", c.CampaignID, "reopen",
		fid, "--actor", "op2")
	if code != 2 || out != "" {
		t.Fatalf("no-reason reopen exit %d out %q", code, out)
	}
	if errS != "ladder reopen failed: reopening a closed ladder needs a "+
		"written reason (the audit trail, not a bypass)\n" {
		t.Fatalf("stderr %q", errS)
	}
	code, out, errS = run(t, "--root", root, "ladder", c.CampaignID, "reopen",
		fid, "--reason", "a cheaper rung appeared after the waiver",
		"--actor", "op2")
	if code != 0 {
		t.Fatalf("reopen exit %d: %q", code, errS)
	}
	if out != "ladder "+ladID+" REOPENED (actor op2) — the closed ladder is "+
		"open again\n" {
		t.Fatalf("stdout %q", out)
	}
}

// TestLadderReportAbsent is the captured `ladder <cid> report` vector.
func TestLadderReportAbsent(t *testing.T) {
	c, root, _ := t23Campaign(t, "ladder-report-absent")
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID, "report")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "{\n  \"finding_id\": null,\n  \"ladder\": null\n}\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

// TestLadderLifecycle drives start -> add -> repro -> set-maximal -> explore
// -> complete -> report through the CLI and asserts every line.
func TestLadderLifecycle(t *testing.T) {
	c, root, fid := t23Campaign(t, "ladder-lifecycle")
	ladID := t23StartLadder(t, root, c.CampaignID, fid)
	rung := t23LifecycleAdd(t, root, c.CampaignID, fid)
	t23LifecycleRepro(t, c, root, fid, rung)
	t23LifecyclePin(t, root, c.CampaignID, fid, rung)
	t23LifecycleExplore(t, root, c.CampaignID, fid)
	t23LifecycleComplete(t, root, c.CampaignID, fid, ladID, rung)
	t23LifecycleReport(t, c, root, fid)
}

// t23LifecycleAdd records the "dust" variant and returns its rung id.
func t23LifecycleAdd(t *testing.T, root, cid, fid string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "ladder", cid, "add",
		fid, "--name", "dust", "--description", "dust the pool with one wei",
		"--axes", "capital-minimization", "--capital", "1", "--ratio", "1",
		"--removes", "victim stakes")
	if code != 0 {
		t.Fatalf("add exit %d: %q", code, errS)
	}
	m := t23RungRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add output %q", out)
	}
	if out != "rung "+m[1]+" recorded: dust (status assumed)\n" {
		t.Fatalf("add stdout %q", out)
	}
	return m[1]
}

// t23LifecycleRepro reproduces the rung against a fresh execution.
func t23LifecycleRepro(t *testing.T, c *state.Campaign, root, fid, rung string) {
	t.Helper()
	exec := t23Exec(t, c, fid)
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID, "repro",
		fid, rung, "--exec", exec)
	if code != 0 {
		t.Fatalf("repro exit %d: %q", code, errS)
	}
	if out != "rung "+rung+" (dust) reproduced from "+exec+
		" — evidence minted onto "+fid+"\n" {
		t.Fatalf("repro stdout %q", out)
	}
}

// t23LifecyclePin pins the claim to the reproduced rung.
func t23LifecyclePin(t *testing.T, root, cid, fid, rung string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "ladder", cid,
		"set-maximal", fid, rung)
	if code != 0 {
		t.Fatalf("set-maximal exit %d: %q", code, errS)
	}
	want := "maximal rung pinned: " + rung + " — claim now follows the " +
		"measurement (extraction 1.0, required capital $1.0)\n"
	if out != want {
		t.Fatalf("set-maximal stdout\n%q\nwant\n%q", out, want)
	}
}

// t23LifecycleExplore walks the four remaining axes; "add" already explored
// capital-minimization, so the counter starts at 2/5.
func t23LifecycleExplore(t *testing.T, root, cid, fid string) {
	t.Helper()
	axes := []string{"cap-saturation", "precondition-removal",
		"role-conflation", "ordering-permutation"}
	for i, axis := range axes {
		code, out, errS := run(t, "--root", root, "ladder", cid,
			"explore", fid, "-", axis, "--note",
			"considered, not applicable here")
		if code != 0 {
			t.Fatalf("explore %s exit %d: %q", axis, code, errS)
		}
		if !strings.HasPrefix(out, "axis "+axis+" explored ("+
			strconv.Itoa(i+2)+"/5: ") {
			t.Fatalf("explore %s stdout %q", axis, out)
		}
	}
}

// t23LifecycleComplete completes the ladder over the maximal rung.
func t23LifecycleComplete(t *testing.T, root, cid, fid, ladID, rung string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "ladder", cid, "complete", fid)
	if code != 0 {
		t.Fatalf("complete exit %d: %q", code, errS)
	}
	if out != "ladder "+ladID+" COMPLETE — maximal "+rung+"\n" {
		t.Fatalf("complete stdout %q", out)
	}
}

// t23LifecycleReport compares the CLI report to the module report.
func t23LifecycleReport(t *testing.T, c *state.Campaign, root, fid string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "ladder", c.CampaignID, "report",
		fid)
	if code != 0 {
		t.Fatalf("report exit %d: %q", code, errS)
	}
	rep, err := maximization.LadderReport(c, fid)
	if err != nil {
		t.Fatalf("ladder report: %v", err)
	}
	if out != validation.DumpIndentedASCII(rep)+"\n" {
		t.Fatalf("report stdout\n%q\nwant\n%q", out, validation.DumpIndentedASCII(rep)+"\n")
	}
}
