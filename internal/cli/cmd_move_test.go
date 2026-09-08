package cli

// P1b CLI tests — `move` (ord 42).
//
// Ports: tests/test_cli.py::{test_move_illegal_transition_fails,
// test_move_disproof_lifecycle_adjacent,
// test_move_disproof_adjacent_clear_succeeds} plus the argparse and
// error-shape vectors captured from the live Python CLI (the `move failed:`
// handler line is NOT main's `error: {e}` mapper — exit 2 without a prefix).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// moveIngestFIDRe is the `ingested F-xxx [STATUS]` line's id.
var moveIngestFIDRe = regexp.MustCompile(`ingested (F-[0-9a-z]+)`)

// moveLadderPayload is tests/test_cli.py::_ingest's payload.
const moveLadderPayload = `{"title":"reentrancy drain hypothesis",` +
	`"root_cause":{"class":"reentrancy","description":"withdraw re-enters ` +
	`the vault before the balance updates"},"affected":[{"path":` +
	`"src/Vault.sol","contract":"Vault","function":"withdraw"}],` +
	`"attacker":{"profile":"EOA","capabilities":[]},` +
	`"invariant":{"id":"INV-1","statement":"balances move atomically"}}`

// moveIngest is tests/test_cli.py::_ingest: ingest one payload through the
// CLI and return the minted finding id.
func moveIngest(t *testing.T, root, cid, payload string) string {
	t.Helper()
	p := t14TestWrite(t, root, "hyp.json", payload)
	code, out, errS := run(t, "--root", root, "ingest", cid, "--json-file", p)
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	m := moveIngestFIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("ingest output missing id: %q", out)
	}
	return m[1]
}

// Port of test_move_illegal_transition_fails: HYPOTHESIS -> CONFIRMED is
// illegal; the CLI surfaces the transition table (exit 2, `move failed:`
// prefix, no `error:` mapper).
func TestMoveIllegalTransitionFails(t *testing.T) {
	c, root := t15Campaign(t, "move-ladder")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"CONFIRMED", "--reason", "jump straight to top")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "move failed: HYPOTHESIS -> CONFIRMED is not a legal transition " +
		"(legal: ['DISPROVED', 'DUPLICATE', 'INFORMATIONAL', 'NEEDS_RESEARCH', " +
		"'OUT_OF_SCOPE', 'POSSIBLE', 'PROVISIONALLY_VALID'])\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// moveLifecycleModel is _lifecycle_cli_finding's protocol model (two gateway
// contracts whose entry points carry lifecycle verbs).
func moveLifecycleModel() validation.Value {
	return validation.VObj(
		kvT("protocol_id", validation.VStr("sib")),
		kvT("name", validation.VStr("Sib")),
		kvT("contracts", validation.VArr(
			validation.VObj(
				kvT("name", validation.VStr("L1Gateway")),
				kvT("path", validation.VStr("a.sol")),
				kvT("entry_points", validation.VArr(
					validation.VStr("deposit"),
					validation.VStr("finalizeWithdrawal")))),
			validation.VObj(
				kvT("name", validation.VStr("L2Gateway")),
				kvT("path", validation.VStr("b.sol")),
				kvT("entry_points", validation.VArr(
					validation.VStr("withdraw"),
					validation.VStr("drop")))))),
		kvT("actors", validation.VArr()),
		kvT("assets", validation.VArr()),
		kvT("relations", validation.VArr()),
		kvT("state_machines", validation.VArr(validation.VObj(
			kvT("name", validation.VStr("rollup")),
			kvT("states", validation.VArr(validation.VObj(
				kvT("id", validation.VStr("open"))))),
			kvT("transitions", validation.VArr(validation.VObj(
				kvT("from", validation.VStr("open")),
				kvT("to", validation.VStr("fin")),
				kvT("trigger", validation.VStr("finalize")))))))),
	)
}

// moveLifecycleFinding is _lifecycle_cli_finding: a campaign with the model
// artifact + default plan and one lifecycle finding advanced to POSSIBLE.
func moveLifecycleFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	model := moveLifecycleModel()
	if err := os.MkdirAll(c.ArtifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(
		filepath.Join(c.ArtifactsDir, "protocol_model.json"), model,
		"protocol_model"); err != nil {
		t.Fatal(err)
	}
	plan, err := planner.DefaultPlanFromModel(c, model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		kvT("title", validation.VStr("drop and withdraw diverge in the "+
			"gateway pair")),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("logic-error")),
			kvT("description", validation.VStr("two roots share the struct")))),
		kvT("affected", validation.VArr(
			validation.VObj(
				kvT("path", validation.VStr("a.sol")),
				kvT("contract", validation.VStr("L1Gateway"))),
			validation.VObj(
				kvT("path", validation.VStr("b.sol")),
				kvT("contract", validation.VStr("L2Gateway"))))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("EOA")),
			kvT("capabilities", validation.VArr()))),
	)
	f, err := findings.IngestHypothesis(c, payload, "lifecycle", "39", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "",
		"", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

// moveSiblingPriorities are the plan's SIBLING rows for one finding.
func moveSiblingPriorities(t *testing.T, c *state.Campaign,
	fid string) []validation.Value {
	t.Helper()
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	var out []validation.Value
	for _, p := range objAt(plan, "priorities").A {
		if objStr(p, "sibling_of") == fid {
			out = append(out, p)
		}
	}
	return out
}

// Port of test_move_disproof_lifecycle_adjacent: DISPROVED on a lifecycle
// finding is refused until the adjacent property is named, and naming it
// spawns the sibling priority.
func TestMoveDisproofLifecycleAdjacent(t *testing.T) {
	c, root := t15Campaign(t, "move-sibling")
	fid := moveLifecycleFinding(t, c)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DISPROVED", "--reason", "ruled out theft path", "--actor", "t")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want := "move failed: DISPROVED on a lifecycle finding must name the " +
		"adjacent unchecked property (--adjacent '...') or attest it clear " +
		"(--adjacent-clear --reason R)\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	code2, out2, err2 := run(t, "--root", root, "move", c.CampaignID, fid,
		"DISPROVED", "--reason", "ruled out theft path",
		"--adjacent", "the other root in the struct", "--actor", "t")
	if code2 != 0 {
		t.Fatalf("exit %d: %q", code2, err2)
	}
	if want := fid + ": DISPROVED (evidence level E0)\n"; out2 != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out2, want)
	}
	if sibs := moveSiblingPriorities(t, c, fid); len(sibs) == 0 {
		t.Fatal("the sibling priority was not added")
	} else if q := objStr(sibs[0], "question"); q !=
		"Check the adjacent unchecked property: the other root in the struct" {
		t.Fatalf("sibling question = %q", q)
	}
}

// Port of test_move_disproof_adjacent_clear_succeeds: attesting the sibling
// is already checked records plan.sibling_cleared and adds no priority.
func TestMoveDisproofAdjacentClearSucceeds(t *testing.T) {
	c, root := t15Campaign(t, "move-clear")
	fid := moveLifecycleFinding(t, c)
	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DISPROVED", "--reason", "sibling already checked",
		"--adjacent-clear", "--actor", "t")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if want := fid + ": DISPROVED (evidence level E0)\n"; out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	if sibs := moveSiblingPriorities(t, c, fid); len(sibs) != 0 {
		t.Fatalf("no sibling priority expected, got %d", len(sibs))
	}
}

// The success path the golden suite walks: HYPOTHESIS -> POSSIBLE ->
// CONFIRMED on a finding that satisfies every gate clause, with the
// evidence level from findings.finding_level on the success line.
func TestMoveSuccessHypothesisToConfirmed(t *testing.T) {
	c, root := t15Campaign(t, "move-confirm")
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := cliPassingLogicError(t, c)
	fid := objStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"POSSIBLE", "--reason", "triage passed the hostile critic",
		"--actor", "golden")
	if code != 0 {
		t.Fatalf("POSSIBLE exit %d: %q", code, errS)
	}
	if want := fid + ": POSSIBLE (evidence level E4)\n"; out != want {
		t.Fatalf("POSSIBLE stdout\n%q\nwant\n%q", out, want)
	}
	code, out, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"CONFIRMED", "--reason", "the PoC reproduces on the pinned fork",
		"--actor", "golden")
	if code != 0 {
		t.Fatalf("CONFIRMED exit %d: %q", code, errS)
	}
	if want := fid + ": CONFIRMED (evidence level E4)\n"; out != want {
		t.Fatalf("CONFIRMED stdout\n%q\nwant\n%q", out, want)
	}
	got, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if s := objStr(got, "status"); s != "CONFIRMED" {
		t.Fatalf("status = %q", s)
	}
	hist := objAt(got, "history").A
	if len(hist) < 2 {
		t.Fatalf("history = %v", hist)
	}
	last := hist[len(hist)-1]
	if a := objStr(last, "actor"); a != "golden" {
		t.Fatalf("history actor = %q", a)
	}
	if a := objStr(last, "from"); a != "POSSIBLE" {
		t.Fatalf("history from = %q", a)
	}
}

// The default actor is `cli` (args.actor or "cli").
func TestMoveDefaultActorIsCLI(t *testing.T) {
	c, root := t15Campaign(t, "move-actor")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"POSSIBLE", "--reason", "triage")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	got, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	hist := objAt(got, "history").A
	if len(hist) == 0 {
		t.Fatal("no history row")
	}
	if a := objStr(hist[len(hist)-1], "actor"); a != "cli" {
		t.Fatalf("history actor = %q, want cli", a)
	}
}

// The argparse surface, pinned byte-for-byte from the live Python CLI.
func TestMoveMissingReasonIsArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "POSSIBLE")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := moveUsage + "webv2 move: error: the following arguments are " +
		"required: --reason\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestMoveMissingToStatusIsArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := moveUsage + "webv2 move: error: the following arguments are " +
		"required: to_status, --reason\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestMoveMissingFindingAndToStatusIsArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := moveUsage + "webv2 move: error: the following arguments are " +
		"required: finding, to_status, --reason\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestMoveReasonExpectedOneArgumentIsArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "POSSIBLE", "--reason")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := moveUsage + "webv2 move: error: argument --reason: expected one " +
		"argument\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// A store_true flag given an explicit value is argparse's "ignored explicit
// argument".
func TestMoveAdjacentClearExplicitValueIsArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "POSSIBLE", "--reason", "r",
		"--adjacent-clear=x")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := moveUsage + "webv2 move: error: argument --adjacent-clear: " +
		"ignored explicit argument 'x'\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// Extra positionals and unknown flags are reported by the ROOT parser — but
// only once the subparser's required arguments are satisfied.
func TestMoveExtraPositionalIsRootArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "POSSIBLE", "--reason", "r",
		"extra")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := t14TopUsage + "webv2: error: unrecognized arguments: extra\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestMoveUnknownFlagIsRootArgparse(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "POSSIBLE", "--reason", "r",
		"--bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := t14TopUsage + "webv2: error: unrecognized arguments: --bogus\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// Unrecognized tokens are listed in ARGV order, not grouped by kind.
func TestMoveMixedUnrecognizedIsArgvOrder(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "POSSIBLE", "--reason", "r",
		"extra", "--bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := t14TopUsage + "webv2: error: unrecognized arguments: extra --bogus\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// Positionals are assigned greedily, so the overflow is the LAST one.
func TestMoveGreedyPositionalOverflow(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "extra", "F-y", "POSSIBLE",
		"--reason", "r")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := t14TopUsage + "webv2: error: unrecognized arguments: POSSIBLE\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// Missing required arguments win over the unknown-flag report (argparse
// parses the subparser before the root parser sees the leftovers).
func TestMoveUnknownFlagStillReportsMissing(t *testing.T) {
	code, _, errS := run(t, "move", "--bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := moveUsage + "webv2 move: error: the following arguments are " +
		"required: campaign, finding, to_status, --reason\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// An unknown campaign keeps main's generic `error: {e}` handler (exit 1).
func TestMoveUnknownCampaign(t *testing.T) {
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "move", "C-000000000000",
		"F-x", "POSSIBLE", "--reason", "r")
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasPrefix(errS, "error: no such campaign: "+
		filepath.Join(root, "campaigns", "C-000000000000")+"\n") {
		t.Fatalf("stderr = %q", errS)
	}
	if !strings.Contains(errS, "hint: no campaigns/ under "+root) {
		t.Fatalf("stderr missing hint: %q", errS)
	}
}

// An unknown finding is a FileNotFoundError in Python: main's handler, not
// cmd_move's `move failed:` line (exit 1).
func TestMoveUnknownFinding(t *testing.T) {
	c, root := t15Campaign(t, "move-unknown")
	code, _, errS := run(t, "--root", root, "move", c.CampaignID,
		"F-000000000000", "POSSIBLE", "--reason", "r")
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	want := "error: no finding 'F-000000000000' in " + c.CampaignID + "\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// A same-status move is a no-op that still prints the current status (the
// transition table's own short-circuit).
func TestMoveSameStatusIsANoOp(t *testing.T) {
	c, root := t15Campaign(t, "move-noop")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"HYPOTHESIS", "--reason", "no change")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if want := fid + ": HYPOTHESIS (evidence level E0)\n"; out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}
