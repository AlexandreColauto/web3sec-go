package cli

// P1b CLI tests — `move` (ord 42).
//
// Ports: tests/test_cli.py::{test_move_illegal_transition_fails,
// test_move_disproof_lifecycle_adjacent,
// test_move_disproof_adjacent_clear_succeeds} plus the argparse and
// error-shape vectors captured from the live Python CLI (the `move failed:`
// handler line is NOT main's `error: {e}` mapper — exit 2 without a prefix).

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/invariants"
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

// TestMoveRefusesOptionLookalikeValue pins the 2026-09-10 fix. The hand-rolled
// value loops consumed args[i+1] unconditionally, so
//
//	webv2 move <c> <f> DISPROVED --reason --actor
//
// recorded the literal string "--actor" as the reason in the hash chain and
// exited 0 — a typo written into the audit trail, with the attribution
// degraded to "cli". argparse refuses the token: exit 2, "expected one
// argument", and nothing logged.
func TestMoveRefusesOptionLookalikeValue(t *testing.T) {
	c, root := t15Campaign(t, "move-flag-swallow")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	before := len(eventTypes(t, c))

	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DISPROVED", "--reason", "--actor")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (argparse): %q", code, errS)
	}
	if !strings.Contains(errS, "argument --reason: expected one argument") {
		t.Errorf("stderr = %q, want the argparse message", errS)
	}
	if after := len(eventTypes(t, c)); after != before {
		t.Errorf("events %d -> %d: a refused command must not write",
			before, after)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(f, "status"); got != "HYPOTHESIS" {
		t.Errorf("status = %q, want HYPOTHESIS (the move must not happen)", got)
	}
}

// TestNoUnguardedValueConsumption is the standing guard for the whole family:
// every `case a == "--flag" && i+1 < len(args):` in this package must also
// refuse a token that looks like an option, or the next typo becomes a value
// again. flagValue in cmd_exec.go is the seam; the check is source-level
// because the alternative is one test per verb.
func TestNoUnguardedValueConsumption(t *testing.T) {
	unguarded := regexp.MustCompile(
		`case a == "--[a-z0-9-]+" && i\+1 < len\(args\):$`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if unguarded.MatchString(strings.TrimSpace(line)) {
				bad = append(bad, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("value-consuming cases must use `&& !looksLikeOption("+
			"args[i+1])` (or flagValue): %s", strings.Join(bad, ", "))
	}
}

// TestMoveRefusesOptionLookalikeAcrossVerbs spot-checks the same shape on the
// other parsers the sweep touched, so a re-introduced hand-rolled loop is
// caught outside `move` too.
func TestMoveRefusesOptionLookalikeAcrossVerbs(t *testing.T) {
	c, root := t15Campaign(t, "flag-swallow-verbs")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"verdict", c.CampaignID, fid, "--verdict", "--actor"},
			"argument --verdict: expected one argument"},
		{[]string{"waive", c.CampaignID, "submit", "--reason", "--actor"},
			"argument --reason: expected one argument"},
		{[]string{"move", c.CampaignID, fid, "DISPROVED",
			"--actor", "--reason"},
			"argument --actor: expected one argument"},
	}
	for _, tc := range cases {
		before := len(eventTypes(t, c))
		code, _, errS := run(t, append([]string{"--root", root},
			tc.args...)...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2 (%q)", tc.args, code, errS)
		}
		if !strings.Contains(errS, tc.want) {
			t.Errorf("%v: stderr = %q, want %q", tc.args, errS, tc.want)
		}
		if after := len(eventTypes(t, c)); after != before {
			t.Errorf("%v: wrote %d event(s)", tc.args, after-before)
		}
	}
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
		"'OUT_OF_SCOPE', 'POSSIBLE', 'PROVISIONALLY_VALID', 'SUPERSEDED'])\n"
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
	fid := validation.ObjStr(f, "finding_id")
	// R3-3: POSSIBLE carries an E2 floor — earn it before the status stamp.
	addFloorEvidence(t, c, fid, "E2")
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
	for _, p := range validation.ObjAt(plan, "priorities").A {
		if validation.ObjStr(p, "sibling_of") == fid {
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
	// R3-3 ripple: the fixture earned the POSSIBLE floor (E2), so the move
	// now reports E2 rather than the pre-floor E0.
	if want := fid + ": DISPROVED (evidence level E2)\n"; out2 != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out2, want)
	}
	if sibs := moveSiblingPriorities(t, c, fid); len(sibs) == 0 {
		t.Fatal("the sibling priority was not added")
	} else if q := validation.ObjStr(sibs[0], "question"); q !=
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
	// R3-3 ripple: the fixture earned the POSSIBLE floor (E2), so the move
	// now reports E2 rather than the pre-floor E0.
	if want := fid + ": DISPROVED (evidence level E2)\n"; out != want {
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
	fid := validation.ObjStr(f, "finding_id")
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
	if s := validation.ObjStr(got, "status"); s != "CONFIRMED" {
		t.Fatalf("status = %q", s)
	}
	hist := validation.ObjAt(got, "history").A
	if len(hist) < 2 {
		t.Fatalf("history = %v", hist)
	}
	last := hist[len(hist)-1]
	if a := validation.ObjStr(last, "actor"); a != "golden" {
		t.Fatalf("history actor = %q", a)
	}
	if a := validation.ObjStr(last, "from"); a != "POSSIBLE" {
		t.Fatalf("history from = %q", a)
	}
}

// The default actor is `cli` (args.actor or "cli").
func TestMoveDefaultActorIsCLI(t *testing.T) {
	c, root := t15Campaign(t, "move-actor")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	// R3-3: the move to POSSIBLE now demands the E2 floor first, and this
	// payload hangs off INV-1 — so the invariant must clear the rise
	// guardrail (registry entry + registered artifact + the logged verdict)
	// before the finding's level can rise.
	invModel := validation.VObj(
		kvT("invariants", validation.VArr(validation.VObj(
			kvT("id", validation.VStr("INV-1")),
			kvT("statement", validation.VStr("balances move atomically")),
		))),
	)
	if _, err := invariants.SeedFromModel(c, invModel); err != nil {
		t.Fatal(err)
	}
	cliVerifyInvariant(t, c, "INV-1", "inv1-check.md")
	addFloorEvidence(t, c, fid, "E2")
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"POSSIBLE", "--reason", "triage")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	got, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	hist := validation.ObjAt(got, "history").A
	if len(hist) == 0 {
		t.Fatal("no history row")
	}
	if a := validation.ObjStr(hist[len(hist)-1], "actor"); a != "cli" {
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

// ---- Task 7c: --of (targeted DUPLICATE) + the reopen ----------------------

// TestMoveDuplicateRequiresOf: a DUPLICATE that names nothing can never be
// re-checked. The verb refuses with the repairing flag named, writes nothing,
// and the accepting path records the target on the finding.
func TestMoveDuplicateRequiresOf(t *testing.T) {
	c, root := t15Campaign(t, "move-duplicate")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	before := len(eventTypes(t, c))

	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want := "move failed: move to DUPLICATE must name the duplicate of " +
		"(--of <finding-id>)\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	if after := len(eventTypes(t, c)); after != before {
		t.Fatalf("refused move wrote %d event(s)", after-before)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(f, "status"); st != "HYPOTHESIS" {
		t.Fatalf("refused move left status = %q", st)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != "" {
		t.Fatalf("refused move left duplicate_of = %q", of)
	}

	// The accepting path names a REAL target (the transition refuses a ghost
	// F- id): the fixture ingests a second finding to merge into.
	tid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling",
		"--of", tid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if want := fid + ": DUPLICATE (evidence level E0)\n"; out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != tid {
		t.Fatalf("duplicate_of = %q, want %q", of, tid)
	}
}

// FIX-1 negative controls for the ValueError class: a ghost --of and a
// self-merge are refused as `move failed: ...` (exit 2) and write nothing.
func TestMoveDuplicateGhostTargetRefused(t *testing.T) {
	c, root := t15Campaign(t, "move-ghost-of")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	before := len(eventTypes(t, c))
	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling",
		"--of", "F-000000000000")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "move failed: duplicate of target does not exist: no finding " +
		"'F-000000000000' in " + c.CampaignID + "\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	if after := len(eventTypes(t, c)); after != before {
		t.Fatalf("refused move wrote %d event(s)", after-before)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(f, "status"); st != "HYPOTHESIS" {
		t.Fatalf("refused move left status = %q", st)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != "" {
		t.Fatalf("refused move left duplicate_of = %q", of)
	}
}

func TestMoveDuplicateSelfMergeRefused(t *testing.T) {
	c, root := t15Campaign(t, "move-self-of")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	before := len(eventTypes(t, c))
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling",
		"--of", fid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want := "move failed: a finding cannot be merged into itself (--of '" +
		fid + "' names the moving finding)\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	if after := len(eventTypes(t, c)); after != before {
		t.Fatalf("refused move wrote %d event(s)", after-before)
	}
}

// FIX-1 retarget guard through the verb: a different --of on an
// already-merged finding is refused (exit 2), and the SAME --of is the
// documented accepted no-op (exit 0, current status printed, nothing written).
func TestMoveRetargetDuplicateAndSamePointerNoOp(t *testing.T) {
	c, root := t15Campaign(t, "move-retarget-of")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	tid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	other := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling", "--of", tid)
	if code != 0 {
		t.Fatalf("merge exit %d: %q", code, errS)
	}
	before := len(eventTypes(t, c))

	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "changed my mind", "--of", other)
	if code != 2 {
		t.Fatalf("retarget exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "move failed: " + fid + " is already merged into " + tid +
		"; reopen it first (DUPLICATE -> HYPOTHESIS) before merging into " +
		other + "\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	if after := len(eventTypes(t, c)); after != before {
		t.Fatalf("refused retarget wrote %d event(s)", after-before)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != tid {
		t.Fatalf("refused retarget moved duplicate_of to %q", of)
	}

	// the exact-same pointer is an accepted no-op: exit 0, status printed,
	// no new history row, no event
	code, out, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "re-affirm the merge", "--of", tid)
	if code != 0 {
		t.Fatalf("no-op exit %d: %q", code, errS)
	}
	if want := fid + ": DUPLICATE (evidence level E0)\n"; out != want {
		t.Fatalf("no-op stdout\n%q\nwant\n%q", out, want)
	}
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(validation.ObjAt(f, "history").A); n != 2 {
		t.Fatalf("no-op appended history: %d rows", n)
	}
	if after := len(eventTypes(t, c)); after != before {
		t.Fatalf("no-op wrote %d event(s)", after-before)
	}
}

// TestMoveOfFlagsTheGuard: `--of` never swallows an option-shaped token (the
// 2026-09-10 flag-swallow fix, applied to the new flag).
func TestMoveOfFlagsTheGuard(t *testing.T) {
	code, _, errS := run(t, "move", "C-x", "F-y", "DUPLICATE", "--reason", "r",
		"--of", "--reason")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want := moveUsage + "webv2 move: error: argument --of: expected one " +
		"argument\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestMoveOfTrimsTheValue: the merge pointer is trimmed at the parse layer —
// a spelled-around id (`--of " F-… "`) lands as the bare id, and a blank
// value is the targetless refusal (the transition layer's TrimSpace blank
// check), never a ghost-target error about a whitespace "finding".
func TestMoveOfTrimsTheValue(t *testing.T) {
	c, root := t15Campaign(t, "move-of-trim")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	tid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling",
		"--of", "  "+tid+"  ")
	if code != 0 {
		t.Fatalf("trimmed merge exit %d: %q", code, errS)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != tid {
		t.Fatalf("duplicate_of = %q, want the trimmed %q", of, tid)
	}
	// negative control: a whitespace-only --of is a MISSING target, refused
	// with the targetless message — not a ghost-target error
	f2 := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, _, errS = run(t, "--root", root, "move", c.CampaignID, f2,
		"DUPLICATE", "--reason", "same root cause as the sibling",
		"--of", "   ")
	if code != 2 {
		t.Fatalf("blank --of exit %d, want 2: %q", code, errS)
	}
	want := "move failed: move to DUPLICATE must name the duplicate of " +
		"(--of <finding-id>)\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestMoveReopenDuplicate: DUPLICATE -> HYPOTHESIS through the verb is the
// operator's undo — the target is cleared, the evidence and history survive,
// and every other exit from DUPLICATE stays illegal.
func TestMoveReopenDuplicate(t *testing.T) {
	c, root := t15Campaign(t, "move-reopen")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	// Evidence on the finding BEFORE the merge: the reopen must not drop it
	// (and a terminal status refuses AddEvidence — the merge froze the record).
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-move-reopen")),
		// E0: the floor of a HYPOTHESIS — no level rise, so the invariant
		// guard (which the CLI harness wires) stays out of this test.
		kv("level", validation.VStr("E0")),
		kv("type", validation.VStr("static-analysis")),
		kv("description", validation.VStr("the receipt that mattered")),
	)); err != nil {
		t.Fatal(err)
	}
	// The merge target is a REAL finding (the transition refuses a ghost id).
	tgt := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "looks like the sibling",
		"--of="+tgt)
	if code != 0 {
		t.Fatalf("merge exit %d: %q", code, errS)
	}
	// Only HYPOTHESIS is a legal target from DUPLICATE.
	code, _, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"POSSIBLE", "--reason", "straight back up")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if want := "move failed: DUPLICATE -> POSSIBLE is not a legal transition " +
		"(legal: ['HYPOTHESIS'])\n"; errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}

	code, out, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"HYPOTHESIS", "--reason", "the two roots are not the same bug")
	if code != 0 {
		t.Fatalf("reopen exit %d: %q", code, errS)
	}
	if want := fid + ": HYPOTHESIS (evidence level E0)\n"; out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(f, "status"); st != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS", st)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != "" {
		t.Fatalf("reopen left duplicate_of = %q", of)
	}
	if n := len(validation.ObjAt(f, "evidence").A); n == 0 {
		t.Fatal("the reopen dropped the finding's evidence")
	}
	hist := validation.ObjAt(f, "history").A
	last := hist[len(hist)-1]
	if validation.ObjStr(last, "from") != "DUPLICATE" || validation.ObjStr(last, "to") != "HYPOTHESIS" {
		t.Fatalf("last history row = %v, want DUPLICATE -> HYPOTHESIS",
			validation.CanonCompact(last))
	}
}

// TestMoveOfRefusedOffDuplicate pins the round-3 inert-flag contract for
// --of: the flag is consumed ONLY by a move whose to_status is DUPLICATE
// (the merge writes the dedup pointer; the reopen clears it without ever
// reading --of), so any other to_status refuses it at exit 2 before the
// campaign is even opened — never silently dropped at exit 0.
func TestMoveOfRefusedOffDuplicate(t *testing.T) {
	c, root := t15Campaign(t, "move-of-inert")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	tid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	before := len(eventTypes(t, c))

	var code int
	var out, errS string
	for _, to := range []string{"HYPOTHESIS", "POSSIBLE", "CONFIRMED",
		"DISPROVED"} {
		code, out, errS = run(t, "--root", root, "move", c.CampaignID, fid,
			to, "--reason", "wearing --of for no reason", "--of", tid)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2: %q", to, code, errS)
		}
		if out != "" {
			t.Fatalf("%s: stdout = %q", to, out)
		}
		want := "move: --of records the duplicate-of pointer of a move to " +
			"DUPLICATE — '" + to + "' is not one, so there is no merge " +
			"pointer to write: drop --of\n"
		if errS != want {
			t.Fatalf("%s: stderr\n%q\nwant\n%q", to, errS, want)
		}
	}
	// the = spelling with an empty value is refused the same way: the
	// refusal keys on the flag being present, not on its value
	code, _, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"CONFIRMED", "--reason", "r", "--of=")
	if code != 2 || !strings.Contains(errS, "drop --of") {
		t.Fatalf("empty --of=: exit %d stderr = %q", code, errS)
	}
	// nothing logged by the refusals
	if after := len(eventTypes(t, c)); after != before {
		t.Fatalf("refused moves wrote %d event(s)", after-before)
	}

	// the reopen path: the merge still works, and a reopen that wears --of
	// is refused (the reopen clears the pointer, it never reads one) —
	// then the bare reopen still undoes the merge
	code, _, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"DUPLICATE", "--reason", "same root cause as the sibling",
		"--of", tid)
	if code != 0 {
		t.Fatalf("merge exit %d: %q", code, errS)
	}
	code, _, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"HYPOTHESIS", "--reason", "the two roots are not the same bug",
		"--of", tid)
	if code != 2 || !strings.Contains(errS, "drop --of") {
		t.Fatalf("reopen with --of: exit %d stderr = %q", code, errS)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if st := validation.ObjStr(f, "status"); st != "DUPLICATE" {
		t.Fatalf("refused reopen left status = %q", st)
	}
	if of := validation.ObjStr(validation.ObjAt(f, "dedup"), "duplicate_of"); of != tid {
		t.Fatalf("refused reopen left duplicate_of = %q", of)
	}
	code, out, errS = run(t, "--root", root, "move", c.CampaignID, fid,
		"HYPOTHESIS", "--reason", "the two roots are not the same bug")
	if code != 0 {
		t.Fatalf("bare reopen exit %d: %q", code, errS)
	}
	if want := fid + ": HYPOTHESIS (evidence level E0)\n"; out != want {
		t.Fatalf("bare reopen stdout\n%q\nwant\n%q", out, want)
	}
}

// TestMoveAdjacentFlagConflictRefused pins r6 issue 5: mutually exclusive
// answers must not silently resolve to whichever the library prefers.
func TestMoveAdjacentFlagConflictRefused(t *testing.T) {
	c, root := t15Campaign(t, "move-conflict")
	fid := moveLifecycleFinding(t, c)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid, "DISPROVED",
		"--reason", "ruled out the theft path as filed",
		"--adjacent", "the timelock window was never probed",
		"--adjacent-clear")
	if code != 2 || !strings.Contains(errS, "mutually exclusive") {
		t.Fatalf("the conflict must be refused: exit %d %q", code, errS)
	}
}

// TestMoveAdjacentEmptyEqualsFormConflict (r7-3): --adjacent= is a SET
// --adjacent with an empty value — with --adjacent-clear it is the same
// contradiction the space form refuses, not a silent pass.
func TestMoveAdjacentEmptyEqualsFormConflict(t *testing.T) {
	c, root := t15Campaign(t, "move-conflict-eq")
	fid := moveLifecycleFinding(t, c)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DISPROVED", "--reason", "ruled out the theft path as filed",
		"--adjacent=", "--adjacent-clear")
	if code != 2 || !strings.Contains(errS, "mutually exclusive") {
		t.Fatalf("empty-value conflict must refuse: exit %d %q", code, errS)
	}
}

// TestMoveAdjacentEmptyValueStillNamed (r7-3 companion): --adjacent= alone
// is a NAMED adjacent with an empty name — the library's own blank guard
// answers it, never a silent no-op.
func TestMoveAdjacentEmptyValueStillNamed(t *testing.T) {
	c, root := t15Campaign(t, "move-adj-empty")
	fid := moveLifecycleFinding(t, c)
	code, _, errS := run(t, "--root", root, "move", c.CampaignID, fid,
		"DISPROVED", "--reason", "ruled out the theft path as filed",
		"--adjacent=")
	if code == 0 || !strings.Contains(errS, "adjacent") {
		t.Fatalf("empty adjacent name must be answered by the blank guard: "+
			"exit %d %q", code, errS)
	}
}
