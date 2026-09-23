package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// TestRegressOneTargetEndToEnd is this plan's end-to-end branch test: it
// drives the real verbs in sequence — add a target, pin it, record a run,
// read it all back through `audit` — and asserts the joined-up result. It is
// the test that would have caught the P1 "feed validated the declaration and
// never recorded it" defect, which no scoped task review could see.
func TestRegressOneTargetEndToEnd(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := regressAddTarget(t, root, cid)
	// Half-pinned state must be RED, and the red must name the reason: the
	// exit criterion is "every snapshot carries a resolved SHA", so a target
	// that has not been pinned is a suite problem, not a blank.
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code == 0 {
		t.Fatalf("audit PASSed with an unpinned target: %q", out)
	}
	if !strings.Contains(out+errS, "resolved_sha") {
		t.Fatalf("the unpinned-target problem does not name resolved_sha: %q", out+errS)
	}
	sha, _ := regressSnapAndPin(t, root, cid, tid)
	regressRecordRun(t, root, cid, tid)
	regressAuditIsGreen(t, root, cid, sha)
	regressStatusCarriesTheLabel(t, root, cid)
}

// regressAddTarget runs `regress target add` and returns the printed id.
func regressAddTarget(t *testing.T, root, cid string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "regress", cid, "target", "add",
		"--kind", "scabench", "--program", "Acme Vault",
		"--record-id", "acme-vault", "--repo", "acme/vault",
		"--shape", "vault-erc4626", "--commit-hint", "main")
	if code != 0 {
		t.Fatalf("target add exit %d: out=%q err=%q", code, out, errS)
	}
	tid := firstID(out, "T-")
	if tid == "" {
		t.Fatalf("target add printed no T- id: %q", out)
	}
	return tid
}

// regressSnapAndPin snapshots a real git tree and pins the target to that
// snapshot, returning the resolved SHA and the snapshot id.
func regressSnapAndPin(t *testing.T, root, cid, tid string) (string, string) {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitInitCommit(t, target)
	code, out, errS := run(t, "--root", root, "snap", cid, target)
	if code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	snapID := firstID(out, "src-")
	if snapID == "" {
		t.Fatalf("snap printed no snapshot id: %q", out)
	}
	sha := gitRevParse(t, target)
	code, out, errS = run(t, "--root", root, "regress", cid, "target", "pin",
		tid, "--resolved-sha", sha, "--snapshot", snapID, "--actor", "operator")
	if code != 0 {
		t.Fatalf("target pin exit %d: out=%q err=%q", code, out, errS)
	}
	return sha, snapID
}

// regressRecordRun records one eval-gold run and checks the D8 label is in the
// operator's face.
func regressRecordRun(t *testing.T, root, cid, tid string) {
	t.Helper()
	score := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(score, []byte(evalGoldCLIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "regress", cid, "run",
		"--target", tid, "--scorer", "eval-gold", "--score-file", score)
	if code != 0 {
		t.Fatalf("run exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "rediscovery") {
		t.Fatalf("the run output does not carry the D8 label: %q", out)
	}
}

// regressAuditIsGreen is the joined-up assertion: after the pin and the run,
// the audit passes and its report carries the section, the SHA and the label.
func regressAuditIsGreen(t *testing.T, root, cid, sha string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit exit %d after pin+run: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{"regression_suite", sha, "rediscovery"} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit --json does not carry %q: %q", want, out)
		}
	}
}

// regressStatusCarriesTheLabel checks the human view carries the same label.
func regressStatusCarriesTheLabel(t *testing.T, root, cid string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "regress", cid, "status")
	if code != 0 {
		t.Fatalf("status exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "measurement: rediscovery") {
		t.Fatalf("status = %q, want the measurement label", out)
	}
}

// evalGoldCLIFixture is a REAL scorer output — the same capture
// internal/regression's run_test.go pins, verbatim from
// `python3 scripts/eval-gold.py --gold <one-gold file> --campaign <empty
// campaign>`: `found` and `missed` are arrays of gold ids (the plan's
// hand-written `"found": 3` is a vocabulary the scorer does not have), and the
// verdict is FAIL because a ScaBench target has no G-01/G-02 pass concept
// (the plan's own Step 21).
const evalGoldCLIFixture = `{
  "found": [],
  "missed": ["G-99"],
  "false_positives": 0,
  "pass": false,
  "bonus": false,
  "verdict": "FAIL",
  "verdict_note": "",
  "operator_confirmed": {}
}
`

func TestRegressRefusalsAreExit1AndArgparseErrorsAreExit2(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	// usage error (argparse contract)
	code, _, errS := run(t, "--root", root, "regress", cid, "target", "add",
		"--kind", "scabench", "--program", "Acme", "--shape", "vault-erc4626")
	if code != 2 || !strings.Contains(errS, "usage: webv2 regress") {
		t.Fatalf("code = %d err = %q, want 2 with the usage block", code, errS)
	}
	// refusal (a real answer of "no")
	code, _, errS = run(t, "--root", root, "regress", cid, "target", "pin",
		"T-000000000000", "--resolved-sha", strings.Repeat("a", 40),
		"--snapshot", "src-abc123def456")
	if code != 1 || !strings.Contains(errS, "no target") {
		t.Fatalf("code = %d err = %q, want 1 naming the missing target", code, errS)
	}
}

// regressControlArgs is one valid `target add-control` command line, minus the
// program — the flag set the two control tests below share.
func regressControlArgs(cid string) []string {
	return []string{"--root", "", "regress", cid, "target", "add-control",
		"--program", "Exploited Protocol", "--record-id", "exploited-protocol",
		"--repo", "org/exploited-protocol",
		"--incident-url", "https://example.test/incident",
		"--incident-date", "2025-09-01", "--loss-usd", "12500000",
		"--loss-source", "post-mortem §2 (recovered funds excluded)",
		"--pre-patch-sha", strings.Repeat("1", 40),
		"--patch-sha", strings.Repeat("2", 40),
		"--harness-runner", "foundry",
		"--harness-command", "forge test --match-test test_exploit"}
}

// TestRegressControlRefusalsThroughTheVerb drives the two Task 2 refusals
// through the CLI — an uncited loss figure and a handoff for a finding that is
// not CONFIRMED — and then proves each is not refusing everything: the same
// command line with --loss-source lands, and the same handoff lands once the
// finding is CONFIRMED.
func TestRegressControlRefusalsThroughTheVerb(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	uncited := regressControlArgs(cid)
	uncited[1] = root
	assertRegressRefuses(t, dropFlag(uncited, "--loss-source"), "loss_source")
}

// TestRegressHandoffThroughTheVerb is the handoff half: a finding that exists
// but is not CONFIRMED is refused by name, and once it is stamped CONFIRMED
// through the store's own writer the same command records the figure and the
// audit reads it back.
func TestRegressHandoffThroughTheVerb(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := addControlThroughTheVerb(t, root, cid)
	// findings.Transition would need E5 evidence and a sandbox — the operator
	// step's job, not a CLI test's — so the status is stamped directly.
	finding := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := validation.ObjStr(finding, "finding_id")
	handoff := []string{"--root", root, "regress", cid, "target", "handoff",
		tid, "--finding", fid, "--extractable-usd", "900000",
		"--source", "reproduction on the pre-patch commit", "--actor", "operator"}
	code, _, errS := run(t, handoff...)
	if code != 1 || !strings.Contains(errS, "status") {
		t.Fatalf("unconfirmed handoff: code = %d err = %q, want 1 naming status",
			code, errS)
	}
	confirmThroughTheStore(t, c, finding)
	code, out, errS := run(t, handoff...)
	if code != 0 {
		t.Fatalf("handoff exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "extractable_usd=900000") {
		t.Fatalf("handoff output = %q, want the extractable figure", out)
	}
	assertUnpinnedControlAuditIsRed(t, root, cid, fid)
}

// addControlThroughTheVerb records a valid control target through the real verb
// and returns the target id it printed.
func addControlThroughTheVerb(t *testing.T, root, cid string) string {
	t.Helper()
	good := regressControlArgs(cid)
	good[1] = root
	code, out, errS := run(t, good...)
	if code != 0 {
		t.Fatalf("add-control exit %d: out=%q err=%q", code, out, errS)
	}
	tid := firstID(out, "T-")
	if tid == "" {
		t.Fatalf("add-control printed no T- id: %q", out)
	}
	return tid
}

// assertUnpinnedControlAuditIsRed drives the real audit verb and asserts it is
// red for the RIGHT reason: the section carries the handoff and the pre-patch
// pin, and the target is unpinned — so the red is the pin, not the handoff.
func assertUnpinnedControlAuditIsRed(t *testing.T, root, cid, fid string) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code == 0 {
		t.Fatalf("audit PASSed with an unpinned control target: %q", out)
	}
	for _, want := range []string{"regression_suite", fid, strings.Repeat("1", 40)} {
		if !strings.Contains(out+errS, want) {
			t.Fatalf("audit --json does not carry %q: %q", want, out+errS)
		}
	}
}

// assertRegressRefuses asserts a regress invocation exits 1 with a refusal that
// names want — a refusal that does not name the field is one the operator
// cannot act on.
func assertRegressRefuses(t *testing.T, args []string, want string) {
	t.Helper()
	code, _, errS := run(t, args...)
	if code != 1 || !strings.Contains(errS, want) {
		t.Fatalf("code = %d err = %q, want 1 naming %q", code, errS, want)
	}
}

// confirmThroughTheStore stamps a finding CONFIRMED through the store's own
// writer. findings.Transition would need E5 evidence and a sandbox, which is the
// operator step's job, not a CLI test's.
func confirmThroughTheStore(t *testing.T, c *state.Campaign, finding validation.Value) {
	t.Helper()
	finding.O = validation.SetOrAppend(finding.O, "status",
		validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &finding); err != nil {
		t.Fatal(err)
	}
}

// dropFlag removes one "--flag value" pair from a command line.
func dropFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func campaignIDOf(t *testing.T, root string) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(root, "campaigns"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("campaigns dir: %v (%d entries)", err, len(ents))
	}
	return ents[0].Name()
}

// firstID returns the first "<prefix><hex-or-dash run>" token in s. The scan
// starts AFTER the prefix: the prefix's own characters are not part of the id.
func firstID(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	j := i + len(prefix)
	for j < len(s) && (s[j] == '-' || (s[j] >= '0' && s[j] <= '9') ||
		(s[j] >= 'a' && s[j] <= 'f')) {
		j++
	}
	return s[i:j]
}

func gitInitCommit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{
		{"-c", "init.defaultBranch=main", "init", "-q"},
		{"add", "-A"}, {"commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func gitRevParse(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// unpriceableHandoffArgs is one `target handoff` command line recording the
// NAMED DECISION in place of a figure — the escape the control target
// T-7e2781f96e25 needs, whose finding F-cfff3ebc0250 is CONFIRMED while its
// extractable_usd was REFUSED (c5ba1048).
func unpriceableHandoffArgs(root, cid, tid, fid string) []string {
	return []string{"--root", root, "regress", cid, "target", "handoff", tid,
		"--finding", fid, "--unpriceable",
		"--ceiling", "capacity basis: no attack was run",
		"--reason", "the 10b spike refused the figure: no attack was run",
		"--source", "10b fork spike (refusal)", "--actor", "operator"}
}

// TestRegressHandoffUnpriceableThroughTheVerb: the escape is reachable from
// the verb. `--unpriceable` is a SWITCH, so the parser must not try to read a
// missing --extractable-usd as a float (that would be exit 2, not a record),
// and the decision's own flags must be the verb's value flags.
func TestRegressHandoffUnpriceableThroughTheVerb(t *testing.T) {
	for _, flag := range []string{"--ceiling", "--reason"} {
		if !regressValueFlags[flag] {
			t.Errorf("%s is not in regressValueFlags — the parser would refuse "+
				"it as an unrecognized argument", flag)
		}
	}
	c, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := addControlThroughTheVerb(t, root, cid)
	finding := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := validation.ObjStr(finding, "finding_id")
	confirmThroughTheStore(t, c, finding)
	code, out, errS := run(t, unpriceableHandoffArgs(root, cid, tid, fid)...)
	if code != 0 {
		t.Fatalf("unpriceable handoff exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "UNPRICEABLE (ceiling: capacity basis") {
		t.Fatalf("handoff output = %q, want the decision and its ceiling", out)
	}
	if strings.Contains(out, "extractable_usd=0") {
		t.Fatalf("handoff output = %q, want no fabricated figure", out)
	}
}

// TestRegressHandoffRefusesAPricedUnpriceable: the escape is not a way to keep
// the figure as well — both at once is refused, by name, with exit 1.
func TestRegressHandoffRefusesAPricedUnpriceable(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := addControlThroughTheVerb(t, root, cid)
	finding := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := validation.ObjStr(finding, "finding_id")
	confirmThroughTheStore(t, c, finding)
	args := append(unpriceableHandoffArgs(root, cid, tid, fid),
		"--extractable-usd", "900000")
	assertRegressRefuses(t, args, "must not carry extractable_usd")
}

// TestRegressStatusShowsTheUnpriceableDecision: the human view prints the
// decision and the ceiling it was made against where the figure used to print
// — never a 0, which would read as a measurement.
func TestRegressStatusShowsTheUnpriceableDecision(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := addControlThroughTheVerb(t, root, cid)
	finding := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := validation.ObjStr(finding, "finding_id")
	confirmThroughTheStore(t, c, finding)
	if code, _, errS := run(t, unpriceableHandoffArgs(root, cid, tid, fid)...); code != 0 {
		t.Fatalf("handoff exit %d: err=%q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "regress", cid, "status")
	if code != 0 {
		t.Fatalf("status exit %d: err=%q", code, errS)
	}
	if !strings.Contains(out, "extractable_usd=unpriceable (ceiling: "+
		"capacity basis: no attack was run)") {
		t.Fatalf("status = %q, want the decision and its ceiling", out)
	}
}

// TestRegressHandoffRefusesAnUnpricedDecisionWithoutItsBasis drives the two
// missing-basis refusals through the verb: the escape needs the ceiling it was
// made against and a written reason, and each refusal names what is missing.
func TestRegressHandoffRefusesAnUnpricedDecisionWithoutItsBasis(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := addControlThroughTheVerb(t, root, cid)
	finding := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := validation.ObjStr(finding, "finding_id")
	confirmThroughTheStore(t, c, finding)
	base := unpriceableHandoffArgs(root, cid, tid, fid)
	assertRegressRefuses(t, dropFlag(base, "--ceiling"), "capacity basis")
	assertRegressRefuses(t, dropFlag(base, "--reason"), "written reason")
	assertRegressRefuses(t, dropFlag(base, "--actor"), "name its actor")
	// The decision needs its own provenance too: --source is what the
	// refusal was read from, and the schema requires it either way.
	assertRegressRefuses(t, dropFlag(base, "--source"), "needs --source")
}

// regressHelpLiteral freezes regressHelp's bytes, for the same reason
// regressUsageLiteral freezes regressUsage's: the help block is a byte-pinned
// operator surface, and building the expectation from the constant the code
// prints is self-referential — a typo in regressHelp would fail nothing. The
// change that added the handoff's unpriceable escape rewrote four lines of the
// `target handoff` entry and no test referenced them, so the block could have
// drifted unobserved.
const regressHelpLiteral = `usage: webv2 regress [-h] [--rows ROWS] [--out OUT]
                     [--dataset DATASET] [--snapshot-date SNAPSHOT_DATE]
                     {labels,campaign} ...

positional arguments:
  {labels,campaign}
    labels             derive the class labels for one ScaBench snapshot's rows
    campaign           a campaign id (C-...): the target/run/status verbs

options:
  -h, --help       show this help message and exit
  --rows ROWS      labels: a JSON array of the snapshot's rows, as extracted
  --out OUT        labels: the label file to write (plus its .sha256 sidecar)
  --dataset DATASET
                   labels: the dataset name (default: scabench)
  --snapshot-date SNAPSHOT_DATE
                   labels: the snapshot date (default: 2025-08-18)

subcommands:
  target add         record one regression target
  target add-control record the already-exploited control target (incident +
                     pre-patch pin + its own harness)
  target handoff     record the P1 handoff: a CONFIRMED finding on the control
                     target and its extractable_usd — or, when no figure is
                     defensible, the unpriceable decision
                     (--unpriceable --ceiling C --reason R --actor A)
  target pin         bind a target to a resolved 40-hex SHA and its snapshot
  target list        list the campaign's targets
  run                record one coarse score for a target
  status             the human view of the suite records
`

// TestRegressHelpIsPinnedToItsLiteral holds regressHelp to its literal, both as
// a constant and as the bytes the verb actually prints: a help block nobody
// reads back is a help block that drifts.
func TestRegressHelpIsPinnedToItsLiteral(t *testing.T) {
	if regressHelp != regressHelpLiteral {
		t.Fatalf("regressHelp drifted from its pinned bytes:\n got %q\nwant %q",
			regressHelp, regressHelpLiteral)
	}
	code, out, errS := run(t, "--root", t.TempDir(), "regress", "-h")
	if code != 0 || out != regressHelpLiteral {
		t.Fatalf("regress -h: code=%d out=%q err=%q, want the pinned block",
			code, out, errS)
	}
}

// TestRegressHandoffRefusesTheFlagNotJustItsValue is D7: the guard's comment
// claims it refuses the flag's mere PRESENCE. `--extractable-usd ""` and
// `--extractable-usd=` set the value to the empty string, which a non-empty
// test lets through — the flag is then silently dropped, which is exactly the
// laundering the guard exists to stop. The zero figure is refused too, and the
// priceable path still records a real one.
func TestRegressHandoffRefusesTheFlagNotJustItsValue(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	tid := addControlThroughTheVerb(t, root, cid)
	finding := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := validation.ObjStr(finding, "finding_id")
	confirmThroughTheStore(t, c, finding)
	for _, extra := range [][]string{
		{"--extractable-usd", ""},
		{"--extractable-usd="},
		{"--extractable-usd", "0"},
	} {
		args := append(unpriceableHandoffArgs(root, cid, tid, fid), extra...)
		assertRegressRefuses(t, args, "must not carry extractable_usd")
	}
	code, out, errS := run(t, "--root", root, "regress", cid, "target", "handoff",
		tid, "--finding", fid, "--extractable-usd", "900000",
		"--source", "reproduction on the pre-patch commit", "--actor", "operator")
	if code != 0 || !strings.Contains(out, "extractable_usd=900000") {
		t.Fatalf("priced handoff exit %d: out=%q err=%q", code, out, errS)
	}
}

// TestRegressStatusCellReadsAnIntegerFigure is D4 at the CLI: a hand-edited
// integer figure must print as the figure, not as the 0 that reading .F
// invented. A Flt still prints exactly as it always did, the decision prints
// its ceiling, and no handoff prints a dash.
func TestRegressStatusCellReadsAnIntegerFigure(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"extractable_usd":900000}`, "900000"},
		{`{"extractable_usd":900000.0}`, "900000"},
		{`{"priceable":false,"ceiling":"no attack was run"}`,
			"unpriceable (ceiling: no attack was run)"},
		{`{}`, "-"},
	} {
		ho, err := validation.ParseOrdered([]byte(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		if got := handoffUSDCell(ho); got != tc.want {
			t.Fatalf("cell for %s = %q, want %q", tc.body, got, tc.want)
		}
	}
}
