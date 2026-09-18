// CLI half of the T21 port: `webv2 immunize` byte-for-byte against the live
// Python CLI (COLUMNS=80). The usage/error strings below were captured from
// the reference twin at HEAD 4fcf779.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// t21ImmunizeMUTS is the CLI --mutations string.
const t21ImmunizeMUTS = "delegatecall variant of the exploit path;" +
	"same exploit re-issued from a second account in one block;" +
	"revert-retry with modified calldata padding"

// t21ImmunizeCampaign builds a campaign with a CONFIRMED unit-only finding
// (EXEC-0000000001, docker-networkless) and a second finding with a
// fork-runner exec that is NOT minted as E5/E6 evidence.
func t21ImmunizeCampaign(t *testing.T) (root, cid, fid, unmintedFid string) {
	t.Helper()
	root = t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "t")
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "src", "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	fid = t21Confirm(t, c, "EXEC-0000000001", "docker-networkless")
	// the fork-runner basis for fid: recorded, minted as E5 only on demand.
	t21ExecRecord(t, c, "EXEC-0000000002", "fork-runner", fid)
	unmintedFid = t21Confirm(t, c, "EXEC-0000000003", "fork-runner")
	return root, c.CampaignID, fid, unmintedFid
}

// t21Confirm ingests + confirms one finding whose unit exec is execID. The
// second finding's exec is fork-runner but stays unminted.
func t21Confirm(t *testing.T, c *state.Campaign, execID,
	profile string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kvT("title", validation.VStr(
			"Rescue function drains user balances without role check")),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("access-control")),
			kvT("cwe", validation.VStr("CWE-284")),
			kvT("description", validation.VStr("rescue() sends every token "+
				"to the caller, no role check")))),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("src/V.sol")),
			kvT("contract", validation.VStr("V")),
			kvT("function", validation.VStr("rescue"))))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	rec := t21ExecRecord(t, c, execID, profile, fid)
	if _, err := findings.AddEvidence(c, fid, t21Evidence(rec, "E4",
		"foundry-test", "unit harness repro", "EV-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"no role check found"); err != nil {
		t.Fatal(err)
	}
	t15GlobalRow(t, "MEM-shared01", "access-control")
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kvT("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kvT("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDictCLI(validation.ObjAt(vf, "verification"))
	ver = setObjFieldCLI(ver, "reproduction", validation.VObj(
		kvT("tier_reached", validation.VStr("T1")),
		kvT("status", validation.VStr("reproduced")),
		kvT("attempts", validation.VArr())))
	vf = setObjFieldCLI(vf, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "unit gate passed",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

// t21ExecRecord writes one finished EXEC record.
func t21ExecRecord(t *testing.T, c *state.Campaign, execID, profile,
	findingID string) validation.Value {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	for _, p := range []string{stdout, stderr} {
		text := ""
		if p == stdout {
			text = "PASS: test_exploit\n"
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rec := validation.VObj(
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr(profile)),
		kvT("finding_id", validation.VStr(findingID)),
		kvT("artifact_id", validation.VNull()),
		kvT("command", validation.VStr("forge test --fork-url "+
			"http://127.0.0.1:8545 --fork-block-number 20000000 "+
			"--match-test test_exploit")),
		kvT("exit_status", validation.VInt(0)),
		kvT("stdout_path", validation.VStr(stdout)),
		kvT("stderr_path", validation.VStr(stderr)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// t21Evidence is conftest.evidence_item.
func t21Evidence(rec validation.Value, level, typ, desc, eid string) validation.Value {
	return validation.VObj(
		kvT("evidence_id", validation.VStr(eid)),
		kvT("level", validation.VStr(level)),
		kvT("type", validation.VStr(typ)),
		kvT("description", validation.VStr(desc)),
		kvT("sandbox_profile", validation.ObjAt(rec, "profile")),
		kvT("artifact_id", validation.ObjAt(rec, "exec_id")),
	)
}

// t21MintFork adds the E5 fork-test evidence minting EXEC-0000000002.
func t21MintFork(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	rec, err := t21LoadExec(t, c, "EXEC-0000000002")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, fid, t21Evidence(rec, "E5",
		"fork-test", "mainnet fork repro", "EV-f")); err != nil {
		t.Fatal(err)
	}
}

// t21LoadExec reads one exec record off disk.
func t21LoadExec(t *testing.T, c *state.Campaign,
	execID string) (validation.Value, error) {
	t.Helper()
	return validation.ReadJson(filepath.Join(c.ExecsDir, execID,
		"exec_record.json"))
}

// test_cmd_immunize_usage_errors pins every argparse failure shape.
func TestCmdImmunizeUsageErrors(t *testing.T) {
	root, cid, fid, _ := t21ImmunizeCampaign(t)
	usage := t21ImmunizeUsage
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no-positionals", []string{"immunize"},
			usage + "webv2 immunize: error: the following arguments are " +
				"required: campaign, finding, --poc-exec, --patch, " +
				"--mutations\n"},
		{"one-positional", []string{"immunize", cid},
			usage + "webv2 immunize: error: the following arguments are " +
				"required: finding, --poc-exec, --patch, --mutations\n"},
		{"no-flags", []string{"immunize", cid, fid},
			usage + "webv2 immunize: error: the following arguments are " +
				"required: --poc-exec, --patch, --mutations\n"},
		{"missing-two", []string{"immunize", cid, fid, "--patch",
			"add the missing role check"},
			usage + "webv2 immunize: error: the following arguments are " +
				"required: --poc-exec, --mutations\n"},
		{"flag-no-value", []string{"immunize", cid, fid, "--poc-exec"},
			usage + "webv2 immunize: error: argument --poc-exec: expected " +
				"one argument\n"},
		{"bogus-only", []string{"immunize", "--bogus"},
			usage + "webv2 immunize: error: the following arguments are " +
				"required: campaign, finding, --poc-exec, --patch, " +
				"--mutations\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errS := run(t, append([]string{"--root", root},
				tc.args...)...)
			if code != 2 {
				t.Fatalf("exit %d, want 2: %q", code, errS)
			}
			if out != "" {
				t.Fatalf("stdout = %q, want empty", out)
			}
			if errS != tc.want {
				t.Fatalf("stderr:\n got %q\nwant %q", errS, tc.want)
			}
		})
	}
}

// test_cmd_immunize_unrecognized: the ROOT parser reports extra tokens.
func TestCmdImmunizeUnrecognized(t *testing.T) {
	root, cid, fid, _ := t21ImmunizeCampaign(t)
	code, out, errS := run(t, "--root", root, "immunize", cid, fid,
		"--poc-exec", "EXEC-0000000002", "--patch",
		"add the missing role check", "--mutations", t21ImmunizeMUTS, "extra")
	want := t14TopUsage + "webv2: error: unrecognized arguments: extra\n"
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want empty", out)
	}
	if errS != want {
		t.Fatalf("stderr:\n got %q\nwant %q", errS, want)
	}
	code, _, errS = run(t, "--root", root, "immunize", cid, fid,
		"--poc-exec", "EXEC-0000000002", "--patch",
		"add the missing role check", "--mutations", t21ImmunizeMUTS,
		"--nope", "x")
	want = t14TopUsage + "webv2: error: unrecognized arguments: --nope x\n"
	if code != 2 || errS != want {
		t.Fatalf("exit %d stderr %q, want 2 %q", code, errS, want)
	}
}

// test_cmd_immunize_happy_path: the IMMUNIZED line is byte-exact.
func TestCmdImmunizeHappyPath(t *testing.T) {
	root, cid, fid, _ := t21ImmunizeCampaign(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	t21MintFork(t, c, fid)
	code, out, errS := run(t, "--root", root, "immunize", cid, fid,
		"--poc-exec", "EXEC-0000000002", "--patch",
		"add the missing role check", "--mutations", t21ImmunizeMUTS)
	want := fid + ": IMMUNIZED — patch blocks the fork PoC " +
		"(EXEC-0000000002) and 3 boundary mutations\n"
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
	if out != want {
		t.Fatalf("stdout:\n got %q\nwant %q", out, want)
	}
}

// test_cmd_immunize_bypass_line: the BYPASS FOUND shape.
func TestCmdImmunizeBypassLine(t *testing.T) {
	root, cid, fid, _ := t21ImmunizeCampaign(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	t21MintFork(t, c, fid)
	code, out, errS := run(t, "--root", root, "immunize", cid, fid,
		"--poc-exec", "EXEC-0000000002", "--patch",
		"add the missing role check", "--mutations", t21ImmunizeMUTS,
		"--bypass", "delegatecall variant still drains 2.1M")
	want := fid + ": BYPASS FOUND — patch blocks the fork PoC " +
		"(EXEC-0000000002) and 3 boundary mutations\n" +
		"  BYPASS: delegatecall variant still drains 2.1M — fix the patch " +
		"and re-verify; the bounty gate fails until it holds\n"
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != want {
		t.Fatalf("stdout:\n got %q\nwant %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
}

// test_cmd_immunize_refusals: every handler-level refusal is exit 2 with
// `immunize failed: {e}` on stderr.
func TestCmdImmunizeRefusals(t *testing.T) {
	root, cid, fid, unminted := t21ImmunizeCampaign(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	// require_fork_basis runs BEFORE the bypass guard: the basis must hold
	// for the short-bypass case to reach its own refusal.
	t21MintFork(t, c, fid)
	base := []string{"immunize", cid, fid, "--poc-exec", "EXEC-0000000002",
		"--patch", "add the missing role check", "--mutations",
		t21ImmunizeMUTS}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unit-basis", []string{"immunize", cid, fid, "--poc-exec",
			"EXEC-0000000001", "--patch", "add the missing role check",
			"--mutations", t21ImmunizeMUTS},
			"immunize failed: immunization is based on the mainnet FORK " +
				"PoC, not a unit test: EXEC-0000000001 ran under profile " +
				"'docker-networkless'. Re-run the PoC on the pinned fork " +
				"(webv2 exec --profile fork-runner --command 'forge test " +
				"--fork-url ...') and re-verify against that exec\n"},
		{"not-minted", []string{"immunize", cid, unminted, "--poc-exec",
			"EXEC-0000000003", "--patch", "add the missing role check",
			"--mutations", t21ImmunizeMUTS},
			"immunize failed: EXEC-0000000003 is not minted on " + unminted +
				" as E5/E6 fork evidence — mint it first: webv2 mint " +
				unminted + " --exec EXEC-0000000003 --type fork-test\n"},
		{"missing-exec", []string{"immunize", cid, fid, "--poc-exec",
			"EXEC-ffffffffff", "--patch", "add the missing role check",
			"--mutations", t21ImmunizeMUTS},
			"immunize failed: \"exec EXEC-ffffffffff not found in the " +
				"campaign's exec ledger\"\n"},
		{"short-patch", []string{"immunize", cid, fid, "--poc-exec",
			"EXEC-0000000002", "--patch", "short", "--mutations",
			t21ImmunizeMUTS},
			"immunize failed: immunization needs a written patch " +
				"description (>=10 chars): what the fix changes and why " +
				"it blocks the exploit\n"},
		{"one-mutation", []string{"immunize", cid, fid, "--poc-exec",
			"EXEC-0000000002", "--patch", "add the missing role check",
			"--mutations", "only one mutation"},
			"immunize failed: immunization requires exactly 3 boundary " +
				"mutations — a patch tested against the PoC alone may " +
				"block one path and leave its neighbors open\n"},
		{"short-bypass", append(append([]string{}, base...),
			"--bypass", "x"),
			"immunize failed: a recorded bypass needs a written " +
				"description (>=5 chars): which mutation, what it " +
				"extracted\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errS := run(t, append([]string{"--root", root},
				tc.args...)...)
			if code != 2 {
				t.Fatalf("exit %d, want 2: %q", code, errS)
			}
			if out != "" {
				t.Fatalf("stdout = %q, want empty", out)
			}
			if errS != tc.want {
				t.Fatalf("stderr:\n got %q\nwant %q", errS, tc.want)
			}
		})
	}
}

// test_cmd_immunize_missing_finding_and_campaign: FileNotFoundError falls
// through to main's handler (exit 1, `error: ...`).
func TestCmdImmunizeMissingFindingAndCampaign(t *testing.T) {
	root, cid, fid, _ := t21ImmunizeCampaign(t)
	_ = fid
	code, out, errS := run(t, "--root", root, "immunize", cid,
		"F-nosuchfinding", "--poc-exec", "EXEC-0000000002", "--patch",
		"add the missing role check", "--mutations", t21ImmunizeMUTS)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want empty", out)
	}
	if !strings.Contains(errS, "no finding 'F-nosuchfinding' in "+cid) {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "--root", root, "immunize", "C-nosuchcampaign",
		"F-x", "--poc-exec", "EXEC-0000000002", "--patch",
		"add the missing role check", "--mutations", t21ImmunizeMUTS)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q", code, errS)
	}
	if !strings.Contains(errS, "no such campaign:") {
		t.Fatalf("stderr = %q", errS)
	}
}

// test_cmd_immunize_registered_ord: the usage block orders immunize at 63.
func TestCmdImmunizeRegisteredOrd(t *testing.T) {
	cmd, ok := commandByName("immunize")
	if !ok {
		t.Fatal("immunize is not registered")
	}
	if cmd.ord != 63 {
		t.Fatalf("ord = %d, want 63", cmd.ord)
	}
	if !strings.Contains(usageText(), "immunize") {
		t.Fatal("usage block does not list immunize")
	}
}
