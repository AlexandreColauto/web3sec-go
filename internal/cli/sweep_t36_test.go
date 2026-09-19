package cli

// T36 testmap: tests/test_cli.py::test_full_ladder_via_cli — the full
// evidence ladder (init -> snap -> model -> ingest -> move -> mint ->
// recall -> verdict -> CONFIRMED -> verify --exec (E6) -> impact (E7))
// driven through the CLI alone, plus the verify argparse vectors.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/sharedmem"
	"websec/internal/state"
)

var t36InitRe = regexp.MustCompile(`initialized (C-[0-9a-z]+)`)
var t36FidRe = regexp.MustCompile(`ingested (F-[0-9a-z]+)`)

const t36Model = `{
  "protocol_id": "toyfi",
  "name": "ToyFi",
  "contracts": [{"name": "Vault", "path": "src/Vault.sol"}],
  "actors": [{"id": "user", "kind": "EOA", "trust": "externally-owned"}],
  "assets": [{"id": "vault-balance", "kind": "token", "decimals": 18}],
  "relations": [],
  "invariants": [{"id": "INV-1", "statement": "balances move atomically",
                  "severity_if_broken": "critical"}]
}`

const t36Hyp = `{
  "title": "reentrancy drain hypothesis",
  "root_cause": {"class": "reentrancy",
                 "description": "withdraw re-enters the vault before the balance updates"},
  "affected": [{"path": "src/Vault.sol", "contract": "Vault",
                "function": "withdraw"}],
  "attacker": {"profile": "EOA", "capabilities": []},
  "invariant": {"id": "INV-1", "statement": "balances move atomically"}
}`

// t36SetupLadder is workspace_ladder + _init_ladder + snap + model + ingest.
func t36SetupLadder(t *testing.T) (string, *state.Campaign, string) {
	t.Helper()
	// conftest's per-test global-memory isolation (monkeypatch.setenv) plus
	// the production seam: a sibling test's cleanup may have reset the
	// shared-memory seam to the absent-store default.
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", t.TempDir())
	ensureSeams()
	findings.SetSharedMemoryRows(sharedmem.LoadSharedMemory)
	root := t.TempDir()
	tgt := filepath.Join(root, "target")
	if err := os.MkdirAll(filepath.Join(tgt, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFileT36(t, filepath.Join(tgt, "README.md"),
		"# toyfi\nINV-1 balances move atomically\n")
	writeFileT36(t, filepath.Join(tgt, "src", "Vault.sol"),
		"contract Vault { uint public total; }")
	code, out, errS := run(t, "--root", root, "init", "--program",
		"CLI Ladder")
	if code != 0 {
		t.Fatalf("init exit %d: %q", code, errS)
	}
	m := t36InitRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("init output %q", out)
	}
	cid := m[1]
	if code, out, errS = run(t, "--root", root, "snap", cid, tgt); code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	model := filepath.Join(root, "model.json")
	writeFileT36(t, model, t36Model)
	if code, out, errS = run(t, "--root", root, "model", cid, model); code != 0 {
		t.Fatalf("model exit %d: %q", code, errS)
	}
	hyp := filepath.Join(root, "hyp.json")
	writeFileT36(t, hyp, t36Hyp)
	code, out, errS = run(t, "--root", root, "ingest", cid,
		"--json-file", hyp)
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	fm := t36FidRe.FindStringSubmatch(out)
	if fm == nil {
		t.Fatalf("ingest output %q", out)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	return root, c, fm[1]
}

func writeFileT36(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// t36Exec is _pillar_exec: an out-of-band harness run registered on disk.
func t36Exec(t *testing.T, c *state.Campaign, fid, profile, command, stdout,
	reportedBy string) string {
	t.Helper()
	f := fid
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: profile, Command: command, FindingID: &f,
		ReportedBy: reportedBy, StdoutText: stdout})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return validation.ObjStr(rec, "exec_id")
}

// t36EvidenceCount counts the evidence rows citing one exec.
func t36EvidenceCount(t *testing.T, c *state.Campaign, fid, execID string) int {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range t14List(f, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			n++
		}
	}
	return n
}

// TestFullLadderViaCLI is test_full_ladder_via_cli.
func TestFullLadderViaCLI(t *testing.T) {
	root, c, fid := t36SetupLadder(t)
	cid := c.CampaignID
	// triage -> POSSIBLE. R3-3: the POSSIBLE rung carries an E2 floor, so the
	// ladder earns the manual reachability item before the status stamp (the
	// CLI has no plain-evidence verb; the file's style is a library call, as
	// with t36Exec below).
	addFloorEvidence(t, c, fid, "E2")
	code, out, errS := run(t, "--root", root, "move", cid, fid, "POSSIBLE",
		"--reason", "triage: reachable path, high prior")
	if code != 0 || !strings.Contains(out, "POSSIBLE") {
		t.Fatalf("move POSSIBLE exit %d out %q err %q", code, out, errS)
	}
	// the exec an out-of-band harness would have produced
	rec := t36Exec(t, c, fid, "docker-networkless",
		"forge test --match-test test_exploit", "PASS: test_exploit\n",
		"harness")
	code, out, errS = run(t, "--root", root, "mint", cid, fid, "--exec", rec,
		"--description", "unit PoC drains", "--tier", "T2",
		"--type", "foundry-test")
	if code != 0 || !strings.Contains(out, "level E4") {
		t.Fatalf("mint exit %d out %q err %q", code, out, errS)
	}
	// idempotent: minting the same exec again adds nothing new
	before := t36EvidenceCount(t, c, fid, rec)
	code, _, errS = run(t, "--root", root, "mint", cid, fid, "--exec", rec,
		"--description", "unit PoC drains", "--tier", "T2",
		"--type", "foundry-test")
	if code != 0 {
		t.Fatalf("re-mint exit %d: %q", code, errS)
	}
	after := t36EvidenceCount(t, c, fid, rec)
	if before != 1 || after != 1 {
		t.Fatalf("evidence rows before=%d after=%d, want 1/1", before, after)
	}
	// gate prerequisites + confirmation
	seedGlobalMemoryRow(t)
	code, out, errS = run(t, "--root", root, "recall", cid, "--finding", fid)
	if code != 0 || !strings.Contains(out, "MEM-shared01") ||
		!strings.Contains(out, "recorded") {
		t.Fatalf("recall exit %d out %q err %q", code, out, errS)
	}
	if code, _, errS = run(t, "--root", root, "verdict", cid, fid,
		"--verdict", "confirmed", "--reason",
		"no compensating control on the re-entry"); code != 0 {
		t.Fatalf("verdict exit %d: %q", code, errS)
	}
	code, out, errS = run(t, "--root", root, "move", cid, fid, "CONFIRMED",
		"--reason", "all gates passed")
	if code != 0 || !strings.Contains(out, "CONFIRMED") {
		t.Fatalf("move CONFIRMED exit %d out %q err %q", code, out, errS)
	}
	// the E6 queue lists the confirmed finding at E4
	code, out, errS = run(t, "--root", root, "verify", cid, "--queue")
	wantQueue := "[advisory] " + fid + "  at E4  reentrancy  — " +
		"reentrancy drain hypothesis\n"
	if code != 0 || out != wantQueue {
		t.Fatalf("verify --queue exit %d out %q err %q want %q", code, out,
			errS, wantQueue)
	}
	// independent verification -> E6 (different exec, different reporter)
	rec2 := t36Exec(t, c, fid, "fork-runner", "forge test --mt independent",
		"Ran 1 test for test/ind.t.sol\n[PASS] ind\n", "verifier-b")
	code, out, errS = run(t, "--root", root, "verify", cid, "--exec", rec2,
		"--finding", fid, "--verifier", "verifier-b", "--description",
		"same block, same drain")
	want := fid + ": independently verified by verifier-b — level E6\n"
	if code != 0 || out != want {
		t.Fatalf("verify --exec exit %d out %q err %q want %q", code, out,
			errS, want)
	}
	// the queue is empty once E6 is recorded — feedback-triage A6: an
	// empty queue says so instead of printing nothing
	code, out, errS = run(t, "--root", root, "verify", cid, "--queue")
	if code != 0 || out != "queue empty — nothing to verify\n" {
		t.Fatalf("verify --queue after exit %d out %q err %q", code, out, errS)
	}
	// the same exec cannot back E6 twice (handler-level exit 2)
	code, out, errS = run(t, "--root", root, "verify", cid, "--exec", rec2,
		"--finding", fid, "--verifier", "verifier-b", "--description",
		"same block, same drain")
	wantDup := "verify failed: exec " + rec2 + " already backs evidence on " +
		fid + "; an independent reproduction must be a fresh execution\n"
	if code != 2 || out != "" || errS != wantDup {
		t.Fatalf("verify --exec repeat exit %d out %q err %q want %q", code,
			out, errS, wantDup)
	}
	// economic impact -> E7
	art := filepath.Join(root, "impact.json")
	writeFileT36(t, art, `{"fork_block": 1, "delta": "attacker +1.2M"}`)
	code, out, errS = run(t, "--root", root, "impact", cid, fid,
		"--extractable", "1200000", "--max-loss", "1200000", "--artifact",
		art, "--description", "1.2M extractable at fork depth")
	if code != 0 || !strings.Contains(out, "E7") {
		t.Fatalf("impact exit %d out %q err %q", code, out, errS)
	}
	// the closing integrity check still passes
	if code, _, errS = run(t, "--root", root, "verify", cid); code != 0 {
		t.Fatalf("verify log exit %d: %q", code, errS)
	}
}

// TestVerifyArgparse pins the verify subparser's usage block and every
// captured error vector (COLUMNS=80, live Python CLI).
func TestVerifyArgparse(t *testing.T) {
	root, c, fid := t36SetupLadder(t)
	cid := c.CampaignID
	rec := t36Exec(t, c, fid, "docker-networkless", "forge test",
		"PASS: t\n", "harness")
	t23WantHelp(t, []string{"verify", "--help"}, t36VerifyHelp)
	wantArg := func(args []string, usage, msg string) {
		t.Helper()
		code, out, errS := run(t, args...)
		if code != 2 || out != "" || errS != usage+"webv2 verify: error: "+
			msg+"\n" {
			t.Fatalf("%v: exit %d out %q err %q", args, code, out, errS)
		}
	}
	wantArg([]string{"verify"}, t36VerifyUsage,
		"the following arguments are required: campaign")
	wantArg([]string{"verify", "--bogus"}, t36VerifyUsage,
		"the following arguments are required: campaign")
	wantArg([]string{"verify", "--exec"}, t36VerifyUsage,
		"argument --exec: expected one argument")
	wantArg([]string{"verify", "--finding"}, t36VerifyUsage,
		"argument --finding: expected one argument")
	wantArg([]string{"verify", "--verifier"}, t36VerifyUsage,
		"argument --verifier: expected one argument")
	wantArg([]string{"verify", "--description"}, t36VerifyUsage,
		"argument --description: expected one argument")
	wantArg([]string{"verify", "--queue=1"}, t36VerifyUsage,
		"argument --queue: ignored explicit argument '1'")
	for _, extra := range [][]string{{"--bogus"}, {"extra"}} {
		code, out, errS := run(t, append([]string{"--root", root, "verify", cid},
			extra...)...)
		if code != 2 || out != "" || !strings.HasPrefix(errS, t14TopUsage) ||
			!strings.Contains(errS, "webv2: error: unrecognized arguments: "+
				strings.Join(extra, " ")+"\n") {
			t.Fatalf("%v: exit %d out %q err %q", extra, code, out, errS)
		}
	}
	// --exec without --verifier/--description (handler-level exit 2)
	code, out, errS := run(t, "--root", root, "verify", cid, "--exec", rec,
		"--finding", fid)
	if code != 2 || out != "" ||
		errS != "verify --exec needs --verifier NAME and --description\n" {
		t.Fatalf("no-verifier: exit %d out %q err %q", code, out, errS)
	}
	// --exec without --finding is Python's load_finding(None) (exit 1)
	code, out, errS = run(t, "--root", root, "verify", cid, "--exec", rec,
		"--verifier", "v", "--description", "d")
	if code != 1 || out != "" || errS != "error: no finding None in "+
		cid+"\n" {
		t.Fatalf("no-finding: exit %d out %q err %q", code, out, errS)
	}
	// --exec=ID is the same option: it reaches the handler (no argparse
	// failure), so the finding lookup is what fails here.
	code, _, errS = run(t, "--root", root, "verify", cid, "--exec="+rec,
		"--verifier", "v", "--description", "d")
	if code != 1 || !strings.Contains(errS, "no finding None in "+cid) {
		t.Fatalf("--exec=ID: exit %d err %q", code, errS)
	}
}

// TestAmendNoticeOnConfirmedFloorMove pins critic r3: converting a live
// CONFIRMED row to a stricter-floor class is legal (the T6 advisory's own
// advice) but never silent — amend prints the movement and the mandatory
// work it creates.
func TestAmendNoticeOnConfirmedFloorMove(t *testing.T) {
	root, c, fid := t36SetupLadder(t)
	cid := c.CampaignID
	// R3-3: the POSSIBLE rung carries an E2 floor — earn it before the stamp.
	addFloorEvidence(t, c, fid, "E2")
	code, _, errS := run(t, "--root", root, "move", cid, fid, "POSSIBLE",
		"--reason", "triage")
	if code != 0 {
		t.Fatalf("move POSSIBLE: %q", errS)
	}
	rec := t36Exec(t, c, fid, "docker-networkless",
		"forge test --match-test test_exploit", "PASS: test_exploit\n",
		"harness")
	if code, _, errS := run(t, "--root", root, "mint", cid, fid,
		"--exec", rec, "--description", "unit PoC drains", "--tier", "T2",
		"--type", "foundry-test"); code != 0 {
		t.Fatalf("mint: %q", errS)
	}
	seedGlobalMemoryRow(t)
	if code, _, errS := run(t, "--root", root, "recall", cid,
		"--finding", fid); code != 0 {
		t.Fatalf("recall: %q", errS)
	}
	if code, _, errS := run(t, "--root", root, "verdict", cid, fid,
		"--verdict", "confirmed", "--reason",
		"no compensating control on the re-entry"); code != 0 {
		t.Fatalf("verdict: %q", errS)
	}
	if code, out, errS := run(t, "--root", root, "move", cid, fid,
		"CONFIRMED", "--reason", "all gates passed"); code != 0 {
		t.Fatalf("move CONFIRMED: %q %q", out, errS)
	}
	code, _, errS = run(t, "--root", root, "amend", cid, fid,
		"--class", "bridge-message",
		"--note", "the failure crosses a bridge message, not a role check")
	if code != 0 {
		t.Fatalf("stricter re-class of a CONFIRMED row must be legal: %q",
			errS)
	}
	if !strings.Contains(errS, "CONFIRMED floor for this finding moved E4 -> E6") ||
		!strings.Contains(errS, "MANDATORY work") {
		t.Fatalf("amend must announce the movement: %q", errS)
	}
}
