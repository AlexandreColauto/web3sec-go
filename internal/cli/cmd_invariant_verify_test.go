package cli

// P1b CLI tests — `invariant-verify` (ord 22).
//
// Ports: tests/test_role_isolation.py::test_cli_invariant_verify_unknown_id_errors
// and ::test_cli_invariant_contradict_and_verify_paths (the --artifact happy
// path), plus the --exec path (cli.py's resolve-exec-artifact) and the
// "exactly one of --artifact/--exec" guard.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// t15SeedInvariant is invariants.seed_from_model with one statement.
func t15SeedInvariant(t *testing.T, c *state.Campaign, invID, statement string) {
	t.Helper()
	model := validation.VObj(kvT("invariants", validation.VArr(
		validation.VObj(
			kvT("id", validation.VStr(invID)),
			kvT("statement", validation.VStr(statement)),
		))))
	if _, err := invariants.SeedFromModel(c, model); err != nil {
		t.Fatalf("seed model: %v", err)
	}
}

// t15ExecRecord writes one finished EXEC record (sandbox.register_exec is a
// later phase; the ledger row is written directly, as port_test.go does).
func t15ExecRecord(t *testing.T, c *state.Campaign, execID string) string {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdout, []byte("PASS: invariant check\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr("docker-networkless")),
		kvT("finding_id", validation.VNull()),
		kvT("artifact_id", validation.VNull()),
		kvT("command", validation.VStr("forge test")),
		kvT("policy_verdict", validation.VObj(
			kvT("allowed", validation.VBool(true)),
			kvT("violations", validation.VArr()))),
		kvT("origin", validation.VStr("externally-reported")),
		kvT("reported_by", validation.VStr("verifier-b")),
		kvT("started_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvT("finished_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvT("exit_status", validation.VInt(0)),
		kvT("stdout_path", validation.VStr(stdout)),
		kvT("stderr_path", validation.VStr("")),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	return stdout
}

func TestInvariantVerifyArtifact(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	aid := t15Register(t, c, "inv-check.md", "other", "")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--artifact", aid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "INV-1: CHECKED_AGAINST_CODE (artifact "+aid+")\n" {
		t.Fatalf("output %q", out)
	}
}

func TestInvariantVerifyExec(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	t15ExecRecord(t, c, "EXEC-0000000001")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--exec", "EXEC-0000000001")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !regexp.MustCompile(`^INV-1: CHECKED_AGAINST_CODE \(artifact (OTH|ART)-`).
		MatchString(out) {
		t.Fatalf("output %q", out)
	}
}

func TestInvariantVerifyUnknownIDExits2OneLine(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	aid := t15Register(t, c, "inv-check.md", "other", "")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-NOPE", "--artifact", aid)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if strings.Count(errS, "\n") != 1 || !strings.Contains(errS, "INV-NOPE") {
		t.Fatalf("stderr %q must be one line naming the id", errS)
	}
}

func TestInvariantVerifyUnknownExecInvariant(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-NOPE", "--exec", "EXEC-0000000001")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if errS != "invariant verify failed: unknown invariant 'INV-NOPE'\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestInvariantVerifyRequiresExactlyOneSource(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1")
	if code != 2 || errS != "invariant-verify: pass --artifact ART-... or "+
		"--exec EXEC-... (one is required)\n" {
		t.Fatalf("exit %d stderr %q", code, errS)
	}
	code, _, errS = run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--artifact", "ART-x", "--exec", "EXEC-x")
	if code != 2 || errS != "invariant-verify: pass exactly one of --artifact "+
		"or --exec (got both: ART-x and EXEC-x)\n" {
		t.Fatalf("exit %d stderr %q", code, errS)
	}
}

func TestInvariantVerifyMissingArgsIsArgparse(t *testing.T) {
	code, _, errS := run(t, "invariant-verify")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["invariant-verify"] +
		"webv2 invariant-verify: error: the following arguments are required: " +
		"campaign, inv_id\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
