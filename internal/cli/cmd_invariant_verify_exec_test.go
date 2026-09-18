package cli

// cmd_invariant_verify_exec_test.go: the nine
// tests/test_attention_ledger.py::test_invariant_verify_exec_* functions, 1:1
// — the executable form of `invariant-verify` captures the exec's recorded
// output as the verification evidence, refreshes on re-run, falls back to the
// stderr log, and exits 2 (never a traceback) on every malformed input.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// execCamp is the `exec_camp` fixture: a seeded INV-008 bound to the optional
// applies_to target, and one finished exec. The exec-relevance gate reads what
// the exec RAN, so a binding makes its recorded command target that contract;
// with no binding the historical untargeted fixture is unchanged.
func execCamp(t *testing.T, execID string, appliesTo ...string) (*state.Campaign,
	string, validation.Value) {
	t.Helper()
	c, root := t15Campaign(t, "inv-exec")
	t15SeedInvariant(t, c, "INV-008", "liveness: the fee accumulator holds",
		appliesTo...)
	command := "forge test --match-test test_liveness"
	if len(appliesTo) > 0 {
		command = "forge test --match-contract " + appliesTo[0]
	}
	return c, root, invExecRecord(t, c, execID, command)
}

// invExecRecord is conftest's sandboxed_exec shape: BOTH capture files exist
// (stdout holds the run, stderr starts empty) and the record is finished. The
// optional command overrides the recorded command line.
func invExecRecord(t *testing.T, c *state.Campaign, execID string,
	command ...string) validation.Value {
	t.Helper()
	cmd := "forge test --match-test test_liveness"
	if len(command) > 0 {
		cmd = command[0]
	}
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout,
		[]byte("INV-008: the fee accumulator holds\nPASS: test_liveness\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderr, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr("docker-networkless")),
		kvT("finding_id", validation.VNull()),
		kvT("artifact_id", validation.VNull()),
		kvT("command", validation.VStr(cmd)),
		kvT("policy_verdict", validation.VObj(
			kvT("allowed", validation.VBool(true)),
			kvT("violations", validation.VArr()))),
		kvT("origin", validation.VStr("externally-reported")),
		kvT("reported_by", validation.VStr("verifier-b")),
		kvT("started_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvT("finished_at", validation.VStr("2026-03-04T05:06:07+00:00")),
		kvT("exit_status", validation.VInt(0)),
		kvT("stdout_path", validation.VStr(stdout)),
		kvT("stderr_path", validation.VStr(stderr)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	return rec
}

// invEntry is INV.load_links(camp)["invariants"][invID].
func invEntry(t *testing.T, c *state.Campaign, invID string) validation.Value {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	return objAt(objAt(links, "invariants"), invID)
}

// resolvedPath is Path(...).resolve() for the paths the tests compare.
func resolvedPath(t *testing.T, p string) string {
	t.Helper()
	out, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// artifactPathOf resolves the artifact row's path.
func artifactPathOf(t *testing.T, c *state.Campaign, aid string) string {
	t.Helper()
	art, err := c.Artifact(aid)
	if err != nil {
		t.Fatal(err)
	}
	p := objStr(art, "path")
	if !filepath.IsAbs(p) {
		p = filepath.Join(c.Root, p)
	}
	return resolvedPath(t, p)
}

// Port of test_invariant_verify_exec_happy_path.
func TestInvariantVerifyExecHappyPath(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", objStr(rec, "exec_id"))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "CHECKED_AGAINST_CODE") {
		t.Fatalf("output %q", out)
	}
	entry := invEntry(t, c, "INV-008")
	if objStr(entry, "status") != "CHECKED_AGAINST_CODE" {
		t.Fatalf("status %q", objStr(entry, "status"))
	}
	if got, want := artifactPathOf(t, c, objStr(entry, "verified_by")),
		resolvedPath(t, objStr(rec, "stdout_path")); got != want {
		t.Fatalf("artifact path %q, want %q", got, want)
	}
	// the log-anchored verdict (status + registered artifact + event) holds
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if !invariants.IsVerified(entry, c, "INV-008", events) {
		t.Fatal("the recorded check must verify")
	}
}

// Port of test_invariant_verify_exec_rerun_refreshes_the_same_artifact.
func TestInvariantVerifyExecRerunRefreshesTheSameArtifact(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
	execID := objStr(rec, "exec_id")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	first := objStr(invEntry(t, c, "INV-008"), "verified_by")
	code, _, errS = run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", execID)
	if code != 0 {
		t.Fatalf("second exit %d: %q", code, errS)
	}
	entry := invEntry(t, c, "INV-008")
	if objStr(entry, "verified_by") != first {
		t.Fatalf("verified_by moved: %q -> %q", first,
			objStr(entry, "verified_by"))
	}
	art, err := c.Artifact(first)
	if err != nil {
		t.Fatal(err)
	}
	if rc := objAt(art, "refresh_count"); rc.Kind != validation.Int || rc.I != 1 {
		t.Fatalf("refresh_count = %s, want 1", validation.CanonCompact(rc))
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	atPath := 0
	for _, a := range objAt(st, "artifacts").A {
		p := objStr(a, "path")
		if !filepath.IsAbs(p) {
			p = filepath.Join(c.Root, p)
		}
		if resolvedPath(t, p) == resolvedPath(t, objStr(rec, "stdout_path")) {
			atPath++
		}
	}
	if atPath != 1 {
		t.Fatalf("artifact rows at the exec output path = %d, want 1", atPath)
	}
}

// Port of test_invariant_verify_exec_falls_back_to_the_stderr_log.
func TestInvariantVerifyExecFallsBackToTheStderrLog(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
	if err := os.Remove(objStr(rec, "stdout_path")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objStr(rec, "stderr_path"),
		[]byte("INV-008: the fee accumulator holds\nFAIL: test_liveness\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", objStr(rec, "exec_id"))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	entry := invEntry(t, c, "INV-008")
	if got, want := artifactPathOf(t, c, objStr(entry, "verified_by")),
		resolvedPath(t, objStr(rec, "stderr_path")); got != want {
		t.Fatalf("artifact path %q, want %q", got, want)
	}
}

// Port of test_invariant_verify_exec_without_captured_output_exits_2.
func TestInvariantVerifyExecWithoutCapturedOutputExits2(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001")
	if err := os.Remove(objStr(rec, "stdout_path")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(objStr(rec, "stderr_path")); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", objStr(rec, "exec_id"))
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, objStr(rec, "exec_id")) {
		t.Fatalf("stderr must name the exec: %q", errS)
	}
	if !strings.Contains(errS, "no captured output") {
		t.Fatalf("stderr %q", errS)
	}
	if strings.Contains(errS, "Traceback") {
		t.Fatalf("stderr carries a traceback: %q", errS)
	}
	if got := objStr(invEntry(t, c, "INV-008"), "status"); got != "UNVERIFIED" {
		t.Fatalf("status %q, want UNVERIFIED", got)
	}
}

// Port of test_invariant_verify_exec_unknown_exec_exits_2.
func TestInvariantVerifyExecUnknownExecExits2(t *testing.T) {
	c, root, _ := execCamp(t, "EXEC-0000000001")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", "EXEC-nope")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "EXEC-nope") {
		t.Fatalf("stderr %q", errS)
	}
	if strings.Contains(errS, "Traceback") {
		t.Fatalf("stderr carries a traceback: %q", errS)
	}
	if got := objStr(invEntry(t, c, "INV-008"), "status"); got != "UNVERIFIED" {
		t.Fatalf("status %q, want UNVERIFIED", got)
	}
}

// Port of test_invariant_verify_exec_incomplete_exec_exits_2.
func TestInvariantVerifyExecIncompleteExecExits2(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001")
	p := filepath.Join(c.ExecsDir, objStr(rec, "exec_id"), "exec_record.json")
	broken, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	broken = setObjFieldCLI(broken, "finished_at", validation.VNull())
	if err := validation.WriteJson(p, broken, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", objStr(rec, "exec_id"))
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, objStr(rec, "exec_id")) {
		t.Fatalf("stderr must name the exec: %q", errS)
	}
	if !strings.Contains(strings.ToLower(errS), "incomplete") {
		t.Fatalf("stderr %q", errS)
	}
}

// Port of test_invariant_verify_rejects_both_options.
func TestInvariantVerifyRejectsBothOptions(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", objStr(rec, "exec_id"), "--artifact", "ART-1")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "--artifact") || !strings.Contains(errS, "--exec") {
		t.Fatalf("stderr %q", errS)
	}
}

// Port of test_invariant_verify_requires_one_option.
func TestInvariantVerifyRequiresOneOption(t *testing.T) {
	c, root, _ := execCamp(t, "EXEC-0000000001")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "--artifact") || !strings.Contains(errS, "--exec") {
		t.Fatalf("stderr %q", errS)
	}
}

// Port of test_invariant_verify_exec_unknown_invariant_exits_2.
func TestInvariantVerifyExecUnknownInvariantExits2(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-NOPE", "--exec", objStr(rec, "exec_id"))
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "INV-NOPE") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestInvariantVerifyExecRelevanceGate: the --exec path is bound twice over.
// (a) the exec-relevance gate: a whole-suite `forge test` targeted no
// applies_to contract, so the citation is refused before the verification axis
// moves — the captured output cannot decide this, because a Foundry suite log
// names every contract it printed. (b) once the exec did target the contract,
// Task 4's byte gate still applies: a captured log naming nothing is refused,
// and the artifact's registry note (which always carries the id) is metadata,
// never evidence. (c) the honest rerun lands.
func TestInvariantVerifyExecRelevanceGate(t *testing.T) {
	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
	execID := objStr(rec, "exec_id")
	// (a) an untargeted whole-suite exec whose log names the invariant.
	suite := invExecRecord(t, c, "EXEC-0000000002", "forge test")
	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", objStr(suite, "exec_id"))
	if code != 2 {
		t.Fatalf("untargeted exec: exit %d, want 2 (%q)", code, errS)
	}
	if !strings.Contains(errS,
		"does not target any applies_to contract of INV-008 (no-target-match)") {
		t.Fatalf("untargeted exec stderr %q", errS)
	}
	if got := objStr(invEntry(t, c, "INV-008"), "status"); got != "UNVERIFIED" {
		t.Fatalf("untargeted exec status %q, want UNVERIFIED", got)
	}
	// (b) a targeted exec with a generic output log.
	if err := os.WriteFile(objStr(rec, "stdout_path"),
		[]byte("PASS: test_liveness\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", execID)
	if code != 2 {
		t.Fatalf("generic output: exit %d, want 2 (%q)", code, errS)
	}
	if !strings.Contains(errS, "does not reference INV-008") {
		t.Fatalf("generic output stderr %q", errS)
	}
	if got := objStr(invEntry(t, c, "INV-008"), "status"); got != "UNVERIFIED" {
		t.Fatalf("generic output status %q, want UNVERIFIED", got)
	}
	// (c) the honest rerun: the captured output names the invariant.
	if err := os.WriteFile(objStr(rec, "stdout_path"),
		[]byte("INV-008: the fee accumulator holds — PASS: test_liveness\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-008", "--exec", execID)
	if code != 0 {
		t.Fatalf("honest output: exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "CHECKED_AGAINST_CODE") {
		t.Fatalf("output %q", out)
	}
	entry := invEntry(t, c, "INV-008")
	if got := objStr(entry, "status"); got != "CHECKED_AGAINST_CODE" {
		t.Fatalf("status %q", got)
	}
	if got, want := artifactPathOf(t, c, objStr(entry, "verified_by")),
		resolvedPath(t, objStr(rec, "stdout_path")); got != want {
		t.Fatalf("artifact path %q, want %q (the exec's stdout)", got, want)
	}
}
