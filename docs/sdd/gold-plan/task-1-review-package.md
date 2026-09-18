# Gold Task 1 review package
## commits (d9da3428..55be2c2e)
55be2c2e fix(invariants): exec-relevance gate for invariant-verify (defect 6)
## diffstat
 internal/cli/cmd_invariant_verify.go               |  10 ++
 .../cmd_invariant_verify_exec_relevance_test.go    | 100 +++++++++++++++
 internal/cli/cmd_invariant_verify_exec_test.go     |  71 ++++++++---
 internal/cli/cmd_invariant_verify_test.go          |  34 +++--
 internal/invariants/invariants.go                  | 121 ++++++++++++++++++
 .../invariants/invariants_exec_relevance_test.go   | 140 +++++++++++++++++++++
 internal/invariants/invariants_test.go             |  12 +-
 7 files changed, 455 insertions(+), 33 deletions(-)
## full diff (-U10)
diff --git a/internal/cli/cmd_invariant_verify.go b/internal/cli/cmd_invariant_verify.go
index 9aff5f2b..27790941 100644
--- a/internal/cli/cmd_invariant_verify.go
+++ b/internal/cli/cmd_invariant_verify.go
@@ -88,20 +88,30 @@ func runInvariantVerify(root string, args []string, r *Runner) int {
 		fmt.Fprintln(r.Err, "invariant-verify: pass --artifact ART-... or "+
 			"--exec EXEC-... (one is required)")
 		return 2
 	}
 	if execID != "" {
 		var code int
 		artifact, code = resolveExecArtifact(c, invID, execID, r)
 		if code != 0 {
 			return code
 		}
+		// The exec-relevance gate: the cited exec must have RUN something
+		// bound to this invariant's applies_to contracts. A full-suite log
+		// names every contract it printed, so the recorded command decides —
+		// and the refusal lands before the verification axis can move.
+		if ok, reason := invariants.ExecTouchesInvariant(c, invID, execID); !ok {
+			fmt.Fprintf(r.Err, "invariant verify failed: cited exec %s does not "+
+				"target any applies_to contract of %s (%s)\n", execID, invID,
+				reason)
+			return 2
+		}
 	}
 	entry, err := invariants.VerifyInvariantStatement(c, invID, artifact)
 	if err != nil {
 		fmt.Fprintf(r.Err, "invariant verify failed: %s\n",
 			validation.PyReprStr(err.Error()))
 		return 2
 	}
 	fmt.Fprintf(r.Out, "%s: CHECKED_AGAINST_CODE (artifact %s)\n", invID,
 		objStr(entry, "verified_by"))
 	// The verdict above is an attestation, not a mechanical proof: say so on
diff --git a/internal/cli/cmd_invariant_verify_exec_relevance_test.go b/internal/cli/cmd_invariant_verify_exec_relevance_test.go
new file mode 100644
index 00000000..35ed7d7e
--- /dev/null
+++ b/internal/cli/cmd_invariant_verify_exec_relevance_test.go
@@ -0,0 +1,100 @@
+package cli
+
+// cmd_invariant_verify_exec_relevance_test.go: Task 1 (defect 6) — the CLI
+// half of the exec-relevance gate. `invariant-verify --exec` only moves the
+// verification axis when the cited exec's recorded command targeted one of the
+// invariant's applies_to contracts; a generic full-suite run is refused before
+// anything is written, however loudly its captured log names the invariant.
+
+import (
+	"os"
+	"strings"
+	"testing"
+
+	"websec/internal/state"
+	"websec/internal/validation"
+)
+
+// relExec is one finished exec whose recorded command and captured log are
+// both in play: the command decides the exec-relevance gate, the log decides
+// Task 4's byte gate.
+func relExec(t *testing.T, c *state.Campaign, execID, command,
+	stdout string) validation.Value {
+	t.Helper()
+	rec := invExecRecord(t, c, execID, command)
+	if err := os.WriteFile(objStr(rec, "stdout_path"), []byte(stdout),
+		0o644); err != nil {
+		t.Fatal(err)
+	}
+	return rec
+}
+
+// relCamp is the exec-relevance fixture: INV-3 bound to the Staking contract,
+// one exec whose command targeted it, and one whole-suite exec whose captured
+// log names the invariant anyway.
+func relCamp(t *testing.T) (c *state.Campaign, root, hit, suite string) {
+	t.Helper()
+	c, root = t15Campaign(t, "inv-exec-rel")
+	t15SeedInvariant(t, c, "INV-3", "staking liveness", "Staking")
+	log := "INV-3: staking liveness\nPASS: test_liveness\n"
+	hit = objStr(relExec(t, c, "EXEC-0000000001",
+		"forge test --match-contract Staking", log), "exec_id")
+	suite = objStr(relExec(t, c, "EXEC-0000000002", "forge test", log),
+		"exec_id")
+	return c, root, hit, suite
+}
+
+// TestInvariantVerifyRefusesUntargetedExec: the cited exec ran a whole-suite
+// `forge test` that targeted no applies_to contract. Its captured log names
+// the invariant, so Task 4's byte gate would have waved it through — the
+// exec-relevance gate refuses it, and nothing about the verification axis
+// moves: no status change, no verified_by, no attestation label, no event.
+func TestInvariantVerifyRefusesUntargetedExec(t *testing.T) {
+	c, root, _, suite := relCamp(t)
+	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
+		"INV-3", "--exec", suite)
+	if code != 2 {
+		t.Fatalf("exit = %d, want 2 (%q)", code, errS)
+	}
+	if !strings.Contains(errS, "cited exec "+suite+
+		" does not target any applies_to contract of INV-3 (no-target-match)") {
+		t.Fatalf("stderr missing the refusal text: %q", errS)
+	}
+	entry := invEntry(t, c, "INV-3")
+	if got := objStr(entry, "status"); got != "UNVERIFIED" {
+		t.Fatalf("status = %q, want UNVERIFIED", got)
+	}
+	if got := objStr(entry, "verified_by"); got != "" {
+		t.Fatalf("verified_by = %q, want empty on a refusal", got)
+	}
+	if got := objStr(entry, "verification_method"); got != "" {
+		t.Fatalf("verification_method = %q, want no attestation label", got)
+	}
+	events, err := c.Events()
+	if err != nil {
+		t.Fatal(err)
+	}
+	for _, ev := range events {
+		if objStr(ev, "type") == "invariant.verified" {
+			t.Fatal("a refusal must emit no invariant.verified event")
+		}
+	}
+}
+
+// TestInvariantVerifyAcceptsTargetedExec: the exec's recorded command targeted
+// the applies_to contract, so the citation lands end-to-end.
+func TestInvariantVerifyAcceptsTargetedExec(t *testing.T) {
+	c, root, hit, _ := relCamp(t)
+	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
+		"INV-3", "--exec", hit)
+	if code != 0 {
+		t.Fatalf("exit = %d, want 0 (%q)", code, errS)
+	}
+	if !strings.Contains(out, "INV-3: CHECKED_AGAINST_CODE") {
+		t.Fatalf("output %q", out)
+	}
+	if got := objStr(invEntry(t, c, "INV-3"), "status"); got !=
+		"CHECKED_AGAINST_CODE" {
+		t.Fatalf("status = %q, want CHECKED_AGAINST_CODE", got)
+	}
+}
diff --git a/internal/cli/cmd_invariant_verify_exec_test.go b/internal/cli/cmd_invariant_verify_exec_test.go
index f7c87f4e..54c8f901 100644
--- a/internal/cli/cmd_invariant_verify_exec_test.go
+++ b/internal/cli/cmd_invariant_verify_exec_test.go
@@ -10,54 +10,68 @@ import (
 	"os"
 	"path/filepath"
 	"strings"
 	"testing"
 
 	"websec/internal/invariants"
 	"websec/internal/state"
 	"websec/internal/validation"
 )
 
-// execCamp is the `exec_camp` fixture: a seeded INV-008 and one finished exec.
-func execCamp(t *testing.T, execID string) (*state.Campaign, string,
-	validation.Value) {
+// execCamp is the `exec_camp` fixture: a seeded INV-008 bound to the optional
+// applies_to target, and one finished exec. The exec-relevance gate reads what
+// the exec RAN, so a binding makes its recorded command target that contract;
+// with no binding the historical untargeted fixture is unchanged.
+func execCamp(t *testing.T, execID string, appliesTo ...string) (*state.Campaign,
+	string, validation.Value) {
 	t.Helper()
 	c, root := t15Campaign(t, "inv-exec")
-	t15SeedInvariant(t, c, "INV-008", "liveness: the fee accumulator holds")
-	return c, root, invExecRecord(t, c, execID)
+	t15SeedInvariant(t, c, "INV-008", "liveness: the fee accumulator holds",
+		appliesTo...)
+	command := "forge test --match-test test_liveness"
+	if len(appliesTo) > 0 {
+		command = "forge test --match-contract " + appliesTo[0]
+	}
+	return c, root, invExecRecord(t, c, execID, command)
 }
 
 // invExecRecord is conftest's sandboxed_exec shape: BOTH capture files exist
-// (stdout holds the run, stderr starts empty) and the record is finished.
-func invExecRecord(t *testing.T, c *state.Campaign, execID string) validation.Value {
+// (stdout holds the run, stderr starts empty) and the record is finished. The
+// optional command overrides the recorded command line.
+func invExecRecord(t *testing.T, c *state.Campaign, execID string,
+	command ...string) validation.Value {
 	t.Helper()
+	cmd := "forge test --match-test test_liveness"
+	if len(command) > 0 {
+		cmd = command[0]
+	}
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
-		kvT("command", validation.VStr("forge test --match-test test_liveness")),
+		kvT("command", validation.VStr(cmd)),
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
@@ -98,21 +112,21 @@ func artifactPathOf(t *testing.T, c *state.Campaign, aid string) string {
 	}
 	p := objStr(art, "path")
 	if !filepath.IsAbs(p) {
 		p = filepath.Join(c.Root, p)
 	}
 	return resolvedPath(t, p)
 }
 
 // Port of test_invariant_verify_exec_happy_path.
 func TestInvariantVerifyExecHappyPath(t *testing.T) {
-	c, root, rec := execCamp(t, "EXEC-0000000001")
+	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
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
@@ -127,21 +141,21 @@ func TestInvariantVerifyExecHappyPath(t *testing.T) {
 	if err != nil {
 		t.Fatal(err)
 	}
 	if !invariants.IsVerified(entry, c, "INV-008", events) {
 		t.Fatal("the recorded check must verify")
 	}
 }
 
 // Port of test_invariant_verify_exec_rerun_refreshes_the_same_artifact.
 func TestInvariantVerifyExecRerunRefreshesTheSameArtifact(t *testing.T) {
-	c, root, rec := execCamp(t, "EXEC-0000000001")
+	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
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
@@ -173,21 +187,21 @@ func TestInvariantVerifyExecRerunRefreshesTheSameArtifact(t *testing.T) {
 			atPath++
 		}
 	}
 	if atPath != 1 {
 		t.Fatalf("artifact rows at the exec output path = %d, want 1", atPath)
 	}
 }
 
 // Port of test_invariant_verify_exec_falls_back_to_the_stderr_log.
 func TestInvariantVerifyExecFallsBackToTheStderrLog(t *testing.T) {
-	c, root, rec := execCamp(t, "EXEC-0000000001")
+	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
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
@@ -305,45 +319,62 @@ func TestInvariantVerifyExecUnknownInvariantExits2(t *testing.T) {
 	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
 		"INV-NOPE", "--exec", objStr(rec, "exec_id"))
 	if code != 2 {
 		t.Fatalf("exit %d, want 2", code)
 	}
 	if !strings.Contains(errS, "INV-NOPE") {
 		t.Fatalf("stderr %q", errS)
 	}
 }
 
-// TestInvariantVerifyExecRelevanceGate: the --exec path still lands
-// end-to-end when the exec's captured output names the invariant it
-// verifies, and refuses a generic run that names nothing. The artifact's
-// registry note (which always carries the id) is metadata, never evidence —
-// if it counted, every --exec would satisfy the gate.
+// TestInvariantVerifyExecRelevanceGate: the --exec path is bound twice over.
+// (a) the exec-relevance gate: a whole-suite `forge test` targeted no
+// applies_to contract, so the citation is refused before the verification axis
+// moves — the captured output cannot decide this, because a Foundry suite log
+// names every contract it printed. (b) once the exec did target the contract,
+// Task 4's byte gate still applies: a captured log naming nothing is refused,
+// and the artifact's registry note (which always carries the id) is metadata,
+// never evidence. (c) the honest rerun lands.
 func TestInvariantVerifyExecRelevanceGate(t *testing.T) {
-	c, root, rec := execCamp(t, "EXEC-0000000001")
+	c, root, rec := execCamp(t, "EXEC-0000000001", "Staking")
 	execID := objStr(rec, "exec_id")
-	// (a) a generic output log: registered as the artifact, then refused.
+	// (a) an untargeted whole-suite exec whose log names the invariant.
+	suite := invExecRecord(t, c, "EXEC-0000000002", "forge test")
+	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
+		"INV-008", "--exec", objStr(suite, "exec_id"))
+	if code != 2 {
+		t.Fatalf("untargeted exec: exit %d, want 2 (%q)", code, errS)
+	}
+	if !strings.Contains(errS,
+		"does not target any applies_to contract of INV-008 (no-target-match)") {
+		t.Fatalf("untargeted exec stderr %q", errS)
+	}
+	if got := objStr(invEntry(t, c, "INV-008"), "status"); got != "UNVERIFIED" {
+		t.Fatalf("untargeted exec status %q, want UNVERIFIED", got)
+	}
+	// (b) a targeted exec with a generic output log.
 	if err := os.WriteFile(objStr(rec, "stdout_path"),
 		[]byte("PASS: test_liveness\n"), 0o644); err != nil {
 		t.Fatal(err)
 	}
-	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
+	code, _, errS = run(t, "--root", root, "invariant-verify", c.CampaignID,
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
-	// (b) the honest rerun: the captured output names the invariant.
+	// (c) the honest rerun: the captured output names the invariant.
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
diff --git a/internal/cli/cmd_invariant_verify_test.go b/internal/cli/cmd_invariant_verify_test.go
index c07a1176..91d514e9 100644
--- a/internal/cli/cmd_invariant_verify_test.go
+++ b/internal/cli/cmd_invariant_verify_test.go
@@ -12,56 +12,69 @@ import (
 	"path/filepath"
 	"regexp"
 	"strings"
 	"testing"
 
 	"websec/internal/invariants"
 	"websec/internal/state"
 	"websec/internal/validation"
 )
 
-// t15SeedInvariant is invariants.seed_from_model with one statement.
-func t15SeedInvariant(t *testing.T, c *state.Campaign, invID, statement string) {
+// t15SeedInvariant is invariants.seed_from_model with one statement. The
+// optional appliesTo binds the invariant to a contract; with none the entry
+// is unbound exactly as before (seed_from_model defaults applies_to to []).
+func t15SeedInvariant(t *testing.T, c *state.Campaign, invID, statement string,
+	appliesTo ...string) {
 	t.Helper()
-	model := validation.VObj(kvT("invariants", validation.VArr(
-		validation.VObj(
-			kvT("id", validation.VStr(invID)),
-			kvT("statement", validation.VStr(statement)),
-		))))
+	entry := validation.VObj(
+		kvT("id", validation.VStr(invID)),
+		kvT("statement", validation.VStr(statement)),
+	)
+	if len(appliesTo) > 0 {
+		targets := make([]validation.Value, len(appliesTo))
+		for i, s := range appliesTo {
+			targets[i] = validation.VStr(s)
+		}
+		entry.O = validation.SetOrAppend(entry.O, "applies_to",
+			validation.VArr(targets...))
+	}
+	model := validation.VObj(kvT("invariants", validation.VArr(entry)))
 	if _, err := invariants.SeedFromModel(c, model); err != nil {
 		t.Fatalf("seed model: %v", err)
 	}
 }
 
 // t15ExecRecord writes one finished EXEC record (sandbox.register_exec is a
 // later phase; the ledger row is written directly, as port_test.go does). Its
 // captured stdout names INV-1 — the honest output the relevance gate requires
-// of the exec the CLI registers as the check artifact.
+// of the exec the CLI registers as the check artifact — and its recorded
+// command targets the Vault contract, so the exec-relevance gate accepts it
+// for an INV-1 bound to Vault (see TestInvariantVerifyExec).
 func t15ExecRecord(t *testing.T, c *state.Campaign, execID string) string {
 	t.Helper()
 	dir := filepath.Join(c.ExecsDir, execID)
 	if err := os.MkdirAll(dir, 0o755); err != nil {
 		t.Fatal(err)
 	}
 	stdout := filepath.Join(dir, "stdout.log")
 	if err := os.WriteFile(stdout,
 		[]byte("INV-1: totalAssets monotone except withdraw\nPASS: invariant check\n"),
 		0o644); err != nil {
 		t.Fatal(err)
 	}
 	rec := validation.VObj(
 		kvT("exec_id", validation.VStr(execID)),
 		kvT("campaign_id", validation.VStr(c.CampaignID)),
 		kvT("profile", validation.VStr("docker-networkless")),
 		kvT("finding_id", validation.VNull()),
 		kvT("artifact_id", validation.VNull()),
-		kvT("command", validation.VStr("forge test")),
+		kvT("command", validation.VStr("forge test --match-contract Vault")),
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
@@ -142,21 +155,22 @@ func TestInvariantVerifyArtifactRelevanceGate(t *testing.T) {
 	if code != 0 {
 		t.Fatalf("honest artifact: exit %d: %q", code, errS)
 	}
 	if !strings.Contains(out, "CHECKED_AGAINST_CODE") {
 		t.Fatalf("output %q", out)
 	}
 }
 
 func TestInvariantVerifyExec(t *testing.T) {
 	c, root := t15Campaign(t, "inv")
-	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
+	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw",
+		"Vault")
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
diff --git a/internal/invariants/invariants.go b/internal/invariants/invariants.go
index 9bf6fa46..dbb1b93c 100644
--- a/internal/invariants/invariants.go
+++ b/internal/invariants/invariants.go
@@ -933,20 +933,141 @@ func referenceTokens(invariantID string, entry validation.Value) []string {
 
 // irrelevantArtifact is the Task 4 refusal: the cited bytes name neither the
 // invariant nor any of its applies_to targets.
 func irrelevantArtifact(artifactID, invariantID string) error {
 	return fmt.Errorf("artifact %s does not reference %s (nor its applies_to) "+
 		"— cite a check that names what it verifies (invariant-verify with "+
 		"--exec <id> re-registers stdout as the artifact)", artifactID,
 		invariantID)
 }
 
+// ---- Task 1: exec relevance binding ---------------------------------------
+
+// ExecTouchesInvariant is the exec-relevance gate: a cited exec only counts as
+// a check of this invariant when the command it RAN targeted one of the
+// entry's applies_to contracts. The captured output cannot decide this — a
+// Foundry full-suite run names every contract in its log, so an exec can cite
+// an invariant it never touched — hence the gate reads the recorded command
+// line, never the log.
+//
+// An invariant bound to nothing cannot be exec-verified: empty applies_to is
+// unbound, never a wildcard (the same law Task 4 pins for artifact
+// references). The token set comes from applies_to ALONE — the invariant id is
+// deliberately out of scope, because `--match-contract INV-3` names the
+// bookkeeping id, not a contract.
+//
+// Reasons: "no-exec-record" (no such exec, or an exec store that cannot be
+// read), "no-command-record" (the record carries no command line), and
+// "no-target-match" (no applies_to token occurs at a left boundary).
+func ExecTouchesInvariant(c *state.Campaign, invID, execID string) (bool, string) {
+	execs, err := state.AllExecs(c)
+	if err != nil {
+		// A store that cannot be read names no exec: fail closed.
+		return false, "no-exec-record"
+	}
+	var rec validation.Value
+	found := false
+	for _, e := range execs {
+		if objStr(e, "exec_id") == execID {
+			rec, found = e, true
+			break
+		}
+	}
+	if !found {
+		return false, "no-exec-record"
+	}
+	command := stripShellQuotes(objStr(rec, "command"))
+	if command == "" {
+		return false, "no-command-record"
+	}
+	links, err := LoadLinks(c)
+	if err != nil {
+		// No readable registry, no applies_to targets: fail closed.
+		return false, "no-target-match"
+	}
+	for _, tok := range appliesToTokens(objAt(regOf(links), invID)) {
+		if tokenOccursLeftBound(command, tok) {
+			return true, ""
+		}
+	}
+	return false, "no-target-match"
+}
+
+// appliesToTokens is the exec-relevance token set: every applies_to string in
+// its recorded spelling and in NormalizeInvID's canonical one, deduplicated,
+// empties dropped. Unlike referenceTokens it excludes the invariant id — see
+// ExecTouchesInvariant.
+func appliesToTokens(entry validation.Value) []string {
+	seen := map[string]bool{}
+	out := []string{}
+	for _, t := range objAt(entry, "applies_to").A {
+		if t.Kind != validation.Str {
+			continue
+		}
+		for _, tok := range []string{t.S, NormalizeInvID(t.S)} {
+			if tok == "" || seen[tok] {
+				continue
+			}
+			seen[tok] = true
+			out = append(out, tok)
+		}
+	}
+	return out
+}
+
+// tokenOccursLeftBound reports whether command contains token starting at a
+// left boundary: the match begins the string, or the character before it is
+// outside [0-9a-z_]. Matching is case-insensitive and there is deliberately NO
+// trailing boundary.
+//
+// This intentionally differs from the Task 4 artifact matcher
+// (artifactReferencesInvariant), which requires a full \b...\b word match.
+// Foundry's --match-contract is a regex/prefix filter, so \bStaking\b would
+// reject `--match-contract StakingTest` — exactly the targeted command this
+// gate must accept — while the left boundary is what keeps `Unstaking` out.
+// The Task 4 matcher stays byte-identical: its refusals are pinned.
+func tokenOccursLeftBound(command, token string) bool {
+	if token == "" {
+		return false
+	}
+	cmd := strings.ToLower(command)
+	tok := strings.ToLower(token)
+	for from := 0; from < len(cmd); {
+		i := strings.Index(cmd[from:], tok)
+		if i < 0 {
+			return false
+		}
+		at := from + i
+		if at == 0 || !isLowerWordByte(cmd[at-1]) {
+			return true
+		}
+		from = at + 1
+	}
+	return false
+}
+
+// isLowerWordByte is the left-boundary alphabet on the lowered command:
+// [0-9a-z_] — the characters a contract name can be glued to.
+func isLowerWordByte(b byte) bool {
+	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
+}
+
+// stripShellQuotes removes one layer of matching surrounding quotes from a
+// recorded command line.
+func stripShellQuotes(s string) string {
+	s = strings.TrimSpace(s)
+	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
+		return s[1 : len(s)-1]
+	}
+	return s
+}
+
 // ContradictInvariantStatement is contradict_invariant_statement:
 // CONTRADICTED with an evidence anchor (file#Lline or a registered artifact
 // id). A finding that depends on a contradicted model invariant cannot
 // advance.
 func ContradictInvariantStatement(c *state.Campaign, invariantID,
 	evidenceRef string) (validation.Value, error) {
 	links, err := LoadLinks(c)
 	if err != nil {
 		return validation.VNull(), err
 	}
diff --git a/internal/invariants/invariants_exec_relevance_test.go b/internal/invariants/invariants_exec_relevance_test.go
new file mode 100644
index 00000000..b3a7da63
--- /dev/null
+++ b/internal/invariants/invariants_exec_relevance_test.go
@@ -0,0 +1,140 @@
+// invariants_exec_relevance_test.go: Task 1 (defect 6) — the exec-relevance
+// gate. A cited exec only counts as a check of an invariant when the command
+// it RAN targeted one of the entry's applies_to contracts. The captured output
+// cannot decide this: a Foundry full-suite run names every contract in its
+// log, which is exactly how a generic suite exec "closed" an invariant it
+// never touched.
+package invariants
+
+import (
+	"path/filepath"
+	"testing"
+
+	"websec/internal/state"
+	"websec/internal/validation"
+)
+
+// seedBound seeds one invariant with an explicit applies_to binding.
+func seedBound(t *testing.T, c *state.Campaign, invID, statement string,
+	appliesTo ...string) {
+	t.Helper()
+	model := validation.VObj(kv("invariants", validation.VArr(validation.VObj(
+		kv("id", validation.VStr(invID)),
+		kv("statement", validation.VStr(statement)),
+		kv("applies_to", strArr(appliesTo)),
+	))))
+	if _, err := SeedFromModel(c, model); err != nil {
+		t.Fatalf("seed model: %v", err)
+	}
+}
+
+// execRan is testExec with only the recorded command line in play.
+func execRan(t *testing.T, c *state.Campaign, command string) validation.Value {
+	t.Helper()
+	return testExec(t, c, "docker-networkless", "", 0, "PASS\n", command)
+}
+
+// execWithoutCommand is an exec record that carries no command line at all.
+func execWithoutCommand(t *testing.T, c *state.Campaign) validation.Value {
+	t.Helper()
+	rec := execRan(t, c, "forge test --match-contract Staking")
+	rec.O = popKey(rec.O, "command")
+	p := filepath.Join(c.ExecsDir, objStr(rec, "exec_id"), "exec_record.json")
+	if err := validation.WriteJson(p, rec, ""); err != nil {
+		t.Fatal(err)
+	}
+	return rec
+}
+
+// TestExecTouchesInvariant pins the binding matcher: a case-insensitive
+// LEFT-boundary token match with no trailing boundary. The trailing side is
+// deliberately open because Foundry's --match-contract is a regex/prefix
+// filter — `\bStaking\b` would reject `--match-contract StakingTest`, exactly
+// the targeted command the gate exists to accept — while the left boundary is
+// what keeps `Unstaking` out.
+func TestExecTouchesInvariant(t *testing.T) {
+	c := invCamp(t)
+	seedBound(t, c, "INV-3", "staking liveness", "Staking")
+	for _, cmd := range []string{
+		"forge test --match-contract Staking",
+		"forge test --match-contract StakingTest",
+		"forge test --match-path src/Staking.t.sol",
+		"forge test --match-contract staking",
+		"'forge test --match-contract Staking'",
+		"forge test --match-contract Staking && forge test",
+	} {
+		ex := execRan(t, c, cmd)
+		ok, reason := ExecTouchesInvariant(c, "INV-3", objStr(ex, "exec_id"))
+		if !ok || reason != "" {
+			t.Errorf("%q: ok=%v reason=%q, want true/\"\"", cmd, ok, reason)
+		}
+	}
+	// Adversarial near-misses: the token sits inside another word (`n`
+	// precedes), belongs to another contract, or is absent altogether.
+	for _, cmd := range []string{
+		"forge test --match-contract Unstaking",
+		"forge test --match-contract OracleTest",
+		"forge test",
+	} {
+		ex := execRan(t, c, cmd)
+		ok, reason := ExecTouchesInvariant(c, "INV-3", objStr(ex, "exec_id"))
+		if ok || reason != "no-target-match" {
+			t.Errorf("%q: ok=%v reason=%q, want false/no-target-match", cmd, ok, reason)
+		}
+	}
+	ok, reason := ExecTouchesInvariant(c, "INV-3", "EXEC-missing")
+	if ok || reason != "no-exec-record" {
+		t.Errorf("missing exec: ok=%v reason=%q, want false/no-exec-record", ok, reason)
+	}
+}
+
+// TestExecTouchesInvariantIgnoresInvariantID: the id is bookkeeping, not a
+// contract. referenceTokens prepends the invariant id (and its canonical
+// spelling), so reusing it here would open a `--match-contract INV-3` bypass —
+// a command naming only the id must never satisfy the gate.
+func TestExecTouchesInvariantIgnoresInvariantID(t *testing.T) {
+	c := invCamp(t)
+	seedBound(t, c, "INV-003", "staking liveness", "Staking")
+	for _, cmd := range []string{
+		"forge test --match-contract INV-003",
+		"forge test --match-contract INV-3",
+		"forge test --match-path src/INV-003.t.sol",
+	} {
+		ex := execRan(t, c, cmd)
+		ok, reason := ExecTouchesInvariant(c, "INV-003", objStr(ex, "exec_id"))
+		if ok || reason != "no-target-match" {
+			t.Errorf("%q: ok=%v reason=%q, want false/no-target-match "+
+				"(the id is not an applies_to target)", cmd, ok, reason)
+		}
+	}
+}
+
+// TestExecTouchesInvariantEmptyAppliesTo: an invariant bound to nothing cannot
+// be exec-verified. Empty applies_to is unbound, never a wildcard — the same
+// law Task 4 pins for artifact references.
+func TestExecTouchesInvariantEmptyAppliesTo(t *testing.T) {
+	c := invCamp(t)
+	seedBound(t, c, "INV-9", "unbound invariant")
+	ex := execRan(t, c, "forge test --match-contract Staking")
+	ok, reason := ExecTouchesInvariant(c, "INV-9", objStr(ex, "exec_id"))
+	if ok || reason != "no-target-match" {
+		t.Errorf("empty applies_to: ok=%v reason=%q, want false/no-target-match",
+			ok, reason)
+	}
+}
+
+// TestExecTouchesInvariantNoCommandRecord: a record with no command line (or
+// an empty one) cannot show what the exec ran — refused with the named reason,
+// never passed by default.
+func TestExecTouchesInvariantNoCommandRecord(t *testing.T) {
+	c := invCamp(t)
+	seedBound(t, c, "INV-3", "staking liveness", "Staking")
+	for _, ex := range []validation.Value{execRan(t, c, ""),
+		execWithoutCommand(t, c)} {
+		ok, reason := ExecTouchesInvariant(c, "INV-3", objStr(ex, "exec_id"))
+		if ok || reason != "no-command-record" {
+			t.Errorf("%s: ok=%v reason=%q, want false/no-command-record",
+				objStr(ex, "exec_id"), ok, reason)
+		}
+	}
+}
diff --git a/internal/invariants/invariants_test.go b/internal/invariants/invariants_test.go
index cfabf93b..2ac951c4 100644
--- a/internal/invariants/invariants_test.go
+++ b/internal/invariants/invariants_test.go
@@ -148,24 +148,30 @@ func findingWithInvariant(t *testing.T, c *state.Campaign, invID string) validat
 		)))
 	if err := findings.SaveFinding(c, &f); err != nil {
 		t.Fatal(err)
 	}
 	return f
 }
 
 var execSeq int
 
 // testExec is the conftest `sandboxed_exec` equivalent (sandbox.register_exec
-// lands with P2): it writes the EXEC ledger record directly.
+// lands with P2): it writes the EXEC ledger record directly. The optional
+// command overrides the historical recorded command line — the field the
+// exec-relevance gate reads.
 func testExec(t *testing.T, c *state.Campaign, profile, findingID string,
-	exitStatus int64, stdout string) validation.Value {
+	exitStatus int64, stdout string, command ...string) validation.Value {
 	t.Helper()
+	cmd := "forge test --match-test test_exploit"
+	if len(command) > 0 {
+		cmd = command[0]
+	}
 	execSeq++
 	execID := fmt.Sprintf("EXEC-%010x", execSeq)
 	dir := filepath.Join(c.ExecsDir, execID)
 	if err := os.MkdirAll(dir, 0o755); err != nil {
 		t.Fatal(err)
 	}
 	stdoutPath := filepath.Join(dir, "stdout.log")
 	stderrPath := filepath.Join(dir, "stderr.log")
 	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
 		t.Fatal(err)
@@ -176,21 +182,21 @@ func testExec(t *testing.T, c *state.Campaign, profile, findingID string,
 	fidV := validation.VNull()
 	if findingID != "" {
 		fidV = validation.VStr(findingID)
 	}
 	rec := validation.VObj(
 		kv("exec_id", validation.VStr(execID)),
 		kv("campaign_id", validation.VStr(c.CampaignID)),
 		kv("profile", validation.VStr(profile)),
 		kv("finding_id", fidV),
 		kv("artifact_id", validation.VNull()),
-		kv("command", validation.VStr("forge test --match-test test_exploit")),
+		kv("command", validation.VStr(cmd)),
 		kv("exit_status", validation.VInt(exitStatus)),
 		kv("stdout_path", validation.VStr(stdoutPath)),
 		kv("stderr_path", validation.VStr(stderrPath)),
 	)
 	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
 		rec, ""); err != nil {
 		t.Fatal(err)
 	}
 	return rec
 }
