# Final fix wave review package
## commits (bc80d151..64d7b11b)
64d7b11b docs(eval): fresh-campaign requirement for the partial-coverage refusal example
50d6da9c fix(cli): refused invariant-verify citations mint no artifact row (defect 6 residue)
## diffstat
 docs/eval/morph-rerun-protocol.md                  |  8 +++++++-
 internal/cli/cmd_invariant_verify.go               | 22 ++++++++++++----------
 .../cmd_invariant_verify_exec_relevance_test.go    | 13 +++++++++++++
 3 files changed, 32 insertions(+), 11 deletions(-)
## full diff (-U10)
diff --git a/docs/eval/morph-rerun-protocol.md b/docs/eval/morph-rerun-protocol.md
index 6342843e..45ed41de 100644
--- a/docs/eval/morph-rerun-protocol.md
+++ b/docs/eval/morph-rerun-protocol.md
@@ -183,21 +183,27 @@ around them — record each firing you see.
       {"name": "message_queue",
        "states": [{"id": "queued"}, {"id": "dropped", "terminal": true}],
        "transitions": [
          {"from": "queued", "to": "dropped", "trigger": "onDropMessage"}]}],
     "invariants": [{"id": "INV-1", "kind": "liveness",
       "severity_if_broken": "critical",
       "statement": "every queued message eventually advances to dropped",
       "applies_to": ["message_queue"]}]}
    ```
 
-   Verbatim output from a scratch campaign, 2026-09-18 (exit 2):
+   Load this variant in a **fresh campaign**. In the §3.1 → §3.2-1 sequence the
+   skeleton's synthesized `INV-1` liveness template already covers
+   `rollup_finalization`; the variant's `INV-1` refreshes that row in place, its
+   `applies_to` never lands, and the gate instead names the *other* machine —
+   `state machine(s) message_queue have no liveness invariant` (reproduced
+   2026-09-18). Verbatim output from a fresh scratch campaign, 2026-09-18
+   (exit 2):
 
    ```
    model load failed: protocol model: state machine(s) rollup_finalization have no liveness invariant (one per machine — stage 37)
    ```
 
    If the uncovered machine is `rollup_finalization`, the gate has just named
    the G-01 gap. Fix the *model* (or register a real liveness invariant
    covering that machine), never the gate.
 2. **Cold-probe nag** — while the phase is DISCOVERY with no probe emit on
    record, the cockpit carries `webv2 probes <C-id> run --emit`:
diff --git a/internal/cli/cmd_invariant_verify.go b/internal/cli/cmd_invariant_verify.go
index 27790941..8402f5d5 100644
--- a/internal/cli/cmd_invariant_verify.go
+++ b/internal/cli/cmd_invariant_verify.go
@@ -88,30 +88,20 @@ func runInvariantVerify(root string, args []string, r *Runner) int {
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
-		// The exec-relevance gate: the cited exec must have RUN something
-		// bound to this invariant's applies_to contracts. A full-suite log
-		// names every contract it printed, so the recorded command decides —
-		// and the refusal lands before the verification axis can move.
-		if ok, reason := invariants.ExecTouchesInvariant(c, invID, execID); !ok {
-			fmt.Fprintf(r.Err, "invariant verify failed: cited exec %s does not "+
-				"target any applies_to contract of %s (%s)\n", execID, invID,
-				reason)
-			return 2
-		}
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
@@ -168,20 +158,32 @@ func resolveExecArtifact(c *state.Campaign, invID, execID string,
 	if !isFile(outPath) {
 		if alt := objStr(rec, "stderr_path"); isFile(alt) {
 			outPath = alt
 		}
 	}
 	if !isFile(outPath) {
 		fmt.Fprintf(r.Err, "invariant-verify: exec %s has no captured output "+
 			"to register\n", validation.PyReprStr(execID))
 		return "", 2
 	}
+	// The exec-relevance gate: the cited exec must have RUN something bound to
+	// this invariant's applies_to contracts. A full-suite log names every
+	// contract it printed, so the recorded command decides — and the refusal
+	// lands HERE, before RegisterOrRefresh, so a refused citation mints no
+	// durable "checked against code" row asserting a verification that was
+	// just refused (the defect-6 record class).
+	if ok, reason := invariants.ExecTouchesInvariant(c, invID, execID); !ok {
+		fmt.Fprintf(r.Err, "invariant verify failed: cited exec %s does not "+
+			"target any applies_to contract of %s (%s)\n", execID, invID,
+			reason)
+		return "", 2
+	}
 	note := fmt.Sprintf("invariant %s checked against code (exec %s)", invID,
 		execID)
 	reason := fmt.Sprintf("exec %s output registered as the check artifact",
 		execID)
 	aid, err := c.RegisterOrRefresh("other", outPath, note, nil, reason)
 	if err != nil {
 		return "", r.withErr(c.Root, func() error { return err })
 	}
 	return aid, 0
 }
diff --git a/internal/cli/cmd_invariant_verify_exec_relevance_test.go b/internal/cli/cmd_invariant_verify_exec_relevance_test.go
index 35ed7d7e..b03ab084 100644
--- a/internal/cli/cmd_invariant_verify_exec_relevance_test.go
+++ b/internal/cli/cmd_invariant_verify_exec_relevance_test.go
@@ -72,20 +72,33 @@ func TestInvariantVerifyRefusesUntargetedExec(t *testing.T) {
 	}
 	events, err := c.Events()
 	if err != nil {
 		t.Fatal(err)
 	}
 	for _, ev := range events {
 		if objStr(ev, "type") == "invariant.verified" {
 			t.Fatal("a refusal must emit no invariant.verified event")
 		}
 	}
+	// F-B: a refused citation mints no artifact row either. The row's note
+	// ("invariant INV-3 checked against code") is a durable record asserting
+	// the verification this gate just refused — the defect-6 record class.
+	st, err := c.State()
+	if err != nil {
+		t.Fatal(err)
+	}
+	for _, a := range objListAt(st, "artifacts") {
+		if strings.Contains(objStr(a, "note"), "INV-3") {
+			t.Fatalf("refused citation minted artifact row %s: note %q",
+				objStr(a, "artifact_id"), objStr(a, "note"))
+		}
+	}
 }
 
 // TestInvariantVerifyAcceptsTargetedExec: the exec's recorded command targeted
 // the applies_to contract, so the citation lands end-to-end.
 func TestInvariantVerifyAcceptsTargetedExec(t *testing.T) {
 	c, root, hit, _ := relCamp(t)
 	code, out, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
 		"INV-3", "--exec", hit)
 	if code != 0 {
 		t.Fatalf("exit = %d, want 0 (%q)", code, errS)
