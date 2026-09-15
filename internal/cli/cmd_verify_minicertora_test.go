package cli

// Task 4 (G8 third kind) — cmd_verify_minicertora_test.go: the third kind
// end to end. The scaffold bytes land as INV.mspec, a hand-written EXEC
// record (profile "minicertora") maps through harness.MapMinicertora, and
// the proof sidecar rides verification.harness.
//
// The proof-key contract pinned here: the key is PRESENT (an object) for
// every attributed verdict line — PROVEN, VIOLATED and UNKNOWN alike — and
// ABSENT (not null) for every unattributed run: scaffold-bound violation
// and report contradiction included.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"encoding/json"
	"websec/internal/state"
	"websec/internal/validation"
)

// The three verdict lines are copies of the Task-2 fixtures
// (internal/harness/minicertora_test.go): package cli cannot reach another
// package's test constants, and the bytes are the contract (rule inv_1).
const (
	mcProvenLine   = `{"schema_version":"1","tool_version":"0.4.2","spec_version":"v0.1","solc_version":"0.8.36","evm_version":"paris","optimizer_enabled":false,"contract":"V.sol","rule":"inv_1","verdict":"PROVEN","confidence":"modeled","reason":null,"details":"","assumptions":["msg.value-default-zero","entry-binding:wrapper"],"bounds":{"loop_bound":4,"loop_bound_exhaustive":true,"path_cap":64,"solver_timeout_ms":30000},"warnings":[]}` + "\n"
	mcViolatedLine = `{"tool_version":"0.4.2","solc_version":"0.8.36","spec_version":"v0.1","evm_version":"paris","contract":"V.sol","rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed","reason":"assertion-violated","details":"","assumptions":["external-call-abstraction"],"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},"failed_assertion":{"expression":"total >= before"},"params":{"x":"2"},"calls":[],"final_storage":{"total":"0"}}` + "\n"
	mcUnknownLine  = `{"contract":"V.sol","rule":"inv_1","verdict":"UNKNOWN","confidence":"modeled","reason":"loop-bound-may-be-exceeded","details":"unrolling exhausted at k=4","assumptions":[],"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000}}` + "\n"
)

// mcCamp seeds INV-1 and scaffolds it as minicertora (the real production
// flow, so the harness_scaffold event and artifact row exist).
func mcCamp(t *testing.T, program string) (*state.Campaign, string) {
	t.Helper()
	c, root := t15Campaign(t, program)
	t15SeedInvariant(t, c, "INV-1", "total always covers sum(payouts)")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("scaffold exit %d: out=%q err=%q", code, out, errS)
	}
	return c, root
}

// mcHarnessExec is harnessExec with profile "minicertora" (the original
// stays untouched; both live in package cli).
func mcHarnessExec(t *testing.T, c *state.Campaign, execID, stdout,
	command string, hashes map[string]string, exitStatus int64) {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr("minicertora")),
		kvT("finding_id", validation.VNull()),
		kvT("artifact_id", validation.VNull()),
		kvT("command", validation.VStr(command)),
		kvT("policy_verdict", validation.VObj(
			kvT("allowed", validation.VBool(true)),
			kvT("violations", validation.VArr()))),
		kvT("origin", validation.VStr("locally-executed")),
		kvT("reported_by", validation.VNull()),
		kvT("started_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kvT("finished_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kvT("exit_status", validation.VInt(exitStatus)),
		kvT("stdout_path", validation.VStr(stdoutPath)),
		kvT("stderr_path", validation.VStr(filepath.Join(dir, "stderr.log"))),
	)
	if hashes != nil {
		kvs := make([]validation.KV, 0, len(hashes))
		for k, v := range hashes {
			kvs = append(kvs, kvT(k, validation.VStr(v)))
		}
		rec.O = validation.SetOrAppend(rec.O, "input_hashes",
			validation.VObj(kvs...))
	}
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
}

// mcScaffoldSHA is the stored INV.mspec content hash (what a bound run's
// input_hashes must echo).
func mcScaffoldSHA(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir, "harness",
		"INV-1", "INV.mspec"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// mcHarness is verification.harness after a run.
func mcHarness(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	return objAt(objAt(harnessEntry(t, c), "verification"), "harness")
}

// objHasKey reports key presence — the proof-key contract distinguishes
// absent from null, so objAt alone cannot pin it.
func objHasKey(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// TestVerifyScaffoldMinicertora pins the scaffold flow for the third kind:
// bytes at artifacts/harness/INV-1/INV.mspec, one harness_scaffold event
// naming HARNESS-INV-1-minicertora, and the unchanged re-run law.
func TestVerifyScaffoldMinicertora(t *testing.T) {
	c, root := t15Campaign(t, "mc-scaffold")
	t15SeedInvariant(t, c, "INV-1", "total always covers sum(payouts)")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := "HARNESS-INV-1-minicertora: scaffolded artifacts/harness/" +
		"INV-1/INV.mspec\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	got, err := os.ReadFile(filepath.Join(c.Dir, "artifacts", "harness",
		"INV-1", "INV.mspec"))
	if err != nil {
		t.Fatalf("INV.mspec missing: %v", err)
	}
	if !strings.Contains(string(got), "rule inv_1(env e) {") {
		t.Fatalf("scaffold bytes lack the pinned rule header:\n%s", got)
	}
	evs := harnessEventsOf(t, c, "harness_scaffold")
	if len(evs) != 1 {
		t.Fatalf("harness_scaffold events = %d, want 1", len(evs))
	}
	sum := sha256.Sum256(got)
	data := evs[0]["data"].(map[string]any)
	for k, w := range map[string]string{
		"artifact_id": "HARNESS-INV-1-minicertora",
		"invariant":   "INV-1",
		"kind":        "minicertora",
		"sha256":      hex.EncodeToString(sum[:]),
	} {
		if data[k] != w {
			t.Errorf("event data %q = %v, want %q", k, data[k], w)
		}
	}
	// Re-run: unchanged, no second event (the T17 law).
	code, out, _ = run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 || out != "HARNESS-INV-1-minicertora: unchanged\n" {
		t.Errorf("re-run = (%d,%q)", code, out)
	}
	if evs := harnessEventsOf(t, c, "harness_scaffold"); len(evs) != 1 {
		t.Errorf("harness_scaffold events after rerun = %d, want 1",
			len(evs))
	}
}

// TestHarnessResultMinicertoraProven is the bound happy path: the recorded
// INV.mspec sha binds the run, MapMinicertora returns proved-bounded k=4
// with the proof sidecar, and the print line names both.
func TestHarnessResultMinicertoraProven(t *testing.T) {
	c, root := mcCamp(t, "mc-proven")
	execID := "EXEC-1"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: proved-bounded (minicertora, k=4, EXEC-1)\n" {
		t.Fatalf("stdout = %q", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "kind") != "minicertora" ||
		objStr(h, "rung") != "proved-bounded" {
		t.Fatalf("harness = %s", validation.CanonCompact(h))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Int || bk.I != 4 {
		t.Fatalf("bounded_k = %s, want 4", validation.CanonCompact(bk))
	}
	p := objAt(h, "proof")
	if p.Kind != validation.Obj {
		t.Fatalf("proof = %s, want an object", validation.CanonCompact(p))
	}
	if objStr(p, "confidence") != "modeled" {
		t.Fatalf("proof.confidence = %q, want modeled",
			objStr(p, "confidence"))
	}
	as := objAt(p, "assumptions")
	if as.Kind != validation.Arr || len(as.A) == 0 ||
		as.A[0].S != "msg.value-default-zero" {
		t.Fatalf("proof.assumptions = %s", validation.CanonCompact(as))
	}
}

// TestHarnessResultMinicertoraViolated pins the counterexample rung and its
// unconfirmed flag reaching the stored summary.
func TestHarnessResultMinicertoraViolated(t *testing.T) {
	c, root := mcCamp(t, "mc-violated")
	execID := "EXEC-2"
	mcHarnessExec(t, c, execID, mcViolatedLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "counterexample") {
		t.Fatalf("stdout %q must name the rung", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "counterexample" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "counterexample: total >= before " +
		"[unconfirmed: crosses a havoc'd call]"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want %q", objStr(h, "summary"), want)
	}
	if !objHasKey(h, "proof") {
		t.Fatal("a VIOLATED line is attributed: the proof key must ride")
	}
}

// TestHarnessResultMinicertoraUnknown pins the Task-2 law at the CLI seam:
// an UNKNOWN line is attributed, so the rung is inconclusive but the proof
// sidecar (with its named reason) IS stored.
func TestHarnessResultMinicertoraUnknown(t *testing.T) {
	c, root := mcCamp(t, "mc-unknown")
	execID := "EXEC-3"
	mcHarnessExec(t, c, execID, mcUnknownLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 2)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("stdout %q must name the rung", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	p := objAt(h, "proof")
	if p.Kind != validation.Obj {
		t.Fatalf("an attributed UNKNOWN must keep its proof sidecar: %s",
			validation.CanonCompact(h))
	}
	if objStr(p, "reason") != "loop-bound-may-be-exceeded" {
		t.Fatalf("proof.reason = %q", objStr(p, "reason"))
	}
}

// TestHarnessResultMinicertoraBoundViolation pins Decision 2b for the
// .mspec filename: a harness-named hash with a foreign sha is a violation,
// never an unbound pass.
func TestHarnessResultMinicertoraBoundViolation(t *testing.T) {
	c, root := mcCamp(t, "mc-violation")
	execID := "EXEC-4"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": strings.Repeat("0", 64)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("stdout %q must name the rung", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "scaffold-bound violation: harness file hash differs " +
		"from stored scaffold"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want %q", objStr(h, "summary"), want)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a refusal stores no proof key (absent, not null)")
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
	}
}

// TestHarnessResultMinicertoraDegradedClaim pins Task 1 (wave L-defer) for
// the third kind: the induction scaffold pins the reviewed claim OUTSIDE
// the BODY window (scaffoldMspec's THE SPLIT), so a weakened `assert` in
// the .mspec file is scaffold drift — and because the EXEC record here
// hashes the TAMPERED file, the hash-bind step alone binds the run (the
// tamper-to-tampered-hash path the L-system deferred). Validate refuses it:
// new arm "scaffold-degraded: invariant assert line changed", rung
// inconclusive, output (a PROVEN line) unused, no proof sidecar.
func TestHarnessResultMinicertoraDegradedClaim(t *testing.T) {
	c, root := t15Campaign(t, "mc-degraded-claim")
	t15SeedInvariant(t, c, "INV-1",
		"invariant:cap_respected of V.total <= cap")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("scaffold exit %d: out=%q err=%q", code, out, errS)
	}
	p := filepath.Join(c.ArtifactsDir, "harness", "INV-1", "INV.mspec")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	weakened := strings.Replace(string(raw), "assert total <= cap;",
		"assert total >= cap;", 1)
	if weakened == string(raw) {
		t.Fatal("fixture must weaken the pinned assert (claim not found)")
	}
	if err := os.WriteFile(p, []byte(weakened), 0o644); err != nil {
		t.Fatal(err)
	}
	execID := "EXEC-7"
	mcHarnessExec(t, c, execID, mcProvenLine, "minicertora --rule inv_1",
		map[string]string{
			"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c),
		}, 0)
	code, out, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	want := "INV-1: inconclusive (minicertora, " + execID + ")\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("a weakened pinned claim must never map: %s",
			validation.CanonCompact(h))
	}
	degraded := "scaffold-degraded: invariant assert line changed"
	if summary := objStr(h, "summary"); summary != degraded {
		t.Fatalf("summary = %q, want %q", summary, degraded)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a refusal stores no proof key (absent, not null)")
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
	}
	evs := harnessEventsOf(t, c, "harness_run")
	if len(evs) != 1 {
		t.Fatalf("harness_run events = %d, want 1", len(evs))
	}
	got, _ := evs[0]["data"].(map[string]any)
	if got["rung"] != "inconclusive" || got["summary"] != degraded {
		t.Fatalf("event data = %v, want the refusal", got)
	}
}

// TestHarnessResultMinicertoraContradiction pins the report-contradiction
// refusal: PROVEN output with exit_status 1 loses the sidecar entirely.
func TestHarnessResultMinicertoraContradiction(t *testing.T) {
	c, root := mcCamp(t, "mc-contradiction")
	execID := "EXEC-5"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("stdout %q must name the rung", out)
	}
	h := mcHarness(t, c)
	want := "inconclusive (report-contradiction: exit 1 with verdict PROVEN)"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want %q", objStr(h, "summary"), want)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a contradicted report stores no proof key")
	}
}

// TestHarnessResultMinicertoraTimedOut pins the S1 gate: a timed-out run
// never reaches MapMinicertora, and its summary is the Step-0 wording —
// "no clean completion" plus the invocation bound read from --loop-bound,
// never MapRun's "timeout after Ns" (N is k, not seconds).
func TestHarnessResultMinicertoraTimedOut(t *testing.T) {
	c, root := mcCamp(t, "mc-timeout")
	execID := "EXEC-6"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 8",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, -1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("stdout %q must name the rung", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "inconclusive (no clean completion; loop bound was 8)"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want %q", objStr(h, "summary"), want)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a timed-out run stores no proof key")
	}
}

// TestHarnessResultMinicertoraTimedOutLoopBound4 is the second row of the
// same S1 gate with a different literal bound: the summary must echo THIS
// run's invocation bound (4), proving the clause is read from the command
// rather than hardcoded to the 8 pinned above.
func TestHarnessResultMinicertoraTimedOutLoopBound4(t *testing.T) {
	c, root := mcCamp(t, "mc-timeout-bound4")
	execID := "EXEC-14"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, -1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: inconclusive (minicertora, EXEC-14)\n" {
		t.Fatalf("stdout = %q, want the inconclusive print", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "inconclusive (no clean completion; loop bound was 4)"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want %q", objStr(h, "summary"), want)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a timed-out run stores no proof key")
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
	}
}

// TestHarnessResultMinicertoraNoCleanExit pins the S3 derivation: a record
// with no exit_status at all is -2, and MapMinicertora's negative floor
// refuses it (PROVEN bytes notwithstanding).
func TestHarnessResultMinicertoraNoCleanExit(t *testing.T) {
	c, root := mcCamp(t, "mc-noexit")
	execID := "EXEC-7"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	// Erase the exit status from the record on disk: absent means unknown.
	recPath := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	kv := make([]validation.KV, 0, len(rec.O))
	for _, e := range rec.O {
		if e.K != "exit_status" {
			kv = append(kv, e)
		}
	}
	rec.O = kv
	if err := validation.WriteJson(recPath, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s, want the negative floor", validation.CanonCompact(h))
	}
	if objStr(h, "summary") != "inconclusive (exit output unmapped)" {
		t.Fatalf("summary = %q", objStr(h, "summary"))
	}
	if objHasKey(h, "proof") {
		t.Fatal("an unknown exit status stores no proof key")
	}
}

// TestHarnessResultMinicertoraAmbiguousKind pins the no-guess rule with the
// third kind in the vocabulary: halmos + minicertora scaffolds and no
// --kind is exit 2 with the full choice list.
func TestHarnessResultMinicertoraAmbiguousKind(t *testing.T) {
	c, root := mcCamp(t, "mc-ambiguous")
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "halmos", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("halmos scaffold exit %d: %q", code, errS)
	}
	execID := "EXEC-8"
	mcHarnessExec(t, c, execID, mcProvenLine, "minicertora", nil, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	want := "verify: 'INV-1' has multiple harness scaffolds; " +
		"pass --kind {halmos|forge-fuzz|minicertora}\n"
	if errS != want {
		t.Fatalf("stderr %q, want %q", errS, want)
	}
}

// TestHarnessResultMinicertoraMissingScaffold pins the named no-scaffold
// error when --kind names a kind that was never scaffolded.
func TestHarnessResultMinicertoraMissingScaffold(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-9"
	mcHarnessExec(t, c, execID, mcProvenLine, "minicertora", nil, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID,
		"--kind", "minicertora")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	want := "verify: no harness scaffold for 'INV-1' (scaffold it first " +
		"with verify --scaffold minicertora --invariant 'INV-1')\n"
	if errS != want {
		t.Fatalf("stderr %q, want %q", errS, want)
	}
}

// mcNoBoundsProvenLine is an attributed PROVEN line with NO bounds object
// at all: MapMinicertora legitimately returns proved-bounded with a nil
// bounded_k here (internal/harness/minicertora_test.go's
// TestMapMinicertoraBoundsMissing pins the mapper side).
const mcNoBoundsProvenLine = `{"rule":"inv_1","verdict":"PROVEN",` +
	`"confidence":"modeled"}` + "\n"

// mcBigBoundProvenLine is the other nil-bounded_k shape: the bound is a
// real integer the tool reported, but it does not fit int64, so the
// convenience pointer is nil while proof.bounds.loop_bound still carries
// the exact decimal text.
const mcBigBoundProvenLine = `{"rule":"inv_1","verdict":"PROVEN",` +
	`"confidence":"modeled","bounds":{"loop_bound":99999999999999999999}}` +
	"\n"

// TestHarnessResultMinicertoraProvenNoBounds is the F1 regression pin: a
// PROVEN line with no bounds object is a *valid* proved-bounded run whose
// bounded_k is nil. The print path must read the display k sidecar-first
// instead of dereferencing the nil pointer — exit 0, the k-less proved
// line byte-exact, proof.bounds.loop_bound null on the stored links, and
// no panic (a panic fails this test outright).
func TestHarnessResultMinicertoraProvenNoBounds(t *testing.T) {
	c, root := mcCamp(t, "mc-nobounds")
	execID := "EXEC-10"
	mcHarnessExec(t, c, execID, mcNoBoundsProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: proved-bounded (minicertora, EXEC-10)\n" {
		t.Fatalf("stdout = %q, want the k-less proved line", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "proved-bounded" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
	}
	p := objAt(h, "proof")
	if p.Kind != validation.Obj {
		t.Fatalf("an attributed PROVEN line keeps its sidecar: %s",
			validation.CanonCompact(h))
	}
	lb := objAt(objAt(p, "bounds"), "loop_bound")
	if lb.Kind != validation.Null {
		t.Fatalf("proof.bounds.loop_bound = %s, want null",
			validation.CanonCompact(lb))
	}
}

// TestHarnessResultMinicertoraProvenBigBound pins display mode 2: the
// k lives in proof.bounds even when the convenience pointer is nil, so a
// bound too large for int64 still renders with its exact decimal text
// (bounded_k itself stays null — only the mapper's int64 copy is lost).
func TestHarnessResultMinicertoraProvenBigBound(t *testing.T) {
	c, root := mcCamp(t, "mc-bigbound")
	execID := "EXEC-11"
	mcHarnessExec(t, c, execID, mcBigBoundProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := "INV-1: proved-bounded (minicertora, k=99999999999999999999, " +
		"EXEC-11)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	h := mcHarness(t, c)
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null (the pointer cannot hold it)",
			validation.CanonCompact(bk))
	}
	lb := objAt(objAt(objAt(h, "proof"), "bounds"), "loop_bound")
	if lb.Kind != validation.Int || lb.Big != "99999999999999999999" {
		t.Fatalf("proof.bounds.loop_bound = %s, want the big int",
			validation.CanonCompact(lb))
	}
}

// TestHarnessResultMinicertoraKilledStatus pins the F2 gate: 128+N is the
// shell's death-by-signal convention, so a 137 (SIGKILL) run never
// completed — its PROVEN bytes map to the same Step-0 inconclusive wording
// the -1 gate renders, and carry no proof key.
func TestHarnessResultMinicertoraKilledStatus(t *testing.T) {
	c, root := mcCamp(t, "mc-killed")
	execID := "EXEC-12"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 8",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 137)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: inconclusive (minicertora, EXEC-12)\n" {
		t.Fatalf("stdout = %q, want the inconclusive print", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "inconclusive (no clean completion; loop bound was 8)"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want the -1 gate's wording",
			objStr(h, "summary"))
	}
	if objHasKey(h, "proof") {
		t.Fatal("a killed run stores no proof key")
	}
}

// TestHarnessResultMinicertoraTimedOutNoBound pins the Step-0 fallback: a
// timed-out minicertora run whose command names NO bound flag renders the
// clause-free wording — never MapRun's "timeout after 0s" (which would
// claim a 0-second budget the run never had).
func TestHarnessResultMinicertoraTimedOutNoBound(t *testing.T) {
	c, root := mcCamp(t, "mc-timeout-nobound")
	execID := "EXEC-13"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"timeout 40s minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, -1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: inconclusive (minicertora, EXEC-13)\n" {
		t.Fatalf("stdout = %q, want the inconclusive print", out)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "inconclusive (no clean completion)"
	if objStr(h, "summary") != want {
		t.Fatalf("summary = %q, want %q", objStr(h, "summary"), want)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a timed-out run stores no proof key")
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
	}
}

// TestVerifyKindMinicertoraChoice pins the parse-time precedence of the
// three-kind --kind guard: a bogus choice is rejected before any campaign
// registry or exec lookup runs — this campaign has no INV-1 and no exec,
// yet the error is the argparse choice text, not "unknown invariant".
func TestVerifyKindMinicertoraChoice(t *testing.T) {
	c, root := t15Campaign(t, "mc-kindchoice")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-nope",
		"--kind", "bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	want := t36VerifyUsage + "webv2 verify: error: argument --kind: " +
		"invalid choice: 'bogus' (choose from 'halmos', 'forge-fuzz', " +
		"'minicertora')\n"
	if errS != want {
		t.Fatalf("stderr %q, want %q", errS, want)
	}
}

// TestInvocationBoundFlags pins the S2 regex gap: the minicertora flag
// --loop-bound N must parse as the invocation bound (otherwise a timeout
// summary reads "timeout after 0s"), while a lookalike flag must not.
func TestInvocationBoundFlags(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    int
	}{
		{"--loop-bound 8", 8},
		// r32 F2: the flag families are per-tool. minicertora's click has
		// no --loop and no --fuzz-runs (`No such option`), so a lone
		// foreign bound flag is an invocation the tool refuses -> floor.
		{"--loop 100", -1}, // harness.BoundDegenerate
		{"--loop-bound=8", 8},
		{"--fuzz-runs 200", -1}, // harness.BoundDegenerate
		{"--loopx 5", 0},
	} {
		if got := invocationBound(tc.command, "minicertora"); got != tc.want {
			t.Errorf("invocationBound(%q) = %d, want %d", tc.command, got,
				tc.want)
		}
	}
}

// mcInvariantProvenLine is the Task-4 invariant-induction verdict line: the
// report names the checked entrypoints (an ARRAY of per-function checks) and
// the init check, so the stored proof sidecar must carry the whole object
// verbatim under the 11th key. The rule name is the scaffold's declaration
// name (MspecRuleName("INV-1") = "inv_1"), which is why attribution needs no
// mapper change for invariant scaffolds.
const mcInvariantProvenLine = `{"schema_version":"1","tool_version":"0.4.2",` +
	`"solc_version":"0.8.36","spec_version":"v0.1","evm_version":"paris",` +
	`"contract":"Capped.sol","rule":"inv_1","verdict":"PROVEN",` +
	`"confidence":"modeled","reason":null,"details":"",` +
	`"assumptions":["invariant-one-step-induction","invariant-init-checked"],` +
	`"bounds":{"loop_bound":4,"loop_bound_exhaustive":true,"path_cap":64,` +
	`"solver_timeout_ms":30000},"warnings":[],` +
	`"invariant":{"name":"cap_respected","per_function":[` +
	`{"selector":"0xd0e30db0","function":"deposit","kind":"proved",` +
	`"reason":null,"details":""},{"selector":"0x8da5cb5b",` +
	`"function":"setCap","kind":"proved","reason":null,"details":""}],` +
	`"init":{"selector":"constructor","function":"constructor",` +
	`"kind":"proved","reason":null,"details":""},"witness_function":null}}` +
	"\n"

// mcInvariantNoInitLine is the invariant-no-constructor shape: init is null
// while the per-function array still rides. Null is a printed value, so the
// sidecar copies it rather than defaulting an init check that never ran.
const mcInvariantNoInitLine = `{"tool_version":"0.4.2",` +
	`"solc_version":"0.8.36","contract":"Capped.sol","rule":"inv_1",` +
	`"verdict":"UNKNOWN","confidence":"modeled",` +
	`"reason":"invariant-uninitialized","details":"",` +
	`"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},` +
	`"invariant":{"name":"cap_respected","per_function":[` +
	`{"selector":"0xd0e30db0","function":"deposit","kind":"proved",` +
	`"reason":null,"details":""}],"init":null,"witness_function":null}}` +
	"\n"

// mcViolatedCallsLine is the Task-3/Task-4 witness line: a counterexample
// whose calls array is the bridged sequence. Before Task 4 the sidecar
// dropped calls, so the audit's derived poc suffix could never fire from
// stored state; this line is the end-to-end proof that it does now.
const mcViolatedCallsLine = `{"tool_version":"0.4.2","solc_version":"0.8.36",` +
	`"spec_version":"v0.1","evm_version":"paris","contract":"V.sol",` +
	`"rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed",` +
	`"reason":"assertion-violated","details":"",` +
	`"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},` +
	`"failed_assertion":{"expression":"total >= before"},"params":{"x":"2"},` +
	`"calls":[{"step":1,"function":"withdraw","target":` +
	`"0x1111111111111111111111111111111111111111","args":["1000"],` +
	`"env":{"msg.sender":"0x2222222222222222222222222222222222222222",` +
	`"msg.value":"0"},"reverted":false,"reentrant":false,"overrides":{}},` +
	`{"step":2,"function":"withdraw","target":` +
	`"0x1111111111111111111111111111111111111111","args":["2000"],` +
	`"env":{"msg.sender":"0x3333333333333333333333333333333333333333",` +
	`"msg.value":"0"},"reverted":true,"reentrant":false,"overrides":{}}],` +
	`"final_storage":{"total":"0"}}` + "\n"

// mcLinkField reads the campaign's invariant_links.json FROM DISK (not from
// the in-memory campaign handle): the stored-state contract, not the wiring.
func mcLinkField(t *testing.T, c *state.Campaign, path ...string) validation.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir,
		"invariant_links.json"))
	if err != nil {
		t.Fatalf("read invariant_links.json: %v", err)
	}
	v, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse invariant_links.json: %v", err)
	}
	for _, k := range path {
		v = objAt(v, k)
	}
	return v
}

// TestHarnessResultMinicertoraInvariantProof is the RULING-12KEY 11th-key
// row: an invariant line's roll-up object rides into the stored links file
// verbatim (inner array, inner object, init included), and the display line
// keeps its historical shape. The invariant decl name is the scaffold's
// attribution name, so nothing in the mapper changed.
func TestHarnessResultMinicertoraInvariantProof(t *testing.T) {
	c, root := mcCamp(t, "mc-invariant")
	execID := "EXEC-15"
	mcHarnessExec(t, c, execID, mcInvariantProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: proved-bounded (minicertora, k=4, EXEC-15)\n" {
		t.Fatalf("stdout = %q", out)
	}
	proof := mcLinkField(t, c, "invariants", "INV-1", "verification",
		"harness", "proof")
	inv := objAt(proof, "invariant")
	if inv.Kind != validation.Obj {
		t.Fatalf("stored proof.invariant = %s, want the verbatim object",
			validation.CanonCompact(inv))
	}
	want := `{"init":{"details":"","function":"constructor","kind":"proved",` +
		`"reason":null,"selector":"constructor"},"name":"cap_respected",` +
		`"per_function":[{"details":"","function":"deposit","kind":"proved",` +
		`"reason":null,"selector":"0xd0e30db0"},{"details":"",` +
		`"function":"setCap","kind":"proved","reason":null,` +
		`"selector":"0x8da5cb5b"}],"witness_function":null}`
	if got := validation.CanonCompact(inv); got != want {
		t.Errorf("stored proof.invariant = %s\nwant %s", got, want)
	}
	// A PROVEN rule line carries no witness: calls rides as null.
	if calls := objAt(proof, "calls"); calls.Kind != validation.Null {
		t.Errorf("stored proof.calls = %s, want null",
			validation.CanonCompact(calls))
	}
}

// TestHarnessResultMinicertoraInvariantInitNull pins the init-null case end
// to end: the null the prover printed survives the store byte for byte.
func TestHarnessResultMinicertoraInvariantInitNull(t *testing.T) {
	c, root := mcCamp(t, "mc-invariant-noinit")
	execID := "EXEC-16"
	mcHarnessExec(t, c, execID, mcInvariantNoInitLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 2)
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	inv := mcLinkField(t, c, "invariants", "INV-1", "verification",
		"harness", "proof", "invariant")
	if init := objAt(inv, "init"); init.Kind != validation.Null {
		t.Fatalf("stored proof.invariant.init = %s, want null",
			validation.CanonCompact(init))
	}
	pf := objAt(inv, "per_function")
	if pf.Kind != validation.Arr || len(pf.A) != 1 ||
		objStr(pf.A[0], "function") != "deposit" {
		t.Fatalf("stored proof.invariant.per_function = %s",
			validation.CanonCompact(pf))
	}
}

// TestHarnessResultMinicertoraRuleLineInvariantNull pins the other half of
// the key contract: a plain rule verdict line (no invariant roll-up on the
// tool's report) stores invariant: null rather than dropping the key — the
// twelve-key set is fixed, exactly as it is for its ten siblings.
func TestHarnessResultMinicertoraRuleLineInvariantNull(t *testing.T) {
	c, root := mcCamp(t, "mc-ruleline-invariant")
	execID := "EXEC-17"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	proof := mcLinkField(t, c, "invariants", "INV-1", "verification",
		"harness", "proof")
	var keys []string
	for _, kv := range proof.O {
		keys = append(keys, kv.K)
	}
	// compiler_pin joined the proof in r18 (A2): the stored solc_version
	// was copied but never compared — the pin row says WHICH compiler
	// the record was checked against (or honestly, unchecked).
	wantKeys := "tool_version,solc_version,spec_version,evm_version," +
		"confidence,reason,bounds,assumptions,warnings,ghosts,invariant," +
		"calls,compiler_pin"
	if got := strings.Join(keys, ","); got != wantKeys {
		t.Fatalf("stored proof keys = %s\nwant %s", got, wantKeys)
	}
	for _, k := range []string{"invariant", "calls"} {
		if v := objAt(proof, k); v.Kind != validation.Null {
			t.Errorf("stored proof.%s = %s, want null", k,
				validation.CanonCompact(v))
		}
	}
	if !strings.HasPrefix(objStr(proof, "compiler_pin"), "unchecked") {
		t.Errorf("a fixture record with no visible pin must say so, got %q",
			objStr(proof, "compiler_pin"))
	}
}

// TestHarnessResultMinicertoraCallsAuditSuffix is the RULING-12KEY e2e: a
// counterexample line's calls array now rides in the sidecar, so the audit's
// derived "| poc: N calls bridged" suffix fires from STORED STATE — the test
// reads invariant_links.json from disk and renders the section through
// `audit --json`, the CLI path an operator actually uses.
func TestHarnessResultMinicertoraCallsAuditSuffix(t *testing.T) {
	c, root := mcCamp(t, "mc-calls-audit")
	execID := "EXEC-18"
	mcHarnessExec(t, c, execID, mcViolatedCallsLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	// The links FILE (not the in-memory handle) carries the verbatim calls.
	calls := mcLinkField(t, c, "invariants", "INV-1", "verification",
		"harness", "proof", "calls")
	if calls.Kind != validation.Arr || len(calls.A) != 2 {
		t.Fatalf("stored proof.calls = %s, want 2 calls",
			validation.CanonCompact(calls))
	}
	// ...and the audit section renders the derived suffix from that state.
	code, out, errS = run(t, "--root", root, "audit", c.CampaignID, "--json")
	if code != 0 {
		t.Fatalf("audit exit %d err=%q", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit --json: %v", err)
	}
	runs := objAt(objAt(objAt(rep, "sections"), "invariant_verification"),
		"harness_runs")
	if runs.Kind != validation.Arr || len(runs.A) == 0 {
		t.Fatalf("harness_runs = %s", validation.CanonCompact(runs))
	}
	want := "INV-1: counterexample (minicertora, EXEC-18) | poc: 2 calls bridged"
	if got := runs.A[0].S; got != want {
		t.Fatalf("audit line = %q, want %q", got, want)
	}
}

// TestHarnessResultMinicertoraUnboundDegradedClaim is the third-kind twin of
// TestVerifyHarnessResultUnboundScaffoldValidate (fix round, wave L-defer):
// with NO hash entry at all, a weakened pinned assert in the on-disk .mspec
// is still scaffold drift — the induction scaffold's claim rides OUTSIDE the
// BODY window, so the unbound run refuses
// "scaffold-degraded: invariant assert line changed" instead of mapping the
// PROVEN line with the honest-limitation suffix.
func TestHarnessResultMinicertoraUnboundDegradedClaim(t *testing.T) {
	c, root := t15Campaign(t, "mc-unbound-degraded-claim")
	t15SeedInvariant(t, c, "INV-1",
		"invariant:cap_respected of V.total <= cap")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("scaffold exit %d: out=%q err=%q", code, out, errS)
	}
	p := filepath.Join(c.ArtifactsDir, "harness", "INV-1", "INV.mspec")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	weakened := strings.Replace(string(raw), "assert total <= cap;",
		"assert total >= cap;", 1)
	if weakened == string(raw) {
		t.Fatal("fixture must weaken the pinned assert (claim not found)")
	}
	if err := os.WriteFile(p, []byte(weakened), 0o644); err != nil {
		t.Fatal(err)
	}
	execID := "EXEC-19"
	// nil hashes: nothing binds this run, so the on-disk .mspec is the
	// only artifact the rail can check — and it is degraded.
	mcHarnessExec(t, c, execID, mcProvenLine, "minicertora --rule inv_1",
		nil, 0)
	code, out, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	want := "INV-1: inconclusive (minicertora, " + execID + ")\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("a weakened pinned claim must never map, bound or not: %s",
			validation.CanonCompact(h))
	}
	degraded := "scaffold-degraded: invariant assert line changed"
	if summary := objStr(h, "summary"); summary != degraded {
		t.Fatalf("summary = %q, want %q", summary, degraded)
	}
	if objHasKey(h, "proof") {
		t.Fatal("a refusal stores no proof key (absent, not null)")
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
	}
	evs := harnessEventsOf(t, c, "harness_run")
	if len(evs) != 1 {
		t.Fatalf("harness_run events = %d, want 1", len(evs))
	}
	got, _ := evs[0]["data"].(map[string]any)
	if got["rung"] != "inconclusive" || got["summary"] != degraded {
		t.Fatalf("event data = %v, want the refusal", got)
	}
}

// TestHarnessResultReadsRelativeRootExec pins r13: `exec` under
// `--root .` stores a CWD-relative stdout_path; the old join against
// execDir double-nested the path and a plainly-present capture read as
// "no captured stdout to map". The canonical derived location must win.
func TestHarnessResultReadsRelativeRootExec(t *testing.T) {
	c, root := mcCamp(t, "mc-relpath")
	execID := "EXEC-rel"
	mcHarnessExec(t, c, execID, mcViolatedLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	recPath := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["stdout_path"] = filepath.Join("execs", execID, "stdout.log")
	blob, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("relative stored path must still map: exit %d %q %q",
			code, out, errS)
	}
	if !strings.Contains(out, "counterexample") {
		t.Fatalf("face = %q", out)
	}
}

// TestHarnessResultUnreadableSaysUnreadable pins the r13 message split:
// an absent capture file must say UNREADABLE with the errno — the old
// code reused "no captured stdout to map" for open failures, hiding a
// deleted/torn artifact as "nothing ran".
func TestHarnessResultUnreadableSaysUnreadable(t *testing.T) {
	c, root := mcCamp(t, "mc-unreadable")
	execID := "EXEC-unread"
	mcHarnessExec(t, c, execID, mcViolatedLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 1)
	if err := os.Remove(filepath.Join(c.ExecsDir, execID, "stdout.log")); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 2 || !strings.Contains(errS, "unreadable") {
		t.Fatalf("want exit 2 unreadable, got exit %d err %q", code, errS)
	}
}

// TestHarnessResultRefusesACompilerMismatch pins r18 A2: the recorded
// solc_version was provenance WITHOUT enforcement — a rung bound to a
// run compiled by a different solc than the exec pinned. The mapper now
// compares the report lines against the visible pin and refuses exit 2
// naming BOTH versions.
func TestHarnessResultRefusesACompilerMismatch(t *testing.T) {
	c, root := mcCamp(t, "mc-toolchain-mismatch")
	execID := "EXEC-18"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	recPath := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	rec, perr := validation.ParseOrdered(raw)
	if perr != nil {
		t.Fatal(perr)
	}
	rec.O = validation.SetOrAppend(rec.O, "environment", validation.VObj(
		kvT("tool_versions", validation.VObj(
			kvT("solc", validation.VStr("0.8.24")))),
	))
	if err := validation.WriteJson(recPath, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 2 || !strings.Contains(errS, "toolchain-mismatch") {
		t.Fatalf("mismatch must refuse exit 2 naming toolchain-mismatch: "+
			"exit %d err %q", code, errS)
	}
	if !strings.Contains(errS, "0.8.36") || !strings.Contains(errS, "0.8.24") {
		t.Fatalf("the refusal must name BOTH versions: %q", errS)
	}
}

// TestHarnessResultChecksAMatchingPin is the other side: the pin agrees,
// and the proof says so instead of hiding the check.
func TestHarnessResultChecksAMatchingPin(t *testing.T) {
	c, root := mcCamp(t, "mc-toolchain-match")
	execID := "EXEC-19"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	recPath := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	raw, _ := os.ReadFile(recPath)
	rec, _ := validation.ParseOrdered(raw)
	rec.O = validation.SetOrAppend(rec.O, "environment", validation.VObj(
		kvT("tool_versions", validation.VObj(
			kvT("solc", validation.VStr("0.8.36")))),
	))
	if err := validation.WriteJson(recPath, rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("a matching pin must map: exit %d err %q", code, errS)
	}
	proof := mcLinkField(t, c, "invariants", "INV-1", "verification",
		"harness", "proof")
	if !strings.Contains(objStr(proof, "compiler_pin"), "checked against pinned solc 0.8.36") {
		t.Fatalf("proof must record the check it passed: %q",
			objStr(proof, "compiler_pin"))
	}
}
