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
// never reaches MapMinicertora — the MapRun timeout wording (with the
// --loop-bound-derived k) is what lands.
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
	if objStr(h, "summary") != "timeout after 8s" {
		t.Fatalf("summary = %q, want the MapRun timeout wording",
			objStr(h, "summary"))
	}
	if objHasKey(h, "proof") {
		t.Fatal("a timed-out run stores no proof key")
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

// TestInvocationBoundFlags pins the S2 regex gap: the minicertora flag
// --loop-bound N must parse as the invocation bound (otherwise a timeout
// summary reads "timeout after 0s"), while a lookalike flag must not.
func TestInvocationBoundFlags(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    int
	}{
		{"--loop-bound 8", 8},
		{"--loop 100", 100},
		{"--loop-bound=8", 8},
		{"--fuzz-runs 200", 200},
		{"--loopx 5", 0},
	} {
		if got := invocationBound(tc.command, "minicertora"); got != tc.want {
			t.Errorf("invocationBound(%q) = %d, want %d", tc.command, got,
				tc.want)
		}
	}
}
