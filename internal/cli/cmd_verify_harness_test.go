package cli

// Task 18 (G8) CLI tests — `verify <campaign> --harness-result INV-id
// --exec EXEC-... [--kind {halmos|forge-fuzz}]`: the rung rides the
// verification.harness field on the invariant entry; no auto-attribution,
// no finding-evidence writes, no learning rows.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessProvedStdout is a bounded halmos proof transcript (success line
// plus a k=100 marker, so bounded_k parses to 100 whatever k rides in).
const harnessProvedStdout = `halmos 0.3.3 --root . --loop 100 --match-contract Inv1InvariantHalmos
Compiling 2 files with Solc 0.8.33
Running 1 test for test/INV1.t.sol:Inv1InvariantHalmos
Status: passed [k=100, paths: 214]
Successfully proved 1 property with bound k=100
Time: 12.44s
Ran 1 test: 1 passed, 0 failed
`

// harnessCounterStdout is a halmos counterexample transcript.
const harnessCounterStdout = `halmos 0.3.3 --root . --match-contract Inv1InvariantHalmos
Compiling 2 files with Solc 0.8.33
Running 1 test for test/INV1.t.sol:Inv1InvariantHalmos
Status: fail
Counterexample:
  getSymbolicAddress(symAddr1) = 0x000000000000000000000000deadbeef0123456789abcdef0123456789ab
Trace: [9773, 9774]
`

// harnessCamp seeds INV-1 and scaffolds it (the real T17 production flow,
// so the harness_scaffold event and artifact row exist as the command
// reads them).
func harnessCamp(t *testing.T, kind, flag string) (*state.Campaign, string) {
	t.Helper()
	c, root := t15Campaign(t, "harness-result")
	t15SeedInvariant(t, c, "INV-1",
		"totalAssets must cover all outstanding shares")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", kind, "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("scaffold exit %d: out=%q err=%q", code, out, errS)
	}
	return c, root
}

// harnessExec writes one EXEC dir by hand (the controller permits direct
// writes: the EXEC must exist on disk with its stdout file) and returns
// the exec id. hashes seeds input_hashes (nil = absent, the unbound
// case); command rides the record for invocationBound.
func harnessExec(t *testing.T, c *state.Campaign, execID, stdout,
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
		kvT("profile", validation.VStr("halmos")),
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

// harnessScaffoldSHA is the stored scaffold's content hash (what a bound
// run's input_hashes must echo).
func harnessScaffoldSHA(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir, "harness",
		"INV-1", "H.t.sol"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// harnessEntry is the registry entry after the run.
func harnessEntry(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	return objAt(objAt(links, "invariants"), "INV-1")
}

// harnessEventsOf returns parsed data payloads of one event type.
func harnessEventsOf(t *testing.T, c *state.Campaign,
	typ string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatal(err)
		}
		if ev["type"] == typ {
			out = append(out, ev)
		}
	}
	return out
}

// harnessMemoryRows counts queued learning rows (the Decision-4 skip pin:
// a counterexample must queue none).
func harnessMemoryRows(t *testing.T, c *state.Campaign) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(c.MemoryDir, "MEM-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

// TestVerifyHarnessResultHappyPath pins the bound proved-bounded flow:
// kind defaults from HARNESS-INV-1-halmos, the recorded scaffold hash
// binds the run, the entry lands verification.harness, and a harness_run
// event carries {rung, exec, invariant, summary}.
func TestVerifyHarnessResultHappyPath(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-0000000007"
	harnessExec(t, c, execID, harnessProvedStdout,
		"halmos check --root . --loop 100 --match-contract Inv1InvariantHalmos",
		map[string]string{"H.t.sol": harnessScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "proved-bounded") ||
		!strings.Contains(out, "k=100") {
		t.Fatalf("output %q must name the rung and bound", out)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "kind") != "halmos" || objStr(h, "rung") != "proved-bounded" ||
		objStr(h, "exec") != execID {
		t.Fatalf("harness object = %s",
			validation.CanonCompact(h))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Int || bk.I != 100 {
		t.Fatalf("bounded_k = %s, want 100", validation.CanonCompact(bk))
	}
	if !strings.Contains(objStr(h, "summary"), "k=100") {
		t.Fatalf("summary %q must carry the bound", objStr(h, "summary"))
	}
	if strings.Contains(objStr(h, "summary"), "unbound") {
		t.Fatalf("bound run must not carry the unbound suffix: %q",
			objStr(h, "summary"))
	}
	evs := harnessEventsOf(t, c, "harness_run")
	if len(evs) != 1 {
		t.Fatalf("harness_run events = %d, want 1", len(evs))
	}
	for _, k := range []string{"rung", "exec", "invariant", "summary"} {
		if _, ok := evs[0]["data"].(map[string]any)[k]; !ok {
			t.Fatalf("harness_run data lacks %q: %v", k, evs[0]["data"])
		}
	}
	// The links doc round-trips the field (no parallel store involved).
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	rt := objAt(objAt(objAt(objAt(links, "invariants"), "INV-1"),
		"verification"), "harness")
	if objStr(rt, "rung") != "proved-bounded" {
		t.Fatal("field must survive a LoadLinks round-trip")
	}
}

// TestVerifyHarnessResultUnboundSuffix pins the no-hash-info path: the
// run still maps (counterexample here) but the summary owns the honest
// limitation suffix — and no learning row is queued (Decision 4: entries
// carry no intent-claim marker, so the sink stays silent).
func TestVerifyHarnessResultUnboundSuffix(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-0000000008"
	harnessExec(t, c, execID, harnessCounterStdout,
		"halmos check --root . --match-contract Inv1InvariantHalmos",
		nil, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "counterexample") {
		t.Fatalf("output %q must name the rung", out)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "rung") != "counterexample" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	if !strings.Contains(objStr(h, "summary"),
		" (unbound: harness file hash not recorded)") {
		t.Fatalf("summary %q lacks the unbound suffix",
			objStr(h, "summary"))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("counterexample bounded_k = %s, want null",
			validation.CanonCompact(bk))
	}
	if n := harnessMemoryRows(t, c); n != 0 {
		t.Fatalf("memory rows = %d, want 0 (no intent-claim marker)", n)
	}
}

// TestVerifyHarnessResultBoundViolation pins Decision 2b's rejection: a
// harness-named hash entry with the wrong sha means the run executed a
// different file — rung inconclusive, output unused, bounded_k null.
func TestVerifyHarnessResultBoundViolation(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-0000000009"
	harnessExec(t, c, execID, harnessProvedStdout,
		"halmos check --root . --loop 100 --match-contract Inv1InvariantHalmos",
		map[string]string{"H.t.sol": strings.Repeat("0", 64)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "inconclusive") {
		t.Fatalf("output %q must name the rung", out)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	want := "scaffold-bound violation: harness file hash differs " +
		"from stored scaffold"
	if objStr(h, "summary") != want {
		t.Fatalf("summary %q, want %q", objStr(h, "summary"), want)
	}
}

// TestVerifyHarnessResultWrongInvariant exits 2 and names the id.
func TestVerifyHarnessResultWrongInvariant(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-0000000010"
	harnessExec(t, c, execID, harnessProvedStdout, "halmos check", nil, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-NOPE", "--exec", execID)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if !strings.Contains(errS, "INV-NOPE") {
		t.Fatalf("stderr %q must name the invariant", errS)
	}
	if strings.Contains(errS, "Traceback") {
		t.Fatalf("stderr carries a traceback: %q", errS)
	}
}

// TestVerifyHarnessResultUnknownExec exits 2 and names the exec.
func TestVerifyHarnessResultUnknownExec(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-nope")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if !strings.Contains(errS, "EXEC-nope") {
		t.Fatalf("stderr %q must name the exec", errS)
	}
}

// TestVerifyHarnessResultNeedsExec pins the required --exec.
func TestVerifyHarnessResultNeedsExec(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1")
	if code != 2 || errS !=
		"verify --harness-result needs --exec EXEC-...\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestVerifyHarnessResultBogusKind pins the --kind choice guard.
func TestVerifyHarnessResultBogusKind(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-1", "--kind", "bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	want := t36VerifyUsage + "webv2 verify: error: argument --kind: " +
		"invalid choice: 'bogus' (choose from 'halmos', 'forge-fuzz')\n"
	if errS != want {
		t.Fatalf("stderr %q, want %q", errS, want)
	}
}

// TestVerifyHarnessResultAmbiguousKind pins the no-guess rule: with both
// skeletons scaffolded and no --kind, the command exits 2 instead of
// attributing the run to either.
func TestVerifyHarnessResultAmbiguousKind(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "forge-fuzz", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("second scaffold exit %d: %q", code, errS)
	}
	execID := "EXEC-0000000011"
	harnessExec(t, c, execID, harnessProvedStdout, "halmos check", nil, 0)
	code, _, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "--kind") {
		t.Fatalf("stderr %q must demand --kind", errS)
	}
	// ...while an explicit --kind resolves the ambiguity.
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID, "--kind", "halmos")
	if code != 0 {
		t.Fatalf("explicit kind exit %d: out=%q err=%q", code, out, errS)
	}
}
