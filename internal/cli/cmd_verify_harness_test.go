package cli

// Task 18 (G8) CLI tests — `verify <campaign> --harness-result INV-id
// --exec EXEC-... [--kind {halmos|forge-fuzz|minicertora}]`: the rung
// rides the verification.harness field on the invariant entry; no
// auto-attribution, no finding-evidence writes, no learning rows.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
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

// r32ForgeScaffoldSHA is harnessScaffoldSHA for the forge-fuzz scaffold:
// the forge skeleton is artifacts/harness/INV-1/F.t.sol (halmos's is
// H.t.sol, which harnessScaffoldSHA reads).
func r32ForgeScaffoldSHA(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir, "harness",
		"INV-1", "F.t.sol"))
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

// TestVerifyHarnessResultKilledStatus pins the cross-kind signal-death
// gate: 128+N is the shell's death-by-signal convention, so a 137 (SIGKILL)
// run never completed — its "Status: fail"/Counterexample bytes map to the
// inconclusive timeout branch, never to the counterexample rung, and carry
// no bound. The minicertora twin is
// TestHarnessResultMinicertoraKilledStatus
// (cmd_verify_minicertora_test.go); this row keeps the shared >=128 gate
// from silently regressing for the prose kinds.
func TestVerifyHarnessResultKilledStatus(t *testing.T) {
	c, root := harnessCamp(t, "halmos", "")
	execID := "EXEC-0000000013"
	harnessExec(t, c, execID, harnessCounterStdout,
		"halmos check --root . --loop 8 --match-contract Inv1InvariantHalmos",
		map[string]string{"H.t.sol": harnessScaffoldSHA(t, c)}, 137)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if out != "INV-1: inconclusive (halmos, EXEC-0000000013)\n" {
		t.Fatalf("stdout = %q, want the inconclusive print", out)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s, want the timeout branch (a killed run's "+
			"bytes are partial by definition)", validation.CanonCompact(h))
	}
	// r32 F3: the summary must NOT carry a number. The old wording was
	// "timeout after 8s" — the BOUND (--loop 8) printed in the seconds
	// slot, and this record's wall clock was never 8s. MapRun holds no
	// record, so it has no real elapsed time to report and says so
	// without a number.
	if objStr(h, "summary") != "inconclusive (timeout)" {
		t.Fatalf("summary = %q, want the numberless timeout wording",
			objStr(h, "summary"))
	}
	if strings.Contains(objStr(h, "summary"), "8") {
		t.Fatalf("the timeout summary printed the BOUND as a duration: %q",
			objStr(h, "summary"))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k = %s, want null", validation.CanonCompact(bk))
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
		"invalid choice: 'bogus' (choose from 'halmos', 'forge-fuzz', " +
		"'minicertora')\n"
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

// ---- Task 1 (wave L-defer): scaffold Validate rides the harness-result path

// harnessArtifactPath is the halmos scaffold artifact T17 wrote.
func harnessArtifactPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "harness", "INV-1", "H.t.sol")
}

// harnessDriftStatement rewrites the registry entry's statement AFTER the
// scaffold artifact was rendered: the claim the bytes were rendered from
// moved, the on-disk harness file did not (the plan's row (a)). The write
// goes through the links store, exactly as any later claim edit would.
func harnessDriftStatement(t *testing.T, c *state.Campaign, invID,
	stmt string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	entry := objAt(reg, invID)
	if entry.Kind != validation.Obj {
		t.Fatalf("no registry entry for %s", invID)
	}
	entry.O = validation.SetOrAppend(entry.O, "statement",
		validation.VStr(stmt))
	reg.O = validation.SetOrAppend(reg.O, invID, entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// harnessTuneBody edits the scaffold artifact INSIDE the BODY window — the
// model tuning the byte-law allows and Validate must never refuse (row
// (b)). The recorded hash is read off the file afterwards, so the run
// stays bound to the bytes it ran.
func harnessTuneBody(t *testing.T, c *state.Campaign) {
	t.Helper()
	p := harnessArtifactPath(c)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	filled := strings.Replace(string(raw), harness.DummyHalmos,
		"uint256 tuned = 1;\n        "+harness.DummyHalmos, 1)
	if filled == string(raw) {
		t.Fatal("fixture must edit the BODY window (DummyHalmos not found)")
	}
	if err := os.WriteFile(p, []byte(filled), 0o644); err != nil {
		t.Fatal(err)
	}
}

// harnessDropEndMarker deletes the BODY end marker line: a degraded
// artifact with no window at all. Validate's BodyRegion refuses it, and the
// refusal must carry that reason verbatim (the non-lineDiffErr shape).
func harnessDropEndMarker(t *testing.T, c *state.Campaign) {
	t.Helper()
	p := harnessArtifactPath(c)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	line := "    " + harness.EndMarker + "\n"
	if !strings.Contains(string(raw), line) {
		t.Fatalf("fixture must drop the end marker line (%q)", line)
	}
	if err := os.WriteFile(p,
		[]byte(strings.Replace(string(raw), line, "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyHarnessResultScaffoldValidate pins Task 1 (wave L-defer): once
// the recorded hash binds a run to the stored scaffold bytes, the rail
// re-renders the scaffold from the CURRENT claim (harness.Validate) and
// byte-compares everything OUTSIDE the BODY window. A claim that drifted
// away from the bytes that ran is refused by the new arm
// "scaffold-degraded: <reason>" — inconclusive, output unused, no proof —
// while in-window model tuning still maps byte-for-byte as before. The
// rows also pin the ORDER: the hash check runs first, so a foreign hash
// refuses with the hash wording even when the claim drifted too (a refusal
// must name the reason the rail actually stopped on).
func TestVerifyHarnessResultScaffoldValidate(t *testing.T) {
	const degradedNatspec = "scaffold-degraded: natspec invariant line changed"
	const hashDiffers = "scaffold-bound violation: harness file hash differs " +
		"from stored scaffold"
	cases := []struct {
		name        string
		edit        func(t *testing.T, c *state.Campaign)
		foreignHash bool
		wantRung    string
		wantSummary string   // exact match when non-empty
		wantHas     []string // summary substrings, when non-empty
	}{
		{
			// (a) statement edited after the run, harness file untouched:
			// the re-render no longer describes the file that ran.
			name: "claim drift after the run refuses",
			edit: func(t *testing.T, c *state.Campaign) {
				harnessDriftStatement(t, c, "INV-1",
					"totalAssets must cover all ISSUED shares")
			},
			wantRung:    "inconclusive",
			wantSummary: degradedNatspec,
		},
		{
			// (b) only the BODY window moved: Validate must not fire.
			name:     "body-window tuning maps normally",
			edit:     harnessTuneBody,
			wantRung: "proved-bounded",
			wantHas:  []string{"k=100"},
		},
		{
			// (d) untampered flow: nothing moved at all.
			name:     "untampered bound run maps normally",
			wantRung: "proved-bounded",
			wantHas:  []string{"k=100"},
		},
		{
			// A degraded artifact with no window at all: the refusal
			// carries BodyRegion's own wording, unparsed.
			name:        "marker-less artifact refuses with its reason",
			edit:        harnessDropEndMarker,
			wantRung:    "inconclusive",
			wantSummary: "scaffold-degraded: missing BODY end marker",
		},
		{
			// Ordering: hash-bind first, Validate second. The hash arm
			// owns the refusal here even though the claim drifted.
			name: "foreign hash refuses before Validate",
			edit: func(t *testing.T, c *state.Campaign) {
				harnessDriftStatement(t, c, "INV-1",
					"totalAssets must cover all ISSUED shares")
			},
			foreignHash: true,
			wantRung:    "inconclusive",
			wantSummary: hashDiffers,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, "halmos", "")
			if tc.edit != nil {
				tc.edit(t, c)
			}
			// The artifact the run was bound to, byte-captured before the
			// command: the harness-result path must never rewrite it.
			pre, err := os.ReadFile(harnessArtifactPath(c))
			if err != nil {
				t.Fatal(err)
			}
			execID := fmt.Sprintf("EXEC-0000000%03d", 14+i)
			hashes := map[string]string{
				"H.t.sol": harnessScaffoldSHA(t, c),
			}
			if tc.foreignHash {
				hashes["H.t.sol"] = strings.Repeat("0", 64)
			}
			harnessExec(t, c, execID, harnessProvedStdout,
				"halmos check --root . --loop 100 "+
					"--match-contract Inv1InvariantHalmos", hashes, 0)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1",
				"--exec", execID)
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			wantOut := fmt.Sprintf("INV-1: %s (halmos, %s)\n",
				tc.wantRung, execID)
			if tc.wantRung == "proved-bounded" {
				wantOut = fmt.Sprintf("INV-1: proved-bounded (halmos, "+
					"k=100, %s)\n", execID)
			}
			if out != wantOut {
				t.Fatalf("stdout = %q, want %q", out, wantOut)
			}
			h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
			if objStr(h, "rung") != tc.wantRung {
				t.Fatalf("rung = %s, want %s", validation.CanonCompact(h),
					tc.wantRung)
			}
			summary := objStr(h, "summary")
			if tc.wantSummary != "" && summary != tc.wantSummary {
				t.Fatalf("summary = %q, want %q", summary, tc.wantSummary)
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(summary, want) {
					t.Fatalf("summary %q lacks %q", summary, want)
				}
			}
			if tc.wantRung == "proved-bounded" &&
				strings.Contains(summary, "scaffold-degraded") {
				t.Fatalf("Validate fired on a legal run: %q", summary)
			}
			if tc.wantRung == "inconclusive" {
				if objHasKey(h, "proof") {
					t.Fatal("a refusal stores no proof key")
				}
				if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
					t.Fatalf("bounded_k = %s, want null",
						validation.CanonCompact(bk))
				}
			}
			// The event carries the same refusal the field does.
			evs := harnessEventsOf(t, c, "harness_run")
			if len(evs) != 1 {
				t.Fatalf("harness_run events = %d, want 1", len(evs))
			}
			got, _ := evs[0]["data"].(map[string]any)
			if got["rung"] != tc.wantRung || got["summary"] != summary {
				t.Fatalf("event data = %v, want rung %q summary %q", got,
					tc.wantRung, summary)
			}
			post, err := os.ReadFile(harnessArtifactPath(c))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pre, post) {
				t.Fatal("the run path must not rewrite the scaffold artifact")
			}
		})
	}
}

// TestVerifyHarnessResultUnboundScaffoldValidate pins the fix-round half of
// Task 1 (wave L-defer): the Validate arm is NOT limited to hash-bound runs.
// An unbound run records no hash at all, so no bytes were proved to have run
// — the harness file the scaffold event points at is the only artifact left,
// and the rail judges exactly those on-disk bytes against the CURRENT claim.
// Drift therefore refuses with the same "scaffold-degraded:" wording the
// bound arm uses (no hash proof was needed for the file to be wrong), while
// an unbound run whose file still matches the claim keeps mapping
// byte-for-byte as before, honest limitation suffix included.
func TestVerifyHarnessResultUnboundScaffoldValidate(t *testing.T) {
	const unboundSuffix = " (unbound: harness file hash not recorded)"
	cases := []struct {
		name        string
		edit        func(t *testing.T, c *state.Campaign)
		wantRung    string
		wantSummary string   // exact match when non-empty
		wantHas     []string // summary substrings, when non-empty
	}{
		{
			// (a) the claim moved after the run and nothing bound the run
			// to the file: the file is the artifact Validate judges, and
			// it no longer describes the claim on record.
			name: "unbound claim drift refuses",
			edit: func(t *testing.T, c *state.Campaign) {
				harnessDriftStatement(t, c, "INV-1",
					"totalAssets must cover all ISSUED shares")
			},
			wantRung:    "inconclusive",
			wantSummary: "scaffold-degraded: natspec invariant line changed",
		},
		{
			// The refusal judges the FILE, bound or not: a damaged frame
			// on disk refuses with its own reason.
			name:        "unbound marker-less artifact refuses",
			edit:        harnessDropEndMarker,
			wantRung:    "inconclusive",
			wantSummary: "scaffold-degraded: missing BODY end marker",
		},
		{
			// Validate passing leaves the unbound path byte-identical:
			// the honest limitation suffix still rides the summary.
			name:     "unbound untampered run keeps its suffix",
			wantRung: "proved-bounded",
			wantHas:  []string{"k=100", unboundSuffix},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, "halmos", "")
			if tc.edit != nil {
				tc.edit(t, c)
			}
			pre, err := os.ReadFile(harnessArtifactPath(c))
			if err != nil {
				t.Fatal(err)
			}
			execID := fmt.Sprintf("EXEC-0000000%03d", 20+i)
			// nil input_hashes: the unbound exec record (no hash info at
			// all) the reviewer-confirmed gap was about.
			harnessExec(t, c, execID, harnessProvedStdout,
				"halmos check --root . --loop 100 "+
					"--match-contract Inv1InvariantHalmos", nil, 0)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1",
				"--exec", execID)
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			wantOut := fmt.Sprintf("INV-1: %s (halmos, %s)\n",
				tc.wantRung, execID)
			if tc.wantRung == "proved-bounded" {
				wantOut = fmt.Sprintf("INV-1: proved-bounded (halmos, "+
					"k=100, %s)\n", execID)
			}
			if out != wantOut {
				t.Fatalf("stdout = %q, want %q", out, wantOut)
			}
			h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
			if objStr(h, "rung") != tc.wantRung {
				t.Fatalf("rung = %s, want %s", validation.CanonCompact(h),
					tc.wantRung)
			}
			summary := objStr(h, "summary")
			if tc.wantSummary != "" && summary != tc.wantSummary {
				t.Fatalf("summary = %q, want %q", summary, tc.wantSummary)
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(summary, want) {
					t.Fatalf("summary %q lacks %q", summary, want)
				}
			}
			if tc.wantRung == "inconclusive" {
				if objHasKey(h, "proof") {
					t.Fatal("a refusal stores no proof key")
				}
				if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
					t.Fatalf("bounded_k = %s, want null",
						validation.CanonCompact(bk))
				}
			}
			// The event carries the same refusal the field does.
			evs := harnessEventsOf(t, c, "harness_run")
			if len(evs) != 1 {
				t.Fatalf("harness_run events = %d, want 1", len(evs))
			}
			got, _ := evs[0]["data"].(map[string]any)
			if got["rung"] != tc.wantRung || got["summary"] != summary {
				t.Fatalf("event data = %v, want rung %q summary %q", got,
					tc.wantRung, summary)
			}
			post, err := os.ReadFile(harnessArtifactPath(c))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pre, post) {
				t.Fatal("the run path must not rewrite the scaffold artifact")
			}
		})
	}
}

// TestR26DegenerateBoundFloorsTheExecPath pins critic r26 F3 end to end:
// the r25 "<1 refuses" law lived only on the autoprove REPORT path, so a
// real exec record invoking `forge test --fuzz-runs 0` over a PASS
// output still bound `proved-bounded (forge-fuzz, k=0)` — a proof about
// nothing with a loudly stated bound, audit-green.
func TestR26DegenerateBoundFloorsTheExecPath(t *testing.T) {
	c, root := harnessCamp(t, "forge-fuzz", "")
	execID := "EXEC-0000000042"
	harnessExec(t, c, execID, r26ForgePass,
		"forge test --fuzz-runs 0", nil, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID,
		"--kind", "forge-fuzz")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("a degenerate bound must NOT bless: %s",
			validation.CanonCompact(h))
	}
	if !strings.Contains(objStr(h, "summary"), "degenerate-bound") {
		t.Fatalf("the floor must be named: %q", objStr(h, "summary"))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k must be null, got %s",
			validation.CanonCompact(bk))
	}
	if code, out, _ := run(t, "--root", root, "audit", c.CampaignID); code != 0 {
		t.Fatalf("audit must agree with the floored bind: exit %d out %.300q",
			code, out)
	}
}

// TestR26UnstatedBoundIsNotZero pins the mirror half: an invocation that
// never named a bound proves, but it states UNSTATED — never "k=0",
// which is a bound nobody stated.
func TestR26UnstatedBoundIsNotZero(t *testing.T) {
	c, root := harnessCamp(t, "forge-fuzz", "")
	execID := "EXEC-0000000043"
	harnessExec(t, c, execID, r26ForgePass, "forge test", nil, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID,
		"--kind", "forge-fuzz")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "rung") != "proved-bounded" {
		t.Fatalf("an honest unstated-bound pass must still prove: %s",
			validation.CanonCompact(h))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("an unstated bound must not ride the slot as k=0: %s",
			validation.CanonCompact(bk))
	}
	if s := objStr(h, "summary"); strings.Contains(s, "k=0") ||
		!strings.Contains(s, "UNSTATED") {
		t.Fatalf("summary %q must say UNSTATED, never k=0", s)
	}
}

// r26ForgePass is a forge-fuzz suite that passes with no FAIL line.
const r26ForgePass = `Compiling 2 files with Solc 0.8.33
Solc 0.8.33 finished in 365ms
Ran 1 test for test/Inv.t.sol:InvInvariantFuzz
[PASS] fuzz_inv_1(uint256) (runs: 256, calls: 1024, reverts: 31)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 9.81ms
---
Ran 1 test suite: 1 passed; 0 failed; 0 skipped
`

// r27McProvenBound is a PROVEN minicertora verdict line whose
// bounds.loop_bound is the given JSON expression — the auditor's own repro
// shape (0, -1 and -2 are statements the twin's VerifierFlags refuses).
func r27McProvenBound(expr string) string {
	return `{"rule":"inv_1","verdict":"PROVEN","confidence":"modeled",` +
		`"assumptions":[],"bounds":{"loop_bound":` + expr + `,` +
		`"path_cap":64,"solver_timeout_ms":30000}}` + "\n"
}

// The two degenerate-bound summaries (the r26 shell's vocabulary, shared
// by MapRun and the minicertora mapper — pinned as exact bytes so a
// wording regression cannot slip).
const (
	r27McRunFloor = "inconclusive (degenerate-bound: the run states " +
		"no bound >= 1)"
	r27McInvocFloor = "inconclusive (degenerate-bound: the invocation " +
		"states no bound >= 1)"
)

// TestR27MinicertoraDegenerateBoundFloorsTheBind pins finding r27 F1's
// proof-level arm end to end: the minicertora path bypassed MapRun
// entirely, so a PROVEN line whose OWN bounds.loop_bound was 0 (or -1/-2)
// used to bind proved-bounded — a proof about nothing, audit-green. The
// floor must floor the rung, name the degenerate bound in the r26
// vocabulary (escalate-bound's class, never a second wording class), keep
// bounded_k out of the slot, and — bind==audit — leave the same campaign's
// audit at exit 0 (no false burn for an honest bind).
func TestR27MinicertoraDegenerateBoundFloorsTheBind(t *testing.T) {
	for _, bound := range []string{"0", "-1", "-2"} {
		t.Run("loop_bound "+bound, func(t *testing.T) {
			c, root := mcCamp(t, "r27-mc-deg-"+
				strings.ReplaceAll(bound, "-", "n"))
			execID := "EXEC-0000000044"
			mcHarnessExec(t, c, execID, r27McProvenBound(bound),
				"minicertora --rule inv_1 --loop-bound 4",
				map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
			code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
				"--harness-result", "INV-1", "--exec", execID)
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			if want := "INV-1: inconclusive (minicertora, " + execID + ")\n"; out != want {
				t.Fatalf("stdout = %q, want %q", out, want)
			}
			h := mcHarness(t, c)
			if rung := objStr(h, "rung"); rung != "inconclusive" {
				t.Fatalf("loop_bound %s must not bless: %s", bound,
					validation.CanonCompact(h))
			}
			if s := objStr(h, "summary"); s != r27McRunFloor {
				t.Fatalf("summary = %q, want %q", s, r27McRunFloor)
			}
			if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
				t.Fatalf("bounded_k must never ride a degenerate bound: %s",
					validation.CanonCompact(bk))
			}
			if objHasKey(h, "proof") {
				t.Fatal("a degenerate-bound refusal stores no proof key")
			}
			// The advice class the tally reads must be escalate-bound,
			// not a second wording class of our own.
			if cls, _, ok := harness.Disposition(objStr(h, "summary")); !ok ||
				cls != harness.EscalateBound {
				t.Fatalf("Disposition(%q) = %q ok=%v, want escalate-bound",
					objStr(h, "summary"), cls, ok)
			}
			// bind==audit: the audit re-derives through the same entry
			// point, so the floored bind must not burn its own campaign.
			if acode, aout, aerr := run(t, "--root", root, "audit",
				c.CampaignID); acode != 0 {
				t.Fatalf("audit must agree with the floored bind: exit %d "+
					"out=%.4000q err=%q", acode, aout, aerr)
			}
		})
	}
}

// TestR27MinicertoraDegenerateInvocationFloorsTheBind pins the
// invocation-level arm: the record's own command says --loop-bound 0, and
// the twin raises for loop_bound < 1, so no run can have executed under it
// — the honest-looking loop_bound 4 in the output must NOT bind as
// proved-bounded with k=4. The audit of that same campaign stays exit 0.
func TestR27MinicertoraDegenerateInvocationFloorsTheBind(t *testing.T) {
	c, root := mcCamp(t, "r27-mc-deg-invoc")
	execID := "EXEC-0000000045"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 0",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out, "proved-bounded") || strings.Contains(out, "k=4") {
		t.Fatalf("a degenerate invocation must not bind k=4: %q", out)
	}
	if want := "INV-1: inconclusive (minicertora, " + execID + ")\n"; out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	h := mcHarness(t, c)
	if objStr(h, "rung") != "inconclusive" {
		t.Fatalf("rung = %s", validation.CanonCompact(h))
	}
	if s := objStr(h, "summary"); s != r27McInvocFloor {
		t.Fatalf("summary = %q, want %q", s, r27McInvocFloor)
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("bounded_k must be null, got %s",
			validation.CanonCompact(bk))
	}
	if code, aout, aerr := run(t, "--root", root, "audit",
		c.CampaignID); code != 0 {
		t.Fatalf("audit must agree with the floored bind: exit %d out=%.300q "+
			"err=%q", code, aout, aerr)
	}
}

// TestR27MinicertoraHonestRunIsByteUnchanged is the control the two floors
// above must never touch: an honest minicertora run (--loop-bound 4 over
// loop_bound 4) keeps its rung, its byte-exact summary and its bounded_k 4,
// and its campaign audits green.
func TestR27MinicertoraHonestRunIsByteUnchanged(t *testing.T) {
	c, root := mcCamp(t, "r27-mc-honest")
	execID := "EXEC-0000000046"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if want := "INV-1: proved-bounded (minicertora, k=4, " + execID + ")\n"; out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	h := mcHarness(t, c)
	if rung := objStr(h, "rung"); rung != "proved-bounded" {
		t.Fatalf("an honest run must still prove: %s",
			validation.CanonCompact(h))
	}
	if s := objStr(h, "summary"); s != "proved bounded (k=4)" {
		t.Fatalf("summary = %q, want %q", s, "proved bounded (k=4)")
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Int || bk.I != 4 {
		t.Fatalf("bounded_k = %s, want 4", validation.CanonCompact(bk))
	}
	p := objAt(h, "proof")
	if p.Kind != validation.Obj {
		t.Fatalf("an attributed PROVEN line keeps its sidecar: %s",
			validation.CanonCompact(h))
	}
	if lb := objAt(objAt(p, "bounds"), "loop_bound"); lb.Kind != validation.Int ||
		lb.I != 4 {
		t.Fatalf("proof.bounds.loop_bound = %s, want 4",
			validation.CanonCompact(lb))
	}
	if code, aout, aerr := run(t, "--root", root, "audit",
		c.CampaignID); code != 0 {
		t.Fatalf("an honest bind must audit green: exit %d out=%.300q err=%q",
			code, aout, aerr)
	}
}

// ---------------------------------------------------------------------
// r32: the invocation bound is read by the OWNING tool's rule
// ---------------------------------------------------------------------

// r32ExecCommandValue writes one EXEC the way the sandbox would, except
// that `command` is whatever JSON value the caller passes — the record read
// path (state.AllExecs -> validation.ReadJson) does no schema check, which
// is exactly the r32 F8 hole.
func r32ExecCommandValue(t *testing.T, c *state.Campaign, execID,
	stdout string, command validation.Value, omitCommand bool,
	hashes map[string]string, exitStatus int64) {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	kvs := []validation.KV{
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr("forge")),
		kvT("origin", validation.VStr("locally-executed")),
		kvT("started_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kvT("finished_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kvT("exit_status", validation.VInt(exitStatus)),
		kvT("stdout_path", validation.VStr(stdoutPath)),
	}
	if !omitCommand {
		kvs = append(kvs, kvT("command", command))
	}
	if hashes != nil {
		hk := make([]validation.KV, 0, len(hashes))
		for k, v := range hashes {
			hk = append(hk, kvT(k, validation.VStr(v)))
		}
		kvs = append(kvs, kvT("input_hashes", validation.VObj(hk...)))
	}
	rec := validation.VObj(kvs...)
	if err := os.WriteFile(filepath.Join(dir, "exec_record.json"),
		[]byte(validation.CanonCompact(rec)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestR32ForgeBoundFollowsForgeEndToEnd is F1's end-to-end pin at the
// level it broke: the cli's invocationBound wrapper discarded the kind, so
// a record invoking `forge test --fuzz-runs 4_000` bound a GREEN
// proved-bounded blessing with k=4000 although no forge run exists under
// that value. Each row quotes the real tool's rejection (OBSERVED, forge
// 1.8.1) and must floor — rung inconclusive, bounded_k null, and the
// summary naming forge and the reason.
func TestR32ForgeBoundFollowsForgeEndToEnd(t *testing.T) {
	rows := []struct {
		name   string
		cmd    string
		reason string
	}{
		// forge test --fuzz-runs 4_000
		//   -> error: invalid value '4_000' for '--fuzz-runs <RUNS>':
		//      invalid digit found in string
		{"underscore grouping", "forge test --fuzz-runs 4_000",
			"invalid digit found in string"},
		// forge test --fuzz-runs ٤٢ -> same "invalid digit found in
		// string" (Rust is ASCII-only).
		{"arabic-indic digit", "forge test --fuzz-runs \u0664\u0662",
			"invalid digit found in string"},
		// forge test --fuzz-runs $'500\r' -> same "invalid digit found in
		// string".
		{"carriage return", "forge test --fuzz-runs 500\r",
			"invalid digit found in string"},
		// forge test --fuzz-runs 4294967296 -> Error: failed to extract
		// foundry config: ... expected u32 for setting `fuzz.runs`.
		{"u32 overflow", "forge test --fuzz-runs 4294967296",
			"expected u32"},
		// forge test --fuzz-runs 0 --fuzz-runs 7 -> error: the argument
		// '--fuzz-runs <RUNS>' cannot be used multiple times. (The old
		// reading bound 7 here.)
		{"repeated flag", "forge test --fuzz-runs 0 --fuzz-runs 7",
			"cannot be used multiple times"},
		// forge test --fuzz-runs 0 -> foundry config error: `fuzz.runs`
		// must be greater than 0.
		{"zero", "forge test --fuzz-runs 0",
			"must be greater than 0"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, "forge-fuzz", "")
			execID := "EXEC-0000000050"
			harnessExec(t, c, execID, r26ForgePass, tc.cmd,
				map[string]string{"F.t.sol": r32ForgeScaffoldSHA(t, c)}, 0)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1",
				"--exec", execID, "--kind", "forge-fuzz")
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			if strings.Contains(out, "proved-bounded") {
				t.Fatalf("no forge ran under %q, so nothing may be "+
					"bounded: %q", tc.cmd, out)
			}
			h := objAt(objAt(harnessEntry(t, c), "verification"),
				"harness")
			if objStr(h, "rung") != "inconclusive" {
				t.Fatalf("rung = %s, want the floor",
					validation.CanonCompact(h))
			}
			summary := objStr(h, "summary")
			if !strings.Contains(summary, "degenerate-bound") ||
				!strings.Contains(summary, "forge") ||
				!strings.Contains(summary, tc.reason) {
				t.Fatalf("summary = %q, want the degenerate-bound "+
					"vocabulary naming forge and %q", summary,
					tc.reason)
			}
			if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
				t.Fatalf("bounded_k = %s, want null",
					validation.CanonCompact(bk))
			}
			if cls, _, ok := harness.Disposition(summary); !ok ||
				cls != harness.EscalateBound {
				t.Fatalf("Disposition(%q) = %q ok=%v, want "+
					"escalate-bound", summary, cls, ok)
			}
			if acode, aout, aerr := run(t, "--root", root, "audit",
				c.CampaignID); acode != 0 {
				t.Fatalf("bind==audit: the audit must not burn the "+
					"floored bind (exit %d out=%.300q err=%q)", acode,
					aout, aerr)
			}
		})
	}
	// Control: a value forge ACCEPTS still binds, with the real bound.
	c, root := harnessCamp(t, "forge-fuzz", "")
	execID := "EXEC-0000000051"
	harnessExec(t, c, execID, r26ForgePass, "forge test --fuzz-runs 500",
		map[string]string{"F.t.sol": r32ForgeScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID, "--kind",
		"forge-fuzz")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
	if objStr(h, "rung") != "proved-bounded" {
		t.Fatalf("an accepted forge value must still bind: %s",
			validation.CanonCompact(h))
	}
	if bk := objAt(h, "bounded_k"); bk.Kind != validation.Int || bk.I != 500 {
		t.Fatalf("bounded_k = %s, want 500", validation.CanonCompact(bk))
	}
}

// TestR32ForeignBoundFlagEndToEnd is F2's end-to-end pin: a LONE
// bound-looking flag that belongs to ANOTHER tool's family used to bind
// proved-bounded for the wrong tool. Each row quotes the real tool's
// refusal and must floor, naming the flag and the tool.
func TestR32ForeignBoundFlagEndToEnd(t *testing.T) {
	// forge-fuzz bound to `forge test --loop 3`:
	//   forge test --loop 3 -> error: unexpected argument '--loop' found
	t.Run("forge has no --loop", func(t *testing.T) {
		c, root := harnessCamp(t, "forge-fuzz", "")
		execID := "EXEC-0000000052"
		harnessExec(t, c, execID, r26ForgePass, "forge test --loop 3",
			map[string]string{"F.t.sol": r32ForgeScaffoldSHA(t, c)}, 0)
		code, out, errS := run(t, "--root", root, "verify",
			c.CampaignID, "--harness-result", "INV-1", "--exec", execID,
			"--kind", "forge-fuzz")
		if code != 0 {
			t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
		}
		if strings.Contains(out, "proved-bounded") {
			t.Fatalf("forge refuses --loop, so nothing may be bounded: %q",
				out)
		}
		h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
		summary := objStr(h, "summary")
		if objStr(h, "rung") != "inconclusive" ||
			!strings.Contains(summary, "--loop") ||
			!strings.Contains(summary, "forge") ||
			!strings.Contains(summary, "unexpected argument") {
			t.Fatalf("the floor must name the flag, the tool and its "+
				"refusal: %s", validation.CanonCompact(h))
		}
		if acode, aout, aerr := run(t, "--root", root, "audit",
			c.CampaignID); acode != 0 {
			t.Fatalf("bind==audit: exit %d out=%.4000q err=%q", acode,
				aout, aerr)
		}
	})
	// halmos bound to `halmos check --fuzz-runs 500`:
	//   halmos: error: unrecognized arguments: --fuzz-runs 500
	t.Run("halmos has no --fuzz-runs", func(t *testing.T) {
		c, root := harnessCamp(t, "halmos", "")
		execID := "EXEC-0000000053"
		harnessExec(t, c, execID, harnessProvedStdout,
			"halmos check --fuzz-runs 500",
			map[string]string{"H.t.sol": harnessScaffoldSHA(t, c)}, 0)
		code, out, errS := run(t, "--root", root, "verify",
			c.CampaignID, "--harness-result", "INV-1", "--exec", execID,
			"--kind", "halmos")
		if code != 0 {
			t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
		}
		if strings.Contains(out, "proved-bounded") {
			t.Fatalf("halmos refuses --fuzz-runs, so nothing may be "+
				"bounded: %q", out)
		}
		h := objAt(objAt(harnessEntry(t, c), "verification"), "harness")
		summary := objStr(h, "summary")
		if objStr(h, "rung") != "inconclusive" ||
			!strings.Contains(summary, "--fuzz-runs") ||
			!strings.Contains(summary, "halmos") ||
			!strings.Contains(summary, "unrecognized arguments") {
			t.Fatalf("the floor must name the flag, the tool and its "+
				"refusal: %s", validation.CanonCompact(h))
		}
		if acode, aout, aerr := run(t, "--root", root, "audit",
			c.CampaignID); acode != 0 {
			t.Fatalf("bind==audit: exit %d out=%.4000q err=%q", acode,
				aout, aerr)
		}
	})
	// minicertora bound to `minicertora V.sol INV.mspec --fuzz-runs 500`:
	//   Error: No such option '--fuzz-runs'.
	t.Run("minicertora has no --fuzz-runs", func(t *testing.T) {
		c, root := mcCamp(t, "r32-foreign-mc")
		execID := "EXEC-0000000054"
		mcHarnessExec(t, c, execID, mcProvenLine,
			"minicertora V.sol INV.mspec --fuzz-runs 500",
			map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, 0)
		code, out, errS := run(t, "--root", root, "verify",
			c.CampaignID, "--harness-result", "INV-1", "--exec", execID,
			"--kind", "minicertora")
		if code != 0 {
			t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
		}
		if strings.Contains(out, "proved-bounded") {
			t.Fatalf("the twin refuses --fuzz-runs, so nothing may be "+
				"bounded: %q", out)
		}
		h := mcHarness(t, c)
		summary := objStr(h, "summary")
		if objStr(h, "rung") != "inconclusive" ||
			!strings.Contains(summary, "--fuzz-runs") ||
			!strings.Contains(summary, "minicertora") ||
			!strings.Contains(summary, "No such option") {
			t.Fatalf("the floor must name the flag, the tool and its "+
				"refusal: %s", validation.CanonCompact(h))
		}
		if acode, aout, aerr := run(t, "--root", root, "audit",
			c.CampaignID); acode != 0 {
			t.Fatalf("bind==audit: exit %d out=%.4000q err=%q", acode,
				aout, aerr)
		}
	})
	// The boundary r32 F2 must not widen: a flag the tool HAS plus an
	// unrelated unknown option still binds.
	c, root := harnessCamp(t, "forge-fuzz", "")
	execID := "EXEC-0000000055"
	harnessExec(t, c, execID, r26ForgePass,
		"forge test --fuzz-runs 500 --loopx 5 --ffi",
		map[string]string{"F.t.sol": r32ForgeScaffoldSHA(t, c)}, 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID, "--kind",
		"forge-fuzz")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "proved-bounded") ||
		!strings.Contains(out, "k=500") {
		t.Fatalf("an unrelated unknown option must not floor an honest "+
			"bound: %q", out)
	}
}

// TestR32NonStringCommandEndToEnd is F8's end-to-end pin: a record whose
// `command` is an ARRAY (["forge","test","--fuzz-runs","0"]) or a NUMBER
// (500) is a STATED, degenerate invocation — not an absent one. The old
// reader (objStr/recordStr) returned "" for both, "" parses as "no bound
// flag", and the run bound proved-bounded (bound UNSTATED) with a GREEN
// audit although the command was right there.
func TestR32NonStringCommandEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shape string
		val   validation.Value
	}{
		{"array command", "JSON array", validation.VArr(
			validation.VStr("forge"), validation.VStr("test"),
			validation.VStr("--fuzz-runs"), validation.VStr("0"))},
		{"number command", "JSON number", validation.VInt(500)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, "forge-fuzz", "")
			execID := "EXEC-0000000056"
			r32ExecCommandValue(t, c, execID, r26ForgePass, tc.val,
				false, map[string]string{
					"F.t.sol": r32ForgeScaffoldSHA(t, c)}, 0)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1",
				"--exec", execID, "--kind", "forge-fuzz")
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			if strings.Contains(out, "proved-bounded") {
				t.Fatalf("a stated-but-unreadable invocation must not "+
					"be bounded: %q", out)
			}
			h := objAt(objAt(harnessEntry(t, c), "verification"),
				"harness")
			summary := objStr(h, "summary")
			if objStr(h, "rung") != "inconclusive" {
				t.Fatalf("rung = %s, want the floor",
					validation.CanonCompact(h))
			}
			if !strings.Contains(summary, "degenerate-bound") ||
				!strings.Contains(summary, "not a string") ||
				!strings.Contains(summary, tc.shape) {
				t.Fatalf("the floor must name the shape %q: %q",
					tc.shape, summary)
			}
			if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
				t.Fatalf("bounded_k = %s, want null",
					validation.CanonCompact(bk))
			}
			// The audit catches the same plant twice, on two rails:
			// section 3 rejects the record itself (the
			// sandbox_execution schema requires a non-empty STRING
			// command: {"type":"string","minLength":1}), and the harness
			// rail floors the bind instead of blessing the UNSTATED
			// bound — which is the half r32 F8 found missing.
			acode, aout, _ := run(t, "--root", root, "audit",
				c.CampaignID)
			if acode == 0 {
				t.Fatalf("a non-string command must be a schema "+
					"problem for section 3: %q", aout)
			}
			if !strings.Contains(aout, "execs=1 problem") {
				t.Fatalf("section 3 must flag the record: %q", aout)
			}
		})
	}
	// The documented other half: a MISSING (absent or null) command is
	// genuinely "no invocation on record" — no flag, no value, no tool — so
	// it keeps today's reading and the run maps with the UNSTATED bound.
	// That cannot bless a degenerate invocation: there is no command text
	// to carry one, and the summary asserts no number at all.
	for _, tc := range []struct {
		name   string
		val    validation.Value
		absent bool
	}{
		{"absent command", validation.VNull(), true},
		{"null command", validation.VNull(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, "forge-fuzz", "")
			execID := "EXEC-0000000057"
			r32ExecCommandValue(t, c, execID, r26ForgePass, tc.val,
				tc.absent, map[string]string{
					"F.t.sol": r32ForgeScaffoldSHA(t, c)}, 0)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1",
				"--exec", execID, "--kind", "forge-fuzz")
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			h := objAt(objAt(harnessEntry(t, c), "verification"),
				"harness")
			if objStr(h, "rung") != "proved-bounded" ||
				!strings.Contains(objStr(h, "summary"), "UNSTATED") {
				t.Fatalf("a record with no command maps with an "+
					"UNSTATED bound: %s",
					validation.CanonCompact(h))
			}
			if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
				t.Fatalf("an UNSTATED bound must not ride the slot: %s",
					validation.CanonCompact(bk))
			}
		})
	}
}

// TestR32TimeoutNoLongerPrintsTheBoundAsSeconds is F3's end-to-end pin. A
// killed run used to print the BOUND in the seconds slot — observed in the
// finding: "timeout after -1s" for --fuzz-runs 0, "timeout after 4s" for a
// run whose wall clock was 2.76s, "timeout after 7s" for a duplicate — and
// a flooring bound escaped the floor entirely on this path.
func TestR32TimeoutNoLongerPrintsTheBoundAsSeconds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cmd      string
		exit     int64
		wantSub  string
		mustFail string
	}{
		{"killed under --fuzz-runs 0", "forge test --fuzz-runs 0", -1,
			"degenerate-bound", ""},
		{"killed under --fuzz-runs 4", "forge test --fuzz-runs 4", -1,
			"inconclusive (timeout)", "4s"},
		{"signal-death under a duplicate",
			"forge test --fuzz-runs 0 --fuzz-runs 7", 137,
			"degenerate-bound", "7s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, root := harnessCamp(t, "forge-fuzz", "")
			execID := "EXEC-0000000058"
			harnessExec(t, c, execID, r26ForgePass, tc.cmd,
				map[string]string{"F.t.sol": r32ForgeScaffoldSHA(t, c)},
				tc.exit)
			code, out, errS := run(t, "--root", root, "verify",
				c.CampaignID, "--harness-result", "INV-1",
				"--exec", execID, "--kind", "forge-fuzz")
			if code != 0 {
				t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
			}
			h := objAt(objAt(harnessEntry(t, c), "verification"),
				"harness")
			summary := objStr(h, "summary")
			if objStr(h, "rung") != "inconclusive" {
				t.Fatalf("a killed run never binds a rung: %s",
					validation.CanonCompact(h))
			}
			if !strings.Contains(summary, tc.wantSub) {
				t.Fatalf("summary = %q, want it to contain %q", summary,
					tc.wantSub)
			}
			if strings.Contains(summary, "timeout after") {
				t.Fatalf("the timeout summary still prints a bound as a "+
					"duration: %q", summary)
			}
			if tc.mustFail != "" &&
				strings.Contains(summary, tc.mustFail) {
				t.Fatalf("summary %q carries the bound %q as seconds",
					summary, tc.mustFail)
			}
			if bk := objAt(h, "bounded_k"); bk.Kind != validation.Null {
				t.Fatalf("bounded_k = %s, want null",
					validation.CanonCompact(bk))
			}
			if acode, aout, aerr := run(t, "--root", root, "audit",
				c.CampaignID); acode != 0 {
				t.Fatalf("bind==audit: exit %d out=%.300q err=%q",
					acode, aout, aerr)
			}
		})
	}
	// The minicertora class half: a killed run under a bound the twin
	// would REFUSE used to lose its escalation entirely — the summary said
	// "no clean completion", which disposition.go keys to EscalateRuntime,
	// so the operator was told to raise the wall clock for a command that
	// cannot start. It must key EscalateBound instead.
	t.Run("minicertora killed under a refused bound", func(t *testing.T) {
		c, root := mcCamp(t, "r32-timeout-mc")
		execID := "EXEC-0000000059"
		mcHarnessExec(t, c, execID, mcProvenLine,
			"minicertora V.sol INV.mspec --loop-bound 0",
			map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)}, -1)
		code, out, errS := run(t, "--root", root, "verify",
			c.CampaignID, "--harness-result", "INV-1", "--exec", execID,
			"--kind", "minicertora")
		if code != 0 {
			t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
		}
		h := mcHarness(t, c)
		summary := objStr(h, "summary")
		if objStr(h, "rung") != "inconclusive" {
			t.Fatalf("a killed run never binds: %s",
				validation.CanonCompact(h))
		}
		if !strings.Contains(summary, "degenerate-bound") ||
			strings.Contains(summary, "timeout after") {
			t.Fatalf("the minicertora timeout floor must keep the "+
				"degenerate-bound class and no duration: %q", summary)
		}
		cls, advice, ok := harness.Disposition(summary)
		if !ok || cls != harness.EscalateBound || advice == "" {
			t.Fatalf("Disposition(%q) = %q %q %v, want "+
				"escalate-bound (the advice the runtime class dropped)",
				summary, cls, advice, ok)
		}
		// OPEN ITEM (r32 F3, file not owned by this change): the audit
		// still burns this legitimate floor. recheckInconclusive's
		// timed-out arm in internal/audit/sections/invariantverification.go
		// (the `if harness.RecordTimedOut(rec)` branch returning "a
		// disposition no run of these bytes can carry") hard-codes
		// EscalateRuntime for ANY killed minicertora run, so it rejects the
		// escalate-bound class F3 requires — although the same function
		// already re-derived the class through harness.DecideBound a few
		// lines above. The fix belongs to that arm (let it fall through to
		// the existing gotCls != wantCls comparison). Asserted here at the
		// bind only, so this test pins the law and not the stale rail.
	})
}
