package backtest

// baseline_test: the I2b comparator contract (Wave I Task 6).
//
// The comparator is scored over the SAME held-out slice backtest.Run
// scores — the one I1b's exclusions already filtered — and it is scored
// with the framework's only interval source, wilson.Format. Two honesty
// laws carry most of these tests:
//
//   - a case the comparator CANNOT check (no local checkout) is skipped,
//     never counted as unflagged: a made-up false negative is worse than
//     a smaller denominator, and the `skipped: k/n` line is how the
//     smaller denominator stays visible;
//   - the `always` floor prints recall n/n beside its price (precision
//     accepted/n), so no recall number can be quoted without it.
//
// Every metric assertion below runs through a fake ToolRunner. Exactly
// one test (TestBaselineRealTools) touches the real binaries, and it is
// binary-gated.

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// The two gold outcomes the comparator reads. blAccepted is the ONLY
// definition of "accepted" — the same one backtest.Run uses.
const (
	blAccepted = "confirmed-exploitable"
	blRejected = "confirmed-not-exploitable"
)

// blCase is one RAW held-out row carrying the two keys the comparator's
// root resolution reads and mkCase (backtest_test.go) does not: code.repo
// and gold.locations[].file.
func blCase(id, outcome, repo string, files ...string) validation.Value {
	locs := make([]validation.Value, 0, len(files))
	for _, f := range files {
		locs = append(locs, validation.VObj(
			validation.KV{K: "file", V: validation.VStr(f)}))
	}
	return validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(id)},
		validation.KV{K: "partition", V: validation.VStr("held-out")},
		validation.KV{K: "gold", V: validation.VObj(
			validation.KV{K: "outcome", V: validation.VStr(outcome)},
			validation.KV{K: "bug_class", V: validation.VStr("reentrancy")},
			validation.KV{K: "root_cause", V: validation.VStr("root cause of " + id)},
			validation.KV{K: "locations", V: validation.VArr(locs...)},
		)},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr(repo)})},
	)
}

// blPayload is the ONE payload shape the comparator reads: affected[].path,
// where both Task 5 loaders put the tool's own location.
func blPayload(files ...string) validation.Value {
	aff := make([]validation.Value, 0, len(files))
	for _, f := range files {
		aff = append(aff, validation.VObj(
			validation.KV{K: "path", V: validation.VStr(f)}))
	}
	return validation.VObj(validation.KV{K: "affected",
		V: validation.VArr(aff...)})
}

// blRunner is a ToolRunner reading a (tool|root) -> basenames table and
// recording every call, so a test can prove the tool ran ONCE PER ROOT.
func blRunner(payloads map[string][]string, calls *[]string) ToolRunner {
	return func(tool, root string) ([]validation.Value, error) {
		*calls = append(*calls, tool+"|"+root)
		out := []validation.Value{}
		for _, f := range payloads[tool+"|"+root] {
			out = append(out, blPayload(f))
		}
		return out, nil
	}
}

// TestBaselineFloorsBytes pins the two floor baselines byte-for-byte. The
// run seam is nil on purpose: neither floor may touch a tool.
func TestBaselineFloorsBytes(t *testing.T) {
	held := []validation.Value{
		blCase("CASE-a", blAccepted, "internal://suite", "src/A.sol"),
		blCase("CASE-b", blAccepted, "internal://suite", "src/B.sol"),
		blCase("CASE-c", blRejected, "internal://suite", "src/C.sol"),
		blCase("CASE-d", blRejected, "internal://suite", "src/D.sol"),
	}
	got := BaselineBlock([]string{"always", "never"}, held, nil)
	want := "baseline always:\n" +
		"recall: 4/4 (95% CI 51.0–100.0%)\n" +
		"precision: 2/4 (95% CI 15.0–85.0%)\n" +
		"baseline never:\n" +
		"recall: 0/4 (95% CI 0.0–49.0%)\n" +
		"precision: 0/0 (95% CI n/a)\n"
	if got != want {
		t.Fatalf("floors mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

// TestBaselineToolFullMarksAndOneRunPerRoot: a runner that flags exactly
// the accepted cases earns full-marks precision, and the suite's single
// root is invoked ONCE, not once per case.
func TestBaselineToolFullMarksAndOneRunPerRoot(t *testing.T) {
	root := t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, root, "src/A.sol"),
		blCase("CASE-b", blAccepted, root, "contracts/B.sol"),
		blCase("CASE-c", blRejected, root, "src/C.sol"),
	}
	var calls []string
	run := blRunner(map[string][]string{
		"slither|" + root: {"src/A.sol", "contracts/B.sol"},
	}, &calls)
	got := BaselineBlock([]string{"slither"}, held, run)
	want := "baseline slither:\n" +
		"recall: 2/3 (95% CI 20.8–93.9%)\n" +
		"precision: 2/2 (95% CI 34.2–100.0%)\n"
	if got != want {
		t.Fatalf("mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	if len(calls) != 1 {
		t.Fatalf("runner calls = %v, want exactly one per distinct root", calls)
	}
}

// TestBaselineToolFlagsNothing: no payloads means no flags, and precision
// must print wilson.Format's literal 0/0 n/a rather than a fabricated 0%.
func TestBaselineToolFlagsNothing(t *testing.T) {
	root := t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, root, "src/A.sol"),
		blCase("CASE-b", blAccepted, root, "src/B.sol"),
		blCase("CASE-c", blRejected, root, "src/C.sol"),
	}
	var calls []string
	got := BaselineBlock([]string{"aderyn"}, held, blRunner(nil, &calls))
	want := "baseline aderyn:\n" +
		"recall: 0/3 (95% CI 0.0–56.1%)\n" +
		"precision: 0/0 (95% CI n/a)\n"
	if got != want {
		t.Fatalf("mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

// TestBaselineNotComputableIsNeverAMiss: four held-out cases, two of them
// uncheckable (a URL repo and a case with no gold location). The skipped
// line discloses them and the metric denominators cover ONLY the two the
// tool could actually be run against — so an uncheckable row can never
// masquerade as a false negative.
func TestBaselineNotComputableIsNeverAMiss(t *testing.T) {
	root := t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, "internal://suite", "src/A.sol"),
		blCase("CASE-b", blAccepted, root, "src/B.sol"),
		blCase("CASE-c", blAccepted, "https://github.com/owner/repo", "src/C.sol"),
		blCase("CASE-d", blAccepted, root), // empty gold.locations
	}
	var calls []string
	run := blRunner(map[string][]string{
		"slither|":        {"src/A.sol"},
		"slither|" + root: {"src/B.sol"},
	}, &calls)
	got := BaselineBlock([]string{"slither"}, held, run)
	want := "baseline slither:\n" +
		"skipped: 2/4 cases (no local checkout)\n" +
		"recall: 2/2 (95% CI 34.2–100.0%)\n" +
		"precision: 2/2 (95% CI 34.2–100.0%)\n"
	if got != want {
		t.Fatalf("mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	if len(calls) != 2 {
		t.Fatalf("runner calls = %v, want one per distinct computed root", calls)
	}
}

// TestBaselineMissingBinarySkips: the binary gate is fail-open. A runner
// reporting exec.ErrNotFound (what exec.LookPath returns) collapses the
// whole block to the one SKIPPED line — no recall, no precision.
func TestBaselineMissingBinarySkips(t *testing.T) {
	root := t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, root, "src/A.sol"),
		blCase("CASE-b", blRejected, root, "src/B.sol"),
	}
	run := func(tool, r string) ([]validation.Value, error) {
		return nil, &exec.Error{Name: tool, Err: exec.ErrNotFound}
	}
	got := BaselineBlock([]string{"slither"}, held, run)
	want := "baseline slither: SKIPPED (slither not on PATH)\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestBaselineToolFailedOnEveryRoot: a present-but-broken tool is reported
// as a coverage failure, never as a detector that found nothing.
func TestBaselineToolFailedOnEveryRoot(t *testing.T) {
	r1, r2 := t.TempDir(), t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, r1, "src/A.sol"),
		blCase("CASE-b", blRejected, r2, "src/B.sol"),
	}
	run := func(tool, root string) ([]validation.Value, error) {
		return nil, errors.New("boom")
	}
	got := BaselineBlock([]string{"aderyn"}, held, run)
	want := "baseline aderyn: SKIPPED (tool failed on 2/2 roots)\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestBaselinePartialRootFailureScoresTheRest: one root fails, one runs.
// The failed root's cases leave the denominators (they are uncheckable,
// not misses) and the failure is disclosed as a root count.
func TestBaselinePartialRootFailureScoresTheRest(t *testing.T) {
	good, bad := t.TempDir(), t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, good, "src/A.sol"),
		blCase("CASE-b", blRejected, good, "src/B.sol"),
		blCase("CASE-c", blAccepted, bad, "src/C.sol"),
	}
	run := func(tool, root string) ([]validation.Value, error) {
		switch root {
		case good:
			return []validation.Value{blPayload("src/A.sol")}, nil
		case bad:
			return nil, errors.New("boom")
		}
		return nil, fmt.Errorf("unexpected root %q", root)
	}
	got := BaselineBlock([]string{"slither"}, held, run)
	want := "baseline slither:\n" +
		"tool errors: 1 roots\n" +
		"recall: 1/2 (95% CI 9.5–90.5%)\n" +
		"precision: 1/1 (95% CI 20.7–100.0%)\n"
	if got != want {
		t.Fatalf("mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

// TestBaselineCanonicalRosterOrder: argv order is accepted but must never
// reach output (two runs with the same flag set print the same bytes), and
// a repeated name prints one block — the roster order is
// always, never, slither, aderyn.
func TestBaselineCanonicalRosterOrder(t *testing.T) {
	root := t.TempDir()
	held := []validation.Value{
		blCase("CASE-a", blAccepted, root, "src/A.sol"),
		blCase("CASE-b", blRejected, root, "src/B.sol"),
	}
	var calls []string
	run := blRunner(nil, &calls)
	argvOrder := BaselineBlock(
		[]string{"aderyn", "never", "slither", "always"}, held, run)
	rosterOrder := BaselineBlock(
		[]string{"always", "never", "slither", "aderyn"}, held, run)
	if argvOrder != rosterOrder {
		t.Fatalf("argv order reached the output:\n--- argv ---\n%s"+
			"--- roster ---\n%s", argvOrder, rosterOrder)
	}
	prev := -1
	for _, marker := range []string{"baseline always:", "baseline never:",
		"baseline slither:", "baseline aderyn:"} {
		i := strings.Index(argvOrder, marker)
		if i < 0 {
			t.Fatalf("missing %q in:\n%s", marker, argvOrder)
		}
		if i <= prev {
			t.Fatalf("%q out of canonical order:\n%s", marker, argvOrder)
		}
		prev = i
	}
	if n := strings.Count(argvOrder, "baseline always:"); n != 1 {
		t.Fatalf("a repeated --baseline always printed %d blocks, want 1", n)
	}
	if twice := BaselineBlock([]string{"always", "always"}, held, run); twice !=
		BaselineBlock([]string{"always"}, held, run) {
		t.Fatalf("duplicate name changed the bytes:\n%s", twice)
	}
}

// TestHeldOutMirrorsRunHeldSlice locks the comparator's scored universe to
// backtest.Run's: Run's own output is the only observable handle on the
// slice it scores (the --top clamp count, the accepted count, and the
// absence of the temporally excluded row), and HeldOut must agree with all
// three without backtest.Run being modified to expose it.
func TestHeldOutMirrorsRunHeldSlice(t *testing.T) {
	cases := []validation.Value{
		mkDated("CASE-dev", "dev", "2026-09-11", "2026-09-11T00:00:00Z",
			"reentrancy", blAccepted,
			"the dev row describes a withdraw path that zeroes the balance first"),
		mkDated("CASE-held-old", "held-out", "2020-01-01", "2020-01-01T00:00:00Z",
			"oracle-manipulation", blAccepted,
			"the ancient held row prices a borrow limit from spot reserves"),
		mkDated("CASE-held-keep", "held-out", "2026-09-11", "2026-09-11T00:00:00Z",
			"bridge-message", blAccepted,
			"the kept held row replays a bridge message with no chain id"),
		mkDated("CASE-held-neg", "held-out", "2026-09-11", "2026-09-11T00:00:00Z",
			"dos-griefing", blRejected,
			"the kept held negative reverts a whole batch on one bad target"),
	}
	held := HeldOut(cases)
	if len(held) != 2 {
		t.Fatalf("HeldOut scored %d rows, want 2", len(held))
	}
	accepted := 0
	for _, c := range held {
		if objStr(c, "case_id") == "CASE-held-old" {
			t.Fatal("the temporally excluded row reached the scored slice")
		}
		if orStr(objAt(objAt(c, "gold"), "outcome")) == blAccepted {
			accepted++
		}
	}
	out, code := Run(cases, 999)
	if code != 0 {
		t.Fatalf("Run exit = %d: %s", code, out)
	}
	for _, want := range []string{
		"note: --top 999 clamped to 2 held-out cases",
		"accepted available: 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Run output is missing %q:\n%s", want, out)
		}
	}
	if accepted != 1 {
		t.Fatalf("HeldOut accepted = %d, Run says 1", accepted)
	}
}

// TestBaselineRealTools is the ONE binary-gated integration test: it runs
// the real Slither (and Aderyn, when present) over the shipped suite
// checkout through the real spawn, and requires the fixture suite to yield
// at least one Slither flag. A fixture suite no real detector can touch
// would make every comparator number meaningless, and Task 5's loader
// repair is what makes those flags visible at all.
func TestBaselineRealTools(t *testing.T) {
	if _, err := exec.LookPath("slither"); err != nil {
		t.Skip("slither is not on PATH — binary-gated integration test skipped")
	}
	suite := filepath.Join("..", "..", "assets", "evalsuite")
	suiteSrc, err := filepath.Abs(filepath.Join(suite, "src"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ReadJson(filepath.Join(suite, "cases.json"))
	if err != nil {
		t.Fatalf("suite cases: %v", err)
	}
	held := HeldOut(doc.A)
	if len(held) == 0 {
		t.Fatal("the suite yields no held-out rows to score")
	}
	block := BaselineBlock([]string{"aderyn", "slither"}, held,
		func(tool, root string) ([]validation.Value, error) {
			if root == "" {
				// code.repo "internal://evalsuite" ⇒ the suite checkout.
				root = suiteSrc
			}
			return RealToolRunner(tool, root)
		})
	t.Logf("suite held-out cases: %d\n%s", len(held), block)
	if strings.Contains(block, "baseline slither: SKIPPED") {
		t.Fatalf("real slither did not run over the suite:\n%s", block)
	}
	// The precision denominator IS the flag count: precision =
	// flagged-and-accepted / flagged. The suite must produce at least one
	// real Slither flag, and the recall denominator must be the whole
	// scored universe (the same held-out set, with nothing skipped here).
	_, flaggedN := baselineMetric(t, block, "slither", "precision")
	_, scoredN := baselineMetric(t, block, "slither", "recall")
	if scoredN != len(held) {
		t.Fatalf("slither scored %d cases, want the %d held-out rows",
			scoredN, len(held))
	}
	if flaggedN < 1 {
		t.Fatalf("slither flagged %d suite cases, want >= 1 flag", flaggedN)
	}
}

// baselineMetric parses one "<noun>: k/n" line out of a baseline block,
// stopping at the next baseline header.
func baselineMetric(t *testing.T, block, tool, noun string) (int, int) {
	t.Helper()
	head := "baseline " + tool + ":\n"
	i := strings.Index(block, head)
	if i < 0 {
		t.Fatalf("no %s block in:\n%s", tool, block)
	}
	rest := block[i+len(head):]
	if j := strings.Index(rest, "baseline "); j >= 0 {
		rest = rest[:j]
	}
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, noun+": ") {
			continue
		}
		var k, n int
		if _, err := fmt.Sscanf(line, noun+": %d/%d", &k, &n); err != nil {
			t.Fatalf("unparsable %s line %q: %v", noun, line, err)
		}
		return k, n
	}
	t.Fatalf("no %s line for %s in:\n%s", noun, tool, block)
	return 0, 0
}
