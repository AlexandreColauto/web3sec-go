package cli

// Port of tests/test_cli.py::test_run_halts_honestly_at_the_first_model_stage.
// The run verb walks the deterministic stages, then halts at the first stage
// that needs a model: exit 3, the summary JSON (needs_model stripped), and
// the HALTED block naming the prompt, the budget class and the context
// blocks. The bytes below were captured from the live Python reference
// (py-run.out [untracked]) and pinned here; only the prompt path is
// derived, because it embeds the twin's repo root (KNOWN_DIVERGENCES D4).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/adapter"
	"websec/internal/state"
	"websec/internal/validation"
)

const runFixtureSource = "contract Vault { uint public total; " +
	"function deposit() public payable { total += msg.value; } }"

// runFixture makes the workspace fixture and returns (root, campaign id).
func runFixture(t *testing.T) (string, string) {
	t.Helper()
	root := mkroot(t)
	cid := initOne(t, root)
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte(runFixtureSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errS := run(t, "--root", root, "snap", cid, target); code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	return root, cid
}

func TestRunHaltsHonestlyAtTheFirstModelStage(t *testing.T) {
	root, cid := runFixture(t)
	code, out, errS := run(t, "--root", root, "run", cid)
	if code != 3 {
		t.Fatalf("run exit %d, want 3 (halted at a model stage, not an "+
			"error)\nout=%q\nerr=%q", code, out, errS)
	}
	if !strings.Contains(out, "HALTED at model stage:") {
		t.Errorf("missing HALTED line: %q", out)
	}
	if !strings.Contains(out, "prompt:") || !strings.Contains(out, "budget:") {
		t.Errorf("missing prompt/budget lines: %q", out)
	}
	if errS != "" {
		t.Errorf("stderr = %q", errS)
	}
}

func TestRunSummaryAndHaltedBlockBytes(t *testing.T) {
	root, cid := runFixture(t)
	code, out, errS := run(t, "--root", root, "run", cid)
	if code != 3 {
		t.Fatalf("run exit %d: %q", code, errS)
	}
	prompt, err := adapter.PromptPath("protocol-model")
	if err != nil {
		t.Fatal(err)
	}
	// The summary JSON has needs_model stripped (Python: {k: v for k, v in
	// summary.items() if k != "needs_model"}) and is indent=2.
	want := `{
  "ran": [
    "scope",
    "snapshot",
    "structural-index"
  ],
  "skipped_completed": [],
  "halt": "blocked on model stages: ['protocol-model']",
  "blocked_stages": [
    "protocol-model"
  ],
  "auto_completed": [],
  "status": "needs-model"
}

HALTED at model stage: protocol-model
  prompt:  ` + prompt + `
  budget:  standard
  context: campaign, snapshot, structural_index_stats
  feed results back through the ingest APIs, then run again.
`
	if out != want {
		t.Errorf("run stdout mismatch\n got: %q\nwant: %q", out, want)
	}
}

// D2: with the report seam installed, `run` reaches the report stage instead
// of failing the LAST deterministic stage with "report module not wired". The
// stages report depends on are seeded done so the run has exactly one
// deterministic stage left; it then halts at `learning` (model), as before.
func TestRunReachesTheReportStage(t *testing.T) {
	root, cid := runFixture(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"scope", "snapshot", "structural-index",
		"protocol-model", "campaign-planning", "discovery", "dedup",
		"hostile-review", "reproduction", "chaining", "maximal-exploitation",
		"independent-verification", "risk-calibration", "mainnet-fork-poc",
		"bounty-gate"} {
		done := "code"
		if err := c.SetStage(sid, "done", validation.VStr("seeded"), &done); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errS := run(t, "--root", root, "run", cid)
	if code != 3 {
		t.Fatalf("run exit %d, want 3 (halts at the model stage after "+
			"report)\nout=%q\nerr=%q", code, out, errS)
	}
	if strings.Contains(out, "not wired") || strings.Contains(errS, "not wired") {
		t.Fatalf("report stage is not wired: out=%q err=%q", out, errS)
	}
	if !strings.Contains(out, "\"report\"") {
		t.Errorf("report stage did not run: %q", out)
	}
	if !strings.Contains(out, "blocked on model stages: ['learning']") {
		t.Errorf("halt text = %q, want the post-report model stage", out)
	}
	if !fileExists(filepath.Join(c.Dir, "report.md")) {
		t.Errorf("the report artifact was not written")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestRunUnknownCampaignIsACleanError(t *testing.T) {
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "run", "C-"+strings.Repeat("0", 10))
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if out != "" {
		t.Errorf("stdout = %q", out)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Errorf("stderr = %q", errS)
	}
}

func TestRunMaxStagesValidatesInt(t *testing.T) {
	root, cid := runFixture(t)
	code, _, errS := run(t, "--root", root, "run", cid, "--max-stages", "abc")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "invalid int value") {
		t.Errorf("stderr = %q", errS)
	}
}

// TestPyIntMatchesArgparseInt pins the parse half of the divergence the live
// twin exposed: Python's int is unbounded and accepts underscore literals,
// so the Go verb must accept the same text and carry the exact decimal text
// for the halt echo when the value does not fit int64.
func TestPyIntMatchesArgparseInt(t *testing.T) {
	cases := []struct {
		val    string
		want   int64
		digits string
		bad    bool
	}{
		{val: "3", want: 3},
		{val: " 3 ", want: 3},
		{val: "+3", want: 3},
		{val: "-3", want: -3},
		{val: "1_000", want: 1000},
		{val: "0", want: 0},
		{val: "9223372036854775807", want: 9223372036854775807},
		{val: "9223372036854775808", want: 9223372036854775807,
			digits: "9223372036854775808"},
		{val: "-9223372036854775808", want: -9223372036854775808},
		{val: "-9223372036854775809", want: -9223372036854775808,
			digits: "-9223372036854775809"},
		{val: "1" + strings.Repeat("0", 30), want: 9223372036854775807,
			digits: "1" + strings.Repeat("0", 30)},
		{val: "-1" + strings.Repeat("0", 30), want: -9223372036854775808,
			digits: "-1" + strings.Repeat("0", 30)},
		{val: "0009", want: 9},
		{val: "abc", bad: true},
		{val: "", bad: true},
		{val: "_1", bad: true},
		{val: "1_", bad: true},
		{val: "1__0", bad: true},
		{val: "1.0", bad: true},
		{val: "0x10", bad: true},
		{val: "+", bad: true},
	}
	for _, c := range cases {
		got, digits, err := parsePyInt(c.val, "--max-stages")
		if c.bad {
			if err == nil {
				t.Errorf("parsePyInt(%q) = %d, want error", c.val, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePyInt(%q): %v", c.val, err)
			continue
		}
		if got != c.want || digits != c.digits {
			t.Errorf("parsePyInt(%q) = (%d, %q), want (%d, %q)",
				c.val, got, digits, c.want, c.digits)
		}
	}
}

// TestRunMaxStagesBeyondInt64EchoesPythonsDigits: the halt message Python
// prints is f"max_stages={max_stages}" with the unbounded value, so a budget
// below int64 min must still print its own digits (the pipeline only ever
// sees the clamped stand-in).
func TestRunMaxStagesBeyondInt64EchoesPythonsDigits(t *testing.T) {
	root, cid := runFixture(t)
	huge := "-999999999999999999999"
	code, out, errS := run(t, "--root", root, "run", cid,
		"--max-stages", huge)
	if code != 2 {
		t.Fatalf("exit %d, want 2\nout=%q\nerr=%q", code, out, errS)
	}
	if !strings.Contains(out, `"halt": "max_stages=`+huge+`"`) {
		t.Errorf("halt does not carry Python's digits: %q", out)
	}
	if !strings.Contains(out, `"status": "halted"`) {
		t.Errorf("status not halted: %q", out)
	}
}

// TestRunMaxStagesBeyondInt64PositiveNeverConsumed: a budget above int64 max
// can never be consumed, so the run proceeds to the model stage exactly as
// Python's does (exit 3), with no clamped number anywhere in the output.
func TestRunMaxStagesBeyondInt64PositiveNeverConsumed(t *testing.T) {
	root, cid := runFixture(t)
	code, out, errS := run(t, "--root", root, "run", cid,
		"--max-stages", "999999999999999999999")
	if code != 3 {
		t.Fatalf("exit %d, want 3\nout=%q\nerr=%q", code, out, errS)
	}
	if strings.Contains(out, "max_stages=") {
		t.Errorf("clamped budget leaked into the output: %q", out)
	}
	if !strings.Contains(out, `"status": "needs-model"`) {
		t.Errorf("status = %q", out)
	}
}
