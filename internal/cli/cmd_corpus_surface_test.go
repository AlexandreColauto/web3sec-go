package cli

// cmd_corpus_surface_test: the corpus-surface CLI contract
// (cli.py cmd_corpus_surface + tests/test_corpus_surface_report.py::
// test_cli_writes_and_registers_artifact).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/evalstore"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const vaultSol = "contract V { uint256 public x; }\n"

// corpusFixture pins a one-file tree so build_report has a target surface.
func corpusFixture(t *testing.T) (root, cid string) {
	t.Helper()
	root = t.TempDir()
	cid = initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "V.sol"), []byte(vaultSol), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	return root, cid
}

func TestCorpusSurfaceHelp(t *testing.T) {
	code, out, errS := run(t, "corpus-surface", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%q)", code, errS)
	}
	if out != corpusSurfaceHelp {
		t.Fatalf("help text mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			out, corpusSurfaceHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
}

func TestCorpusSurfaceArgErrors(t *testing.T) {
	code, _, errS := run(t, "corpus-surface")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "the following arguments are required: campaign") {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "corpus-surface", "c", "extra")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "unrecognized arguments: extra") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestCorpusSurfaceNoActiveSnapshot(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "corpus-surface", cid)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	want := "error: campaign " + cid + " has no active snapshot — pin one " +
		"(webv2 snap) before running the corpus sweep\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestCorpusSurfaceWritesAndRegisters(t *testing.T) {
	root, cid := corpusFixture(t)
	code, out, errS := run(t, "--root", root, "corpus-surface", cid)
	if code != 0 {
		t.Fatalf("exit = %d: %q", code, errS)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(c.ArtifactsDir, "corpus_surface.json")
	doc, err := validation.ReadJson(art)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if objStr(doc, "campaign_id") != cid {
		t.Fatalf("campaign_id = %q, want %q", objStr(doc, "campaign_id"), cid)
	}
	if len(listAtCLI(doc, "class_exposure")) == 0 {
		t.Fatal("artifact carries no class exposure")
	}
	if !strings.Contains(strings.ToLower(out), "exposure") {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(out, "class exposure (top 10):\n") {
		t.Fatalf("stdout = %q", out)
	}
	registered := false
	for _, row := range listAtCLI(mustState(t, c), "artifacts") {
		if objStr(row, "kind") == "corpus-surface" {
			registered = true
		}
	}
	if !registered {
		t.Fatal("the sweep artifact was not registered")
	}
}

func mustState(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCorpusSurfaceDeterministicArtifact(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T00:00:00.000000+00:00")
	root, cid := corpusFixture(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(c.ArtifactsDir, "corpus_surface.json")
	if code, _, errS := run(t, "--root", root, "corpus-surface", cid); code != 0 {
		t.Fatalf("first run exit %d: %q", code, errS)
	}
	first, err := os.ReadFile(art)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errS := run(t, "--root", root, "corpus-surface", cid); code != 0 {
		t.Fatalf("second run exit %d: %q", code, errS)
	}
	second, err := os.ReadFile(art)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("a pinned clock must make the artifact byte-identical")
	}
	if !strings.Contains(string(first), "2026-09-09T00:00:00.000000+00:00") {
		t.Fatal("generated_at did not honor WEBV2_NOW")
	}
}

// ---- corpus-surface --backtest (Task 12) ----------------------------------

// seedEvalCase writes one eval row through evalstore.AddCase — the only
// production path into the store — with explicit case_id, partition,
// and severity (Task 7's helper shape, extended for the backtest's
// held-out scorecard and band-carrying pseudo-findings). An empty
// severity omits gold.severity (the schema leaves it optional).
//
// narrative is the row's own root-cause sentence, and it is deliberately
// explicit: I1b's near-dup scan keys on class + root_cause + file
// basenames + repo and compares EVERY held-out row against EVERY
// dev/training row, so a shared boilerplate narrative would make the whole
// store mutually duplicate by construction and empty the held-out leg.
// These fixtures are about prior arithmetic — each row states its own bug.
func seedEvalCase(t *testing.T, caseID, partition, class, outcome,
	severity, recordID, narrative string) {
	t.Helper()
	gold := []validation.KV{
		{K: "outcome", V: validation.VStr(outcome)},
		{K: "bug_class", V: validation.VStr(class)},
		{K: "root_cause", V: validation.VStr(narrative)},
	}
	if severity != "" {
		gold = append(gold,
			validation.KV{K: "severity", V: validation.VStr(severity)})
	}
	doc := validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(caseID)},
		validation.KV{K: "partition", V: validation.VStr(partition)},
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "dataset", V: validation.VStr("manual")},
			validation.KV{K: "record_id", V: validation.VStr(recordID)},
		)},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr("BacktestProgram")},
		)},
		validation.KV{K: "gold", V: validation.VObj(gold...)},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr("internal://test")},
		)},
	)
	if _, err := evalstore.AddCase(doc); err != nil {
		t.Fatalf("seed %s: %v", caseID, err)
	}
}

// seedDevClass writes n dev rows for one class, the first k of them
// accepted. Case ids ride a caller base so two classes never collide. The
// rows share one narrative, which is safe on purpose: dev-dev pairs are
// not scanned (same-partition duplication is the loader's problem), only
// held-out-vs-dev is — so the narrative must differ from every HELD-OUT
// narrative of any class, and does.
func seedDevClass(t *testing.T, class string, accepted, n, base int,
	tag, narrative string) {
	t.Helper()
	for i := 0; i < n; i++ {
		outcome := "disproved"
		if i < accepted {
			outcome = "confirmed-exploitable"
		}
		seedEvalCase(t, fmt.Sprintf("CASE-%012x", base+i), "dev",
			class, outcome, "", fmt.Sprintf("%s-%d", tag, i), narrative)
	}
}

// seedImprovesStore engineers the improves fixture: dev makes the
// reentrancy prior .8 against an oracle-manipulation .2 (global .5, so
// wPrior is +0.2/-0.2), while every held-out row carries band low —
// tied on severity alone, so method A ranks by case_id and its top-2
// holds two oracle-manipulation negatives, and method B's prior lifts
// the two accepted reentrancy rows above them.
func seedImprovesStore(t *testing.T) {
	t.Helper()
	seedDevClass(t, "reentrancy", 8, 10, 0x100, "impr-re",
		"the vault releases funds before the balance is zeroed")
	seedDevClass(t, "oracle-manipulation", 2, 10, 0x200, "impr-or",
		"the borrow limit is priced from instantaneous spot reserves")
	seedEvalCase(t, "CASE-000000000001", "held-out",
		"oracle-manipulation", "disproved", "low", "impr-h1",
		"a signature digest omits the chain id so one claim replays")
	seedEvalCase(t, "CASE-000000000002", "held-out",
		"oracle-manipulation", "out-of-scope", "low", "impr-h2",
		"the queue reverts the whole batch whenever a single target fails")
	seedEvalCase(t, "CASE-000000000003", "held-out",
		"reentrancy", "confirmed-exploitable", "low", "impr-h3",
		"a first depositor donates tokens to inflate the share price")
	seedEvalCase(t, "CASE-000000000004", "held-out",
		"reentrancy", "confirmed-exploitable", "low", "impr-h4",
		"the fee division floors dust amounts away to zero")
}

const backtestHeader = "backtest: priors from dev partition only " +
	"(leave-one-out for held-out cases; no self-confirmation); " +
	"pseudo-findings carry class+band ONLY — this certifies the " +
	"SIGNAL, not a full pipeline.\n"

// backtestBands mirrors backtest.BandLine byte-for-byte: the schema
// honesty label printed on every run.
const backtestBands = "bands: critical is unrepresentable in gold.severity " +
	"(schema) — critical-band rows score 0 here; " +
	"loaders must fold (see G3)\n"

func TestCorpusBacktestImproves(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	seedImprovesStore(t)
	// The campaign positional is required but ignored: C-nope is never
	// opened, so a missing campaign still scores.
	code, out, errS := run(t, "corpus-surface", "C-nope",
		"--backtest", "--top", "2")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%q)", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
	// CI strings are wilson.Format's numbers (computed via go run over
	// the wilson package first: 0/2 -> 0.0-65.8%, 2/2 -> 34.2-100.0%),
	// pinned byte-for-byte here.
	want := backtestHeader +
		backtestBands +
		"eval store: 24 adjudicated, 0 skipped\n" +
		"band coverage: 4/4 rows contributed\n" +
		"method A (severity-only):\n" +
		"top-2 precision: 0/2 (95% CI 0.0–65.8%)\n" +
		"selected accepted: 0\n" +
		"accepted available: 2\n" +
		"method B (with dev priors):\n" +
		"top-2 precision: 2/2 (95% CI 34.2–100.0%)\n" +
		"selected accepted: 2\n" +
		"accepted available: 2\n" +
		"verdict: improves\n"
	if out != want {
		t.Fatalf("stdout mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			out, want)
	}
}

func TestCorpusBacktestFlatIndistinguishable(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	// One class, uniform severity: the class rate IS the global rate,
	// so wPrior computes to exactly zero and method B ranks
	// bit-identically to method A — the same experiment, no verdict.
	seedDevClass(t, "reentrancy", 5, 10, 0x300, "flat-re",
		"the withdraw path is reentrancy-free and checks effects first")
	seedEvalCase(t, "CASE-000000000001", "held-out",
		"reentrancy", "disproved", "medium", "flat-h1",
		"liquidation values collateral with a manipulable spot ratio")
	seedEvalCase(t, "CASE-000000000002", "held-out",
		"reentrancy", "disproved", "medium", "flat-h2",
		"the upgrade initializer is callable by any external account")
	seedEvalCase(t, "CASE-000000000003", "held-out",
		"reentrancy", "confirmed-exploitable", "medium", "flat-h3",
		"a merkle proof is accepted without any depth or length check")
	code, out, errS := run(t, "corpus-surface", "C-nope",
		"--backtest", "--top", "2")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%q)", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
	want := backtestHeader +
		backtestBands +
		"eval store: 13 adjudicated, 0 skipped\n" +
		"band coverage: 3/3 rows contributed\n" +
		"method A (severity-only):\n" +
		"top-2 precision: 0/2 (95% CI 0.0–65.8%)\n" +
		"selected accepted: 0\n" +
		"accepted available: 1\n" +
		"method B (with dev priors):\n" +
		"top-2 precision: 0/2 (95% CI 0.0–65.8%)\n" +
		"selected accepted: 0\n" +
		"accepted available: 1\n" +
		"verdict: indistinguishable\n"
	if out != want {
		t.Fatalf("stdout mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			out, want)
	}
}

func TestCorpusBacktestClamp(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	seedImprovesStore(t)
	code, out, errS := run(t, "corpus-surface", "C-nope",
		"--backtest", "--top", "99")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%q)", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
	// Clamped to the 4 held-out rows, both methods select the same SET
	// (2/4 each) — same experiment at full width, indistinguishable.
	want := backtestHeader +
		backtestBands +
		"eval store: 24 adjudicated, 0 skipped\n" +
		"band coverage: 4/4 rows contributed\n" +
		"note: --top 99 clamped to 4 held-out cases\n" +
		"method A (severity-only):\n" +
		"top-4 precision: 2/4 (95% CI 15.0–85.0%)\n" +
		"selected accepted: 2\n" +
		"accepted available: 2\n" +
		"method B (with dev priors):\n" +
		"top-4 precision: 2/4 (95% CI 15.0–85.0%)\n" +
		"selected accepted: 2\n" +
		"accepted available: 2\n" +
		"verdict: indistinguishable\n"
	if out != want {
		t.Fatalf("stdout mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			out, want)
	}
}

func TestCorpusBacktestEmpty(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	code, _, errS := run(t, "corpus-surface", "C-nope", "--backtest")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	want := "eval store: no adjudicated rows — the backtest certifies " +
		"nothing without ground truth\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestCorpusBacktestTopArgErrors(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	seedImprovesStore(t)
	for _, top := range []string{"0", "-3"} {
		code, _, errS := run(t, "corpus-surface", "C-nope",
			"--backtest", "--top", top)
		if code != 2 {
			t.Fatalf("--top %s: exit = %d, want 2", top, code)
		}
		want := corpusSurfaceUsage + "webv2 corpus-surface: error: " +
			fmt.Sprintf("argument --top: must be >= 1 (got %s)", top) + "\n"
		if errS != want {
			t.Fatalf("--top %s: stderr = %q, want %q", top, errS, want)
		}
	}
	code, _, errS := run(t, "corpus-surface", "C-nope",
		"--backtest", "--top", "many")
	if code != 2 {
		t.Fatalf("--top many: exit = %d, want 2", code)
	}
	want := corpusSurfaceUsage + "webv2 corpus-surface: error: " +
		"argument --top: invalid int value: 'many'\n"
	if errS != want {
		t.Fatalf("--top many: stderr = %q, want %q", errS, want)
	}
	// Campaign stays required under --backtest (argparse shape
	// unchanged); its value is ignored once present.
	code, _, errS = run(t, "corpus-surface", "--backtest")
	if code != 2 {
		t.Fatalf("missing campaign: exit = %d, want 2", code)
	}
	if !strings.Contains(errS,
		"the following arguments are required: campaign") {
		t.Fatalf("missing campaign: stderr = %q", errS)
	}
}

func TestCorpusBacktestTopRequiresBacktest(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	seedImprovesStore(t)
	// --top is a --backtest window: beside the plain sweep it used to be
	// accepted and silently ignored. Now an argparse usage error, exit 2.
	code, _, errS := run(t, "corpus-surface", "C-nope", "--top", "2")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	want := corpusSurfaceUsage + "webv2 corpus-surface: error: " +
		"--top requires --backtest\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestCorpusBacktestDeterministic(t *testing.T) {
	t.Setenv("WEBV2_EVAL_DIR", t.TempDir())
	seedImprovesStore(t)
	_, first, errS := run(t, "corpus-surface", "C-nope",
		"--backtest", "--top", "2")
	if errS != "" {
		t.Fatalf("first stderr = %q", errS)
	}
	_, second, errS := run(t, "corpus-surface", "C-nope",
		"--backtest", "--top", "2")
	if errS != "" {
		t.Fatalf("second stderr = %q", errS)
	}
	if first != second {
		t.Fatalf("two runs differ:\n--- first ---\n%s\n--- second ---\n%s",
			first, second)
	}
}

func TestCorpusBacktestHelpCarriesSignalLine(t *testing.T) {
	code, out, _ := run(t, "corpus-surface", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(strings.ReplaceAll(out, "\n              ", " "),
		"the backtest measures the RANKING "+
			"SIGNALS THE STORE ACTUALLY CARRIES") {
		t.Fatalf("help must carry the signal line:\n%s", out)
	}
}
