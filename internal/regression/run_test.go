package regression

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// evalGoldFixture is a REAL scorer output, captured verbatim from
// scripts/eval-gold.py against a campaign with an empty findings/ dir, an
// empty events.jsonl and a one-gold benchmark:
//
//	$ python3 scripts/eval-gold.py --gold <one-gold file> --campaign <empty campaign>
//	{"found": [], "missed": ["G-99"], "false_positives": 0, "pass": false,
//	 "bonus": false, "verdict": "FAIL", "verdict_note": "", "operator_confirmed": {}}
//
// `found` and `missed` are ARRAYS of gold ids, not integers — the plan's
// hand-written `"found": 3` fixture was a vocabulary the scorer does not have
// (the realism law). TestEvalGoldKeysMatchTheRealScorer runs the real script
// and normalizes its real output, so the adapter cannot drift from it.
const evalGoldFixture = `{
  "found": [],
  "missed": ["G-99"],
  "false_positives": 0,
  "pass": false,
  "bonus": false,
  "verdict": "FAIL",
  "verdict_note": "",
  "operator_confirmed": {}
}
`

// parseFixture is one ordered-JSON fixture value.
func parseFixture(t *testing.T, s string) validation.Value {
	t.Helper()
	raw, err := validation.ParseOrdered([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// writeScoreFile writes one scorer-output fixture into a temp file.
func writeScoreFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// addAcmeTarget records the one target the run tests score against.
func addAcmeTarget(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// assertScoreInt pins one normalized count.
func assertScoreInt(t *testing.T, score validation.Value, key string, want int64) {
	t.Helper()
	if got := validation.ObjAt(score, key); got.Kind != validation.Int || got.I != want {
		t.Fatalf("%s = %v, want %d", key, got, want)
	}
}

func TestNormalizeScoreAcceptsTheRealScorerOutput(t *testing.T) {
	good, err := NormalizeScore("eval-gold", parseFixture(t, evalGoldFixture))
	if err != nil {
		t.Fatal(err)
	}
	// The scorer's arrays of gold ids become counts; the ids stay in the
	// score file, whose sha256 every run records.
	assertScoreInt(t, good, "found", 0)
	assertScoreInt(t, good, "missed", 1)
	assertScoreInt(t, good, "false_positives", 0)
	if got := validation.ObjStr(good, "verdict"); got != "FAIL" {
		t.Fatalf("verdict = %q, want FAIL", got)
	}
}

func TestNormalizeScoreRefusesAnUnknownKeyAndAnUnknownScorer(t *testing.T) {
	raw := parseFixture(t, evalGoldFixture)
	// An unknown key is refused, not ignored: a scorer that grew a key must be
	// re-read by a human, not silently half-ingested.
	raw.O = validation.SetOrAppend(raw.O, "detection_rate", validation.VFloat(0.75))
	if _, err := NormalizeScore("eval-gold", raw); err == nil ||
		!strings.Contains(err.Error(), "detection_rate") {
		t.Fatalf("err = %v, want a refusal naming the unknown key", err)
	}
	if _, err := NormalizeScore("vendor-scorer", raw); err == nil {
		t.Fatal("NormalizeScore accepted an unknown scorer")
	}
}

func TestRecordRunCarriesTheD8Label(t *testing.T) {
	c := regressionCampaign(t, "C-regressrun0001")
	target := addAcmeTarget(t, c)
	run, err := RecordRun(c, RunSpec{
		TargetID:  validation.ObjStr(target, "target_id"),
		Scorer:    "eval-gold",
		ScoreFile: writeScoreFile(t, evalGoldFixture),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(run, "measurement"); got != "rediscovery" {
		t.Fatalf("measurement = %q, want rediscovery (§3a D8)", got)
	}
	if got := validation.ObjAt(run, "is_detection_rate"); got.Kind != validation.Bool || got.B {
		t.Fatalf("is_detection_rate = %v, want false", got)
	}
	if got := validation.ObjStr(run, "score_file_sha256"); len(got) != 64 {
		t.Fatalf("score_file_sha256 = %q, want 64 hex", got)
	}
	assertScoreInt(t, validation.ObjAt(run, "score"), "missed", 1)
}

func TestRecordRunRecordsATranscribedJudgeScore(t *testing.T) {
	c := regressionCampaign(t, "C-regressrun0002")
	target := addAcmeTarget(t, c)
	// The transcribed judge path: no file, but a cited report.
	judge, err := RecordRun(c, RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "scabench-judge",
		Found:    3, Missed: 1, FalsePositives: 2, Verdict: "pass",
		ReportURL: "https://example.test/report/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(judge, "report_url"); got == "" {
		t.Fatal("a transcribed judge score must cite its report")
	}
	assertScoreInt(t, validation.ObjAt(judge, "score"), "found", 3)
	runs, err := LoadRuns(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("%d run record(s), want 1", len(runs))
	}
}

func TestRecordRunRefusesAnUncitedScoreAndAnUnknownTarget(t *testing.T) {
	c := regressionCampaign(t, "C-regressrun0003")
	target := addAcmeTarget(t, c)
	scoreFile := writeScoreFile(t, evalGoldFixture)
	// A transcribed score with no citation is refused.
	if _, err := RecordRun(c, RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "scabench-judge",
		Found:    3, Verdict: "pass",
	}); err == nil {
		t.Fatal("RecordRun accepted a transcribed score with no report_url")
	}
	// A run for a target that does not exist is refused.
	if _, err := RecordRun(c, RunSpec{
		TargetID: "T-000000000000", Scorer: "eval-gold", ScoreFile: scoreFile,
	}); err == nil {
		t.Fatal("RecordRun accepted a run for an unknown target")
	}
	runs, err := LoadRuns(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("%d run record(s) survived two refusals, want 0", len(runs))
	}
}

// evalGoldProbeCampaign builds the smallest campaign-dir contract
// scripts/eval-gold.py accepts (findings/ plus an empty events.jsonl) and a
// one-gold benchmark in the scorer's own gold-file shape (its docstring's
// GOLD_REQUIRED_KEYS + SCORING_REQUIRED_KEYS; the same shape Task 1's operator
// step builds from a ScaBench project). The plan's `[]` benchmark is refused
// by the scorer ("is not a JSON object"), which made this test skip forever.
func evalGoldProbeCampaign(t *testing.T) (string, string) {
	t.Helper()
	camp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(camp, "findings"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(camp, "events.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	gold := filepath.Join(t.TempDir(), "gold.json")
	body := `{"gold_findings": [{"gold_id": "G-99", "title": "probe", ` +
		`"match_criteria": "alpha beta gamma"}], ` +
		`"scoring": {"pass": "G-01 found", "bonus": "G-02 also found", ` +
		`"false_positive_budget": "at most 3 FPs"}}`
	if err := os.WriteFile(gold, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return camp, gold
}

// assertScorerKeysMatch compares the real scorer's stdout key set with
// evalGoldKeys (sorted: the scorer's own emission order is not the contract).
func assertScorerKeysMatch(t *testing.T, raw validation.Value) {
	t.Helper()
	got := make([]string, 0, len(raw.O))
	for _, kvp := range raw.O {
		got = append(got, kvp.K)
	}
	want := append([]string(nil), evalGoldKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scorer keys %v != evalGoldKeys %v — the adapter and the scorer "+
			"have drifted", got, want)
	}
}

// assertScorerNormalizes pins the value shape, not just the key set: the
// adapter must translate the scorer's own arrays of gold ids into counts.
func assertScorerNormalizes(t *testing.T, raw validation.Value, out []byte) {
	t.Helper()
	norm, err := NormalizeScore("eval-gold", raw)
	if err != nil {
		t.Fatalf("NormalizeScore refused the scorer's real output: %v\n%s", err, out)
	}
	for _, k := range []string{"found", "missed"} {
		if got := validation.ObjAt(norm, k); got.Kind != validation.Int {
			t.Fatalf("normalized %s = %v, want the array's count\nscorer: %s",
				k, got, out)
		}
	}
	if got := validation.ObjStr(norm, "verdict"); got != validation.ObjStr(raw, "verdict") {
		t.Fatalf("normalized verdict %q != the scorer's %q", got,
			validation.ObjStr(raw, "verdict"))
	}
}

// TestEvalGoldKeysMatchTheRealScorer runs the real scorer and compares its
// actual stdout keys with evalGoldKeys, then normalizes that same real output
// through the adapter. It is the realism law applied across languages: the Go
// adapter and the Python scorer cannot drift apart — in key set OR in value
// shape — without a red test. Skipped only when python3 is absent (a missing
// operator tool is a skip, never a silent pass).
func TestEvalGoldKeysMatchTheRealScorer(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	camp, gold := evalGoldProbeCampaign(t)
	cmd := exec.Command("python3",
		filepath.Join(repo, "scripts", "eval-gold.py"),
		"--gold", gold, "--campaign", camp)
	cmd.Dir = repo
	out, _ := cmd.Output() // a malformed/empty campaign is a legitimate exit 2
	if len(out) == 0 {
		t.Skip("the scorer printed nothing for an empty campaign — the key-set " +
			"contract is unverifiable here; check scripts/eval_gold_test.py instead")
	}
	raw, err := validation.ParseOrdered(out)
	if err != nil {
		t.Fatalf("scorer stdout is not one JSON object: %v\n%s", err, out)
	}
	assertScorerKeysMatch(t, raw)
	assertScorerNormalizes(t, raw, out)
}
