package cli

// Task 3's CLI half: the repo-level `regress labels` action. The usage block
// and the argparse refusal are byte-pinned (a moved surface must be a
// deliberate diff), and every new flag is asserted to be a VALUE flag of this
// verb — an unknown `--flag` is refused by the parser, so a flag that never
// reached regressValueFlags would look like a typo to the operator.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/regression"
	"websec/internal/validation"
)

// regressLabelsRows is the extractor's output shape: the dataset's four fields
// plus the joined-in project, two high rows and one medium.
const regressLabelsHighRows = `[
 {"finding_id": "S-1", "project": "acme-vault", "severity": "high",
  "title": "Reentrancy in withdraw()",
  "description": "the callback re-enters before the balance is written"},
 {"finding_id": "S-2", "project": "acme-vault", "severity": "high",
  "title": "Deposit works as documented", "description": "nothing unusual"}
]
`

const regressLabelsRows = `[
 {"finding_id": "S-1", "project": "acme-vault", "severity": "high",
  "title": "Reentrancy in withdraw()",
  "description": "the callback re-enters before the balance is written"},
 {"finding_id": "S-2", "project": "acme-vault", "severity": "high",
  "title": "Deposit works as documented", "description": "nothing unusual"},
 {"finding_id": "S-3", "project": "acme-vault", "severity": "medium",
  "title": "Rounding in the share math", "description": "truncation"}
]
`

// regressUsageLiteral freezes regressUsage's bytes. The usage block is a
// byte-pinned operator surface, and building the expectations below from
// regressUsage itself made the pin self-referential: a typo in regressUsage
// failed nothing, because the expectation moved with it. It is a raw literal
// rather than a golden file because the repo's golden convention
// (scripts/golden/ + golden-run.py recipes + scripts/check-golden.py) is a
// whole campaign-replay harness — far more machinery than a four-line usage
// block is worth.
const regressUsageLiteral = `usage: webv2 regress [-h] [--rows ROWS] [--out OUT]
                     [--dataset DATASET] [--snapshot-date SNAPSHOT_DATE]
                     {labels,campaign} ...
`

func TestRegressLabelsUsageAndFlags(t *testing.T) {
	if regressUsage != regressUsageLiteral {
		t.Fatalf("regressUsage drifted from its pinned bytes:\n got %q\nwant %q",
			regressUsage, regressUsageLiteral)
	}
	// The four flags are the verb's own value flags, spelled with the leading
	// dashes the parser keys on.
	for _, flag := range []string{"--rows", "--out", "--dataset", "--snapshot-date"} {
		if !regressValueFlags[flag] {
			t.Errorf("%s is not in regressValueFlags — the parser would refuse it "+
				"as an unrecognized argument", flag)
		}
	}
	code, _, errS := run(t, "--root", t.TempDir(), "regress", "labels")
	want := regressUsageLiteral + "webv2 regress: error: the following arguments " +
		"are required: --rows, --out\n"
	if code != 2 || errS != want {
		t.Fatalf("`regress labels` with no flags: code=%d err=%q, want 2 and %q",
			code, errS, want)
	}
}

// TestRegressLabelsRefusesAMediumRow: the verb's answer to an extraction that
// carries a medium row is a refusal that names it — never a label file that
// counts a medium finding as gold.
func TestRegressLabelsRefusesAMediumRow(t *testing.T) {
	dir, rows, out := regressLabelsFixture(t, regressLabelsRows)
	code, stdout, errS := run(t, "--root", dir, "regress", "labels",
		"--rows", rows, "--out", out)
	if code != 1 {
		t.Fatalf("a medium row in the extraction: exit %d (out=%q err=%q), want 1",
			code, stdout, errS)
	}
	for _, want := range []string{"S-3", "high findings only"} {
		if !strings.Contains(errS, want) {
			t.Errorf("the refusal %q does not name %q", errS, want)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a refused run left a label file behind")
	}
}

// TestRegressLabelsClassifiesAndSidecars is the happy path end to end: the
// rows classify, the counts are the ordered tally, the sidecar is written, and
// the medium row never appears.
func TestRegressLabelsClassifiesAndSidecars(t *testing.T) {
	dir, rows, out := regressLabelsFixture(t, regressLabelsHighRows)
	code, stdout, errS := run(t, "--root", dir, "regress", "labels",
		"--rows", rows, "--out", out, "--dataset", "scabench",
		"--snapshot-date", "2025-08-18")
	if code != 0 {
		t.Fatalf("regress labels exit %d: out=%q err=%q", code, stdout, errS)
	}
	want := "2 row(s) labelled, 1 unmapped -> " + out + "\n"
	if !strings.HasPrefix(stdout, want) {
		t.Fatalf("stdout = %q, want it to start with %q", stdout, want)
	}
	if !strings.Contains(stdout, "unmapped rows are the named source of error") {
		t.Fatalf("the review prompt is missing: %q", stdout)
	}
	assertLabelFile(t, out)
}

// assertLabelFile reads the written label file back through the sidecar and
// asserts its content: the classes, the ordered tally, the provenance and the
// sidecar itself.
func assertLabelFile(t *testing.T, out string) {
	t.Helper()
	labels, err := regression.LoadLabels(out)
	if err != nil {
		t.Fatal(err)
	}
	rows := validation.ObjAt(labels, "rows").A
	if got := validation.ObjStr(rows[0], "class"); got != "reentrancy" {
		t.Fatalf("row 0 class = %q, want reentrancy", got)
	}
	// The unmatched row's class is the literal wire value the schema's counts
	// object and Task 4's picker key on — pinned here, in the package that
	// does not own the constant, so a rename of that constant cannot move the
	// value silently.
	if got := validation.ObjStr(rows[1], "class"); got != "unmapped" {
		t.Fatalf("row 1 class = %q, want the literal \"unmapped\"", got)
	}
	if got := regression.UnmappedCount(labels); got != 1 {
		t.Fatalf("unmapped = %d, want 1", got)
	}
	if got := validation.ObjStr(labels, "dataset"); got != "scabench" {
		t.Fatalf("dataset = %q", got)
	}
	if _, err := os.Stat(out + ".sha256"); err != nil {
		t.Fatalf("no sidecar beside the label file: %v", err)
	}
}

// TestRegressLabelsRefusesWhatIsNotARowArray: --rows must be a JSON array; an
// object would otherwise classify as zero rows and be reported as a success.
func TestRegressLabelsRefusesWhatIsNotARowArray(t *testing.T) {
	dir, rows, out := regressLabelsFixture(t, `{"rows": []}`)
	code, _, errS := run(t, "--root", dir, "regress", "labels",
		"--rows", rows, "--out", out)
	if code != 1 || !strings.Contains(errS, "--rows must be a JSON array of rows") {
		t.Fatalf("code=%d err=%q, want 1 naming the array requirement", code, errS)
	}
}

// TestRegressUnknownActionKeepsTheCampaignPath: the repo-level branch is
// entered by NAME, not by the absence of a `C-` prefix, so a first positional
// that names no repo action keeps the pre-existing campaign path. Before the
// labels action landed, `regress mycamp status` refused the malformed id with
// exit 1 and "malformed campaign id"; routing anything non-`C-` to the repo
// branch changed that to an argparse "invalid choice" (exit 2) for no gain —
// the prefix is not the id grammar, and only the campaign path can decide a
// malformed id. `regress bogus` (one positional) keeps its old missing-argument
// refusal too.
func TestRegressUnknownActionKeepsTheCampaignPath(t *testing.T) {
	code, _, errS := run(t, "--root", t.TempDir(), "regress", "mycamp", "status")
	if want := "error: malformed campaign id: 'mycamp'\n"; code != 1 || errS != want {
		t.Fatalf("`regress mycamp status`: code=%d err=%q, want 1 and %q",
			code, errS, want)
	}
	code, _, errS = run(t, "--root", t.TempDir(), "regress", "bogus")
	want := regressUsageLiteral + "webv2 regress: error: the following arguments " +
		"are required: campaign, action\n"
	if code != 2 || errS != want {
		t.Fatalf("`regress bogus`: code=%d err=%q, want 2 and %q", code, errS, want)
	}
}

// TestRegressLabelsRefusesATrailingPositional: `regress labels extra` must not
// silently drop "extra" — a swallowed positional is how an operator typo
// becomes a run that looks successful.
func TestRegressLabelsRefusesATrailingPositional(t *testing.T) {
	dir, rows, out := regressLabelsFixture(t, regressLabelsHighRows)
	code, _, errS := run(t, "--root", dir, "regress", "labels", "extra",
		"--rows", rows, "--out", out)
	want := t14TopUsage + "webv2: error: unrecognized arguments: extra\n"
	if code != 2 || errS != want {
		t.Fatalf("code=%d err=%q, want 2 and %q", code, errS, want)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a refused run left a label file behind")
	}
}

// regressLabelsFixture writes one --rows file into a temp dir and returns the
// root, the rows path and the --out path, so each test spends its lines on the
// assertion rather than on the plumbing.
func regressLabelsFixture(t *testing.T, body string) (dir, rows, out string) {
	t.Helper()
	dir = t.TempDir()
	rows = filepath.Join(dir, "rows.json")
	if err := os.WriteFile(rows, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, rows, filepath.Join(dir, "labels.json")
}
