package cli

// Task 4's CLI half: the repo-level `regress select` action. The usage block
// and the argparse refusal are byte-pinned above (cmd_regress_labels_test.go),
// and every new flag is asserted to be a VALUE flag of this verb — an unknown
// `--flag` is refused by the parser, so a flag that never reached
// regressValueFlags would look like a typo to the operator.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/regression"
	"websec/internal/validation"
)

// regressSelectShapesJSON is the shape map for the six fixture projects (see
// selectLabelsDoc). Keys are project ids, never display names.
const regressSelectShapesJSON = `{
 "acme-vault": "vault-erc4626", "acme-pool": "vault-erc4626",
 "acme-lend": "lending-liquidation", "acme-dao": "lending-liquidation",
 "acme-bridge": "bridge-messaging",
 "acme-oracle": "non-rollup-l2-or-oracle"
}
`

// selectHeldOut is the two held-out projects, both of which the greedy picks
// (Picks=6 over six candidates), so the verb records a real partition.
const selectHeldOut = "acme-vault,acme-bridge"

// selectFixture is one prepared root: the labels file (with its sidecar), the
// shapes file and the --out path.
type selectFixture struct{ root, labels, shapes, out string }

func regressSelectFixture(t *testing.T) selectFixture {
	t.Helper()
	root := t.TempDir()
	labels := filepath.Join(root, "labels.json")
	if err := regression.WriteRepoRecord(labels, selectLabelsDoc(t),
		"regression_labels"); err != nil {
		t.Fatal(err)
	}
	shapes := filepath.Join(root, "shapes.json")
	if err := os.WriteFile(shapes, []byte(regressSelectShapesJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return selectFixture{root: root, labels: labels, shapes: shapes,
		out: filepath.Join(root, "selection.json")}
}

// selectLabelsDoc is the label file the verb consumes: the six rows through
// the real classifier, with the review flag Task 3's operator run set.
func selectLabelsDoc(t *testing.T) validation.Value {
	t.Helper()
	rows := []validation.Value{}
	for _, r := range []struct{ project, title, desc string }{
		{"acme-vault", "Rounding in the share math", "truncation"},
		{"acme-pool", "Reentrancy in withdraw()", "the callback re-enters"},
		{"acme-lend", "Liquidation leaves bad debt", "the position is insolvent"},
		{"acme-dao", "Missing access control", "anyone can call the function"},
		{"acme-bridge", "Cross-chain replay", "the same signature is replayed"},
		{"acme-oracle", "Stale oracle price", "the stale oracle is read"},
	} {
		rows = append(rows, validation.VObj(
			kv("finding_id", validation.VStr(r.project+"-H-01")),
			kv("project", validation.VStr(r.project)),
			kv("severity", validation.VStr("high")),
			kv("title", validation.VStr(r.title)),
			kv("description", validation.VStr(r.desc)),
		))
	}
	labels, err := regression.DeriveLabels(rows, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	labels.O = validation.SetOrAppend(labels.O, "unmapped_reviewed",
		validation.VBool(true))
	return labels
}

func TestRegressSelectUsageAndFlags(t *testing.T) {
	for _, flag := range []string{"--labels", "--shapes", "--held-out",
		"--picks", "--diagnosed", "--control"} {
		if !regressValueFlags[flag] {
			t.Errorf("%s is not in regressValueFlags — the parser would refuse it "+
				"as an unrecognized argument", flag)
		}
	}
	code, _, errS := run(t, "--root", t.TempDir(), "regress", "select")
	want := regressUsageLiteral + "webv2 regress: error: the following " +
		"arguments are required: --labels\n"
	if code != 2 || errS != want {
		t.Fatalf("`regress select` with no flags: code=%d err=%q, want 2 and %q",
			code, errS, want)
	}
}

func TestRegressSelectRefusesAPicksThatIsNotAnInt(t *testing.T) {
	f := regressSelectFixture(t)
	code, _, errS := run(t, "--root", f.root, "regress", "select",
		"--labels", f.labels, "--shapes", f.shapes,
		"--held-out", selectHeldOut, "--picks", "six", "--out", f.out)
	want := regressUsageLiteral + "webv2 regress: error: argument --picks: " +
		"invalid int value: \"six\"\n"
	if code != 2 || errS != want {
		t.Fatalf("--picks six: code=%d err=%q, want 2 and %q", code, errS, want)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("a refused run left a selection file behind")
	}
}

// TestRegressSelectRecordsTheSelection is the happy path end to end: the six
// targets are picked, the coverage line is printed, and the file is readable
// back through its sidecar with the input's known-unfit caveat on it.
func TestRegressSelectRecordsTheSelection(t *testing.T) {
	f := regressSelectFixture(t)
	code, stdout, errS := run(t, "--root", f.root, "regress", "select",
		"--labels", f.labels, "--shapes", f.shapes,
		"--held-out", selectHeldOut, "--diagnosed", "diagnosed-l2",
		"--control", "exploited", "--out", f.out)
	if code != 0 {
		t.Fatalf("regress select exit %d: out=%q err=%q", code, stdout, errS)
	}
	want := "6 target(s) selected -> " + f.out + "\n" +
		"coverage: 6 of 6 gold finding(s), 6 of 6 class(es)\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
	sel, err := regression.ReadRepoRecord(f.out)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(validation.ObjAt(sel, "picks").A); got != 6 {
		t.Fatalf("%d picks in the written file, want 6", got)
	}
	if got := validation.ObjStr(sel, "method"); got !=
		"greedy-set-cover-weighted-by-gold-finding-count" {
		t.Fatalf("method = %q", got)
	}
	for _, key := range []string{"diagnosed_program", "control_program",
		"input_class_fitness"} {
		if validation.ObjStr(sel, key) == "" {
			t.Errorf("the written selection has no %s", key)
		}
	}
}

// TestRegressSelectRefusesAOneProjectHoldOut is the refusal the plan names: a
// one-project --held-out exits 1 and says the rule it broke.
func TestRegressSelectRefusesAOneProjectHoldOut(t *testing.T) {
	f := regressSelectFixture(t)
	code, _, errS := run(t, "--root", f.root, "regress", "select",
		"--labels", f.labels, "--shapes", f.shapes,
		"--held-out", "acme-vault", "--out", f.out)
	if code != 1 || !strings.Contains(errS, "holds out exactly 2") {
		t.Fatalf("a one-project hold-out: code=%d err=%q, want 1 naming the "+
			"hold-out rule", code, errS)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("a refused run left a selection file behind")
	}
}

// TestRegressSelectRefusesShapesThatAreNotAnObject: a JSON array is not a
// {project: shape} map, and folding it into an empty map would turn an
// operator's mistake into a "fewer than the picks" refusal about something
// else entirely.
func TestRegressSelectRefusesShapesThatAreNotAnObject(t *testing.T) {
	f := regressSelectFixture(t)
	if err := os.WriteFile(f.shapes, []byte(`["vault-erc4626"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", f.root, "regress", "select",
		"--labels", f.labels, "--shapes", f.shapes,
		"--held-out", selectHeldOut, "--out", f.out)
	if code != 1 || !strings.Contains(errS, "--shapes must be a JSON object") {
		t.Fatalf("an array --shapes: code=%d err=%q, want 1 naming the object "+
			"requirement", code, errS)
	}
}

// TestRegressSelectRefusesAShapeValueThatIsNotAString: `{"acme-vault": 1}` is
// an object with a non-string value. Folding it in would hand Select a shape
// outside §3a's vocabulary and refuse the run with a message about the four
// shapes — naming something other than the file the operator got wrong.
func TestRegressSelectRefusesAShapeValueThatIsNotAString(t *testing.T) {
	f := regressSelectFixture(t)
	if err := os.WriteFile(f.shapes, []byte(`{"acme-vault": 1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", f.root, "regress", "select",
		"--labels", f.labels, "--shapes", f.shapes,
		"--held-out", selectHeldOut, "--out", f.out)
	want := `--shapes value for "acme-vault" must be a string`
	if code != 1 || !strings.Contains(errS, want) {
		t.Fatalf("a non-string --shapes value: code=%d err=%q, want 1 naming %q",
			code, errS, want)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("a refused run left a selection file behind")
	}
}

// TestRegressSelectRefusesATrailingPositional: `regress select extra` must not
// silently drop "extra", exactly as `regress labels extra` must not.
func TestRegressSelectRefusesATrailingPositional(t *testing.T) {
	f := regressSelectFixture(t)
	code, _, errS := run(t, "--root", f.root, "regress", "select", "extra",
		"--labels", f.labels, "--shapes", f.shapes,
		"--held-out", selectHeldOut, "--out", f.out)
	want := t14TopUsage + "webv2: error: unrecognized arguments: extra\n"
	if code != 2 || errS != want {
		t.Fatalf("code=%d err=%q, want 2 and %q", code, errS, want)
	}
}
