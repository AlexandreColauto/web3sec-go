// T26 cmd_cost tests: the record line, the argparse surface, and the
// costs.jsonl row. Vectors captured from the live Python CLI via
// parity.py [untracked] (cost_* steps, 121/121 byte-exact).
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/costs"
)

func pinCostIDs(t *testing.T, ids ...string) {
	t.Helper()
	i := 0
	costs.SetCostIDSource(func() string {
		id := "COST-pinned0001"
		if i < len(ids) {
			id = ids[i]
		}
		i++
		return id
	})
	t.Cleanup(func() { costs.SetCostIDSource(nil) })
}

func TestCostRecordLine(t *testing.T) {
	pinCostIDs(t)
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "cost", cid, "--kind", "model",
		"--amount", "30", "--trajectory", "economic", "--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "recorded COST-pinned0001 model $30.00 trajectory=economic\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	// No --trajectory: the suffix is omitted entirely.
	code, out, _ = run(t, "--root", root, "cost", cid, "--kind", "compute",
		"--amount", "10.5")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out != "recorded COST-pinned0001 compute $10.50\n" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestCostRowLandsInCostsJsonl(t *testing.T) {
	pinCostIDs(t, "COST-abcdef012345")
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "cost", cid, "--kind",
		"human-review", "--amount", "40", "--trajectory", "economic",
		"--actor", "reviewer", "--note", "triage", "--stage", "recon")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	body, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"costs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	line := string(body)
	for _, want := range []string{
		`"cost_id": "COST-abcdef012345"`,
		`"kind": "human-review"`,
		`"amount_usd": 40.0`,
		`"trajectory": "economic"`,
		`"stage": "recon"`,
		`"actor": "reviewer"`,
		`"note": "triage"`,
		`"finding_id": null`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("costs.jsonl = %s\nmissing %s", line, want)
		}
	}
	if !strings.HasSuffix(line, "\n") {
		t.Errorf("costs.jsonl missing trailing newline: %q", line)
	}
}

func TestCostArgparse(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	cases := []struct {
		name, want string
		args       []string
	}{
		{"missing-kind", "webv2 cost: error: the following arguments are " +
			"required: --kind\n",
			[]string{"cost", cid, "--amount", "5"}},
		{"bad-kind", "webv2 cost: error: argument --kind: invalid choice: " +
			"'nope' (choose from 'model', 'compute', 'human-review')\n",
			[]string{"cost", cid, "--kind", "nope", "--amount", "5"}},
		{"bad-float", "webv2 cost: error: argument --amount: invalid float " +
			"value: 'abc'\n",
			[]string{"cost", cid, "--kind", "model", "--amount", "abc"}},
	}
	for _, tc := range cases {
		code, out, errS := run(t, append([]string{"--root", root},
			tc.args...)...)
		if code != 2 || out != "" {
			t.Fatalf("%s: exit %d out=%q err=%q", tc.name, code, out, errS)
		}
		if !strings.HasSuffix(errS, tc.want) {
			t.Errorf("%s: stderr = %q, want suffix %q", tc.name, errS,
				tc.want)
		}
		if !strings.HasPrefix(errS, t26CostUsage) {
			t.Errorf("%s: stderr does not start with the usage block: %q",
				tc.name, errS)
		}
	}
}

func TestCostNegativeAmountIsAValue(t *testing.T) {
	// argparse: no option looks like a negative number, so -5 is --amount's
	// value; record_cost then rejects it (>= 0), and main renders the
	// ValueError as "error: ..." with exit 1.
	pinCostIDs(t)
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "cost", cid, "--kind", "model",
		"--amount", "-5")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := "error: amount_usd must be a number >= 0, got -5.0\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	// 0 is a legal amount (only the price table requires > 0).
	code, out, errS = run(t, "--root", root, "cost", cid, "--kind", "model",
		"--amount", "0")
	if code != 0 || out != "recorded COST-pinned0001 model $0.00\n" {
		t.Fatalf("zero: exit %d out=%q err=%q", code, out, errS)
	}
}

// TestCostLensPassthrough is the G13 writer path: --lens lands on the row
// (and the record line); omitting it leaves the key absent (never null);
// a non-L-NN id is an argparse error, not a silent "unattributed".
func TestCostLensPassthrough(t *testing.T) {
	pinCostIDs(t, "COST-lens000001", "COST-lens000002")
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "cost", cid, "--kind",
		"model", "--amount", "12.5", "--actor", "golden", "--lens", "L-01")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "recorded COST-lens000001 model $12.50 lens=L-01\n" {
		t.Fatalf("stdout = %q", out)
	}
	code, out, errS = run(t, "--root", root, "cost", cid, "--kind",
		"compute", "--amount", "3")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "recorded COST-lens000002 compute $3.00\n" {
		t.Fatalf("stdout = %q", out)
	}
	body, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"costs.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("rows = %d, want 2", len(lines))
	}
	if !strings.Contains(lines[0], `"lens": "L-01"`) {
		t.Errorf("row[0] missing lens: %s", lines[0])
	}
	if strings.Contains(lines[1], `"lens"`) {
		t.Errorf("lens-less row carries a lens key: %s", lines[1])
	}
	code, _, errS = run(t, "--root", root, "cost", cid, "--kind", "model",
		"--amount", "1", "--lens", "liveness")
	if code != 2 {
		t.Fatalf("bad lens: exit %d, want 2", code)
	}
	if !strings.Contains(errS, "argument --lens: invalid lens id") {
		t.Errorf("bad lens stderr = %q", errS)
	}
}
