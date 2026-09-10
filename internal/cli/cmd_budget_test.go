package cli

// T14 cmd_budget tests: the ceiling/discovery report, --set/--clear, the
// argparse float/int errors, and the money formatter. Vectors captured from
// the live Python CLI (.scratch/t14/py5.json twin run).

import (
	"strings"
	"testing"
)

const t14BudgetDiscoveryLine = "discovery: 0/400 findings recorded " +
	"(ceiling: webv2 budget <campaign> --set-discovery N)\n"

func TestBudgetNoCeiling(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "budget", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "cost: $0.00 spent — NO CEILING SET (unbounded; set one with " +
		"`webv2 budget <c> --set USD --actor <name>`)\n" +
		t14BudgetDiscoveryLine
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestBudgetSetCeiling(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "budget", cid, "--set", "1000",
		"--actor", "lead")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "cost: $0.00 spent vs $1,000.00 limit — within limit " +
		"($1,000.00 remaining)\n" + t14BudgetDiscoveryLine
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	// --set 0 is a real (zero) ceiling, not "unbounded"
	code, out, _ = run(t, "--root", root, "budget", cid, "--set", "0",
		"--actor", "lead")
	if code != 0 {
		t.Fatalf("zero exit %d", code)
	}
	if !strings.Contains(out, "vs $0.00 limit — within limit "+
		"($0.00 remaining)") {
		t.Fatalf("zero ceiling = %q", out)
	}
}

func TestBudgetJSONSpentIsIntZero(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	if code, _, errS := run(t, "--root", root, "budget", cid, "--set",
		"1000", "--actor", "lead"); code != 0 {
		t.Fatalf("set exit %d: %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "budget", cid, "--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	// Python's sum() over no cost rows is the INT 0 — the JSON says 0
	want := "{\n  \"limit_usd\": 1000.0,\n  \"spent_usd\": 0,\n  " +
		"\"status\": \"within\",\n  \"remaining_usd\": 1000.0,\n  " +
		"\"over_by_usd\": 0.0\n}\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestBudgetSetDiscovery(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "budget", cid,
		"--set-discovery", "7", "--actor", "lead")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "discovery: max_discovery_findings -> 7 (0 recorded so far; "+
		"actor: lead)\n" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	// the report now shows the new discovery ceiling
	code, out, _ = run(t, "--root", root, "budget", cid)
	if code != 0 {
		t.Fatalf("report exit %d", code)
	}
	if !strings.Contains(out, "discovery: 0/7 findings recorded") {
		t.Fatalf("report = %q", out)
	}
}

func TestBudgetErrors(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "budget", cid, "--set", "-5",
		"--actor", "lead")
	if code != 1 {
		t.Fatalf("negative exit %d: %q", code, errS)
	}
	if errS != "error: campaign_state validation failed at "+
		"budget/max_total_cost_usd: -5.0 is less than the minimum of 0 "+
		"(+0 more errors)\n" {
		t.Fatalf("negative stderr = %q", errS)
	}
	code, _, errS = run(t, "--root", root, "budget", cid, "--set-discovery",
		"0", "--actor", "lead")
	if code != 2 {
		t.Fatalf("zero discovery exit %d: %q", code, errS)
	}
	if errS != "budget failed: max_discovery_findings must be a positive "+
		"integer\n" {
		t.Fatalf("zero discovery stderr = %q", errS)
	}
	code, _, errS = run(t, "--root", root, "budget", cid, "--set", "100",
		"--set-discovery", "5")
	if code != 2 {
		t.Fatalf("combined exit %d: %q", code, errS)
	}
	if errS != "budget: --set-discovery cannot be combined with "+
		"--set/--clear\n" {
		t.Fatalf("combined stderr = %q", errS)
	}
}

func TestBudgetArgparseErrors(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "budget", cid, "--set", "abc")
	if code != 2 {
		t.Fatalf("float exit %d: %q", code, errS)
	}
	if errS != t14BudgetUsage+"webv2 budget: error: argument --set: "+
		"invalid float value: 'abc'\n" {
		t.Fatalf("float stderr = %q", errS)
	}
	code, _, errS = run(t, "--root", root, "budget", cid, "--set-discovery",
		"abc")
	if code != 2 {
		t.Fatalf("int exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(errS, "webv2 budget: error: argument "+
		"--set-discovery: invalid int value: 'abc'\n") {
		t.Fatalf("int stderr = %q", errS)
	}
	code, _, errS = run(t, "--root", root, "budget")
	if code != 2 {
		t.Fatalf("required exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(errS, "webv2 budget: error: the following "+
		"arguments are required: campaign\n") {
		t.Fatalf("required stderr = %q", errS)
	}
}

func TestBudgetMoneyFormat(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0.00"},
		{1000, "1,000.00"},
		{1234567.891, "1,234,567.89"},
		{-1234.5, "-1,234.50"},
		{0.005, "0.01"},
	}
	for _, c := range cases {
		if got := t14Money(c.in); got != c.want {
			t.Errorf("t14Money(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := t14Money(999.999); got != "1,000.00" {
		t.Fatalf("t14Money rounding = %q", got)
	}
}

func TestBudgetHelp(t *testing.T) {
	code, out, errS := run(t, "budget", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14BudgetHelp {
		t.Fatalf("help = %q, want %q", out, t14BudgetHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestBudgetRejectsClearWithSet pins the mutual exclusion: --clear + --set
// used to be accepted with --clear silently dropped (the set branch won), so
// the operator believed a ceiling had been cleared when it had been raised.
func TestBudgetRejectsClearWithSet(t *testing.T) {
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "budget", "--clear",
		"--set", "5", "C-1")
	if code != 2 {
		t.Fatalf("exit %d, want 2: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "argument --clear: not allowed with "+
		"argument --set") {
		t.Errorf("stderr = %q, want the mutual-exclusion message", errS)
	}
}

// TestBudgetRefusesOptionLookalikeValue: the --set family is hand-parsed too,
// so it carries the same guard as the case-based parsers.
func TestBudgetRefusesOptionLookalikeValue(t *testing.T) {
	root := mkroot(t)
	code, _, errS := run(t, "--root", root, "budget", "C-1", "--set", "--json")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "argument --set: expected one argument") {
		t.Errorf("stderr = %q, want the argparse message", errS)
	}
}
