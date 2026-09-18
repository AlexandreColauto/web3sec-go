// T26 cmd_yields tests: the per-trajectory yield table and the TOTAL line.
// Vectors captured from the live Python CLI (parity.py [untracked], step
// `yields`, byte-exact).
package cli

import (
	"strings"
	"testing"
)

func TestYieldsTable(t *testing.T) {
	pinCostIDs(t)
	root := mkroot(t)
	cid := initOne(t, root)
	for _, a := range [][]string{
		{"--kind", "model", "--amount", "30", "--trajectory", "economic"},
		{"--kind", "compute", "--amount", "10.5", "--trajectory", "economic"},
		{"--kind", "model", "--amount", "200", "--trajectory", "static"},
		{"--kind", "model", "--amount", "5"},
	} {
		if code, _, errS := run(t, append([]string{"--root", root, "cost",
			cid}, a...)...); code != 0 {
			t.Fatalf("cost %v exit %d: %q", a, code, errS)
		}
	}
	code, out, errS := run(t, "--root", root, "yields", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "" +
		"economic             cost=$    40.50 confirmed=0 value=$        0.00  yield=0.0x\n" +
		"static               cost=$   200.00 confirmed=0 value=$        0.00  yield=0.0x\n" +
		"unattributed         cost=$     5.00 confirmed=0 value=$        0.00  yield=0.0x\n" +
		"TOTAL                cost=$   245.50 confirmed=0 value=$        0.00  yield=0.0x\n" +
		"  advice #1: economic — no confirmed value yet — spend is a bet, watch the next pass\n" +
		"  advice #2: static — no confirmed value yet — spend is a bet, watch the next pass\n" +
		"  advice #3: unattributed — no confirmed value yet — spend is a bet, watch the next pass\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestYieldsEmptyCampaign(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "yields", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	// No rows: trajectories is empty, the zero totals still print, and
	// yield is null -> "n/a" (allocation_advice has nothing to advise).
	want := "TOTAL                cost=$     0.00 confirmed=0 value=$" +
		"        0.00  yield=n/a\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
}

func TestYieldsArgparse(t *testing.T) {
	code, out, errS := run(t, "yields")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := t26YieldsUsage + "webv2 yields: error: the following arguments " +
		"are required: campaign\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	code, out, errS = run(t, "yields", "C-abc", "--json")
	if code != 2 || out != "" {
		t.Fatalf("--json: exit %d out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(errS, "unrecognized arguments: --json") {
		t.Fatalf("--json stderr = %q", errS)
	}
}
