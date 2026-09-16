package cli

// C-12f17fd555 §8c: the disposition and grading contracts must be discoverable
// from the CLI itself. `answered --help` printed the UNION anchor enum (A6)
// but never which probe produced which anchor, so dispositioning cost one
// failure per row type; `plan` ended without naming the read-only join that
// grades the campaign. Both contracts are pinned here: anchorHelp() renders
// the per-probe table from the same registry the gate reads
// (probes.AnchorAllowed), so help and enforcement cannot drift.

import (
	"strings"
	"testing"
)

// wantAnchorHelp is the pinned rendering of anchorHelp(): one line per
// registered probe, probes and anchors in sorted order.
const wantAnchorHelp = `  per-probe anchors (the anchor must be one the probe produced):
    accumulator-basis-skew: --anchor accumulator|companion|plain|rounded
    assertion-strength: --anchor asserter|concept|consumer
    custody-primitive: --anchor base|consumer|custody|sibling
    sequential-cursor: --anchor cursor|guard|stranded_entry
    short-circuitable-guard: --anchor guard|safety|sentinel
    trust-assumption: --anchor actor|invariant
`

func TestAnchorHelpPinsEveryProbe(t *testing.T) {
	if got := anchorHelp(); got != wantAnchorHelp {
		t.Fatalf("anchorHelp() = %q, want %q", got, wantAnchorHelp)
	}
	code, out, errS := run(t, "answered", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	if !strings.Contains(out, wantAnchorHelp) {
		t.Fatalf("answered --help is missing the per-probe anchor table: %q", out)
	}
	// The row-type ref conventions ride the same block: the shapes the
	// refusal messages imply but the help never named.
	for _, want := range []string{
		"assertion-strength",
		"<consumer contract>#L<line>",
		"<actor name>",
		"<primitive verb>",
		"the guard expression as printed on the row",
		"--passes takes a literal, not prose",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("answered --help is missing %q", want)
		}
	}
}

// The plan summary must name the grading path: the eval join is read-only, so
// the operator can dry-run it while every finding is still editable
// (C-12f17fd555 §8c).
func TestPlanNamesTheGradingPath(t *testing.T) {
	root, cid := t14SeededPlanCampaign(t)
	out := runPlanCapture(t, root, cid)
	want := "grading: webv2 scorecard <campaign> --gold <pack.json>"
	if !strings.Contains(out, want) {
		t.Fatalf("plan output is missing %q: %q", want, out)
	}
	if !strings.Contains(out, "read-only") {
		t.Fatalf("the grading pointer must say the join is read-only: %q", out)
	}
}
