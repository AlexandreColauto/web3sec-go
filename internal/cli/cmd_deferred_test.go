package cli

// cmd_deferred_test.go — FIX-5's second half: the reverse sweep. The sweep
// lists the tier-0 closures whose recorded reason vocabulary implies a
// failure consequence and that price none of it, and it REPORTS — the plan
// file and the event log are byte-for-byte untouched.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// dfPlanBytes reads the campaign plan file raw, for the does-not-mutate pin.
func dfPlanBytes(t *testing.T, root, cid string) string {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestDeferredSweepListsKnownBad closes Q-005 through the logged override
// with a reason that carries the tell (the shape a pre-gate closure has),
// then sweeps: the closure is listed with its row and tokens, and the sweep
// leaves the plan and the event log untouched.
func TestDeferredSweepListsKnownBad(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	// the pre-gate shape: the tell sits in the accepted reason, the closure
	// went through the logged override, nothing prices the window
	code, _, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason",
		"the row stays unfinalizable, funds strand in the escrow",
		"--anchor", "asserter", "--override-dismissal", "--override-reason",
		"accepted as designed")
	if code != 0 {
		t.Fatalf("seed closure exit %d: %q", code, errS)
	}
	before := dfPlanBytes(t, root, cid)
	code, out, errS := run(t, "--root", root, "deferred", cid)
	if code != 0 {
		t.Fatalf("sweep exit %d: %q", code, errS)
	}
	for _, want := range []string{
		"deferred: 1 tier-0 closure(s)",
		"Q-005 probe row 81dfad6492 (tier 0, assertion_gap 4)",
		"'unfinalizable'", "'strand'",
		"--finding F-<id>", "--interim STATEMENT",
		"report only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sweep output missing %q:\n%s", want, out)
		}
	}
	// the sweep reports; it does not mutate
	if after := dfPlanBytes(t, root, cid); after != before {
		t.Error("the sweep mutated the plan file")
	}
	evts := dgEventsOfType(t, root, cid, "plan.priority_status")
	if len(evts) != 1 {
		t.Fatalf("the sweep logged %d plan.priority_status events", len(evts))
	}
	// --json emits the same flags as data
	code, out, _ = run(t, "--root", root, "deferred", cid, "--json")
	if code != 0 {
		t.Fatalf("json sweep exit %d", code)
	}
	for _, want := range []string{"\"flags\"", "\"Q-005\"",
		"\"unfinalizable\""} {
		if !strings.Contains(out, want) {
			t.Errorf("json sweep missing %q:\n%s", want, out)
		}
	}
}

// TestDeferredSweepSkipsPricedAndClean: a closure that already carries an
// interim statement is not re-flagged, a clean closure is never flagged, and
// an empty sweep prints its none-line.
func TestDeferredSweepSkipsPricedAndClean(t *testing.T) {
	// (1) the tell priced with an interim statement: not flagged
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	code, _, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason",
		"the row stays unfinalizable in commitBatch until the asserter runs",
		"--anchor", "asserter", "--interim",
		"until finalizeBatch asserts prev:state, commitBatch accepts a "+
			"stale root")
	if code != 0 {
		t.Fatalf("priced closure exit %d: %q", code, errS)
	}
	code, out, _ := run(t, "--root", root, "deferred", cid)
	if code != 0 || !strings.Contains(out,
		"no tier-0 closure defers its check") {
		t.Fatalf("priced closure swept anyway: exit %d out = %q", code, out)
	}

	// (2) the tell priced with a filed finding ref: not flagged either (the
	// interim_finding record is the other exit the sweep asks for)
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	dgSeedProbeCampaign(t, root2, cid2)
	dgSeedFinding(t, root2, cid2, "F-1a2b3c4d5e6f")
	code, _, errS = run(t, "--root", root2, "answered", cid2, "Q-005",
		"answered", "--reason",
		"the row stays unfinalizable in commitBatch until the asserter runs",
		"--anchor", "asserter", "--finding", "F-1a2b3c4d5e6f")
	if code != 0 {
		t.Fatalf("clean closure exit %d: %q", code, errS)
	}
	code, out, _ = run(t, "--root", root2, "deferred", cid2)
	if code != 0 || !strings.Contains(out,
		"no tier-0 closure defers its check") {
		t.Fatalf("clean closure swept anyway: exit %d out = %q", code, out)
	}

	// (3) no plan loaded: the standard guard
	root3 := mkroot(t)
	cid3 := initOne(t, root3)
	code, _, errS = run(t, "--root", root3, "deferred", cid3)
	if code != 2 || !strings.Contains(errS, "no campaign plan loaded") {
		t.Fatalf("no-plan: exit %d stderr = %q", code, errS)
	}
}

func TestDeferredHelp(t *testing.T) {
	code, out, errS := run(t, "deferred", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != deferredHelp {
		t.Fatalf("help = %q, want %q", out, deferredHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestDeferredSweepSkipsReemittedRows pins FIX-3: a tell-bearing closure whose
// probe row no longer resolves against the current surface (the surface was
// re-emitted after the closure was written) is NOT silently dropped from the
// sweep — it is named in a skipped list, and nothing is flagged for it.
func TestDeferredSweepSkipsReemittedRows(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	dgSeedProbeCampaign(t, root, cid)
	// the pre-gate shape: the tell sits in the accepted reason, the closure
	// went through the logged override, nothing prices the window
	code, _, errS := run(t, "--root", root, "answered", cid, "Q-005",
		"answered", "--reason",
		"the row stays unfinalizable, funds strand in the escrow",
		"--anchor", "asserter", "--override-dismissal", "--override-reason",
		"accepted as designed")
	if code != 0 {
		t.Fatalf("seed closure exit %d: %q", code, errS)
	}
	// re-emit: the row is gone from the surface (its id changed)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	surfacePath := filepath.Join(c.ArtifactsDir, "probe_surface.json")
	surface, err := validation.ReadJson(surfacePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range t14List(surface, "rows").A {
		if objStr(r, "row_id") == "81dfad6492" {
			r.O = validation.SetOrAppend(r.O, "row_id",
				validation.VStr("ffffffffffff"))
		}
	}
	if err := validation.WriteJson(surfacePath, surface, ""); err != nil {
		t.Fatal(err)
	}

	code, out, errS := run(t, "--root", root, "deferred", cid)
	if code != 0 {
		t.Fatalf("sweep exit %d: %q", code, errS)
	}
	for _, want := range []string{
		"no tier-0 closure defers its check",
		"skipped 1 closure(s)",
		"Q-005 (probe row 81dfad6492)",
		"not in the current surface",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sweep output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tier 0, assertion_gap 4") {
		t.Errorf("the unrankable closure was flagged anyway:\n%s", out)
	}
}
