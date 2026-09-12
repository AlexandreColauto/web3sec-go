package cli

// cmd_answered_inert_test.go — round-3 chief items 1-2: flags are never
// inert. --finding/--interim/--passes/--anchor are refused on any L-* lens
// route (a lens entry has no probe row), and --reconcile is refused
// everywhere but the L-04 closure that consumes it (a Q-* priority, and a
// non-closing lens status). Every refusal exits 2, prints the runnable
// verbatim shape, and leaves the plan file and the event log untouched.

import (
	"strings"
	"testing"
)

// TestAnsweredLensRefusesProbeRowFlags pins the lens-route refusals: each of
// the four probe-row flags on an L-* closure is refused with the route and
// the drop named, nothing is written, and a ghost --finding id can no longer
// ride a lens closure unheard.
func TestAnsweredLensRefusesProbeRowFlags(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	before := dfPlanBytes(t, root, cid)
	lensEvents := len(dgEventsOfType(t, root, cid, "plan.lens_status"))
	var code int
	var out, errS string

	cases := []struct{ name, flag, val, want string }{
		{"ghost finding", "--finding", "F-000000000000",
			"answered: --finding records the interim window of a Q-* " +
				"probe row on a filed finding — 'L-01' is an L-* lens " +
				"route, so there is no probe row to price: drop --finding\n"},
		{"interim", "--interim", "until finalizeBatch runs",
			"answered: --interim prices a Q-* probe row's interim window " +
				"with a statement — 'L-01' is an L-* lens route, so there " +
				"is no probe row to price: drop --interim\n"},
		{"passes", "--passes", "42",
			"answered: --passes records the passing value of a " +
				"sentinel-guarded Q-* probe row — 'L-01' is an L-* lens " +
				"route, so there is no guard to satisfy: drop --passes\n"},
		{"anchor", "--anchor", "consumer",
			"answered: --anchor dispositions a Q-* probe row by naming " +
				"the field it claims is safe — 'L-01' is an L-* lens " +
				"route, so there is no probe row to disposition: drop " +
				"--anchor\n"},
	}
	for _, tc := range cases {
		code, out, errS = run(t, "--root", root, "answered", cid, "L-01",
			"answered", "--families", "protocol", "--reason",
			"the protocol stays live under every reachable state",
			tc.flag, tc.val)
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2: %q", tc.name, code, errS)
		}
		if out != "" {
			t.Fatalf("%s: stdout = %q", tc.name, out)
		}
		if errS != tc.want {
			t.Fatalf("%s: stderr\n%q\nwant\n%q", tc.name, errS, tc.want)
		}
	}
	// the = spelling is refused identically (the parse layer feeds the
	// same field either way)
	code, _, errS = run(t, "--root", root, "answered", cid, "L-01",
		"answered", "--families", "protocol", "--reason",
		"the protocol stays live under every reachable state",
		"--finding=F-000000000000")
	if code != 2 || !strings.Contains(errS, "drop --finding") {
		t.Fatalf("= spelling: exit %d stderr = %q", code, errS)
	}

	// nothing moved: the plan file and the lens event log are untouched
	if after := dfPlanBytes(t, root, cid); after != before {
		t.Error("the refusals mutated the plan file")
	}
	if n := len(dgEventsOfType(t, root, cid, "plan.lens_status")); n != lensEvents {
		t.Fatalf("the refusals logged %d plan.lens_status events", n-lensEvents)
	}

	// negative control: without the inert flags the same closure succeeds —
	// the refusals are flag-shaped, not lens-shaped
	code, out, errS = run(t, "--root", root, "answered", cid, "L-01",
		"answered", "--families", "protocol", "--reason",
		"the protocol stays live under every reachable state", "--actor", "op")
	if code != 0 {
		t.Fatalf("clean closure exit %d: %q", code, errS)
	}
	if out != "L-01: status -> answered\n" {
		t.Fatalf("clean closure stdout = %q", out)
	}
}

// TestAnsweredReconcileRefusedOffLensRoutes pins --reconcile's route: a Q-*
// single closure, a Q-* batch and a non-closing lens status all refuse the
// flag (exit 2, the L-04 closing route named), and a refusal never wipes a
// reconciliation already on record.
func TestAnsweredReconcileRefusedOffLensRoutes(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	rcSeedDivergenceSurface(t, root, cid, rcDivergenceSurfaceJSON)
	rcRunRecon(t, root, cid)
	// attestation one: L-04 closed with two reconciliation records on file
	code, _, errS := run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason",
		"the divergences are benign duals of the same custody model",
		"--reconcile", rcGoodSpec, "--actor", "operator")
	if code != 0 {
		t.Fatalf("seed attestation exit %d: %q", code, errS)
	}
	var out string

	// (1) a Q-* single closure: refused, the L-04 route named
	code, out, errS = run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason", "the vault is empty on first deposit",
		"--reconcile", rcGoodSpec)
	if code != 2 {
		t.Fatalf("q single: exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("q single: stdout = %q", out)
	}
	want := "answered: --reconcile reconciles the divergence rows of an " +
		"L-04 primitive-symmetry lens closure — 'Q-001' is a Q-* priority, " +
		"so there is nothing to reconcile: drop --reconcile\n"
	if errS != want {
		t.Fatalf("q single: stderr\n%q\nwant\n%q", errS, want)
	}

	// (2) a Q-* batch: refused the same way
	code, _, errS = run(t, "--root", root, "answered", cid, "Q-001", "Q-002",
		"answered", "--reason-all", "the vault is empty on first deposit",
		"--reconcile", rcGoodSpec)
	if code != 2 || !strings.Contains(errS, "drop --reconcile") {
		t.Fatalf("q batch: exit %d stderr = %q", code, errS)
	}

	// (3) a non-closing lens status: refused, and the stored reconciliation
	// survives (a silent drop here would have wiped it outright)
	code, _, errS = run(t, "--root", root, "answered", cid, "L-04", "open",
		"--reconcile", rcGoodSpec, "--actor", "operator")
	if code != 2 {
		t.Fatalf("non-closing lens: exit %d: %q", code, errS)
	}
	want = "answered: --reconcile is consumed only by an L-04 " +
		"primitive-symmetry lens closure — 'L-04' with status 'open' is " +
		"not a closure, so there is nothing to reconcile: drop --reconcile\n"
	if errS != want {
		t.Fatalf("non-closing lens: stderr\n%q\nwant\n%q", errS, want)
	}
	if got := len(objAt(rcStoredLens(t, root, cid, "L-04"),
		"reconciliation").A); got != 2 {
		t.Fatalf("stored reconciliation has %d records, want 2", got)
	}

	// (4) the consuming route still works: the L-04 closure with
	// --reconcile keeps working (negative control in the other direction)
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	rcSeedDivergenceSurface(t, root2, cid2, rcDivergenceSurfaceJSON)
	rcRunRecon(t, root2, cid2)
	code, _, errS = run(t, "--root", root2, "answered", cid2, "L-04",
		"answered", "--families", "protocol", "--reason",
		"the divergences are benign duals of the same custody model",
		"--reconcile", rcGoodSpec, "--actor", "operator")
	if code != 0 {
		t.Fatalf("consuming route exit %d: %q", code, errS)
	}
	if got := len(objAt(rcStoredLens(t, root2, cid2, "L-04"),
		"reconciliation").A); got != 2 {
		t.Fatalf("consuming route recorded %d records, want 2", got)
	}
}
