package cli

// cmd_answered_reconcile_test.go — FIX-6 CLI: the --reconcile flag on the
// L-04 attestation. The operator's G-02 miss: a lens closure that reconciled
// funding-mismatch divergences with prose and never a single file#L cite.
// Every refusal path (uncited row, ghost finding, symbol not on the row) is
// a negative control that must leave the plan and the event log untouched;
// the positive path records the reconciliation; a re-run of the same command
// is idempotent.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// rcDivergenceSurfaceJSON is a probe surface carrying two divergence rows
// (the G-02 shape: the forward path burns, the drop path transfers out; and
// two siblings disagreeing on the deposit column).
const rcDivergenceSurfaceJSON = `{"rows":[` +
	`{"row_id":"divrow1","probe":"custody-primitive","contract":"L2Gateway",` +
	`"consumer":"drop","base":"L1Gateway","forward":["deposit"],` +
	`"divergence":"funding-mismatch","family":"L1Gateway","direction":"drop",` +
	`"asset":"erc20","expected":"burn","observed":"transfer-out",` +
	`"members":["L1Gateway.deposit","L2Gateway.drop"]},` +
	`{"row_id":"divrow2","probe":"custody-primitive",` +
	`"contract":"L1ReverseCustomGateway","consumer":"_depositByTransfer",` +
	`"base":"L1Gateway","forward":["deposit"],` +
	`"divergence":"member-disagreement","family":"L1Gateway",` +
	`"direction":"deposit","asset":"erc20","expected":"transfer-in",` +
	`"observed":"transfer-out",` +
	`"members":["L1Gateway._deposit",` +
	`"L1ReverseCustomGateway._depositByTransfer"]}]}`

// rcGoodSpec reconciles both divergence rows per member.
const rcGoodSpec = "divrow1=transfer-out:L2Gateway.drop#L77|" +
	"burn:L1Gateway.deposit#L42;divrow2=transfer-in:L1Gateway._deposit#L12|" +
	"transfer-out:L1ReverseCustomGateway._depositByTransfer#L33"

// rcSeedDivergenceSurface writes the divergence surface into the campaign's
// artifacts so the attestation gate sees real rows.
func rcSeedDivergenceSurface(t *testing.T, root, cid, surfaceJSON string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	surface := jsonValueAt(t, surfaceJSON)
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"), surface, ""); err != nil {
		t.Fatal(err)
	}
}

// jsonValueAt parses a fixture JSON text.
func jsonValueAt(t *testing.T, s string) validation.Value {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := validation.ReadJson(p)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return v
}

// rcStoredLens reads one lens entry back off the campaign's saved plan.
func rcStoredLens(t *testing.T, root, cid, lid string) validation.Value {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range t14List(plan, "lenses").A {
		if objStr(l, "id") == lid {
			return l
		}
	}
	t.Fatalf("lens %s not in the stored plan", lid)
	return validation.VNull()
}

func TestAnsweredLensReconcile(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	rcSeedDivergenceSurface(t, root, cid, rcDivergenceSurfaceJSON)

	// (1) refusal: the attestation reconciles neither divergence row
	code, out, errS := run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason",
		"the divergences are benign duals of the same custody model")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	for _, want := range []string{"divrow1", "divrow2", "funding-mismatch",
		"member-disagreement", "no reconciliation on record",
		"--reconcile 'RID=primitive:Symbol#L<line>|...'",
		"--reconcile 'RID=F-<12 hex digits>'"} {
		if !strings.Contains(errS, want) {
			t.Errorf("stderr missing %q:\n%s", want, errS)
		}
	}
	l := rcStoredLens(t, root, cid, "L-04")
	if got := objStr(l, "status"); got != "open" {
		t.Fatalf("refused attestation changed the status to %q", got)
	}
	if objAt(l, "reconciliation").Kind != validation.Null {
		t.Fatalf("refused attestation recorded a reconciliation")
	}
	if evts := dgEventsOfType(t, root, cid, "plan.lens_status"); len(evts) != 0 {
		t.Fatalf("refused attestation logged %d plan.lens_status events",
			len(evts))
	}

	// (2) accept: the same closure with the per-member cites
	code, _, errS = run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason",
		"the divergences are benign duals of the same custody model",
		"--reconcile", rcGoodSpec, "--actor", "operator")
	if code != 0 {
		t.Fatalf("accept exit %d: %q", code, errS)
	}
	l = rcStoredLens(t, root, cid, "L-04")
	if got := objStr(l, "status"); got != "answered" {
		t.Fatalf("status = %q", got)
	}
	recs := objAt(l, "reconciliation").A
	if len(recs) != 2 {
		t.Fatalf("reconciliation records = %d, want 2", len(recs))
	}
	if got := objStr(recs[0], "row_id"); got != "divrow1" {
		t.Fatalf("first record row_id = %q", got)
	}
	if got := len(objAt(recs[0], "cites").A); got != 2 {
		t.Fatalf("divrow1 cites = %d, want 2", got)
	}

	// (3) idempotent: the same command again still passes and does not
	// double-fire the records
	code, _, errS = run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason",
		"the divergences are benign duals of the same custody model",
		"--reconcile", rcGoodSpec, "--actor", "operator")
	if code != 0 {
		t.Fatalf("re-run exit %d: %q", code, errS)
	}
	l = rcStoredLens(t, root, cid, "L-04")
	if got := len(objAt(l, "reconciliation").A); got != 2 {
		t.Fatalf("re-run recorded %d reconciliations, want 2", got)
	}
}

func TestAnsweredLensReconcileRefusals(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	rcSeedDivergenceSurface(t, root, cid, rcDivergenceSurfaceJSON)
	reason := "the payout is funded from the deposited balance"

	// ghost finding: the id does not exist in this campaign
	code, _, errS := run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason", reason,
		"--reconcile", "divrow1=F-111111111111;divrow2=F-111111111111")
	if code != 2 || !strings.Contains(errS,
		"F-111111111111 does not exist in this campaign") {
		t.Fatalf("ghost finding: exit %d stderr = %q", code, errS)
	}

	// a cite naming a symbol the row's own surface entry does not carry
	code, _, errS = run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason", reason,
		"--reconcile", "divrow1=burn:UnrelatedContract#L9|"+
			"burn:L1Gateway.deposit#L42;divrow2="+
			"transfer-in:L1Gateway._deposit#L12|"+
			"transfer-out:L1ReverseCustomGateway._depositByTransfer#L33")
	if code != 2 || !strings.Contains(errS,
		"names no symbol from the row's own surface entry") {
		t.Fatalf("off-row symbol: exit %d stderr = %q", code, errS)
	}

	// the = spelling parses identically (the refusals above prove the flag
	// flows; here the happy path rides the = form)
	code, _, errS = run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason", reason,
		"--reconcile="+rcGoodSpec, "--actor", "operator")
	if code != 0 {
		t.Fatalf("= spelling exit %d: %q", code, errS)
	}

	// negative control: the rule is lens-scoped — L-02 closes on the same
	// surface with no reconciliation at all
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	rcSeedDivergenceSurface(t, root2, cid2, rcDivergenceSurfaceJSON)
	code, _, errS = run(t, "--root", root2, "answered", cid2, "L-02",
		"answered", "--families", "user", "--reason",
		"the inverted incentive is priced in the model", "--actor", "op")
	if code != 0 || strings.Contains(errS, "--reconcile") {
		t.Fatalf("lens-scoped rule fired on L-02: exit %d stderr = %q",
			code, errS)
	}

	// negative control: --reconcile on a lens that owns no divergence rows
	// is refused, never silently recorded
	code, _, errS = run(t, "--root", root2, "answered", cid2, "L-01",
		"answered", "--families", "protocol", "--reason",
		"the protocol stays live under every reachable state",
		"--reconcile", rcGoodSpec)
	if code != 2 || !strings.Contains(errS,
		"--reconcile reconciles the divergence rows of a "+
			"primitive-symmetry lens") {
		t.Fatalf("reconcile on non-symmetry lens: exit %d stderr = %q",
			code, errS)
	}
}
