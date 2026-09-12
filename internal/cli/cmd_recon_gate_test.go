package cli

// cmd_recon_gate_test.go — FIX-8: recon is not free. The operator's campaign
// never ran `webv2 sinks` or `webv2 prescreen`; the L-04 divergence-gate
// close let them attest over divergence rows the mechanical recon never saw.
// Every refusal path here is a negative control that must leave the plan and
// the event log untouched; the positive path runs the REAL CLI verbs (the
// gate must be satisfiable the way the operator satisfies it); and the
// sinks stamp is proven idempotent under a double run.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// rgCloseL04 is the L-04 attestation command (no --reconcile: a campaign
// with no probe surface has nothing to reconcile, the FIX-6 grandfather).
func rgCloseL04(t *testing.T, root, cid string) (int, string) {
	t.Helper()
	code, _, errS := run(t, "--root", root, "answered", cid, "L-04",
		"answered", "--families", "protocol", "--reason",
		"the drop path's payout is funded by the burned deposits",
		"--actor", "operator")
	return code, errS
}

// rgReconStamp reads the sinks stamp back off the campaign state.
func rgReconStamp(t *testing.T, root, cid string) validation.Value {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := c.ReconStamp("sinks")
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

func TestReconGateRefusesWithoutRecon(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)

	code, errS := rgCloseL04(t, root, cid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	// the refusal names BOTH commands, runnable verbatim for this campaign
	for _, want := range []string{
		"no archetype prescreen on record",
		"no `webv2 sinks` run on record",
		"webv2 prescreen " + cid + " --src SRC",
		"webv2 sinks " + cid + " --src SRC",
	} {
		if !strings.Contains(errS, want) {
			t.Errorf("refusal missing %q:\n%s", want, errS)
		}
	}
	// the refusal is a decision that did not happen: the lens stays open and
	// the event log is silent
	l := rcStoredLens(t, root, cid, "L-04")
	if got := objStr(l, "status"); got != "open" {
		t.Fatalf("refused attestation changed the status to %q", got)
	}
	if evts := dgEventsOfType(t, root, cid, "plan.lens_status"); len(evts) != 0 {
		t.Fatalf("refused attestation logged %d plan.lens_status events",
			len(evts))
	}
}

func TestReconGateNamesOnlyTheMissingStamp(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	tree := t25Tree(t, "sink")

	// prescreen only: the sinks command is the one still owed
	code, _, errS := run(t, "--root", root, "prescreen", cid, "--src", tree)
	if code != 0 {
		t.Fatalf("prescreen exit %d: %q", code, errS)
	}
	code, errS = rgCloseL04(t, root, cid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "no `webv2 sinks` run on record") ||
		!strings.Contains(errS, "webv2 sinks "+cid+" --src SRC") {
		t.Fatalf("refusal does not name the sinks command:\n%s", errS)
	}
	if strings.Contains(errS, "webv2 prescreen "+cid) {
		t.Fatalf("refusal demands the prescreen that is on record:\n%s", errS)
	}

	// fresh campaign, sinks only: the prescreen command is the one owed
	root2 := mkroot(t)
	cid2 := initOne(t, root2)
	t14TestSeed(t, root2, cid2)
	code, _, errS = run(t, "--root", root2, "sinks", cid2, "--src", tree)
	if code != 0 {
		t.Fatalf("sinks exit %d: %q", code, errS)
	}
	code, errS = rgCloseL04(t, root2, cid2)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS, "no archetype prescreen on record") ||
		!strings.Contains(errS, "webv2 prescreen "+cid2+" --src SRC") {
		t.Fatalf("refusal does not name the prescreen command:\n%s", errS)
	}
	if strings.Contains(errS, "webv2 sinks "+cid2) {
		t.Fatalf("refusal demands the sinks run that is on record:\n%s", errS)
	}
}

func TestReconGatePassesAfterRealRecon(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	tree := t25Tree(t, "sink")

	code, _, errS := run(t, "--root", root, "prescreen", cid, "--src", tree)
	if code != 0 {
		t.Fatalf("prescreen exit %d: %q", code, errS)
	}
	code, _, errS = run(t, "--root", root, "sinks", cid, "--src", tree)
	if code != 0 {
		t.Fatalf("sinks exit %d: %q", code, errS)
	}
	// the sinks stamp is on record and names the tree it ran over
	stamp := rgReconStamp(t, root, cid)
	if objStr(stamp, "src") != tree {
		t.Fatalf("recon.sinks.src = %q, want %q", objStr(stamp, "src"), tree)
	}
	if objStr(stamp, "at") == "" {
		t.Fatal("recon.sinks.at is empty")
	}
	// the gate passes: the L-04 attestation lands
	code, errS = rgCloseL04(t, root, cid)
	if code != 0 {
		t.Fatalf("attested closure refused: %q", errS)
	}
	l := rcStoredLens(t, root, cid, "L-04")
	if got := objStr(l, "status"); got != "answered" {
		t.Fatalf("status = %q", got)
	}
}

func TestSinksStampIsIdempotent(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tree := t25Tree(t, "sink")
	for i := 0; i < 2; i++ {
		code, _, errS := run(t, "--root", root, "sinks", cid, "--src", tree)
		if code != 0 {
			t.Fatalf("sinks run %d exit %d: %q", i+1, code, errS)
		}
	}
	// the stamp is ONE row per verb: a double run replaced, never appended
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	recon := objAt(st, "recon")
	if recon.Kind != validation.Obj {
		t.Fatalf("state.recon = %s", validation.CanonCompact(recon))
	}
	if len(recon.O) != 1 || recon.O[0].K != "sinks" {
		t.Fatalf("recon keys = %s", validation.CanonCompact(recon))
	}
	stamp := objAt(recon, "sinks")
	if len(stamp.O) != 3 || objStr(stamp, "src") != tree ||
		objStr(stamp, "at") == "" ||
		objStr(stamp, "campaign_id") != cid {
		t.Fatalf("sinks stamp = %s", validation.CanonCompact(stamp))
	}
	// and the gate helper reads the same row
	if got := objStr(rgReconStamp(t, root, cid), "src"); got != tree {
		t.Fatalf("ReconStamp src = %q", got)
	}
}
