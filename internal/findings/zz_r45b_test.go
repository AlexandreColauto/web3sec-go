package findings

// r45b pins for the CONFIRMED gate's own pin reader.
//
// gate.go:351 used to stat the ACTIVE snapshot's pin manifest and, on ANY
// stat error, fall through to the benign "no deployment/chain pin on the
// active snapshot — fork evidence has no fork target" advisory — so EACCES on
// a pin that exists and is active was reported as a pin that does not exist.
// activeForkTargetPin is the r44 pinnedCompiler shape now: ENOENT is the FACT
// "no pin", every other stat/read failure is a REFUSAL naming the path and
// the errno.
//
// sequenceCoverage (the clause the old falsehood discharged silently) reads
// the pin itself before judging, so the refusal reaches the CONFIRMED gate
// through this package even while the wired bool predicate is fail-closed.
//
// In-package on purpose: sequencepoc imports findings, so an in-package test
// cannot install the real predicate — it stubs the seam, and
// internal/sequencepoc/zz_r45b_test.go pins the other half (that the real
// predicate answers TRUE, never "not required", on an unreadable pin).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// r45bPinnedCampaign is a campaign with one active source-only pin; the
// returned path is its pin manifest.
func r45bPinnedCampaign(t *testing.T, name string) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	return c, filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")
}

// r45bHide makes a file unreadable (EACCES) for the duration of the test.
// Skipped as root, where mode bits do not deny the read.
func r45bHide(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny the read")
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })
}

// r45bStubSequenceRequired makes the wired predicate answer what the REAL
// fail-closed predicate answers for a sequenced finding whose pin could not
// be read: true.
func r45bStubSequenceRequired(t *testing.T) {
	t.Helper()
	prev := onchainSequenceRequiredFunc
	onchainSequenceRequiredFunc = func(*state.Campaign, validation.Value) bool {
		return true
	}
	t.Cleanup(func() { onchainSequenceRequiredFunc = prev })
}

// r45bFinding ingests + loads one real finding, so the exported gate can run
// its whole clause chain (a synthetic value fails the finding lookup first).
func r45bFinding(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	payload := validation.VObj(
		validation.KV{K: "title", V: validation.VStr("multi-tx bug")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("access-control")},
			validation.KV{K: "description", V: validation.VStr("missing check across two calls")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "contract", V: validation.VStr("V")},
			validation.KV{K: "function", V: validation.VStr("claim")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})})
	f, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFinding(c, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func r45bClause(t *testing.T, out []Clause, checkID string) Clause {
	t.Helper()
	for _, cl := range out {
		if cl.CheckID == checkID {
			return cl
		}
	}
	t.Fatalf("no %s clause in %v", checkID, out)
	return Clause{}
}

// TestR45bActiveForkTargetPinAbsentIsAFact: no active snapshot and no pin
// manifest are facts — (absent, no error) — never refusals.
func TestR45bActiveForkTargetPinAbsentIsAFact(t *testing.T) {
	c, err := state.Init(t.TempDir(), "r45b-absent", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	pin, present, err := activeForkTargetPin(c)
	if err != nil || present {
		t.Fatalf("no active snapshot: (pin=%v, present=%v, err=%v), want "+
			"(null, false, nil)", validation.CanonCompact(pin), present, err)
	}

	c, pinPath := r45bPinnedCampaign(t, "r45b-removed")
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	pin, present, err = activeForkTargetPin(c)
	if err != nil || present {
		t.Fatalf("ENOENT is a fact, not a refusal: (pin=%v, present=%v, "+
			"err=%v)", validation.CanonCompact(pin), present, err)
	}
}

// TestR45bReachabilityDiagnosticUnreadablePinIsRefusal: the honest shapes stay
// identical (a readable source-only pin still yields the fork-target
// advisory), while EACCES is a refusal instead of that advisory.
func TestR45bReachabilityDiagnosticUnreadablePinIsRefusal(t *testing.T) {
	c, pinPath := r45bPinnedCampaign(t, "r45b-reach")

	diag, err := ReachabilityDiagnostic(c, "E5", nil)
	if err != nil {
		t.Fatalf("a readable source-only pin must not refuse: %v", err)
	}
	joined := strings.Join(diag, " | ")
	if !strings.Contains(joined, "no deployment/chain pin on the active "+
		"snapshot") {
		t.Errorf("readable source-only pin: advisory missing: %q", joined)
	}

	r45bHide(t, pinPath)
	diag, err = ReachabilityDiagnostic(c, "E5", nil)
	if err == nil {
		t.Fatalf("EACCES reported as %q instead of a refusal", strings.Join(
			diag, " | "))
	}
	if !strings.Contains(err.Error(), pinPath) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the refusal must name the path %s and the errno: %v",
			pinPath, err)
	}
}

// TestR45bGateSequenceCoverageRefusesUnreadablePin: the clause the old
// falsehood discharged silently. With the predicate fail-closed (true), an
// unreadable pin must make the clause REFUSE, and a readable pin must keep
// the normal fail-closed coverage failure.
func TestR45bGateSequenceCoverageRefusesUnreadablePin(t *testing.T) {
	r45bStubSequenceRequired(t)
	c, pinPath := r45bPinnedCampaign(t, "r45b-seqcov")

	// Readable pin, no recorded attempt: the ordinary behaviour.
	g := &gateRun{campaign: c, finding: validation.VObj(), out: []Clause{}}
	if err := g.sequenceCoverage(validation.VObj()); err != nil {
		t.Fatalf("readable pin: %v", err)
	}
	if cl := r45bClause(t, g.out, "sequence-coverage"); cl.OK {
		t.Errorf("readable pin with no attempt must fail closed: %v", cl)
	} else if !strings.Contains(cl.Message, "multi-tx PoC") {
		t.Errorf("unexpected clause message: %q", cl.Message)
	}

	// The exported consumer: the same campaign, same predicate, refusal.
	r45bHide(t, pinPath)
	g = &gateRun{campaign: c, finding: validation.VObj(), out: []Clause{}}
	err := g.sequenceCoverage(validation.VObj())
	if err == nil {
		t.Fatalf("unreadable pin discharged the clause: %v", g.out)
	}
	if !strings.Contains(err.Error(), pinPath) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the refusal must name the path %s and the errno: %v",
			pinPath, err)
	}
	if len(g.out) != 0 {
		t.Errorf("a refused clause must not append a verdict: %v", g.out)
	}

	if _, err := ConfirmationGateClauses(c, r45bFinding(t, c)); err == nil {
		t.Fatal("the CONFIRMED gate must refuse on an unreadable pin")
	} else if !strings.Contains(err.Error(), pinPath) {
		t.Errorf("the gate refusal must name the pin path %s: %v", pinPath, err)
	}
	if _, err := ConfirmationGateDetail(c, r45bFinding(t, c)); err == nil {
		t.Fatal("confirmation_gate_detail must refuse on an unreadable pin")
	}
}
