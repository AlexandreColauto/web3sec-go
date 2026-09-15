package maximization

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40 P1 — WaiveLadder was the NINTH ladder write site and the only one
// without the r18 unwind.
//
// Pre-fix shape (both doors reproduced live, see the report): WaiveLadder
// saved the ladder doc (`disposition.state = "waived"`), stamped the
// finding (`maximization.disposition = "waived"`) and only THEN called
// completion.Waive. Every refusal of that call — the >=10-char reason
// rule, an empty actor, or the ledger refusing the completion.waived
// append — returned rc=2 with BOTH files already rewritten, no waiver row
// (waivers.jsonl absent), no completion.waived event, and `verify`/`audit`
// green: a waived ladder the ledger never heard of. The two tests below
// pin byte-identity of the pair across both refusal doors, and the third
// pins that the honest, fully-logged waive still works end to end.
// ---------------------------------------------------------------------------

// r40Ladders is the completion.MaximizationAPI seam the CLI installs, so a
// test can read the GATE's own verdict (proofMaximalExploitation loads
// ladders through it) instead of guessing it from the files.
type r40Ladders struct{}

// LoadLadder adapts *Value (Python's None) onto the seam's
// Value-with-Null shape, exactly as the CLI's t23Maximization does.
func (r40Ladders) LoadLadder(c *state.Campaign, findingID string) (validation.Value, error) {
	lad, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if lad == nil {
		return validation.VNull(), nil
	}
	return *lad, nil
}

// r40WireGate installs the seam for one test and restores the default.
func r40WireGate(t *testing.T) {
	t.Helper()
	completion.SetMaximization(r40Ladders{})
	t.Cleanup(func() { completion.SetMaximization(nil) })
}

// r40GateDone is the maximal-exploitation proof's `done` flag.
func r40GateDone(t *testing.T, c *state.Campaign) bool {
	t.Helper()
	pr, err := completion.ProofStatus(c, "maximal-exploitation")
	if err != nil {
		t.Fatalf("proof status: %v", err)
	}
	d := objAt(pr, "done")
	return d.Kind == validation.Bool && d.B
}

// r40Sha is the sha256 of one file (or "absent"), the byte-identity pin.
func r40Sha(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// r40WaivedEvents counts the ledger's completion.waived anchors.
func r40WaivedEvents(t *testing.T, c *state.Campaign) int {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), "completion.waived")
}

// r40LadderState is the ladder doc's disposition state (or "absent").
func r40LadderState(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	raw, err := os.ReadFile(ladderPath(c, fid))
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("read ladder: %v", err)
	}
	lad, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse ladder: %v", err)
	}
	return objStr(asObj(objAt(lad, "disposition")), "state")
}

// TestR40RefusedWaiveShortReasonLeavesPairUntouched pins the short-reason
// door: the >=10-char rule lives inside completion.Waive, which runs AFTER
// the ladder and the finding were written, so the refusal happens with
// both files touched. The r18 door restores them.
func TestR40RefusedWaiveShortReasonLeavesPairUntouched(t *testing.T) {
	r40WireGate(t)
	c := newCampaign(t, "Waive Burn")
	f := confirmedFinding(t, c, "Fee skim via rounding")
	fid := objStr(f, "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	ladBefore := r40Sha(t, ladderPath(c, fid))
	findBefore := r40Sha(t, findings.FindingPath(c, fid))
	eventsBefore := r40Sha(t, c.EventsPath)
	if r40GateDone(t, c) {
		t.Fatal("gate is DONE before any waive — fixture is not the sharp case")
	}
	// The critic's door: a 5-char reason fails the >=10-char rule.
	if _, err := WaiveLadder(c, fid, "short", "tester"); err == nil ||
		!strings.Contains(err.Error(), "written reason") {
		t.Fatalf("short-reason waive err = %v (want the >=10-char refusal)", err)
	}
	// The pair is byte-identical to pre-call, the ladder does NOT say
	// waived, the ledger gained no event, no waiver row landed.
	if got := r40Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across a refused waive:\n before %s\n after  %s",
			ladBefore, got)
	}
	if got := r40Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across a refused waive:\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r40Sha(t, c.EventsPath); got != eventsBefore {
		t.Fatalf("the refused waive wrote to the ledger: %s -> %s", eventsBefore, got)
	}
	if st := r40LadderState(t, c, fid); st != "open" {
		t.Fatalf("ladder disposition after a refused waive = %q (want open)", st)
	}
	if _, err := os.Stat(completion.WaiversPath(c)); !os.IsNotExist(err) {
		t.Fatalf("waivers.jsonl exists after a refused waive: %v", err)
	}
	if n := r40WaivedEvents(t, c); n != 0 {
		t.Fatalf("%d completion.waived event(s) after a refused waive", n)
	}
	if r40GateDone(t, c) {
		t.Fatal("gate completes off a waiver that never happened")
	}
	// Nothing was burned: the honest retry works and logs exactly once.
	if _, err := WaiveLadder(c, fid, "budget exhausted before the ladder closed",
		"tester"); err != nil {
		t.Fatalf("honest retry after a refused waive: %v", err)
	}
	if n := r40WaivedEvents(t, c); n != 1 {
		t.Fatalf("honest retry emitted %d completion.waived event(s), want 1", n)
	}
}

// TestR40RefusedWaiveLedgerDoorLeavesPairUntouched pins the honest refusal
// an operator can always hit: grow the ledger, then cut events.jsonl to a
// shorter PREFIX so the state mirror is LONGER than the log. The
// completion.waived append is refused inside AppendJsonlThenLog (which
// unwinds its own waiver row); the ladder pair must come back too.
func TestR40RefusedWaiveLedgerDoorLeavesPairUntouched(t *testing.T) {
	r40WireGate(t)
	c := newCampaign(t, "Ledger Door")
	f := confirmedFinding(t, c, "Flash-loan price manipulation")
	fid := objStr(f, "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	// Grow the ledger a few events, then drop the tail line: the mirror
	// (updated by the same Log calls) is now one event AHEAD of the log.
	for i := 0; i < 3; i++ {
		data := validation.VObj(kv("note", validation.VStr("r40 ledger growth")))
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ladBefore := r40Sha(t, ladderPath(c, fid))
	findBefore := r40Sha(t, findings.FindingPath(c, fid))
	eventsBefore := r40Sha(t, c.EventsPath)
	if r40GateDone(t, c) {
		t.Fatal("gate is DONE before any waive — fixture is not the sharp case")
	}
	// A VALID reason: the refusal comes from the ledger, not the rule.
	_, err = WaiveLadder(c, fid, "budget exhausted before the ladder closed",
		"tester")
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door waive err = %v (want the projection refusal)", err)
	}
	if got := r40Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the ledger refusal:\n before %s\n after  %s",
			ladBefore, got)
	}
	if got := r40Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across the ledger refusal:\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r40Sha(t, c.EventsPath); got != eventsBefore {
		t.Fatalf("the refused waive touched the ledger: %s -> %s", eventsBefore, got)
	}
	if st := r40LadderState(t, c, fid); st != "open" {
		t.Fatalf("ladder disposition after the ledger refusal = %q (want open)", st)
	}
	if _, err := os.Stat(completion.WaiversPath(c)); !os.IsNotExist(err) {
		t.Fatalf("waivers.jsonl exists after the ledger refusal: %v", err)
	}
	if r40GateDone(t, c) {
		t.Fatal("gate completes off a waiver the ledger refused")
	}
	// doctor's sanctioned rebuild clears the shape; the retry then lands.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WaiveLadder(c, fid, "budget exhausted before the ladder closed",
		"tester"); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if n := r40WaivedEvents(t, c); n != 1 {
		t.Fatalf("retry emitted %d completion.waived event(s), want 1", n)
	}
}

// TestR40SuccessfulWaiveStillCompletesGate is the happy-path pin: the
// waiver row lands, the completion.waived event lands, and the gate
// completes — the fix must not turn a real waive into a refusal.
func TestR40SuccessfulWaiveStillCompletesGate(t *testing.T) {
	r40WireGate(t)
	c := newCampaign(t, "Honest Waive")
	f := confirmedFinding(t, c, "Rounding loss")
	fid := objStr(f, "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	if r40GateDone(t, c) {
		t.Fatal("gate is DONE before a waive — the ladder is still open")
	}
	lad, err := WaiveLadder(c, fid, "budget exhausted before the ladder closed",
		"operator")
	if err != nil {
		t.Fatalf("honest waive refused: %v", err)
	}
	if st := objStr(asObj(objAt(lad, "disposition")), "state"); st != "waived" {
		t.Fatalf("ladder disposition = %q, want waived", st)
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(asObj(objAt(f2, "maximization")), "disposition"); got != "waived" {
		t.Fatalf("finding maximization.disposition = %q, want waived", got)
	}
	if _, err := os.Stat(completion.WaiversPath(c)); err != nil {
		t.Fatalf("waiver row not recorded: %v", err)
	}
	if n := r40WaivedEvents(t, c); n != 1 {
		t.Fatalf("completion.waived events = %d, want 1", n)
	}
	if !r40GateDone(t, c) {
		t.Fatal("gate still NOT done after a recorded, logged waiver")
	}
}
