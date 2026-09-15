package findings

// r41 P1 — RecordMemoryCheck's unwind door (memory.go: SaveThenLog) landed
// without a test. This is that test.
//
// The hazard: the CONFIRMED gate's memory-check clause does not read the
// ledger — gate.go's gateRun.memoryCheck (:547) calls MemoryCheckFails,
// which reads provenance.memory_checks off the FINDING FILE. So before the
// door, a refused `finding.memory_checked` append left the finding
// "certified" by an act the ledger never recorded (`recall` printed the
// projection refusal and exited 1 while the gate clause flipped to
// ✓ memory-check with 0 events behind it, and the retry then logged
// {"added": 0} forever).
//
// The honest refusal an operator can always hit (the r40b door): grow the
// ledger, then cut events.jsonl to a shorter NON-EMPTY prefix so the state
// mirror is LONGER than the log — the next Log refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M".
//
// The pins below: the refusal (a) leaves the finding file's bytes IDENTICAL
// (sha256 over the whole file, with the clock moved forward so any stray
// re-stamp is visible), (b) leaves the gate's memory-check clause FAILING,
// (c) adds zero finding.memory_checked events — and the repaired-ledger
// retry then records the check exactly once, satisfying the clause.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// r41MemoryChecks is the one-check payload the fixture records.
func r41MemoryChecks(mode string) []validation.Value {
	return []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr(mode)))}
}

// r41RecordedChecks counts the checks on the finding FILE — the artifact the
// gate reads (as opposed to the ledger event, which is counted separately).
func r41RecordedChecks(t *testing.T, c *state.Campaign, fid string) int {
	t.Helper()
	f, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	return len(objAt(asDict(objAt(f, "provenance")), "memory_checks").A)
}

// TestR41RefusedMemoryCheckRestoresFindingBytesAndFailsTheGate pins the
// refusal: the finding is byte-identical, the gate clause still fails, and
// the ledger holds no finding.memory_checked event.
func TestR41RefusedMemoryCheckRestoresFindingBytesAndFailsTheGate(t *testing.T) {
	// The clock pin makes a half-land deterministic: the fixture stamps
	// updated_at under day 1; SaveFinding re-stamps it under day 2, so the
	// pre-fix bytes provably moved.
	t.Setenv("WEBV2_NOW", "2026-01-01T00:00:00.000000+00:00")
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	fid := objStr(f, "finding_id")
	path := FindingPath(c, fid)
	raw := r40bCutLedger(t, c)
	before := r40bSha(t, path)
	if before == "absent" {
		t.Fatal("fixture is not the sharp case: no finding file")
	}
	t.Setenv("WEBV2_NOW", "2026-01-02T00:00:00.000000+00:00")
	_, err := RecordMemoryCheck(c, fid, r41MemoryChecks("negative"))
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door recall = %v (want the projection refusal)", err)
	}
	if got := r40bSha(t, path); got != before {
		t.Fatalf("finding bytes changed across the refused recall (the "+
			"memory check stamped without its event):\n before %s\n after  %s",
			before, got)
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != 0 {
		t.Fatalf("finding.memory_checked events = %d, want 0 (the refusal "+
			"must add none)", got)
	}
	// The CONFIRMED gate's clause: gate.go gateRun.memoryCheck calls
	// MemoryCheckFails, so a nil here would mean the refused act certified
	// the finding.
	msg, err := MemoryCheckFails(c, fid)
	if err != nil {
		t.Fatalf("MemoryCheckFails: %v", err)
	}
	if msg == nil {
		t.Fatal("the gate's memory-check clause PASSED after a refused " +
			"recall — the finding is certified by an act the ledger never " +
			"recorded")
	}
	if !strings.Contains(*msg, "no verified graph-memory recall recorded") {
		t.Fatalf("gate message = %q, want the no-verified-recall clause", *msg)
	}
	// Nothing was burned: the retry on the repaired ledger (the cut tail
	// restored — what `webv2 doctor` reconstructs) records the check once.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := RecordMemoryCheck(c, fid, r41MemoryChecks("negative"))
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r41RecordedChecks(t, c, fid); got != 1 {
		t.Fatalf("recorded memory_checks = %d, want 1", got)
	}
	entry := objAt(asDict(objAt(out, "provenance")), "memory_checks").A[0]
	if got := objStr(entry, "row_digest"); got == "" {
		t.Fatal("the recorded check carries no row_digest stamp")
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != 1 {
		t.Fatalf("finding.memory_checked events after the retry = %d, want 1",
			got)
	}
	msg, err = MemoryCheckFails(c, fid)
	if err != nil {
		t.Fatalf("MemoryCheckFails after the retry: %v", err)
	}
	if msg != nil {
		t.Fatalf("the recorded check does not satisfy the gate clause: %q", *msg)
	}
	// A repeat of the SAME (ids, mode) is a no-op for the gate's evidence:
	// the entry is recorded exactly once (dedupe on (frozenset(ids), mode)).
	if _, err := RecordMemoryCheck(c, fid, r41MemoryChecks("negative")); err != nil {
		t.Fatalf("repeat recall: %v", err)
	}
	if got := r41RecordedChecks(t, c, fid); got != 1 {
		t.Fatalf("repeat recall recorded the check %d times, want 1", got)
	}
	// OBSERVED SEAM (pinned, reported): the repeat still APPENDS a
	// finding.memory_checked event carrying {"added": 0}. The dedupe is on
	// the gate's evidence (the file), not on the ledger anchor — so the
	// count is 2, not 1. Pinned here so the claim is explicit rather than
	// assumed; memory.go is out of this task's write scope.
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != 2 {
		t.Fatalf("finding.memory_checked events after the repeat = %d; the "+
			"recorded behaviour is 2 (the no-op repeat still logs an "+
			"anchor with added:0) — if this changed, update the pin", got)
	}
}

// TestR41RefusedMemoryCheckLedgerIsUntouched is the ledger half of the pin:
// the refusal adds no event of any kind and leaves events.jsonl byte-
// identical (the cut bytes are the fixture's own, so this only checks that
// nothing new was appended before the refusal), and the honest path adds
// exactly one finding.memory_checked anchor.
func TestR41RefusedMemoryCheckLeavesLedgerAlone(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	fid := objStr(f, "finding_id")
	raw := r40bCutLedger(t, c)
	ledgerBefore := r40bSha(t, c.EventsPath)
	eventsBefore := r40bEventCount(t, c, "finding.memory_checked")
	if _, err := RecordMemoryCheck(c, fid, r41MemoryChecks("comparative")); err == nil {
		t.Fatal("the cut ledger did not refuse the recall")
	}
	if got := r40bSha(t, c.EventsPath); got != ledgerBefore {
		t.Fatalf("events.jsonl changed across the refusal: %s -> %s",
			ledgerBefore, got)
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != eventsBefore {
		t.Fatalf("finding.memory_checked events = %d, want %d", got, eventsBefore)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordMemoryCheck(c, fid, r41MemoryChecks("comparative")); err != nil {
		t.Fatalf("honest recall on a healthy ledger: %v", err)
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != eventsBefore+1 {
		t.Fatalf("honest recall logged %d event(s), want %d",
			got, eventsBefore+1)
	}
	if got := r41RecordedChecks(t, c, fid); got != 1 {
		t.Fatalf("honest recall recorded %d check(s), want 1", got)
	}
}
