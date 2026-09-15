package findings

// r42 P3-a — a refused corpus.gap event must be re-emittable, and the retry
// must never report `{"added": 0}` as if there were nothing left to say.
//
// The hazard: the gap payloads were built only for the checks that were NEW
// in the call (memory.go's loop, non-duplicate branch). Once the check entry
// itself was recorded, no later call could recompute its signal — every
// retry saw a duplicate, skipped it, logged finding.memory_checked
// {"added": 0} and returned. A corpus.gap append refused after the entry
// landed therefore left the relevance signal unrecorded forever while every
// retry printed a success-shaped anchor; absence of the signal was read as
// "nothing to say" instead of "not yet said".
//
// Two pins, both against the real ledger door (r40b's shape: grow the
// ledger, cut events.jsonl to a shorter prefix so the state mirror is LONGER
// than the log — the next Log refuses with "events.jsonl holds N event(s)
// but the state projection mirrors M"):
//
//   1. TestR42RefusedSignalStateIsReEmittedByTheRetry reconstructs the exact
//      durable state a refused corpus.gap leaves — entry + anchor on record,
//      signal absent, ledger healthy again (the operator's doctor step) —
//      by cutting the signal line and rebuilding the mirror FROM the log
//      with doctor's own API, then proves the retry emits the missing event
//      and that a third call does not emit a second copy.
//   2. TestR42LedgerDoorRefusalRetryLandsTheSignal forces the refusal on a
//      call that owes a gap: nothing half-lands (the finding file's bytes
//      are identical, no anchor, no signal, the gate clause still fails),
//      and the healed retry lands check + anchor + signal — never a
//      {"added": 0} no-op.
//
// The mutation with teeth (observed, recorded in the task report): making
// emitOwedCorpusGaps return nil without emitting makes pin 1 fail on
// "corpus.gap events after the retry = 0, want 1".

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// r42Check is the one zero-overlap check the fixtures record: a `negative`
// cite of a row that shares no structural tag with a logic-error finding.
func r42Check(mode string) []validation.Value {
	return []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-defi0001"))),
		kv("mode", validation.VStr(mode)))}
}

// r42Store installs the store that check cites.
func r42Store(t *testing.T) {
	t.Helper()
	installMemoryStore(t, relevanceRow("MEM-defi0001", "oracle-manipulation"))
}

// r42DropLastEvent cuts the ledger's last line (returning the parsed event,
// so the caller can prove which event it cut) and heals the state mirror the
// way `webv2 doctor` does: rebuild it FROM the log (EventsMirrorFromLog) and
// write it back through the canonical SaveState. Cutting alone would leave
// the campaign in the door's refusal state (mirror longer than the log); the
// rebuild is the sanctioned repair an operator runs after a refusal, so what
// remains is exactly the durable state a refused append leaves behind.
func r42DropLastEvent(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	dropped, err := validation.ParseOrdered([]byte(lines[len(lines)-1]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mirror, err := c.EventsMirrorFromLog()
	if err != nil {
		t.Fatalf("mirror rebuild refused: %v", err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.VArr(mirror...))
	if err := c.SaveState(st); err != nil {
		t.Fatalf("mirror heal: %v", err)
	}
	return dropped
}

// TestR42RefusedSignalStateIsReEmittedByTheRetry is pin 1.
func TestR42RefusedSignalStateIsReEmittedByTheRetry(t *testing.T) {
	c := ingestCamp(t)
	r42Store(t)
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := objStr(f, "finding_id")

	// The honest call on a healthy ledger: entry + anchor + signal.
	recordCheck(t, c, fid, []string{"MEM-defi0001"}, "negative", "")
	gaps := corpusGapData(t, c)
	if len(gaps) != 1 {
		t.Fatalf("baseline corpus.gap events = %d, want 1", len(gaps))
	}
	want := validation.CanonCompact(gaps[0])
	anchors := r40bEventCount(t, c, "finding.memory_checked")

	// The refused-signal state: the entry and its anchor stay, the signal
	// does not, and the ledger is healthy again.
	dropped := r42DropLastEvent(t, c)
	if got := objStr(dropped, "type"); got != "corpus.gap" {
		t.Fatalf("the cut event is %q, not the signal — the fixture is not "+
			"the sharp case", got)
	}
	if n := len(corpusGapData(t, c)); n != 0 {
		t.Fatalf("corpus.gap events after the cut = %d, want 0 (the state "+
			"the refusal leaves)", n)
	}
	if got := r41RecordedChecks(t, c, fid); got != 1 {
		t.Fatalf("recorded memory_checks = %d, want 1 (the entry landed "+
			"before the signal was refused)", got)
	}

	// The retry: the check is already recorded, so the anchor says
	// {"added": 0} — and the owed signal must be re-derived and emitted.
	if _, err := RecordMemoryCheck(c, fid, r42Check("negative")); err != nil {
		t.Fatalf("retry after the refused signal: %v", err)
	}
	gaps = corpusGapData(t, c)
	if len(gaps) != 1 {
		t.Fatalf("corpus.gap events after the retry = %d, want 1 (the retry "+
			"must emit the missing signal, not a {\"added\": 0} no-op)", len(gaps))
	}
	if got := validation.CanonCompact(gaps[0]); got != want {
		t.Fatalf("re-emitted signal =\n %s\nwant the recorded verdict's own "+
			"payload\n %s", got, want)
	}
	if got := objStr(gaps[0], "reason_code"); got != GAP_NO_SHARED_TAG {
		t.Fatalf("re-emitted reason_code = %q, want %q", got,
			GAP_NO_SHARED_TAG)
	}
	if got := r41RecordedChecks(t, c, fid); got != 1 {
		t.Fatalf("recorded memory_checks after the retry = %d, want 1 (the "+
			"retry must not re-record)", got)
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != anchors+1 {
		t.Fatalf("finding.memory_checked events = %d, want %d (the retry's "+
			"added:0 anchor is the recorded behaviour)", got, anchors+1)
	}

	// Idempotence: the signal is now in the ledger, so a third call adds
	// nothing — no duplicate gap, no re-record.
	if _, err := RecordMemoryCheck(c, fid, r42Check("negative")); err != nil {
		t.Fatalf("third call: %v", err)
	}
	if got := len(corpusGapData(t, c)); got != 1 {
		t.Fatalf("corpus.gap events after a third call = %d, want 1 (no "+
			"duplicate signal)", got)
	}
}

// TestR42LedgerDoorRefusalRetryLandsTheSignal is pin 2: the refusal itself,
// aimed at a call that owes a gap.
func TestR42LedgerDoorRefusalRetryLandsTheSignal(t *testing.T) {
	c := ingestCamp(t)
	r42Store(t)
	f := mintRelevanceFinding(t, c, "logic-error", "", nil, nil)
	fid := objStr(f, "finding_id")
	path := FindingPath(c, fid)
	raw := r40bCutLedger(t, c)
	before := r40bSha(t, path)
	if before == "absent" {
		t.Fatal("fixture is not the sharp case: no finding file")
	}
	_, err := RecordMemoryCheck(c, fid, r42Check("negative"))
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door recall = %v (want the projection refusal)", err)
	}
	if got := r40bSha(t, path); got != before {
		t.Fatalf("finding bytes changed across the refused recall:\n"+
			" before %s\n after  %s", before, got)
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != 0 {
		t.Fatalf("finding.memory_checked events = %d, want 0", got)
	}
	if got := len(corpusGapData(t, c)); got != 0 {
		t.Fatalf("corpus.gap events = %d, want 0 (the refusal must add none)",
			got)
	}
	if msg, err := MemoryCheckFails(c, fid); err != nil || msg == nil {
		t.Fatalf("the gate clause after the refusal = %v, %v; want a "+
			"failure message (nothing was recorded)", msg, err)
	}
	// The operator's repair (restore the cut tail), then the retry: check +
	// anchor + signal, exactly once each.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordMemoryCheck(c, fid, r42Check("negative")); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r41RecordedChecks(t, c, fid); got != 1 {
		t.Fatalf("recorded memory_checks = %d, want 1", got)
	}
	if got := r40bEventCount(t, c, "finding.memory_checked"); got != 1 {
		t.Fatalf("finding.memory_checked events after the retry = %d, want 1",
			got)
	}
	if got := len(corpusGapData(t, c)); got != 1 {
		t.Fatalf("corpus.gap events after the retry = %d, want 1 (the retry "+
			"must land the signal, not a {\"added\": 0} no-op)", got)
	}
	if msg, err := MemoryCheckFails(c, fid); err != nil || msg != nil {
		t.Fatalf("the gate clause after the retry = %v, %v; want nil, nil",
			msg, err)
	}
}
