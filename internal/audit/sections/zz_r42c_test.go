package sections

// zz_r42c_test.go — r42c P3 on the AUDIT side.
//
// The event_log section delegates the whole verdict to state's VerifyLog
// (one implementation of the ledger law, not two), so a torn ledger tail —
// events.jsonl whose last byte is not a newline, the shape the write path's
// framing guard refuses — must come back as ok:false with the tail problem
// in `problems`. Before the fix the section reported ok:true, the audit said
// PASS, and the campaign could not be written to by any verb.
//
// These pins also hold the section's report CONTRACT still: the key set is
// verify_log's (events/ok/problems/chained/legacy_unchained/malformed_lines)
// and the honest ledger stays ok:true with an empty problems list.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func zzR42cSectionCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r42c audit target",
		state.InitOpts{CampaignID: "C-r42csection01"})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	return c
}

// zzR42cSectionTear drops the ledger's trailing newline (the final record
// stays complete in every other byte).
func zzR42cSectionTear(t *testing.T, c *state.Campaign) {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("fixture is not a terminated ledger")
	}
	if err := os.WriteFile(c.EventsPath, raw[:len(raw)-1], 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestR42cEventLogSectionRefusesATornTail(t *testing.T) {
	c := zzR42cSectionCamp(t)

	// Honest first: the section certifies a terminated ledger, one key set.
	sec, err := EventLog(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(sec, "ok").B || len(objAt(sec, "problems").A) != 0 {
		t.Fatalf("honest ledger must pass: %s", validation.DumpsOrdered(sec, false))
	}
	wantKeys := []string{"events", "ok", "problems", "chained",
		"legacy_unchained", "malformed_lines"}
	if len(sec.O) != len(wantKeys) {
		t.Fatalf("the section key set is contractual: %s",
			validation.DumpsOrdered(sec, false))
	}
	for i, k := range wantKeys {
		if sec.O[i].K != k {
			t.Fatalf("key %d = %q, want %q", i, sec.O[i].K, k)
		}
	}
	if got := objAt(sec, "events").I; got != 3 {
		t.Fatalf("events = %d, want 3", got)
	}

	// The repro: no trailing newline. The section must not say ok.
	zzR42cSectionTear(t, c)
	sec, err = EventLog(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(sec, "ok").B {
		t.Fatalf("the event_log section certified a torn ledger: %s",
			validation.DumpsOrdered(sec, false))
	}
	probs := objAt(sec, "problems").A
	if len(probs) != 1 {
		t.Fatalf("one problem, naming the tear: %s",
			validation.DumpsOrdered(sec, false))
	}
	if !strings.HasPrefix(probs[0].S, "events.jsonl:") ||
		!strings.Contains(probs[0].S, "does not end in a newline") {
		t.Fatalf("the problem must name the file and the shape: %q", probs[0].S)
	}
	// The surviving prefix is still reported, so a FAIL is explainable.
	if objAt(sec, "chained").I != 3 || objAt(sec, "malformed_lines").I != 0 {
		t.Fatalf("the prefix accounting must survive the tear: %s",
			validation.DumpsOrdered(sec, false))
	}
}

// TestR42cEventLogSectionKeepsTheDocumentedTear: a tear that cut INTO the
// final record keeps the RUNBOOK's output — the line problem alone — and the
// section reports it as verify_log does (chained 0, malformed_lines 1).
func TestR42cEventLogSectionKeepsTheDocumentedTear(t *testing.T) {
	c := zzR42cSectionCamp(t)
	fh, err := os.OpenFile(c.EventsPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString(`{"seq": 3, "type": "note.a`); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	sec, err := EventLog(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(sec, "ok").B || objAt(sec, "malformed_lines").I != 1 {
		t.Fatalf("the mid-record tear must be red on its line: %s",
			validation.DumpsOrdered(sec, false))
	}
	probs := objAt(sec, "problems").A
	if len(probs) != 1 ||
		!strings.Contains(probs[0].S, "line 4: not valid JSON") {
		t.Fatalf("the documented line problem alone: %s",
			validation.DumpsOrdered(sec, false))
	}
	if strings.Contains(probs[0].S, "does not end in a newline") {
		t.Fatalf("one damage, one attribution: %q", probs[0].S)
	}
}
