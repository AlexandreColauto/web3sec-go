package state

// zz_r42c_test.go — r42c P3, the false certification.
//
// Repro: take a healthy campaign and remove the trailing newline from
// events.jsonl (the "torn write" shape the write path's framing guard,
// validation/atomicio.go checkJsonlTail, refuses). Every mutating verb then
// refuses forever — "refusing to append ... the file does not end in a
// newline (torn write or external edit)" — while verify printed
// {"ok": true, "problems": []} and exited 0: the ONE corruption class the
// writer refuses was invisible to the reader that certifies. These pins fix
// the reader's side of the law and, just as important, pin the HONEST shapes
// that must stay green: a ledger whose last record IS terminated, a
// zero-byte ledger, an absent ledger, and the RUNBOOK's documented
// mid-record tear (whose output names the line and nothing else).
//
// The byte shape is ambiguous by nature — "final record present, no newline"
// is the same bytes for an interrupted append and for a deleted newline, and
// both are equally un-appendable — so the verdict names the shape and does
// not guess the cause (see LedgerTail's comment).

import (
	"os"
	"strings"
	"testing"

	"websec/internal/validation"
)

// zzR42cCamp is a campaign with three ledger events (Init logs one).
func zzR42cCamp(t *testing.T, id string) *Campaign {
	t.Helper()
	c, err := Init(t.TempDir(), "r42c torn tail", InitOpts{CampaignID: id})
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

// zzR42cTear removes the ledger's trailing newline, leaving the final record
// complete in every other byte — the repro the finding was filed against.
func zzR42cTear(t *testing.T, c *Campaign) {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("fixture is not a terminated ledger: %q", raw[len(raw)-1:])
	}
	if err := os.WriteFile(c.EventsPath, raw[:len(raw)-1], 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestR42cTornTailIsNotCertified: the reconciling pin. The write path
// refuses the torn ledger AND verify refuses to certify it, naming the file
// and the shape, and it still reports the surviving prefix (the verdict is
// produced, not raised).
func TestR42cTornTailIsNotCertified(t *testing.T) {
	c := zzR42cCamp(t, "C-r42ctorn0001")
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("fixture must verify green before the tear: %+v %v", v, err)
	}
	zzR42cTear(t, c)

	// The write path's own answer, for the record: refused, bytes untouched.
	before, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	_, lerr := c.Log("note.added", nil, nil)
	if lerr == nil {
		t.Fatal("the framing guard must refuse to append behind an " +
			"unterminated record")
	}
	if !strings.Contains(lerr.Error(), "does not end in a newline") {
		t.Fatalf("the refusal must be the framing guard's own: %v", lerr)
	}
	if after, rerr := os.ReadFile(c.EventsPath); rerr != nil ||
		string(after) != string(before) {
		t.Fatalf("the refused append must leave the ledger byte-identical: %v", rerr)
	}

	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("verify certified a ledger its own writer refuses: %+v", v)
	}
	if !hasProblem(v, "events.jsonl") {
		t.Fatalf("the problem must name the file: %+v", v.Problems)
	}
	if !hasProblem(v, "does not end in a newline") {
		t.Fatalf("the problem must name the shape: %+v", v.Problems)
	}
	if !hasProblem(v, "not terminated") {
		t.Fatalf("the problem must say the final record is not terminated: %+v",
			v.Problems)
	}
	// The surviving prefix is still accounted for: this is a verdict, not a
	// crash, and "3 events / 3 chained" is what the reader actually saw.
	if v.Events != 3 || v.Chained != 3 || v.MalformedLines != 0 {
		t.Fatalf("the surviving prefix must still be reported: %+v", v)
	}
	// Prepended: the 10-problem cap may never hide the one corruption class
	// the write path itself refuses.
	if len(v.Problems) == 0 || !strings.HasPrefix(v.Problems[0], "events.jsonl") {
		t.Fatalf("the tail problem must lead: %+v", v.Problems)
	}
}

// TestR42cHonestShapesStayGreen pins the other half of the law: the shapes
// the write path CAN append to, plus the documented recovery, are green.
func TestR42cHonestShapesStayGreen(t *testing.T) {
	t.Run("terminated last record", func(t *testing.T) {
		c := zzR42cCamp(t, "C-r42cgreen001")
		v, err := c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if !v.OK || len(v.Problems) != 0 || v.Events != 3 {
			t.Fatalf("a terminated ledger must stay green: %+v", v)
		}
	})

	t.Run("zero-byte ledger", func(t *testing.T) {
		c := zzR42cCamp(t, "C-r42cgreen002")
		// The mirror is emptied with it: a zero-byte ledger under a live
		// mirror is the r34/r39b truncation shape, separately red.
		r38SetMirror(t, c, []validation.Value{})
		if err := os.WriteFile(c.EventsPath, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		v, err := c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if !v.OK {
			t.Fatalf("genesis (a zero-byte ledger) must stay green: %+v", v)
		}
	})

	t.Run("absent ledger", func(t *testing.T) {
		c := zzR42cCamp(t, "C-r42cgreen003")
		r38SetMirror(t, c, []validation.Value{})
		if err := os.Remove(c.EventsPath); err != nil {
			t.Fatal(err)
		}
		v, err := c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if !v.OK {
			t.Fatalf("an absent ledger is genesis, not damage: %+v", v)
		}
	})

	t.Run("runbook recovery cut", func(t *testing.T) {
		c := zzR42cCamp(t, "C-r42cgreen004")
		zzR42cTear(t, c)
		if v, err := c.VerifyLog(); err != nil || v.OK {
			t.Fatalf("the tear must be red before the repair: %+v %v", v, err)
		}
		// RUNBOOK step 3: cut back to the last complete record (the last
		// newline, inclusive).
		raw, err := os.ReadFile(c.EventsPath)
		if err != nil {
			t.Fatal(err)
		}
		i := strings.LastIndex(string(raw), "\n")
		if i < 0 {
			t.Fatal("fixture has no newline to cut back to")
		}
		if err := os.WriteFile(c.EventsPath, raw[:i+1], 0o644); err != nil {
			t.Fatal(err)
		}
		// The cut DROPS the record whose newline the tear removed, so the
		// mirror now projects one event more than the ledger holds: the
		// framing problem is gone and the RUNBOOK's second branch applies
		// ("state event tail does not match the log suffix" — the
		// projection is re-derived FROM the ledger, never the reverse).
		v, err := c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if v.OK || hasProblem(v, "does not end in a newline") {
			t.Fatalf("the cut repairs the framing and exposes the mirror: %+v", v)
		}
		if !hasProblem(v, "state event tail is LONGER than the log") {
			t.Fatalf("the projection must be the remaining problem: %+v",
				v.Problems)
		}
		// The sanctioned rebuild (doctor's own door) then ends green.
		fresh, err := c.EventsMirrorFromLog()
		if err != nil {
			t.Fatal(err)
		}
		r38SetMirror(t, c, fresh)
		v, err = c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if !v.OK || v.Events != 2 {
			t.Fatalf("the documented recovery must end green: %+v", v)
		}
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("the repaired ledger must accept the next append: %v", err)
		}
	})

	// The case the RUNBOOK documents as the ordinary crash-mid-append: the
	// final record is in the ledger but the projection was never updated
	// (the mirror still holds only the terminated prefix). Its documented
	// recovery — cut back to the last complete record — must end green,
	// with no doctor step at all.
	t.Run("documented in-flight crash", func(t *testing.T) {
		c := zzR42cCamp(t, "C-r42cgreen005")
		mirrorBeforeTear := append([]validation.Value{}, r34Mirror(t, c)...)
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(c.EventsPath)
		if err != nil {
			t.Fatal(err)
		}
		// The interrupted append: the fourth record landed byte-complete
		// but never got its newline, and the mirror save never ran.
		if err := os.WriteFile(c.EventsPath, raw[:len(raw)-1], 0o644); err != nil {
			t.Fatal(err)
		}
		r38SetMirror(t, c, mirrorBeforeTear)
		v, err := c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if v.OK {
			t.Fatalf("the torn ledger must be red before the cut: %+v", v)
		}
		// The documented cut: back to the last newline.
		i := strings.LastIndex(string(raw[:len(raw)-1]), "\n")
		if i < 0 {
			t.Fatal("fixture has no newline to cut back to")
		}
		if err := os.WriteFile(c.EventsPath, raw[:i+1], 0o644); err != nil {
			t.Fatal(err)
		}
		v, err = c.VerifyLog()
		if err != nil {
			t.Fatal(err)
		}
		if !v.OK || v.Events != 3 {
			t.Fatalf("the documented in-flight-crash recovery must verify "+
				"green over the surviving prefix: %+v", v)
		}
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("the recovered ledger must accept the next append: %v", err)
		}
	})
}

// TestR42cMidRecordTearKeepsTheDocumentedShape: a tear that cut INTO the
// final record is attributed to its line — exactly what the RUNBOOK's
// torn-log walkthrough prints (line number, decoder message, chained 0) —
// and is NOT re-reported as a tail problem. One damage, one attribution.
func TestR42cMidRecordTearKeepsTheDocumentedShape(t *testing.T) {
	c := zzR42cCamp(t, "C-r42ctorn0002")
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
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || v.MalformedLines != 1 {
		t.Fatalf("the mid-record tear must be red on its line: %+v", v)
	}
	if !hasProblem(v, `line 4: not valid JSON (unexpected EOF)`) {
		t.Fatalf("the documented line problem must be reported: %+v", v.Problems)
	}
	if len(v.Problems) != 1 {
		t.Fatalf("one damage, one attribution — the RUNBOOK shows the line "+
			"problem alone: %+v", v.Problems)
	}
	if hasProblem(v, "does not end in a newline") {
		t.Fatalf("the tail problem must not restate a tear already "+
			"attributed to its line: %+v", v.Problems)
	}
	if v.Events != 4 { // the unreadable line counts, as documented
		t.Fatalf("events must count the unreadable line: %+v", v)
	}
}

// TestR42cLedgerTailFraming pins the shared predicate doctor reads.
func TestR42cLedgerTailFraming(t *testing.T) {
	c := zzR42cCamp(t, "C-r42ctorn0003")
	lt, err := c.LedgerTailFraming()
	if err != nil {
		t.Fatal(err)
	}
	if !lt.Present || lt.Torn || lt.TailBytes != 0 {
		t.Fatalf("terminated ledger: %+v", lt)
	}
	zzR42cTear(t, c)
	lt, err = c.LedgerTailFraming()
	if err != nil {
		t.Fatal(err)
	}
	if !lt.Present || !lt.Torn {
		t.Fatalf("torn ledger: %+v", lt)
	}
	if lt.TailBytes <= 0 {
		t.Fatalf("TailBytes must count the unterminated tail: %+v", lt)
	}
	raw := mustRead(t, c.EventsPath)
	if want := len(raw) - strings.LastIndexByte(string(raw), '\n') - 1; lt.TailBytes != want ||
		lt.Size != int64(len(raw)) {
		t.Fatalf("TailBytes/Size must describe the file: %+v (want tail %d)",
			lt, want)
	}
	if p := TornTailProblem("events.jsonl", lt.TailBytes); !strings.HasPrefix(p, "events.jsonl:") ||
		!strings.Contains(p, "does not end in a newline") {
		t.Fatalf("the shared sentence must name the file and the shape: %s", p)
	}
	// Absent ledger: not present, not torn (the first append is allowed).
	if err := os.Remove(c.EventsPath); err != nil {
		t.Fatal(err)
	}
	lt, err = c.LedgerTailFraming()
	if err != nil {
		t.Fatal(err)
	}
	if lt.Present || lt.Torn {
		t.Fatalf("absent ledger: %+v", lt)
	}
}

// TestR42cUnreadableLedgerIsNotCertified: a reader that could not read the
// ledger has no evidence about it. Before this pin the failed read fell
// through as "zero events" and certified green whenever the mirror was
// empty.
func TestR42cUnreadableLedgerIsNotCertified(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file; the shape needs a real denial")
	}
	c := zzR42cCamp(t, "C-r42ctorn0004")
	r38SetMirror(t, c, []validation.Value{})
	if err := os.Chmod(c.EventsPath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(c.EventsPath, 0o644) })
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("an unreadable ledger must not be certified: %+v", v)
	}
	if !hasProblem(v, "events.jsonl: unreadable") {
		t.Fatalf("the problem must say the ledger was never read: %+v",
			v.Problems)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
