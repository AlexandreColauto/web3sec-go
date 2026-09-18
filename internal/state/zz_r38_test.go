package state

import (
	"os"
	"strings"
	"testing"

	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r38 — the heal/classifier line: ONE blank predicate, the cap-aware
// genesis disclosure, and the mirror classifier's head-hole refusal.
//
// Three findings, all in the ledger's heal/classifier line:
//   - P2-1: logLines (TrimSpace, Unicode) and verify's isBlank (ASCII
//     only) DISAGREED on Unicode whitespace, so a U+00A0-only ledger was
//     "genesis" to the write path (appended a success line) and malformed
//     forever to verify. One predicate now (blankLine), semantics explicit:
//     a U+00A0-only line is a RECORD this decoder cannot parse → the heal
//     refuses, verify reports it, doctor's rebuild refuses.
//   - P2-3: the genesis heal disclosed dropped_tail = len(mirror) as "the
//     loss" even at the 1000-event cap, where the tool cannot know the
//     total. At the cap the disclosure is additive: mirror_capped:true +
//     a stated meaning; the count is the mirrored tail dropped, not the
//     loss. Below the cap the shape is unchanged (exact).
//   - P2-4: classifyLaggingMirror certified ANY tail-aligned suffix as
//     health, so a mirror that lost its HEAD (last 3 of a 1006-event
//     ledger) wrote rc 0 with no disclosure and 997 mirrored events gone
//     invisibly. The tail-window branch now requires m == mirrorCap; the
//     head-hole shape refuses like the mid-hole, and verify refuses to
//     certify a tail-suffix whose length is not the mirror rule's.
// ---------------------------------------------------------------------------

// r38MintLedger mints n syntactically AND cryptographically valid chained
// events with the package's own eventHash, so a fixture exercises the REAL
// verify/log/classifier paths without a >1000-event O(n^2) Log loop (see
// LEARNINGS 20260908: flood tests stay in-memory). seq 0..n-1, each
// prev_hash continuing the chain from GenesisHash.
func r38MintLedger(n int) []validation.Value {
	evs := make([]validation.Value, 0, n)
	prev := GenesisHash
	for i := 0; i < n; i++ {
		ev := validation.VObj(
			kv("seq", validation.VInt(int64(i))),
			kv("at", validation.VStr("2026-01-01T00:00:00.000000+00:00")),
			kv("type", validation.VStr("note.added")),
			kv("ref", validation.VNull()),
			kv("data", validation.VObj()),
			kv("prev_hash", validation.VStr(prev)),
		)
		h := eventHash(ev)
		ev = validation.VObj(append(append([]validation.KV{}, ev.O...),
			kv("event_hash", validation.VStr(h)))...)
		evs = append(evs, ev)
		prev = h
	}
	return evs
}

// r38Lines renders minted events as the on-disk JSONL lines (the same
// ASCII canonical form the writer emits).
func r38Lines(evs []validation.Value) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, validation.CanonSpaced(e))
	}
	return out
}

// r38SetMirror writes the given slice as the state's events projection via
// the canonical state writer.
func r38SetMirror(t *testing.T, c *Campaign, mirror []validation.Value) {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "events",
		validation.Value{Kind: validation.Arr, A: mirror})
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
}

// r38SeedSynthetic installs a ledger of n minted events plus the mirror a
// healthy campaign would carry for it (tailEvents folded over the whole
// chain), and asserts the result is verify-green before any tamper — the
// fixture is exactly the long-campaign shape the findings describe, built
// without 1000 live Log calls.
func r38SeedSynthetic(t *testing.T, id string, n int) (*Campaign, []validation.Value) {
	t.Helper()
	c, err := Init(t.TempDir(), "r38 synthetic", InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	evs := r38MintLedger(n)
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(validation.CanonSpaced(e))
		b.WriteString("\n")
	}
	if err := os.WriteFile(c.EventsPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	var mirror []validation.Value
	for _, e := range evs {
		mirror = tailEvents(mirror, e)
	}
	r38SetMirror(t, c, mirror)
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("fixture must be verify-green before the tamper: %v %v",
			v.Problems, err)
	}
	return c, evs
}

// ---------------------------------------------------------------------------
// P2-1 — one blank predicate, explicit semantics, fail-closed.
// ---------------------------------------------------------------------------

// TestR38BlankPredicateMatrix pins the ONE predicate's decision on the
// exact framing set: ASCII framing whitespace is blank; every Unicode
// whitespace (U+00A0 NBSP included) and every line with content is a
// RECORD.
func TestR38BlankPredicateMatrix(t *testing.T) {
	blank := []string{"", " ", "\t", "\r", "\n", "\v", "\f", " \t\r\n\v\f "}
	for _, s := range blank {
		if !blankLine(s) {
			t.Errorf("blankLine(%q) = false, want true (ASCII framing whitespace)", s)
		}
	}
	record := []string{"\u00a0", "\u2028", "\u2029", "\u3000",
		"\u00a0\u00a0", " {\n", "{}", " \u00a0 "}
	for _, s := range record {
		if blankLine(s) {
			t.Errorf("blankLine(%q) = true, want false (a record, not blank)", s)
		}
	}
}

// TestR38NBSPOnlyLedgerIsARecordNotGenesis pins the P2-1 repro: a ledger
// holding ONLY a U+00A0 line is a record the decoder cannot parse, so the
// write REFUSES (naming the line) instead of appending a success line over
// it, verify REPORTS it (malformed, red — the damage is the ledger's own,
// the write adds none), and doctor's rebuild REFUSES instead of silently
// skipping the line and certifying the mirror. Nothing may self-inflict the
// permanent red the old split produced.
func TestR38NBSPOnlyLedgerIsARecordNotGenesis(t *testing.T) {
	c := r34Seed3(t, "C-r38nbsp0001")
	if err := os.WriteFile(c.EventsPath, []byte("\u00a0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	logBefore := r34Bytes(t, c.EventsPath)
	stBefore := r34Bytes(t, c.StatePath)

	// One predicate: logLines must see ONE record, not zero.
	lines, err := c.logLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 {
		t.Fatalf("a U+00A0-only ledger is ONE record to the heal decision, "+
			"got %d lines", len(lines))
	}

	// doctor's rebuild (EventsMirrorFromLog) must REFUSE, not skip.
	if _, merr := c.EventsMirrorFromLog(); merr == nil {
		t.Fatal("doctor's rebuild must refuse a U+00A0-only ledger, not " +
			"skip the line and certify the mirror")
	} else if !strings.Contains(merr.Error(), "line 1") ||
		!strings.Contains(merr.Error(), "rebuild refused") {
		t.Fatalf("rebuild refusal must name the line: %v", merr)
	}

	// The write must REFUSE, naming the line.
	_, lerr := c.Log("note.added", nil, nil)
	if lerr == nil {
		t.Fatal("a write over a U+00A0-only ledger must REFUSE, not append " +
			"a success line over an unparseable record")
	}
	if !strings.Contains(lerr.Error(), "line 1") ||
		!strings.Contains(lerr.Error(), "does not parse") {
		t.Fatalf("the refusal must name the line: %v", lerr)
	}
	if got := r34Bytes(t, c.EventsPath); got != logBefore {
		t.Fatal("the refused write must leave the ledger byte-identical")
	}
	if got := r34Bytes(t, c.StatePath); got != stBefore {
		t.Fatal("the refused write must leave the projection byte-identical")
	}

	// verify tells the same story: malformed, red — the ledger's OWN
	// damage, truthfully reported; the write added none.
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || v.MalformedLines != 1 || !hasProblem(v, "line 1: not valid JSON") {
		t.Fatalf("verify must report the U+00A0 line as malformed: %+v", v)
	}
}

// TestR38NBSPMidLedgerRefusesAndVerifyAgrees pins the neighbouring shape:
// a U+00A0 line in the MIDDLE of an otherwise healthy ledger is never
// silently skipped by the heal — the write refuses (line 2) and verify
// reports the same line. One predicate, one answer everywhere.
func TestR38NBSPMidLedgerRefusesAndVerifyAgrees(t *testing.T) {
	c := r34Seed3(t, "C-r38nbsp0002")
	raw := r34Bytes(t, c.EventsPath)
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("fixture must hold 3 lines, got %d", len(lines))
	}
	// events.jsonl = [e0, U+00A0, e1, e2] — four lines, the second unparseable.
	if err := os.WriteFile(c.EventsPath,
		[]byte(lines[0]+"\n\u00a0\n"+lines[1]+"\n"+lines[2]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, lerr := c.Log("note.added", nil, nil)
	if lerr == nil {
		t.Fatal("a write over a ledger with a U+00A0 line in the middle " +
			"must REFUSE")
	}
	if !strings.Contains(lerr.Error(), "line 2") {
		t.Fatalf("the refusal must attribute the U+00A0 line: %v", lerr)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || v.MalformedLines != 1 || !hasProblem(v, "line 2: not valid JSON") {
		t.Fatalf("verify must report the middle U+00A0 line: %+v", v)
	}
}

// TestR38FramingBlankShapesStillHeal pins that tightening the predicate to
// the ASCII framing set did NOT stop the zero-byte, newline-only, or
// ASCII-whitespace-only ledgers from healing as genesis (the r34 shapes).
func TestR38FramingBlankShapesStillHeal(t *testing.T) {
	cases := []struct {
		shape string
		id    string
		bytes []byte
	}{
		{"zero bytes", "C-r38zb000001", nil},
		{"single newline", "C-r38nl000001", []byte("\n")},
		{"CRLF", "C-r38crlf0001", []byte("\r\n")},
		{"ASCII whitespace", "C-r38ws000001", []byte(" \t\n  \n")},
	}
	for _, tc := range cases {
		t.Run(tc.shape, func(t *testing.T) {
			c := r34Seed3(t, tc.id)
			if err := os.WriteFile(c.EventsPath, tc.bytes, 0o644); err != nil {
				t.Fatal(err)
			}
			r34AssertHealedGenesis(t, c, tc.shape, 3)
		})
	}
}

// ---------------------------------------------------------------------------
// P2-3 — the genesis disclosure must not state a loss count it cannot know.
// ---------------------------------------------------------------------------

// TestR38GenesisDisclosureBelowCapStaysExact pins the knowable shape: a
// mirror below the cap has never been truncated, so its count IS the loss
// and the disclosure keeps its exact pre-r38 shape (no extra keys).
func TestR38GenesisDisclosureBelowCapStaysExact(t *testing.T) {
	c := r34Seed3(t, "C-r38discl001")
	if err := os.WriteFile(c.EventsPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatalf("a below-cap genesis ledger must heal: %v", err)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	lr := validation.ObjAt(validation.ObjAt(evts[0], "data"), "ledger_rewound")
	if lr.Kind != validation.Obj {
		t.Fatalf("the rewind must be disclosed: %s",
			validation.DumpsOrdered(evts[0], false))
	}
	if got := validation.ObjAt(lr, "dropped_tail"); got.Kind != validation.Int || got.I != 3 {
		t.Fatalf("below the cap the count is exact: %s",
			validation.DumpsOrdered(evts[0], false))
	}
	if got := validation.ObjAt(lr, "mirror_capped"); got.Kind != validation.Null {
		t.Fatalf("a below-cap mirror was never truncated, so the capped "+
			"marker must be ABSENT (the knowable shape is unchanged): %s",
			validation.DumpsOrdered(evts[0], false))
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("verify must be green: %v %v", v.Problems, err)
	}
}

// TestR38GenesisDisclosureAtCapSaysLossUnknown pins the P2-3 fix: the
// mirror is AT its 1000-event cap, so 1000 mirrored events dropped may
// stand for a 1000-event campaign OR a 100 000-event one — the tool cannot
// know. The disclosure keeps dropped_tail (the mirrored tail that was
// dropped) and ADDS mirror_capped:true plus a stated meaning, so the count
// is never presented as the total loss.
func TestR38GenesisDisclosureAtCapSaysLossUnknown(t *testing.T) {
	c, _ := r38SeedSynthetic(t, "C-r38disclcap", 1006)
	if n := len(r34Mirror(t, c)); n != mirrorCap {
		t.Fatalf("fixture: the mirror must be at its cap (%d), got %d",
			mirrorCap, n)
	}
	// Genesis: the ledger is gone (zero bytes); the capped mirror is all
	// that survives of the dead history.
	if err := os.WriteFile(c.EventsPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatalf("a capped-mirror genesis must still heal: %v", err)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	lr := validation.ObjAt(validation.ObjAt(evts[0], "data"), "ledger_rewound")
	if lr.Kind != validation.Obj {
		t.Fatalf("the rewind must be disclosed: %s",
			validation.DumpsOrdered(evts[0], false))
	}
	if got := validation.ObjAt(lr, "dropped_tail"); got.Kind != validation.Int ||
		got.I != mirrorCap {
		t.Fatalf("the mirrored tail dropped must be %d: %s", mirrorCap,
			validation.DumpsOrdered(evts[0], false))
	}
	if got := validation.ObjAt(lr, "mirror_capped"); got.Kind != validation.Bool || !got.B {
		t.Fatalf("a capped mirror must say so (mirror_capped:true): %s",
			validation.DumpsOrdered(evts[0], false))
	}
	meaning := validation.ObjAt(lr, "dropped_tail_meaning")
	if meaning.Kind != validation.Str ||
		!strings.Contains(meaning.S, "UNKNOWN") ||
		!strings.Contains(meaning.S, "lower bound") {
		t.Fatalf("the count's meaning must state that the true loss is "+
			"UNKNOWN and the count a lower bound: %s",
			validation.DumpsOrdered(evts[0], false))
	}
	if n := len(r34Mirror(t, c)); n != 1 {
		t.Fatalf("the mirror must be rewound to the new chain, got %d", n)
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("verify must be green: %v %v", v.Problems, err)
	}
}

// TestR38TailEventsCapIsOneNumber pins the shared cap constant at its
// boundary: 999 stays whole, 1000 drops to the last 999 + the new one.
func TestR38TailEventsCapIsOneNumber(t *testing.T) {
	evs := r38MintLedger(mirrorCap)
	got := tailEvents(evs, evs[0])
	if len(got) != mirrorCap {
		t.Fatalf("a full mirror must stay at %d, got %d", mirrorCap, len(got))
	}
	if s := validation.ObjAt(got[0], "seq"); s.Kind != validation.Int || s.I != 1 {
		t.Fatalf("the capped tail must start at seq 1 (the head dropped), "+
			"got %s", validation.DumpsOrdered(got[0], false))
	}
	short := evs[:mirrorCap-1]
	if got := tailEvents(short, evs[0]); len(got) != mirrorCap {
		t.Fatalf("a %d-event mirror grows to %d, got %d",
			mirrorCap-1, mirrorCap, len(got))
	}
}

// ---------------------------------------------------------------------------
// P2-4 — a head hole is not tail-aligned health.
// ---------------------------------------------------------------------------

// TestR38HeadHoleMirrorRefusesAndVerifyDoesNotCertifyIt is the finding's
// repro: a 1006-line ledger whose mirror was hand-edited down to only the
// LAST 3 events. The pre-fix classifier called any tail suffix healthy, so
// the next write exited 0 with no disclosure and verify/audit certified a
// projection that had permanently lost 997 mirrored events. Now the write
// REFUSES (like the mid-hole shape) and verify refuses the length that is
// not the mirror rule's — nothing certifies it.
func TestR38HeadHoleMirrorRefusesAndVerifyDoesNotCertifyIt(t *testing.T) {
	c, _ := r38SeedSynthetic(t, "C-r38headhole", 1006)
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	full := validation.ObjAt(st, "events").A
	if len(full) != mirrorCap {
		t.Fatalf("fixture: mirror must hold %d, got %d", mirrorCap, len(full))
	}
	head := full[len(full)-3:] // seqs 1003..1005 — the head is gone
	r38SetMirror(t, c, head)

	// verify must NOT certify it (pre-fix: OK).
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("verify certified a head-hole mirror: %+v", v)
	}
	if !hasProblem(v, "where the projection rule keeps 1000 for a 1006-event log") ||
		!hasProblem(v, "HEAD is missing") {
		t.Fatalf("verify must name the head hole and the rule's length: %v",
			v.Problems)
	}

	// The write must REFUSE, like the mid-hole shape.
	logBefore := r34Bytes(t, c.EventsPath)
	stBefore := r34Bytes(t, c.StatePath)
	_, lerr := c.Log("note.added", nil, nil)
	if lerr == nil {
		t.Fatal("a write over a head-hole mirror must REFUSE, not append " +
			"behind a success line")
	}
	for _, want := range []string{
		"holds 1006 event(s)", "mirrors 3",
		"holds seq 1003 where the ledger holds seq 0",
		"its head is missing",
	} {
		if !strings.Contains(lerr.Error(), want) {
			t.Fatalf("the refusal must contain %q: %v", want, lerr)
		}
	}
	if got := r34Bytes(t, c.EventsPath); got != logBefore {
		t.Fatal("the refused write must leave the ledger byte-identical")
	}
	if got := r34Bytes(t, c.StatePath); got != stBefore {
		t.Fatal("the refused write must leave the projection byte-identical")
	}
}

// TestR38HonestCapWindowStaysHealthy pins the branch's reason to exist: a
// mirror holding EXACTLY the cap window of a longer ledger is health — the
// write proceeds, discloses nothing, and the mirror stays the tail window.
// (This is r37b's pin, re-checked against the new m == mirrorCap
// precondition with a synthetic ledger instead of 1000 live writes.)
func TestR38HonestCapWindowStaysHealthy(t *testing.T) {
	c, _ := r38SeedSynthetic(t, "C-r38capok0001", 1006)
	ev, err := c.Log("note.added", nil, nil)
	if err != nil {
		t.Fatalf("a tail-aligned capped mirror is health: %v", err)
	}
	if validation.ObjAt(validation.ObjAt(ev, "data"), "mirror_lag_healed").Kind != validation.Null {
		t.Fatalf("a healthy write must disclose nothing: %s",
			validation.DumpsOrdered(ev, false))
	}
	mirror := r34Mirror(t, c)
	if len(mirror) != mirrorCap {
		t.Fatalf("the capped mirror must stay at %d, got %d",
			mirrorCap, len(mirror))
	}
	if s := validation.ObjAt(mirror[len(mirror)-1], "seq"); s.Kind != validation.Int ||
		s.I != 1006 {
		t.Fatalf("the new event must sit at the mirror's tail: %s",
			validation.DumpsOrdered(mirror[len(mirror)-1], false))
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("verify must be green: %v %v", v.Problems, err)
	}
}

// TestR38ClassifierMatrixKeepsItsPins pins the whole classifyLaggingMirror
// matrix on the pure function (fast, no integration loop): the honest cap
// window is 0 (healthy), a proper prefix and an empty mirror heal by
// adopting, and the head hole / dropped middle seq refuse with the counts
// and the first divergent seq named.
func TestR38ClassifierMatrixKeepsItsPins(t *testing.T) {
	const n = 6
	evs := r38MintLedger(n)
	lines := r38Lines(evs)

	// Honest cap window: a 1006-event ledger, mirror == last 1000.
	bigEvs := r38MintLedger(1006)
	if got, back, err := classifyLaggingMirror(r38Lines(bigEvs),
		bigEvs[1006-mirrorCap:]); err != nil || back != 0 ||
		len(got) != 1006 {
		t.Fatalf("honest cap window must be healthy (back=0): back=%d err=%v",
			back, err)
	}
	// Head hole: the mirror is a tail suffix, but shorter than the cap.
	if _, _, err := classifyLaggingMirror(lines, evs[3:]); err == nil {
		t.Fatal("a head-hole mirror (last 3 of 6) must REFUSE, not pass as " +
			"tail-aligned health")
	} else if !strings.Contains(err.Error(), "holds seq 3 where the ledger holds seq 0") {
		t.Fatalf("the refusal must name the first divergence: %v", err)
	}
	// Dropped middle seq: [0,1,3,4,5] over [0..5].
	mid := append(append([]validation.Value{}, evs[0:2]...), evs[3:]...)
	if _, _, err := classifyLaggingMirror(lines, mid); err == nil {
		t.Fatal("a mirror that skipped a seq must REFUSE")
	} else if !strings.Contains(err.Error(), "holds seq 3 where the ledger holds seq 2") {
		t.Fatalf("the refusal must name the skipped seq: %v", err)
	}
	// Dropped last seq (a proper prefix): heal by adopting one event.
	if got, back, err := classifyLaggingMirror(lines, evs[:n-1]); err != nil ||
		back != 1 || len(got) != n {
		t.Fatalf("a proper prefix must heal by adopting: back=%d err=%v",
			back, err)
	}
	// Empty mirror: adopt everything.
	if _, back, err := classifyLaggingMirror(lines, nil); err != nil || back != n {
		t.Fatalf("an empty mirror must adopt all %d: back=%d err=%v",
			n, back, err)
	}
	// A torn ledger line anywhere is inconclusive → refusal.
	torn := r38Lines(r38MintLedger(3))
	torn[1] = torn[1][:20]
	if _, _, err := classifyLaggingMirror(torn, evs[:1]); err == nil {
		t.Fatal("a torn ledger line must make the shape inconclusive and refuse")
	}
}
