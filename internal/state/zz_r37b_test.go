package state

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r37b F4 — A WRITE OBSERVING A MIRROR SHORTER THAN THE LOG.
//
// r34 closed the mirror-LONGER direction; the crash (or SIGKILL) between
// the log append and the mirror save leaves the mirror SHORTER, and the
// pre-r37b write appended onto the STALE mirror: the new event landed at
// the projection's tail while the unmirrored ledger events stayed
// unmirrored — a HOLE in the middle ([0,1,2] rolled back to [0,1], the
// next write mirrors [0,1,3]), baked in behind a rc=0 success line and
// found only later by verify's generic tail mismatch. The two shapes that
// live in that gap now take different branches:
//
//   - a clean LAGGING copy (a proper prefix of the ledger, or an empty
//     mirror): the sanctioned crash shape — the write heals by
//     re-deriving the projection from the LEDGER (the truth) and
//     discloses the adoption in the new event's hashed data
//     (mirror_lag_healed{adopted_from_log:N}); verify is green after.
//   - a mid-ledger hole (a mirror that skips a seq while later seqs are
//     present): the write REFUSES like the truncation case, naming both
//     counts and the missing seq, and leaves ledger and projection
//     byte-identical.
// ---------------------------------------------------------------------------

// r37bDropMirrorEvent surgically removes one event from the state
// projection ONLY (the ledger is untouched) — the exact damage shape a
// rolled-back campaign_state.json carries.
func r37bDropMirrorEvent(t *testing.T, c *Campaign, seq int64) {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	ev := validation.ObjAt(st, "events")
	kept := ev.A[:0]
	for _, e := range ev.A {
		if s := validation.ObjAt(e, "seq"); s.Kind == validation.Int && s.I == seq {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) != len(ev.A)-1 {
		t.Fatalf("fixture: expected to drop exactly seq %d", seq)
	}
	ev.A = kept
	st.O = validation.SetOrAppend(st.O, "events", ev)
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
}

// TestR37bMidHoleMirrorRefusesAndNamesTheMissingSeq pins the refusal: a
// mirror holding seq 3 where the ledger holds seq 2 is NOT a lagging copy
// (nothing was dropped from the ledger — the projection skips it), so the
// write must refuse, name both counts and the seq the projection skips,
// and leave ledger and projection byte-identical. The pre-fix write
// appended, printed success, and baked the hole permanently.
func TestR37bMidHoleMirrorRefusesAndNamesTheMissingSeq(t *testing.T) {
	c := r34Seed3(t, "C-r37bhole001")
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatal(err)
	}
	r37bDropMirrorEvent(t, c, 2) // mirror [0,1,3] over ledger [0,1,2,3]
	logBefore := r34Bytes(t, c.EventsPath)
	stBefore := r34Bytes(t, c.StatePath)
	_, err := c.Log("note.added", nil, nil)
	if err == nil {
		t.Fatal("a write observing a mid-hole mirror must REFUSE, not " +
			"append and bake the hole in behind a success line")
	}
	msg := err.Error()
	for _, want := range []string{
		"holds 4 event(s)", "mirrors 3", "where the ledger holds seq 2",
		"doctor",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal must name %q: %v", want, err)
		}
	}
	if got := r34Bytes(t, c.EventsPath); got != logBefore {
		t.Fatal("the refused write must leave the ledger byte-identical")
	}
	if got := r34Bytes(t, c.StatePath); got != stBefore {
		t.Fatal("the refused write must leave the projection byte-identical")
	}
	// The ledger is intact and verify's own gate still parses it — the
	// refusal adopted nothing and destroyed nothing.
	if _, err := c.Events(); err != nil {
		t.Fatal(err)
	}
}

// TestR37bLaggingPrefixHealsFromLogAndDiscloses pins the honest prefix
// shape: a mirror rolled back one event behind the ledger (the crash
// between the log append and the mirror save) must keep the write
// WORKING, and the healed projection must contain the event the stale
// mirror had never mirrored — no mid-hole baked. The heal is disclosed in
// the new event's hashed data and verify is green afterwards.
func TestR37bLaggingPrefixHealsFromLogAndDiscloses(t *testing.T) {
	c := r34Seed3(t, "C-r37blag0001")
	r37bDropMirrorEvent(t, c, 2) // mirror [0,1] over ledger [0,1,2]
	ev, err := c.Log("note.added", nil, nil)
	if err != nil {
		t.Fatalf("the sanctioned crash shape must keep working: %v", err)
	}
	if n := len(r34Mirror(t, c)); n != 4 {
		t.Fatalf("the healed mirror must hold all 4 events (no mid-hole), "+
			"got %d", n)
	}
	seqs := map[int64]bool{}
	for _, e := range r34Mirror(t, c) {
		if s := validation.ObjAt(e, "seq"); s.Kind == validation.Int {
			seqs[s.I] = true
		}
	}
	for _, want := range []int64{0, 1, 2, 3} {
		if !seqs[want] {
			t.Fatalf("healed mirror is missing seq %d — the hole was baked", want)
		}
	}
	lh := validation.ObjAt(validation.ObjAt(ev, "data"), "mirror_lag_healed")
	if lh.Kind != validation.Obj {
		t.Fatalf("the lag heal must be disclosed in the new event: %s",
			validation.DumpsOrdered(ev, false))
	}
	if got := validation.ObjAt(lh, "adopted_from_log"); got.Kind != validation.Int || got.I != 1 {
		t.Fatalf("adopted_from_log must be 1, got %s",
			validation.DumpsOrdered(ev, false))
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("verify must be GREEN after the lag heal: %v", v.Problems)
	}
}

// TestR37bEmptyMirrorOverLiveLedgerHeals pins the boundary case: a
// projection holding NO events under a live ledger is the lag shape taken
// to its end — appending onto it used to mirror ONLY the new event,
// erasing every ledger event from the projection. It heals from the
// ledger instead, with the full adoption disclosed.
func TestR37bEmptyMirrorOverLiveLedgerHeals(t *testing.T) {
	c := r34Seed3(t, "C-r37bempty01")
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.VArr())
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	ev, err := c.Log("note.added", nil, nil)
	if err != nil {
		t.Fatalf("an empty mirror under a live ledger must heal, not "+
			"erase the ledger from the projection: %v", err)
	}
	if n := len(r34Mirror(t, c)); n != 4 {
		t.Fatalf("the healed mirror must hold all 4 events, got %d", n)
	}
	lh := validation.ObjAt(validation.ObjAt(ev, "data"), "mirror_lag_healed")
	if lh.Kind != validation.Obj ||
		validation.ObjAt(lh, "adopted_from_log").I != 3 {
		t.Fatalf("the heal must disclose adopting 3 ledger events: %s",
			validation.DumpsOrdered(ev, false))
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("verify must be green after the heal: %v %v", v.Problems, err)
	}
}

// TestR37bHealthyCappedMirrorStillWrites pins the shape the heal must NOT
// touch: a ledger longer than the projection cap has a mirror SHORTER
// than the log on EVERY write (the mirror keeps the last 1000). That is
// tail-aligned health, not a crash shape: the write proceeds, discloses
// nothing, and the mirror stays the ledger's tail window.
func TestR37bHealthyCappedMirrorStillWrites(t *testing.T) {
	c, err := Init(t.TempDir(), "C-r37bcap0001", InitOpts{CampaignID: "C-r37bcap0001"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1002; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if n := len(r34Mirror(t, c)); n != 1000 {
		t.Fatalf("fixture: capped mirror must hold 1000, got %d", n)
	}
	logN, err := c.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	if logN != 1003 { // campaign.created + 1002 notes
		t.Fatalf("fixture: ledger must hold 1003, got %d", logN)
	}
	ev, err := c.Log("note.added", nil, nil)
	if err != nil {
		t.Fatalf("a tail-aligned capped mirror is health, not a crash "+
			"shape: %v", err)
	}
	if validation.ObjAt(validation.ObjAt(ev, "data"), "mirror_lag_healed").Kind != validation.Null {
		t.Fatalf("a healthy write must disclose nothing: %s",
			validation.DumpsOrdered(ev, false))
	}
	if n := len(r34Mirror(t, c)); n != 1000 {
		t.Fatalf("the capped mirror must stay at 1000, got %d", n)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	mirror := validation.ObjAt(st, "events").A
	if s := validation.ObjAt(mirror[len(mirror)-1], "seq"); s.Kind != validation.Int ||
		s.I != int64(logN) {
		t.Fatalf("the new event must sit at the mirror's tail, got %s",
			validation.DumpsOrdered(mirror[len(mirror)-1], false))
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("verify must be green: %v %v", v.Problems, err)
	}
}
