package reviewsession

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// lockWindow is how long the sibling writer holds the campaign lock while the
// production call is in flight. It only has to dwarf an unlocked State() read
// (microseconds), which is what makes the interleave below deterministic.
const lockWindow = 200 * time.Millisecond

func campaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStartThenEndRecordsBothEvents(t *testing.T) {
	c := campaign(t)
	s, err := Start(c, "operator", []string{"ART-aaaa1111", "src/V.sol"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	sid := validation.ObjStr(s, "session_id")
	if !strings.HasPrefix(sid, "RS-") {
		t.Fatalf("session_id = %q, want an RS- id", sid)
	}
	if _, err := End(c, sid, "operator", 412); err != nil {
		t.Fatalf("end: %v", err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range evs {
		seen[validation.ObjStr(e, "type")] = true
	}
	for _, want := range []string{"review_session.started", "review_session.ended"} {
		if !seen[want] {
			t.Errorf("no %s event", want)
		}
	}
}

func TestEndRefusesAnUnknownOrDoubleClosedSession(t *testing.T) {
	c := campaign(t)
	if _, err := End(c, "RS-deadbeef", "operator", 10); err == nil ||
		!strings.Contains(err.Error(), "no open review session") {
		t.Fatalf("err = %v, want the unknown-session refusal", err)
	}
	s, err := Start(c, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(s, "session_id")
	if _, err := End(c, sid, "operator", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := End(c, sid, "operator", 20); err == nil {
		t.Fatal("a second end on the same session must be refused")
	}
}

func TestStartRefusesASecondOpenSession(t *testing.T) {
	c := campaign(t)
	if _, err := Start(c, "operator", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(c, "operator", nil); err == nil ||
		!strings.Contains(err.Error(), "already open") {
		t.Fatalf("err = %v, want the one-open-session refusal", err)
	}
}

// TestReviewSessionUsesRealWallClock pins the difference between telemetry
// and a fixture: WEBV2_NOW is a golden-recipe TEST pin, so an operator run
// must read the real clock. Two sessions a second apart that share
// started_at can only mean the clock was pinned — this test cannot pass on a
// fixed date.
func TestReviewSessionUsesRealWallClock(t *testing.T) {
	t.Setenv("WEBV2_NOW", "") // the pin must not be in play
	c := campaign(t)
	first, err := Start(c, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := End(c, validation.ObjStr(first, "session_id"), "operator", 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := Start(c, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(first, "started_at") == validation.ObjStr(second, "started_at") {
		t.Fatal("two sessions a second apart share started_at — the clock is pinned")
	}
}

// TestStartHoldsTheCampaignLockAcrossTheReadModifyWrite pins the r14 law
// (internal/state/campaign.go's "any read-modify-write of campaign_state
// holds the campaign lock for its whole duration", internal/floors/floors.go's
// incident) for the review_sessions projection: a sibling writer that lands
// between Start's State() read and its SaveState must NOT vanish. Before the
// fix Start read unlocked and saved unlocked-then-locked, so the sibling's
// row was clobbered while both callers exited 0.
//
// The sibling is a SECOND *state.Campaign over the same directory: flock is
// held per open-file-description, so its lock really contends with the one
// Start takes (LockProcess on the same object would re-enter by depth and
// prove nothing). The lockWindow hold is the interleave: an unlocked read
// finishes in microseconds, so on the unfixed code Start's write provably
// lands after the sibling's row, while the fixed Start is parked on the lock
// and therefore reads the sibling's row.
func TestStartHoldsTheCampaignLockAcrossTheReadModifyWrite(t *testing.T) {
	c := campaign(t)
	sibling := lockSibling(t, c)
	defer sibling.UnlockProcess()
	started := make(chan error, 1)
	go func() {
		_, err := Start(c, "operator", nil)
		started <- err
	}()
	time.Sleep(lockWindow)
	sid := "RS-sibling1"
	siblingWrite(t, sibling, closedSessionRow(sid))
	sibling.UnlockProcess()
	if err := <-started; err != nil {
		t.Fatalf("Start: %v", err)
	}
	rows := sessionRows(t, c)
	if len(rows) != 2 {
		t.Fatalf("the review_sessions projection holds %d row(s), want 2: "+
			"Start's read-modify-write clobbered the sibling's row", len(rows))
	}
	if !hasSession(rows, sid) {
		t.Fatalf("sibling session %s vanished from the projection", sid)
	}
}

// TestRefusedStartRestoresThePreWriteStateBytes pins the unwind half of the
// paired write: a Start whose ledger append is refused must leave
// campaign_state.json BYTE-IDENTICAL to the file it found (state.RawState /
// state.UnwindState, the r16/r17 door). The old unwind re-saved the parsed
// prior value through SaveState, which bumps updated_at — so the two clock
// pins below make the difference unmissable: the pre-write file carries pin
// A, and only a byte restore puts pin A back.
func TestRefusedStartRestoresThePreWriteStateBytes(t *testing.T) {
	const pinA = "2026-01-01T00:00:00.000000+00:00"
	const pinB = "2026-01-02T00:00:00.000000+00:00"
	t.Setenv("WEBV2_NOW", pinA)
	c := campaign(t)
	cutLedger(t, c) // the state mirror is now longer than the log
	before := stateSha(t, c.StatePath)
	t.Setenv("WEBV2_NOW", pinB)
	if _, err := Start(c, "operator", nil); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("refused start err = %v, want the ledger refusal", err)
	}
	if after := stateSha(t, c.StatePath); after != before {
		t.Fatalf("the refused start rewrote campaign_state.json instead of "+
			"restoring its bytes:\n before %s\n after  %s", before, after)
	}
	if rows := sessionRows(t, c); len(rows) != 0 {
		t.Fatalf("the refused start left %d review_sessions row(s) behind", len(rows))
	}
	if hasEvent(t, c, "review_session.started") {
		t.Fatal("the refused start logged review_session.started anyway")
	}
}

// lockSibling opens a second campaign object on the same directory and takes
// the cross-process lock it owns (its own fd, so it contends).
func lockSibling(t *testing.T, c *state.Campaign) *state.Campaign {
	t.Helper()
	sibling, err := state.Open(c.Root, c.CampaignID)
	if err != nil {
		t.Fatal(err)
	}
	if err := sibling.LockProcess(); err != nil {
		t.Fatal(err)
	}
	return sibling
}

// siblingWrite is the locked read-modify-write a sibling verb performs: load,
// append one projection row, save, log.
func siblingWrite(t *testing.T, c *state.Campaign, row validation.Value) {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	rows := append(validation.ObjAt(st, projectionKey).A, row)
	st.O = validation.SetOrAppend(st.O, projectionKey, validation.VArr(rows...))
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(row, "session_id")
	if _, err := c.Log("review_session.ended", &sid, &row); err != nil {
		t.Fatal(err)
	}
}

// closedSessionRow is a schema-valid review_sessions row for a finished
// session (the shape a sibling writer's projection holds).
func closedSessionRow(sid string) validation.Value {
	return validation.VObj(
		validation.KV{K: "session_id", V: validation.VStr(sid)},
		validation.KV{K: "actor", V: validation.VStr("sibling")},
		validation.KV{K: "started_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "ended_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "artifacts_covered", V: validation.VArr()},
		validation.KV{K: "loc", V: validation.VInt(7)},
		validation.KV{K: "open", V: validation.VBool(false)},
	)
}

func sessionRows(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(st, projectionKey).A
}

func hasSession(rows []validation.Value, sid string) bool {
	for _, r := range rows {
		if validation.ObjStr(r, "session_id") == sid {
			return true
		}
	}
	return false
}

// cutLedger grows the ledger, then cuts its last line so the state mirror is
// LONGER than the log: the next Log refuses (r40e's ledger-door fixture).
func cutLedger(t *testing.T, c *state.Campaign) {
	t.Helper()
	data := validation.VObj(validation.KV{K: "note", V: validation.VStr("ledger growth")})
	for i := 0; i < 3; i++ {
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	cut := strings.Join(lines[:len(lines)-1], "\n") + "\n"
	if err := os.WriteFile(c.EventsPath, []byte(cut), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stateSha(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func hasEvent(t *testing.T, c *state.Campaign, eventType string) bool {
	t.Helper()
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evts {
		if validation.ObjStr(e, "type") == eventType {
			return true
		}
	}
	return false
}
