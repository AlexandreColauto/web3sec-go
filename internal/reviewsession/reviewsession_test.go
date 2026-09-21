package reviewsession

import (
	"strings"
	"testing"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

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
