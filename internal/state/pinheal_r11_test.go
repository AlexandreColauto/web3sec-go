package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestRePinHealsStrippedPinnedEvent pins r11 issue 1: an erased
// snapshot.pinned (both ledger copies) used to make the projection check
// unhealable — re-pin no-oped because the STATE row existed, and the only
// exit was the hand-edit the audit exists to catch. The event decision
// now keys on the LEDGER: a re-pin whose id has no pinned event re-emits
// it, disclosed as reconciled.
func TestRePinHealsStrippedPinnedEvent(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "C-heal0000001", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Pin one snapshot manually through the state API (no snapshot dir
	// needed for the projection layer):
	snap := validation.VObj(
		kv("snapshot_id", validation.VStr("src-content-0000000000ab")),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr(NowIso())),
		kv("pass", validation.VInt(1)),
		kv("pinned", validation.VBool(true)),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("no-vcs")),
			kv("git_commit", validation.VNull()),
			kv("git_dirty", validation.VNull()),
			kv("content_hash", validation.VStr(strings.Repeat("a", 64))),
			kv("root", validation.VStr("/tmp/x")),
			kv("file_count", validation.VInt(0)),
		)),
		kv("deployment", validation.VNull()),
		kv("chain", validation.VNull()),
	)
	if _, err := c.PinSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	// Erase the event from BOTH copies (strip the tail line):
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	stripped := strings.Join(lines[:len(lines)-1], "\n")
	if !strings.Contains(stripped, "campaign.pinned") && len(lines) > 1 {
		// last line is snapshot.pinned by construction
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(stripped+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The state-side events mirror tail: trim its last entry too.
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	ev := objAt(st, "events")
	if ev.Kind == validation.Arr && len(ev.A) > 0 {
		ev.A = ev.A[:len(ev.A)-1]
		st.O = validation.SetOrAppend(st.O, "events", ev)
		if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
			t.Fatal(err)
		}
	}
	// Projection now lists a state row with no event. Re-pin the SAME
	// snapshot: must RE-EMIT, not noop.
	if _, err := c.PinSnapshot(snap); err != nil {
		t.Fatalf("heal re-pin must succeed: %v", err)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	found, reconciled := false, false
	for _, e := range evts {
		if objStr(e, "type") == "snapshot.pinned" &&
			objStr(e, "ref") == "src-content-0000000000ab" {
			found = true
			if objAt(e, "data").Kind == validation.Obj {
				for _, k := range objAt(e, "data").O {
					if k.K == "reconciled" {
						reconciled = true
					}
				}
			}
		}
	}
	if !found || !reconciled {
		t.Fatalf("heal event must land marked reconciled: found=%v rec=%v",
			found, reconciled)
	}
	// Third re-pin: event exists now -> no-op (no duplicate).
	if _, err := c.PinSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	evts, _ = c.Events()
	n := 0
	for _, e := range evts {
		if objStr(e, "type") == "snapshot.pinned" {
			n++
		}
	}
	if n != 1 { // one heal (the original was erased), no third emission
		t.Fatalf("no-op must NOT duplicate the event; got %d pinned events", n)
	}
}

func init() { _ = filepath.Join }
