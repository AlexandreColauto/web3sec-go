package sections

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestProjectionStateRowsPolicedWithoutEvents pins r10 issue 1: the
// snapshot-row direction used to be gated on the ledger holding at least
// one snapshot.pinned event — so stripping the event from BOTH ledger
// copies (events.jsonl tail AND state.events, the r9 lie's second
// disguise) produced a green audit over a state that still listed a
// snapshot the ledger never recorded. The check is unconditional now.
func TestProjectionStateRowsPolicedWithoutEvents(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "C-proj", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Hand-forge the lying projection: a state snapshot row + active id,
	// with NO snapshot.pinned event anywhere (the file was written by a
	// pin whose event was then erased from both copies).
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	row := validation.VObj(
		validation.KV{K: "snapshot_id", V: validation.VStr("src-content-000000000000")},
		validation.KV{K: "pass", V: validation.VInt(1)},
		validation.KV{K: "pinned", V: validation.VBool(true)},
		validation.KV{K: "registered_at", V: validation.VStr(state.NowIso())},
	)
	st.O = validation.SetOrAppend(st.O, "snapshots",
		validation.VArr(row))
	st.O = validation.SetOrAppend(st.O, "active_snapshot_id",
		validation.VStr("src-content-000000000000"))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Join
	sec, err := Projection(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(sec, "ok").B {
		t.Fatal("a state-only snapshot with no ledger event must NOT audit green")
	}
	var msgs []string
	for _, p := range objAt(sec, "problems").A {
		msgs = append(msgs, p.S)
	}
	if !strings.Contains(strings.Join(msgs, "\n"),
		"state lists snapshot src-content-000000000000 with no snapshot.pinned event") {
		t.Fatalf("twin message expected, got %v", msgs)
	}
}
