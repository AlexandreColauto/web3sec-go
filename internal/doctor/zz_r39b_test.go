package doctor

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r39b — the JSON delta discloses the loss; the human surface must carry it.
//
// F1's shape: the documented partial-restore cut ('head -n 5 events.jsonl')
// on a log whose mirror held MORE events than the cut log leaves. The
// rebuild is positional (mirrorDelta compares same-index rows), so the delta
// comes back {kept:0, changed:5, dropped_from_projection:3,
// added_from_log:0} — the dropped rows are the projection's memory that the
// rebuild ERASES, and the JSON discloses them. The CLI's human renderer had
// an if/else-if that made the dropped branch dead whenever changed > 0 (the
// NORMAL shape on a capped mirror), so the operator never saw the loss; this
// pins the JSON facts the human surface is required to carry.
// ---------------------------------------------------------------------------

// zzR39bCutFixture builds a 10-event live ledger, points the projection at
// a head-hole mirror of its last 8 events, then applies the documented
// partial-restore cut (head -n 5) to the log. The rebuild from the cut log
// then differs from the old mirror at every one of the 5 overlapping
// positions (changed=5) AND erases 3 rows the projection remembered
// (dropped=3) — changed and dropped together, the shape the old renderer
// could not report honestly.
func zzR39bCutFixture(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r39b doctor", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	text := validation.VObj(validation.KV{K: "text", V: validation.VStr("r39b")})
	for i := 0; i < 9; i++ {
		if _, err := c.Log("note.added", nil, &text); err != nil {
			t.Fatal(err)
		}
	} // live 10-event ledger
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	evs := objAt(st, "events")
	if len(evs.A) != 10 {
		t.Fatalf("fixture: mirror must hold 10, got %d", len(evs.A))
	}
	// Head-hole mirror: the projection holds only the last 8 events.
	st.O = validation.SetOrAppend(st.O, "events",
		validation.Value{Kind: validation.Arr, A: evs.A[2:]})
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	// The documented partial-restore cut: keep the first 5 log lines.
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, ln := range strings.Split(string(raw), "\n") {
		if ln == "" {
			continue
		}
		lines = append(lines, ln)
	}
	if len(lines) != 10 {
		t.Fatalf("fixture: log must hold 10 lines, got %d", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:5], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestR39bStateHealthDeltaDisclosesTheLoss pins the JSON side of F1.
func TestR39bStateHealthDeltaDisclosesTheLoss(t *testing.T) {
	c := zzR39bCutFixture(t)
	res, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(res, "events_mirror_rebuilt").B {
		t.Fatalf("fixture must rebuild the mirror: %s", validation.PyRepr(res))
	}
	d := objAt(res, "events_mirror_delta")
	for k, want := range map[string]int64{
		"kept":                    0,
		"changed":                 5,
		"dropped_from_projection": 3,
		"added_from_log":          0,
	} {
		if got := objAt(d, k); got.Kind != validation.Int || got.I != want {
			t.Errorf("delta.%s = %s, want %d", k, validation.PyRepr(got), want)
		}
	}
	// The rebuild actually happened: the mirror now matches the cut log.
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(st, "events").A); got != 5 {
		t.Errorf("mirror after rebuild holds %d events, want 5", got)
	}
}
