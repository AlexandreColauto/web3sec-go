package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r39b — the human surface may not omit what the JSON discloses.
//
// F1: printDoctor's if/else-if made the dropped branch dead whenever
// changed > 0, and on a capped mirror a head-cut log is the NORMAL
// truncation shape — the operator was told "this positional delta is all
// the evidence here" while 995 remembered events were erased without one
// line naming them. Two requirements pinned here: (a) the dropped (and
// added) counts reach the human IN ADDITION to the positional delta, and
// (b) the sentence says only what the comparison knows — an edit, a hole
// and a shift are indistinguishable from it; the delta is NOT "all the
// evidence". Checked on every doctor mode that can rebuild (--state-only
// and the default full doctor; --snapshot-only never rebuilds, it is a
// read-only scope report).
//
// P3 (last predicate copy): countLearnings counted a U+00A0-only line as
// blank (strings.TrimSpace) while state.BlankLine — the ONE framing
// predicate every other reader uses — counts it a record. One predicate
// now.
// ---------------------------------------------------------------------------

// r39bCutFixture returns (root, campaignID) in the F1 shape: a 10-event
// live ledger, a head-hole projection holding its last 8 events, then the
// documented partial-restore cut ('head -n 5 events.jsonl'). The rebuild
// is {kept:0, changed:5, dropped_from_projection:3, added_from_log:0}.
func r39bCutFixture(t *testing.T) (string, string) {
	t.Helper()
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	text := validation.VObj(validation.KV{K: "text", V: validation.VStr("r39b")})
	for i := 0; i < 9; i++ {
		if _, err := c.Log("note.added", nil, &text); err != nil {
			t.Fatal(err)
		}
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	evs := objAt(st, "events")
	if len(evs.A) != 10 {
		t.Fatalf("fixture: mirror must hold 10, got %d", len(evs.A))
	}
	st.O = validation.SetOrAppend(st.O, "events",
		validation.Value{Kind: validation.Arr, A: evs.A[2:]})
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
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
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:5], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, cid
}

func TestR39bDoctorHumanSurfaceNamesTheLoss(t *testing.T) {
	// One fresh fixture per mode: the first doctor run rebuilds the
	// mirror, so the second mode needs an undiverged campaign of its own.
	for _, mode := range [][]string{{"--state-only"}, {}} {
		root, cid := r39bCutFixture(t)
		args := append([]string{"--root", root, "doctor", cid}, mode...)
		code, out, errS := run(t, args...)
		if code != 0 {
			t.Fatalf("doctor %v exit %d: %q", mode, code, errS)
		}
		// The positional delta is still reported...
		if !strings.Contains(out, "5 mirrored events DISAGREE with the "+
			"log at the same positions") {
			t.Errorf("doctor %v: stdout lacks the positional delta: %q",
				mode, out)
		}
		// ...and the loss is named IN ADDITION, never instead.
		// r40c P3: and named in the right DIRECTION — the 3 rows exist
		// only in the projection; the log is the store that no longer
		// holds them (doctor.json: dropped_from_projection == 3).
		if !strings.Contains(out, "3 event(s) the projection remembered are "+
			"GONE from the log") {
			t.Errorf("doctor %v: stdout omits the erased 3 events: %q",
				mode, out)
		}
		if strings.Contains(out, "the projection lost") {
			t.Errorf("doctor %v: the r39 sentence is inverted again — the "+
				"projection did not lose the rows, the LOG no longer holds "+
				"them: %q", mode, out)
		}
		// (b) no claim the comparison cannot support.
		if strings.Contains(out, "all the evidence here") {
			t.Errorf("doctor %v: the positional delta is still called "+
				"'all the evidence here' — an edit, a hole and a shift "+
				"are NOT distinguishable from it: %q", mode, out)
		}
		if !strings.Contains(out, "indistinguishable from this comparison") {
			t.Errorf("doctor %v: the honest epistemics are gone: %q",
				mode, out)
		}
		// The safe instruction survives the reword.
		if !strings.Contains(out, "treat the campaign dir as tampered") {
			t.Errorf("doctor %v: the tamper instruction is gone: %q", mode, out)
		}
	}
}

// TestR39bVerifyAndAuditRefuseEmptyMirror is the finding's repro at verb
// level: with the state's events array set to [] under a live 2-event
// ledger, verify used to print ok:true and audit exited 0. Both must go
// red now.
func TestR39bVerifyAndAuditRefuseEmptyMirror(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatal(err)
	} // live 2-event ledger
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "events",
		validation.Value{Kind: validation.Arr, A: []validation.Value{}})
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "--root", root, "verify", cid)
	if code == 0 || strings.Contains(out, `"ok": true`) {
		t.Fatalf("verify certified an empty mirror under a live ledger: "+
			"exit %d, %q", code, out)
	}
	if !strings.Contains(out, "state events projection is EMPTY") {
		t.Errorf("verify must name the empty projection: %q", out)
	}
	code, _, _ = run(t, "--root", root, "audit", cid)
	if code == 0 {
		t.Fatalf("audit exited 0 over an empty mirror under a live ledger")
	}
}

// TestR39bSnapshotOnlyNeverRebuilds pins (c)'s negative half: the only
// mode that does NOT render the "state" block is --snapshot-only, and it
// must not rebuild anything either — SnapshotScope is a read-only scope
// report, so there is no rebuild-capable branch that skips the delta line.
func TestR39bSnapshotOnlyNeverRebuilds(t *testing.T) {
	root, cid := r39bCutFixture(t)
	code, out, errS := run(t, "--root", root, "doctor", cid, "--snapshot-only")
	if code != 0 {
		t.Fatalf("snapshot-only exit %d: %q", code, errS)
	}
	if strings.Contains(out, "rebuilt the events mirror") ||
		strings.Contains(out, "state:") {
		t.Errorf("--snapshot-only rendered state-repair output: %q", out)
	}
}

// TestR39bDoctorJSONDeltaUnchanged pins the JSON shape: the finding is about
// the human surface, so --json stays byte-for-byte the same fields.
func TestR39bDoctorJSONDeltaUnchanged(t *testing.T) {
	root, cid := r39bCutFixture(t)
	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only",
		"--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	stObj := data["state"].(map[string]any)
	delta := stObj["events_mirror_delta"].(map[string]any)
	for k, want := range map[string]float64{
		"kept":                    0,
		"changed":                 5,
		"dropped_from_projection": 3,
		"added_from_log":          0,
	} {
		if got := delta[k].(float64); got != want {
			t.Errorf("delta.%s = %v, want %v", k, got, want)
		}
	}
}

// TestR39bCountLearningsOnePredicate pins the P3: a U+00A0-only line is a
// RECORD to state.BlankLine, so the counter counts it — the TrimSpace copy
// that called it blank is gone.
func TestR39bCountLearningsOnePredicate(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	// Three lines: two records and one U+00A0-only line.
	body := "first\n\u00a0\nthird\n"
	if err := os.WriteFile(filepath.Join(c.Dir, "learnings.jsonl"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := countLearnings(c); got != 3 {
		t.Fatalf("countLearnings = %d, want 3 (the U+00A0-only line is a "+
			"record to state.BlankLine, the one predicate)", got)
	}
	// Honest ASCII blanks are still not records.
	if err := os.WriteFile(filepath.Join(c.Dir, "learnings.jsonl"),
		[]byte("first\n\n   \n\t\nthird\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := countLearnings(c); got != 2 {
		t.Fatalf("countLearnings = %d, want 2 (ASCII blank lines are blank)",
			got)
	}
}
