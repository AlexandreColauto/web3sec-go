package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r37b — honesty of the doctor surface (F6, F3, F2).
//
// F6: `doctor --state-only` bills a schema-dead state as green. Every
// other verb (the default doctor included) refuses a state that cannot be
// parsed/validated; StateHealth reads the RAW bytes without validating, so
// the flag-shaped path printed the clean bill a healthy campaign gets.
// Now it refuses, naming what was NOT checked.
//
// F3: the mirror-delta human line asserted "ADOPTED IN EDITED FORM ...
// treat the campaign dir as tampered" from a POSITIONAL comparison, which
// a mid-ledger hole (the r34/r37b crash window) fires with nobody having
// edited a byte. The line now names what the evidence actually shows — a
// positional disagreement an edit, a hole or a shift cannot be told apart
// from — without weakening the safe instruction.
//
// F2: the snapshot-only human line rendered a MISSING ground-truth pin as
// "snapshot <id>: None files, 0.0 MB" — an empty-but-present snapshot —
// because the printer had no exists/note branch. The human line carries
// the same exists/note fact the JSON carries now.
// ---------------------------------------------------------------------------

// r37bSchemaDead sets state.budget to a bare string, bypassing the writer
// schema — a state every verb refuses to load.
func r37bSchemaDead(t *testing.T, root, cid string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "budget", validation.VStr("not-an-object"))
	if err := validation.WriteJson(c.StatePath, st, ""); err != nil {
		t.Fatal(err)
	}
}

// TestR37bStateOnlyRefusesSchemaDeadState pins F6: --state-only on a state
// no verb can load must not print a clean bill. It does NOT refuse (doctor
// is the one repair path for a drifted state — the r14/r15 law and the
// r36b note-cap convergence pins stand on it reaching a schema-dead file);
// it says plainly that the state is unreadable and what was NOT checked,
// in the human line AND the JSON.
func TestR37bStateOnlyRefusesSchemaDeadState(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	r37bSchemaDead(t, root, cid)
	// The finding's own observation, kept as the fixture's contract:
	// every other verb refuses this state.
	code, _, errS := run(t, "--root", root, "doctor", cid)
	if code != 1 {
		t.Fatalf("default doctor exit %d, want 1 (fixture: the state is "+
			"schema-dead)", code)
	}
	if !strings.Contains(errS, "budget") {
		t.Fatalf("default doctor stderr = %q, want the budget schema error", errS)
	}
	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("--state-only exit %d: out=%q err=%q (the repair must "+
			"stay reachable for a drifted state)", code, out, errS)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "state:") {
		t.Fatalf("stdout must keep the bill but stop it being clean: %q", out)
	}
	for _, want := range []string{
		"cannot be parsed/validated",
		"NOT performed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want it to say %q", out, want)
		}
	}
	if strings.Index(out, "WARNING") > strings.Index(out, "state:") {
		t.Errorf("the warning must precede the size bill: %q", out)
	}
	// The JSON discloses the same fact (the human surface may not hide
	// what the JSON discloses, nor the reverse).
	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only",
		"--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	sv := data["state"].(map[string]any)["state_validation"].(map[string]any)
	if sv["ok"] != false {
		t.Fatalf("json must carry state_validation.ok=false: %s", out)
	}
	if !strings.Contains(sv["error"].(string), "budget") {
		t.Fatalf("json must carry the validation error: %s", out)
	}
}

// TestR37bTamperWarningNamesWhatIsKnown pins F3: the changed>0 mirror
// delta must stop asserting "ADOPTED IN EDITED FORM" (a positional
// comparison cannot know that) and must keep the safe tamper instruction.
// The JSON delta shape is unchanged.
func TestR37bTamperWarningNamesWhatIsKnown(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	d := validation.VObj(validation.KV{K: "text", V: validation.VStr("original")})
	if _, err := c.Log("note.added", nil, &d); err != nil {
		t.Fatal(err)
	}
	// Edit the PROJECTION's copy of the note event only (no byte of the
	// ledger is touched): the rebuild then reports changed=1.
	editMirror := func() {
		st, err := c.State()
		if err != nil {
			t.Fatal(err)
		}
		evs := objAt(st, "events")
		for i := range evs.A {
			if objStr(evs.A[i], "type") != "note.added" {
				continue
			}
			data := objAt(evs.A[i], "data")
			data.O = validation.SetOrAppend(data.O, "text",
				validation.VStr("projection-only edit"))
			evs.A[i].O = validation.SetOrAppend(evs.A[i].O, "data", data)
		}
		st.O = validation.SetOrAppend(st.O, "events", evs)
		if err := c.SaveState(st); err != nil {
			t.Fatal(err)
		}
	}
	editMirror()
	// JSON shape unchanged: the delta still counts what moved.
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
	if stObj["events_mirror_rebuilt"] != true {
		t.Fatalf("fixture must rebuild the mirror: %s", out)
	}
	delta := stObj["events_mirror_delta"].(map[string]any)
	if delta["changed"].(float64) != 1 {
		t.Fatalf("delta.changed must be 1: %s", out)
	}
	// The human line: what is known, not what the count cannot prove.
	editMirror() // the first doctor run rebuilt the projection; re-diverge
	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("human exit %d: %q", code, errS)
	}
	if strings.Contains(out, "ADOPTED IN EDITED FORM") {
		t.Fatalf("the human line still asserts EDITED, which the "+
			"positional delta cannot know: %q", out)
	}
	for _, want := range []string{
		"DISAGREE with the log at the same positions",
		"treat the campaign dir as tampered",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want %q", out, want)
		}
	}
}

// r37bPinFixture pins a snapshot through the state API (no snapshot dir is
// needed at the projection layer) — the pinheal fixture shape.
func r37bPinFixture(t *testing.T, root, cid string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	snap := validation.VObj(
		validation.KV{K: "snapshot_id", V: validation.VStr("src-content-0000000000ab")},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "created_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "pass", V: validation.VInt(1)},
		validation.KV{K: "pinned", V: validation.VBool(true)},
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "ladder", V: validation.VStr("no-vcs")},
			validation.KV{K: "git_commit", V: validation.VNull()},
			validation.KV{K: "git_dirty", V: validation.VNull()},
			validation.KV{K: "content_hash", V: validation.VStr(strings.Repeat("a", 64))},
			validation.KV{K: "root", V: validation.VStr("/tmp/x")},
			validation.KV{K: "file_count", V: validation.VInt(0)},
		)},
		validation.KV{K: "deployment", V: validation.VNull()},
		validation.KV{K: "chain", V: validation.VNull()},
	)
	if _, err := c.PinSnapshot(snap); err != nil {
		t.Fatal(err)
	}
}

// TestR37bHumanSurfaceCarriesMissingPin pins F2: with the pinned
// snapshot's directory gone, the JSON says exists:false + note; the human
// line must carry the same fact instead of "None files, 0.0 MB".
func TestR37bHumanSurfaceCarriesMissingPin(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	r37bPinFixture(t, root, cid)
	// Remove the ground truth the pin names.
	snapDir := root + "/campaigns/" + cid + "/snapshots/src-content-0000000000ab"
	if err := os.RemoveAll(snapDir); err != nil {
		t.Fatal(err)
	}
	// JSON stays honest (unchanged shape).
	code, out, errS := run(t, "--root", root, "doctor", cid,
		"--snapshot-only", "--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	snap := data["snapshot"].(map[string]any)
	if snap["exists"] != false {
		t.Fatalf("json must report exists:false: %s", out)
	}
	if snap["note"] == "" {
		t.Fatalf("json must carry the note: %s", out)
	}
	// The human line carries the same fact now.
	code, out, errS = run(t, "--root", root, "doctor", cid, "--snapshot-only")
	if code != 0 {
		t.Fatalf("human exit %d: %q", code, errS)
	}
	if strings.Contains(out, "None files") {
		t.Fatalf("a missing pin must not read as empty-but-present: %q", out)
	}
	for _, want := range []string{
		"MISSING",
		"snapshot src-content-0000000000ab directory missing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout = %q, want %q", out, want)
		}
	}
}
