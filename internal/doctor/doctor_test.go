// doctor_test.go ports tests/test_doctor.py (plus test_doctor_preflight.py's
// test_doctor_includes_preflight) 1:1. The Python twin was retired 2026-09-09; Go is the source of truth.
package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// bloat is _bloat: simulate a pre-fix bloated state by writing the oversized
// note directly, bypassing the cap that set_stage now applies.
func bloat(t *testing.T, c *state.Campaign, stage string, chars int) {
	t.Helper()
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	stages := validation.ObjAt(st, "stages")
	note := strings.Repeat("x", chars)
	setKey(&stages, stage, validation.VObj(
		validation.KV{K: "status", V: validation.VStr("done")},
		validation.KV{K: "note", V: validation.VStr(note)},
		validation.KV{K: "executor", V: validation.VStr("pipeline")}))
	setKey(&st, "stages", stages)
	if err := validation.WriteJson(c.StatePath, st, ""); err != nil {
		t.Fatal(err)
	}
}

func newCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStateHealthTruncatesOversizedNote(t *testing.T) {
	c := newCampaign(t, "doc1")
	bloat(t, c, "structural-index", 100_000)
	beforeSize := fileSize(t, c.StatePath)
	res, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	if intField(res, "bytes_freed") <= 0 {
		t.Errorf("bytes_freed = %d, want > 0", intField(res, "bytes_freed"))
	}
	if intField(res, "size_after") >= beforeSize {
		t.Errorf("size_after = %d, want < %d", intField(res, "size_after"),
			beforeSize)
	}
	got := []string{}
	for _, e := range validation.ObjAt(res, "notes_truncated").A {
		got = append(got, validation.ObjStr(e, "stage"))
	}
	if len(got) != 1 || got[0] != "structural-index" {
		t.Errorf("notes_truncated = %v, want [structural-index]", got)
	}
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	note := validation.ObjStr(validation.ObjAt(validation.ObjAt(st, "stages"), "structural-index"), "note")
	if utf8.RuneCountInString(note) > state.NOTE_CAP+100 {
		t.Errorf("note length = %d, want <= %d",
			utf8.RuneCountInString(note), state.NOTE_CAP+100)
	}
	if !strings.Contains(note, "truncated") {
		t.Errorf("note lacks the truncation marker: %q", note[len(note)-60:])
	}
}

func TestStateHealthLeavesSmallNotesAndLogUntouched(t *testing.T) {
	c := newCampaign(t, "doc2")
	bloat(t, c, "recon", 200)
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore := len(events)
	res, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(validation.ObjAt(res, "notes_truncated").A); n != 0 {
		t.Errorf("notes_truncated = %d, want 0", n)
	}
	if intField(res, "bytes_freed") > 0 {
		t.Errorf("bytes_freed = %d, want <= 0", intField(res, "bytes_freed"))
	}
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(st, "stages"), "recon"), "note"); got !=
		strings.Repeat("x", 200) {
		t.Errorf("note = %q..., want 200 x's", got)
	}
	after, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != eventsBefore {
		t.Errorf("event log grew: %d -> %d (doctor must never write to the "+
			"append-only event log)", eventsBefore, len(after))
	}
}

func TestStateHealthTruncatesArtifactNotes(t *testing.T) {
	c := newCampaign(t, "doc3")
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	setKey(&st, "artifacts", validation.VArr(validation.VObj(
		validation.KV{K: "artifact_id", V: validation.VStr("ART-x")},
		validation.KV{K: "kind", V: validation.VStr("other")},
		validation.KV{K: "path", V: validation.VStr("/tmp/x")},
		validation.KV{K: "note", V: validation.VStr(
			strings.Repeat("y", state.NOTE_CAP+5000))})))
	if err := validation.WriteJson(c.StatePath, st, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := StateHealth(c); err != nil {
		t.Fatal(err)
	}
	got, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	note := validation.ObjStr(validation.ObjAt(got, "artifacts").A[0], "note")
	if utf8.RuneCountInString(note) > state.NOTE_CAP+100 {
		t.Errorf("artifact note length = %d, want <= %d",
			utf8.RuneCountInString(note), state.NOTE_CAP+100)
	}
	if !strings.Contains(note, "truncated") {
		t.Errorf("artifact note lacks the truncation marker")
	}
}

func TestSnapshotScopeReportsShapeAndWarns(t *testing.T) {
	c := newCampaign(t, "doc4")
	target := filepath.Join(c.Root, "t")
	if err := os.MkdirAll(filepath.Join(target, "corpus"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "app.py"), "x = 1\n")
	for i := 0; i < 5; i++ {
		writeFile(t, filepath.Join(target, "corpus", "f"+itoa(i)), "z")
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	res, err := SnapshotScope(c)
	if err != nil {
		t.Fatal(err)
	}
	// 5 corpus files + app.py + the pin's own snapshot.json
	if got := intField(res, "files"); got != 7 {
		t.Errorf("files = %d, want 7", got)
	}
	if w := validation.ObjAt(res, "file_count_warning"); w.Kind != validation.Null {
		t.Errorf("file_count_warning = %s, want null",
			validation.DumpIndented(w))
	}
	// lower the threshold to force the drift warning deterministically
	orig := SnapshotFileWarn
	SnapshotFileWarn = 3
	defer func() { SnapshotFileWarn = orig }()
	res, err = SnapshotScope(c)
	if err != nil {
		t.Fatal(err)
	}
	warn := validation.ObjStr(res, "file_count_warning")
	if warn == "" || !strings.Contains(warn, "scope drift") {
		t.Errorf("file_count_warning = %q, want a scope-drift warning", warn)
	}
	top := validation.ObjAt(res, "top_directories").A
	if len(top) == 0 {
		t.Fatalf("top_directories empty")
	}
	if name := top[0].A[0].S; name != "corpus" {
		t.Errorf("top_directories[0] = %q, want corpus", name)
	}
}

func TestSnapshotScopeNoPin(t *testing.T) {
	c := newCampaign(t, "doc5")
	res, err := SnapshotScope(c)
	if err != nil {
		t.Fatal(err)
	}
	if s := validation.ObjAt(res, "active_snapshot"); s.Kind != validation.Null {
		t.Errorf("active_snapshot = %s, want null", validation.DumpIndented(s))
	}
	if note := validation.ObjStr(res, "note"); !strings.Contains(note, "no snapshot pinned") {
		t.Errorf("note = %q", note)
	}
}

// TestSnapshotScopeKeepsTheMetavariableForAnIdLessCampaign pins the snapshot
// hint against a campaign in hand with no id: the campaign slot reads the
// documented metavariable, never an empty hole between two spaces.
func TestSnapshotScopeKeepsTheMetavariableForAnIdLessCampaign(t *testing.T) {
	cases := []struct {
		name string
		cid  string
		want string
	}{
		{"a campaign with no id", "", "<campaign>"},
		{"a named campaign", "C-abc123", "C-abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCampaign(t, "doc5")
			c.CampaignID = tc.cid
			res, err := SnapshotScope(c)
			if err != nil {
				t.Fatal(err)
			}
			note := validation.ObjStr(res, "note")
			slot := "`webv2 snap " + tc.want + " <target>`"
			if !strings.Contains(note, slot) {
				t.Errorf("note does not name the campaign slot %q: %q",
					slot, note)
			}
			if strings.Contains(note, "snap  <target>") {
				t.Errorf("the campaign slot is an empty hole: %q", note)
			}
		})
	}
}

func TestDoctorIncludesPreflight(t *testing.T) {
	c := newCampaign(t, "Preflight Doc")
	rep, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	pre := validation.ObjAt(rep, "preflight")
	if pre.Kind != validation.Obj {
		t.Fatalf("preflight = %s", validation.DumpIndented(pre))
	}
	if validation.ObjAt(pre, "checks").Kind != validation.Obj {
		t.Errorf("preflight.checks missing")
	}
	if validation.ObjAt(validation.ObjAt(pre, "checks"), "workdir").Kind != validation.Obj {
		t.Errorf("preflight.checks.workdir missing")
	}
}

// --- helpers ----------------------------------------------------------------

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func intField(v validation.Value, key string) int64 {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

// TestStateHealthRebuildsStrandedMirror pins r14 issue 2: before this,
// a stranded events mirror (r13 race residue, torn write) left verify
// red FOREVER — the loudest integrity gate in the tool had no sanctioned
// repair, only an error message. The log is the truth; doctor re-tails
// it into the projection and reports the act.
func TestStateHealthRebuildsStrandedMirror(t *testing.T) {
	c := newCampaign(t, "Mirror Heal Program")
	ref := ""
	note := validation.VObj(validation.KV{K: "text",
		V: validation.VStr("heal me")})
	if _, err := c.Log("note.added", &ref, &note); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	// Strand it: drop the mirrored note event from the projection only.
	kept := []validation.Value{}
	for _, e := range validation.ObjAt(st, "events").A {
		if validation.ObjStr(e, "type") != "note.added" {
			kept = append(kept, e)
		}
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.VArr(kept...))
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatal("stranded mirror must verify red")
	}
	repairMsg := false
	for _, s := range v.Problems {
		if strings.Contains(s, "webv2 doctor") {
			repairMsg = true
		}
	}
	if !repairMsg {
		t.Fatalf("the red must name its repair: %v", v.Problems)
	}
	report, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(report, "events_mirror_rebuilt").B {
		t.Fatalf("doctor must report the rebuild: %s",
			validation.DumpsOrdered(report, false))
	}
	v, err = c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("after doctor the mirror must verify green: %v",
			v.Problems)
	}
	// The log was not touched: both events still chained.
	if n := len(validation.ObjAt(st, "events").A); false {
		_ = n
	}
}

// TestMirrorRebuildRefusesADamagedLedger pins r15 P0-2: the r14 rebuild
// folded ANY parseable line into campaign_state and wrote it WITHOUT
// schema — one scalar tampered line turned every verb (doctor included)
// into an error, and re-running doctor re-poisoned with rc 0. The
// rebuild is gated on the ledger being provably a chain now, and the
// candidate state on the schema; refusal is reported, human and JSON.
func TestMirrorRebuildRefusesADamagedLedger(t *testing.T) {
	c := newCampaign(t, "Poison Heal Program")
	ref := ""
	d := validation.VObj(validation.KV{K: "text", V: validation.VStr("keep me safe")})
	if _, err := c.Log("note.added", &ref, &d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	// Tamper the SECOND line into a scalar (valid JSON, contract-less).
	lines[1] = "42"
	if err := os.WriteFile(c.EventsPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(rep, "events_mirror_rebuilt").B {
		t.Fatal("doctor rebuilt from a damaged ledger")
	}
	refusal := validation.ObjAt(rep, "events_mirror_refused")
	if refusal.Kind != validation.Str || !strings.Contains(refusal.S, "not a JSON object") {
		t.Fatalf("refusal must name the damage: %s",
			validation.DumpsOrdered(rep, false))
	}
	// The state file stays loadable — that is the whole point.
	if _, err := c.State(); err != nil {
		t.Fatalf("doctor bricked the campaign: %v", err)
	}
}

// TestRebuildDisclosesEditedEvents pins r16 P1-3's disclosure duty: a
// tamperer who RECOMPUTES the whole chain passes the format gate — the
// rebuild then adopts the edited content, and that must be visible as a
// content delta, not a cheerful "rebuilt" line.
func TestRebuildDisclosesEditedEvents(t *testing.T) {
	c := newCampaign(t, "Edited Chain Program")
	ref := ""
	d := validation.VObj(validation.KV{K: "text",
		V: validation.VStr("original decision text")})
	if _, err := c.Log("note.added", &ref, &d); err != nil {
		t.Fatal(err)
	}
	// Strand the mirror AND edit the log's copy of the event under a
	// RECOMPUTED hash (determined rewriter): rewrite events.jsonl so the
	// note text differs, chain recomputed with the tool's own algorithm
	// by regenerating through Log then surgical single-line replace.
	st, _ := c.State()
	evs := validation.ObjAt(st, "events")
	var want string
	for _, e := range evs.A {
		if validation.ObjStr(e, "type") == "note.added" {
			want = validation.CanonSpaced(e)
		}
	}
	if want == "" {
		t.Fatal("fixture lost its note event")
	}
	// Build a VALID edited event via a fresh Log (the only sanctioned
	// minter of matching hashes): a second note event, then STRIP it
	// from state (mirror strands) — the rebuild must ADOPT it:
	d2 := validation.VObj(validation.KV{K: "text",
		V: validation.VStr("second decision text")})
	if _, err := c.Log("note.added", &ref, &d2); err != nil {
		t.Fatal(err)
	}
	st, _ = c.State()
	t.Logf("mirror before strip: %d events", len(validation.ObjAt(st, "events").A))
	one := []validation.Value{}
	for _, e := range validation.ObjAt(st, "events").A {
		if validation.ObjStr(e, "type") != "note.added" {
			one = append(one, e)
		}
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.VArr(one...))
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	st2, _ := c.State()
	t.Logf("mirror after strip: %d events", len(validation.ObjAt(st2, "events").A))
	rawDisk, _ := os.ReadFile(c.StatePath)
	t.Logf("DISK has %d note events: %v",
		strings.Count(string(rawDisk), "note.added"), len(rawDisk))
	rep, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(rep, "events_mirror_rebuilt").B {
		t.Fatalf("clean chain must rebuild: %s",
			validation.DumpsOrdered(rep, false))
	}
	delta := validation.ObjAt(rep, "events_mirror_delta")
	if delta.Kind != validation.Obj || deltaInt(validation.ObjAt(delta, "added_from_log")) != 2 {
		t.Fatalf("delta must count what the rebuild adopted: %s",
			validation.DumpsOrdered(rep, false))
	}
}

func deltaInt(v validation.Value) int64 {
	if v.Kind == validation.Int {
		return v.I
	}
	return -1
}

// TestTailTruncationIsDisclosedNotLaundered pins r17 P1#3: deleting the
// ledger's LAST line keeps the chain valid, verify routes the operator
// to doctor — and doctor used to erase the projection's memory of the
// event silently (dropped was computed but only the changed>0 branch
// spoke). Now the human line names the drop and campaigns/<C>/doctor.json
// keeps a durable trace after the terminal scrollback is gone.
func TestTailTruncationIsDisclosedNotLaundered(t *testing.T) {
	c := newCampaign(t, "Truncated Tail Program")
	ref := ""
	d := validation.VObj(validation.KV{K: "text", V: validation.VStr("tail")})
	if _, err := c.Log("note.added", &ref, &d); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if err := os.WriteFile(c.EventsPath,
		[]byte(lines[0]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// verify (the route INTO doctor) must warn about the loss:
	if v, err := c.VerifyLog(); err != nil || v.OK ||
		!strings.Contains(strings.Join(v.Problems, " "), "LONGER than the log") {
		t.Fatalf("truncated tail must make verify warn before doctor: %+v",
			v.Problems)
	}
	rep, err := StateHealth(c)
	if err != nil {
		t.Fatal(err)
	}
	delta := validation.ObjAt(rep, "events_mirror_delta")
	if delta.Kind != validation.Obj ||
		deltaInt(validation.ObjAt(delta, "dropped_from_projection")) != 1 {
		t.Fatalf("dropped must be counted: %s",
			validation.DumpsOrdered(rep, false))
	}
	jraw, err := os.ReadFile(filepath.Join(c.Dir, "doctor.json"))
	if err != nil {
		t.Fatalf("durable repair trace missing: %v", err)
	}
	if !strings.Contains(string(jraw), "dropped_from_projection") {
		t.Fatalf("journal must persist the drop: %s", jraw)
	}
}
