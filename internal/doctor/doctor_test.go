// doctor_test.go ports tests/test_doctor.py (plus test_doctor_preflight.py's
// test_doctor_includes_preflight) 1:1. Python wins.
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
	stages := objAt(st, "stages")
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
	for _, e := range objAt(res, "notes_truncated").A {
		got = append(got, objStr(e, "stage"))
	}
	if len(got) != 1 || got[0] != "structural-index" {
		t.Errorf("notes_truncated = %v, want [structural-index]", got)
	}
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	note := objStr(objAt(objAt(st, "stages"), "structural-index"), "note")
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
	if n := len(objAt(res, "notes_truncated").A); n != 0 {
		t.Errorf("notes_truncated = %d, want 0", n)
	}
	if intField(res, "bytes_freed") > 0 {
		t.Errorf("bytes_freed = %d, want <= 0", intField(res, "bytes_freed"))
	}
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(objAt(objAt(st, "stages"), "recon"), "note"); got !=
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
	note := objStr(objAt(got, "artifacts").A[0], "note")
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
	if w := objAt(res, "file_count_warning"); w.Kind != validation.Null {
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
	warn := objStr(res, "file_count_warning")
	if warn == "" || !strings.Contains(warn, "scope drift") {
		t.Errorf("file_count_warning = %q, want a scope-drift warning", warn)
	}
	top := objAt(res, "top_directories").A
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
	if s := objAt(res, "active_snapshot"); s.Kind != validation.Null {
		t.Errorf("active_snapshot = %s, want null", validation.DumpIndented(s))
	}
	if note := objStr(res, "note"); !strings.Contains(note, "no snapshot pinned") {
		t.Errorf("note = %q", note)
	}
}

func TestDoctorIncludesPreflight(t *testing.T) {
	c := newCampaign(t, "Preflight Doc")
	rep, err := Doctor(c)
	if err != nil {
		t.Fatal(err)
	}
	pre := objAt(rep, "preflight")
	if pre.Kind != validation.Obj {
		t.Fatalf("preflight = %s", validation.DumpIndented(pre))
	}
	if objAt(pre, "checks").Kind != validation.Obj {
		t.Errorf("preflight.checks missing")
	}
	if objAt(objAt(pre, "checks"), "workdir").Kind != validation.Obj {
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
	f := objAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}
