package cli

// zz_r36b_test.go — R36B P2 at the CLI surface: doctor's note repair must
// report a repair it MADE, must converge, and the human and --json surfaces
// must say the same thing.
//
// The repro: inflate one stage note to 100,000 chars and run `doctor`
// repeatedly. Pre-fix the note is capped to 4,179 runes, then 4,176, then
// "4,176 -> 4,176" forever — campaign_state.json is rewritten on every run
// (mtime advances), the note never gets inside the cap and the "all stage
// notes within the cap" line can never print.
//
// These tests run the verb through Run() in-process, on temp roots, and
// verify every reported number against the bytes on disk (a number the
// operator can check with wc -m is the only number worth printing), plus the
// no-op run: a second doctor must not rewrite the state file at all.

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"websec/internal/state"
	"websec/internal/validation"
)

// r36bNoteLine is the human surface's truncation line (wording pinned:
// "truncated note on stage %s: %d -> %d chars").
var r36bNoteLine = regexp.MustCompile(
	`truncated note on stage '([^']*)': ([\d,]+) -> ([\d,]+) chars`)

const r36bWithinCapLine = "all stage notes within the cap"

// r36bDoctorReport is the slice of doctor --json this file asserts on.
type r36bDoctorReport struct {
	State struct {
		SizeBefore     int64 `json:"size_before"`
		SizeAfter      int64 `json:"size_after"`
		BytesFreed     int64 `json:"bytes_freed"`
		NotesTruncated []struct {
			Stage  string `json:"stage"`
			Before int64  `json:"before"`
			After  int64  `json:"after"`
		} `json:"notes_truncated"`
	} `json:"state"`
}

func r36bJSON(t *testing.T, out string) r36bDoctorReport {
	t.Helper()
	var rep r36bDoctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("doctor --json is not JSON: %v\n%s", err, out)
	}
	return rep
}

// r36bNum parses a human-formatted count ("100,000").
func r36bNum(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(strings.ReplaceAll(s, ",", ""), 10, 64)
	if err != nil {
		t.Fatalf("number %q: %v", s, err)
	}
	return n
}

// r36bStat is the state file's mtime (ns) and content hash: either one
// advancing proves a rewrite.
func r36bStat(t *testing.T, path string) (int64, string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := validation.Sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime().UnixNano(), sum
}

func r36bStatePath(t *testing.T, root, cid string) string {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	return c.StatePath
}

// r36bNoteRunes is the REAL length of the stage note in campaign_state.json.
func r36bNoteRunes(t *testing.T, root, cid, stage string) int {
	t.Helper()
	st, err := validation.ReadJson(r36bStatePath(t, root, cid))
	if err != nil {
		t.Fatal(err)
	}
	note := validation.ObjAt(validation.ObjAt(validation.ObjAt(st, "stages"), stage), "note")
	if note.Kind != validation.Str {
		t.Fatalf("stage %q note is not a string: %s", stage,
			validation.DumpIndented(note))
	}
	return utf8.RuneCountInString(note.S)
}

// TestR36BDoctorNoteRepairConverges pins requirement 2 end to end: one honest
// repair, true numbers on both surfaces, and a second run that reports
// nothing and touches nothing.
func TestR36BDoctorNoteRepairConverges(t *testing.T) {
	const stage = "campaign-planning"
	root := mkroot(t)
	cid := initOne(t, root)
	bloat(t, root, cid, stage, 100_000)
	path := r36bStatePath(t, root, cid)

	// --- run 1: the repair is reported and MADE ------------------------------
	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("run 1 exit %d: %q", code, errS)
	}
	m := r36bNoteLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("run 1 reported no truncation: %q", out)
	}
	if m[1] != stage {
		t.Errorf("run 1 stage = %q, want %q", m[1], stage)
	}
	before, after := r36bNum(t, m[2]), r36bNum(t, m[3])
	if before != 100_000 {
		t.Errorf("run 1 before = %d, want 100000 (the note as it is in the file)",
			before)
	}
	if after > state.NOTE_CAP {
		t.Errorf("run 1 after = %d, want <= NOTE_CAP (%d): the reported repair "+
			"did not get the note inside the cap it claims", after, state.NOTE_CAP)
	}
	if onDisk := r36bNoteRunes(t, root, cid, stage); int64(onDisk) != after {
		t.Errorf("run 1 reported %d -> %d but the note on disk is %d runes: "+
			"the report must be the repair it MADE", before, after, onDisk)
	}

	// --- run 2: nothing left to repair, nothing rewritten --------------------
	mtime1, sha1 := r36bStat(t, path)
	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("run 2 exit %d: %q", code, errS)
	}
	if r36bNoteLine.MatchString(out) {
		t.Errorf("run 2 still reports a truncation (the repair does not "+
			"converge): %q", out)
	}
	if !strings.Contains(out, r36bWithinCapLine) {
		t.Errorf("run 2 does not print %q: %q", r36bWithinCapLine, out)
	}
	mtime2, sha2 := r36bStat(t, path)
	if sha2 != sha1 {
		t.Errorf("run 2 rewrote campaign_state.json: sha256 %s -> %s",
			sha1[:12], sha2[:12])
	}
	if mtime2 != mtime1 {
		t.Errorf("run 2 advanced the state file mtime (%d -> %d)",
			mtime1, mtime2)
	}

	// --- run 3: --json agrees that there is nothing to report ----------------
	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only",
		"--json")
	if code != 0 {
		t.Fatalf("run 3 exit %d: %q", code, errS)
	}
	if rep := r36bJSON(t, out); len(rep.State.NotesTruncated) != 0 {
		t.Errorf("run 3 json notes_truncated = %+v, want []",
			rep.State.NotesTruncated)
	}
}

// TestR36BDoctorHumanAndJSONAgree pins requirement 3: identical fixtures, one
// read through the human surface and one through --json, must report the same
// stage and the same before/after — and both must match the bytes on disk.
func TestR36BDoctorHumanAndJSONAgree(t *testing.T) {
	const stage = "campaign-planning"
	hRoot := mkroot(t)
	hCid := initOne(t, hRoot)
	bloat(t, hRoot, hCid, stage, 100_000)
	jRoot := mkroot(t)
	jCid := initOne(t, jRoot)
	bloat(t, jRoot, jCid, stage, 100_000)

	code, out, errS := run(t, "--root", hRoot, "doctor", hCid, "--state-only")
	if code != 0 {
		t.Fatalf("human run exit %d: %q", code, errS)
	}
	m := r36bNoteLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("human run reported no truncation: %q", out)
	}
	hStage, hBefore, hAfter := m[1], r36bNum(t, m[2]), r36bNum(t, m[3])

	code, out, errS = run(t, "--root", jRoot, "doctor", jCid, "--state-only",
		"--json")
	if code != 0 {
		t.Fatalf("json run exit %d: %q", code, errS)
	}
	rep := r36bJSON(t, out)
	if len(rep.State.NotesTruncated) != 1 {
		t.Fatalf("json notes_truncated = %+v, want exactly one entry",
			rep.State.NotesTruncated)
	}
	j := rep.State.NotesTruncated[0]

	if hStage != j.Stage || hBefore != j.Before || hAfter != j.After {
		t.Errorf("surfaces disagree: human says %s %d -> %d, json says %s %d -> %d",
			hStage, hBefore, hAfter, j.Stage, j.Before, j.After)
	}
	if j.Before != 100_000 {
		t.Errorf("before = %d, want 100000", j.Before)
	}
	for _, side := range []struct {
		name  string
		root  string
		cid   string
		after int64
	}{
		{"human", hRoot, hCid, hAfter},
		{"json", jRoot, jCid, j.After},
	} {
		if side.after > state.NOTE_CAP {
			t.Errorf("%s surface: after = %d, want <= NOTE_CAP (%d)",
				side.name, side.after, state.NOTE_CAP)
		}
		if got := r36bNoteRunes(t, side.root, side.cid, stage); int64(got) !=
			side.after {
			t.Errorf("%s surface reported after = %d, but the note on disk is "+
				"%d runes", side.name, side.after, got)
		}
	}
}

// TestR36BDoctorLeavesAWithinCapNoteAlone pins requirement (c): a note already
// inside the cap is neither reported nor rewritten (pre-fix doctor rewrote the
// projection unconditionally, so its mtime advanced on every run).
func TestR36BDoctorLeavesAWithinCapNoteAlone(t *testing.T) {
	const stage = "recon"
	root := mkroot(t)
	cid := initOne(t, root)
	bloat(t, root, cid, stage, 200)
	path := r36bStatePath(t, root, cid)
	mtime1, sha1 := r36bStat(t, path)

	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if r36bNoteLine.MatchString(out) {
		t.Errorf("a 200-rune note was reported as truncated: %q", out)
	}
	if !strings.Contains(out, r36bWithinCapLine) {
		t.Errorf("stdout = %q, want %q", out, r36bWithinCapLine)
	}
	if got := r36bNoteRunes(t, root, cid, stage); got != 200 {
		t.Errorf("note = %d runes, want the untouched 200", got)
	}
	mtime2, sha2 := r36bStat(t, path)
	if sha2 != sha1 || mtime2 != mtime1 {
		t.Errorf("doctor rewrote a state file that needed no repair "+
			"(sha %s -> %s, mtime %d -> %d)", sha1[:12], sha2[:12],
			mtime1, mtime2)
	}

	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only",
		"--json")
	if code != 0 {
		t.Fatalf("json exit %d: %q", code, errS)
	}
	rep := r36bJSON(t, out)
	if len(rep.State.NotesTruncated) != 0 {
		t.Errorf("json notes_truncated = %+v, want []",
			rep.State.NotesTruncated)
	}
	if rep.State.BytesFreed > 0 {
		t.Errorf("json bytes_freed = %d, want <= 0 (nothing was repaired)",
			rep.State.BytesFreed)
	}
	if rep.State.SizeBefore != rep.State.SizeAfter {
		t.Errorf("json size %d -> %d, want unchanged",
			rep.State.SizeBefore, rep.State.SizeAfter)
	}
}

// TestR36BDoctorHealsAPoisonedNoteInOneRun covers the upgrade path the repro
// leaves behind: a state file already carrying the pre-fix output (a cap-sized
// body plus the marker, 4,176 runes — still over the cap). One run must get it
// inside the cap; the next must be quiet.
func TestR36BDoctorHealsAPoisonedNoteInOneRun(t *testing.T) {
	const stage = "campaign-planning"
	root := mkroot(t)
	cid := initOne(t, root)
	// The byte-for-byte shape the old capNote wrote for a 100,000-rune note:
	// NOTE_CAP runes of body plus the marker for the remaining 95,904.
	poisoned := strings.Repeat("a", state.NOTE_CAP) +
		" \u2026[truncated 95904 chars \u2014 full content must live in an " +
		"artifact, not a stage note]"
	bloatNote(t, root, cid, stage, poisoned)
	if n := r36bNoteRunes(t, root, cid, stage); n <= state.NOTE_CAP {
		t.Fatalf("fixture: poisoned note is %d runes, must be over the cap", n)
	}

	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("run 1 exit %d: %q", code, errS)
	}
	m := r36bNoteLine.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("run 1 reported no truncation for a poisoned note: %q", out)
	}
	if got := r36bNoteRunes(t, root, cid, stage); got > state.NOTE_CAP {
		t.Errorf("after one run the note is %d runes, want <= NOTE_CAP (%d)",
			got, state.NOTE_CAP)
	}
	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("run 2 exit %d: %q", code, errS)
	}
	if r36bNoteLine.MatchString(out) {
		t.Errorf("a poisoned note was not healed in one run: %q", out)
	}
}

// TestR36BDoctorArtifactNoteRepairAlsoConverges pins requirement 5: the
// artifact-note branch of the same loop used to re-cap its note on every run
// (same over-cap capNote output, same unconditional write). It carries no
// stage key, so it stays out of the stage-keyed report — but it must still
// converge and must not churn the state file.
func TestR36BDoctorArtifactNoteRepairAlsoConverges(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "artifacts", validation.VArr(validation.VObj(
		validation.KV{K: "artifact_id", V: validation.VStr("ART-r36b")},
		validation.KV{K: "kind", V: validation.VStr("other")},
		validation.KV{K: "path", V: validation.VStr("/tmp/r36b")},
		validation.KV{K: "note", V: validation.VStr(strings.Repeat("y", 100_000))},
	)))
	if err := validation.WriteJson(c.StatePath, st, ""); err != nil {
		t.Fatal(err)
	}
	noteLen := func() int {
		t.Helper()
		got, err := validation.ReadJson(c.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		arts := validation.ObjAt(got, "artifacts")
		if len(arts.A) == 0 {
			t.Fatal("fixture lost its artifact")
		}
		return utf8.RuneCountInString(validation.ObjStr(arts.A[0], "note"))
	}

	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("run 1 exit %d: %q", code, errS)
	}
	if n := noteLen(); n > state.NOTE_CAP {
		t.Errorf("after one run the artifact note is %d runes, want <= "+
			"NOTE_CAP (%d)", n, state.NOTE_CAP)
	}
	if !strings.Contains(out, r36bWithinCapLine) {
		t.Errorf("run 1 stdout = %q, want %q (the report is stage-keyed; the "+
			"artifact cap is not a stage truncation)", out, r36bWithinCapLine)
	}
	mtime1, sha1 := r36bStat(t, c.StatePath)
	code, out, errS = run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("run 2 exit %d: %q", code, errS)
	}
	if r36bNoteLine.MatchString(out) {
		t.Errorf("run 2 reports a stage truncation: %q", out)
	}
	if mtime2, sha2 := r36bStat(t, c.StatePath); mtime2 != mtime1 || sha2 != sha1 {
		t.Errorf("the artifact-note repair does not converge: run 2 rewrote "+
			"campaign_state.json (sha %s -> %s, mtime %d -> %d)",
			sha1[:12], sha2[:12], mtime1, mtime2)
	}
}

// bloatNote writes an EXACT note (bloat only writes repeats) into a stage.
func bloatNote(t *testing.T, root, cid, stage, note string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	stages := validation.ObjAt(st, "stages")
	stages.O = validation.SetOrAppend(stages.O, stage, validation.VObj(
		validation.KV{K: "status", V: validation.VStr("done")},
		validation.KV{K: "note", V: validation.VStr(note)},
		validation.KV{K: "executor", V: validation.VStr("pipeline")}))
	st.O = validation.SetOrAppend(st.O, "stages", stages)
	if err := validation.WriteJson(c.StatePath, st, ""); err != nil {
		t.Fatal(err)
	}
}
