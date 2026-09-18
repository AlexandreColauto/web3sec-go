// Package doctor is webv2/doctor.py: campaign health — repair + scope-drift
// diagnosis.
//
// `webv2 doctor` is the operator's self-check. Two jobs, both read-mostly:
//
//   - state health — the state file is re-read and re-written by every CLI
//     command, so one oversized stage note (a 2 GB index inlined by an old
//     pipeline run) made the whole campaign pay gigabytes of IO per command.
//     doctor truncates any note above the cap, IN THE PROJECTION ONLY: the
//     append-only event log is never touched, and the audit verifies the
//     chain plus content-hashed artifacts — never the state file — so the
//     repair is audit-safe.
//   - snapshot scope — the pin is the campaign's ground truth, and a pin that
//     swallowed the framework's own repository (128k files for a 122-line
//     vault) silently poisoned every derived index. doctor reports what the
//     pin actually covers and warns when it looks like scope drift.
package doctor

import (
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"fmt"
	"websec/internal/envgo"
	"websec/internal/state"
	"websec/internal/validation"
)

// SnapshotFileWarn is SNAPSHOT_FILE_WARN: a pin this large is almost never
// "the target": real audit targets are source trees of hundreds to low
// thousands of files. Above this the operator is warned (not blocked) — some
// protocols legitimately ship large corpora, and the waiver is the operator's
// call. A package var so tests can force the drift warning (Python mutates
// DOC.SNAPSHOT_FILE_WARN).
var SnapshotFileWarn = 5000

// StateHealth is state_health: report the state file size and repair
// oversized stage notes. Rewrites the projection (campaign_state.json) with
// every note capped; the event log is untouched.
func StateHealth(campaign *state.Campaign) (validation.Value, error) {
	// r15: doctor WRITES campaign_state (note caps, mirror rebuild) —
	// it is a state writer like any other and takes the lock for its
	// whole load->repair->write window; the raw WriteJson at the bottom
	// is inside this span. Racing a repair against a `floors set` used
	// to lose the floor decision silently.
	if err := campaign.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer campaign.UnlockProcess()
	path := campaign.StatePath
	before := int64(0)
	if fi, err := os.Stat(path); err == nil {
		before = fi.Size()
	}
	// r36b P2: keep the bytes we parse. They answer "is this file already the
	// canonical projection?" without a second read of a state file that can
	// be gigabytes (the 1.7 GB state the note cap exists for), and that answer
	// is what decides whether a quiet run writes at all.
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), err
	}
	st, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	// pendingNote is one note this run actually SHORTENS: the stage key, the
	// length read from the file before the write, and the capped text. doctor
	// reports what it staged here and nothing else — the r36b P2 finding was a
	// report of a repair that capNote's own over-cap output kept undoing.
	type pendingNote struct {
		stage  string
		before int
		capped string
	}
	var pending []pendingNote
	if stages := validation.ObjAt(st, "stages"); stages.Kind == validation.Obj {
		for i := range stages.O {
			entry := stages.O[i].V
			if entry.Kind != validation.Obj {
				continue
			}
			note := validation.ObjAt(entry, "note")
			if note.Kind != validation.Str {
				continue
			}
			capped := state.CapNote(note)
			if capped == note.S {
				// Already the cap's fixed point: nothing to repair, nothing
				// to report. This is the test that makes the SECOND run
				// silent (pre-r36b the test was "runeLen > NOTE_CAP", which
				// capNote's own output kept true forever).
				continue
			}
			pending = append(pending, pendingNote{
				stage:  stages.O[i].K,
				before: runeLen(note),
				capped: capped,
			})
			setKey(&stages.O[i].V, "note", validation.VStr(capped))
		}
		setKey(&st, "stages", stages)
	}
	// artifact notes ride the same rule (they are summaries too). They carry
	// no stage key, so — as before — they stay out of the stage-keyed
	// notes_truncated report; the fixed-point test is what keeps them from
	// being re-capped on every run.
	artifactsRepaired := 0
	if arts := validation.ObjAt(st, "artifacts"); arts.Kind == validation.Arr {
		for i := range arts.A {
			art := arts.A[i]
			if art.Kind != validation.Obj {
				continue
			}
			note := validation.ObjAt(art, "note")
			if note.Kind != validation.Str {
				continue
			}
			capped := state.CapNote(note)
			if capped == note.S {
				continue
			}
			setKey(&arts.A[i], "note", validation.VStr(capped))
			artifactsRepaired++
		}
		setKey(&st, "artifacts", arts)
	}
	// r14: the events mirror is a PROJECTION of the log, and an unflocked
	// era (or the r13 twin-package race) can strand it mid-file — verify
	// goes red forever with no verb to fix it. Doctor owns repairs of
	// projection-only damage: rebuild the tail from the log (the log is
	// never touched; its chain is the truth). Reported, never silent.
	mirrorRebuilt := false
	var mirrorRefusal string
	mirrorDeltaNote := validation.VNull()
	fresh, merr := campaign.EventsMirrorFromLog()
	if merr != nil {
		// r15: a refused rebuild is DISCLOSED, never silent — but it
		// does not veto the note-cap repair (an oversized note still
		// gets capped; the mirror stays as-is, visible to verify).
		mirrorRefusal = merr.Error()
	} else if validation.CanonSpaced(validation.ObjAt(st, "events")) !=
		validation.CanonSpaced(validation.Value{Kind: validation.Arr,
			A: fresh}) {
		// r16: capture the OLD mirror BEFORE cand is built —
		// SetOrAppend writes through the shared []KV backing array,
		// so st["events"] reads the NEW value once cand exists (and a
		// delta computed from st afterwards is zero by construction
		// — it was, until a pin caught it).
		oldMirror := validation.ObjAt(st, "events")
		cand := st
		cand.O = validation.SetOrAppend(cand.O, "events",
			validation.Value{Kind: validation.Arr, A: fresh})
		// The rebuild must not poison the file it repairs: if the
		// candidate state fails the schema (or the log could not be
		// read as a whole), skip the rebuild rather than write a state
		// NO verb can load afterward.
		if verr := validation.Validate(cand, "campaign_state", 1); verr != nil {
			mirrorRefusal = fmt.Sprintf("rebuilt state would not "+
				"validate: %v", verr)
		} else {
			// r16: the rebuild adopts the log's version of EVENTS —
			// when that means content the projection remembered
			// differently (edited payloads, rewritten history), the
			// operator sees HOW it changes, not just that it did:
			// the chain gate proves format and continuity, not
			// authorship (see verifylog's boundary note).
			adopted, changed, dropped, added := mirrorDelta(
				oldMirror,
				validation.Value{Kind: validation.Arr, A: fresh})
			st = cand
			mirrorRebuilt = true
			mirrorDeltaNote = validation.VObj(
				validation.KV{K: "kept", V: validation.VInt(adopted)},
				validation.KV{K: "changed", V: validation.VInt(changed)},
				validation.KV{K: "dropped_from_projection", V: validation.VInt(dropped)},
				validation.KV{K: "added_from_log", V: validation.VInt(added)},
			)
		}
	}
	// no schema validation on the repair write: doctor's job is to make the
	// file loadable again, not to re-judge its shape — a state that drifted
	// from the schema must still be repairable (the audit is what judges).
	//
	// r36b P2: write only when this run CHANGES the projection. Pre-r36b the
	// write was unconditional, so campaign_state.json's mtime advanced on
	// every run — a run that repaired nothing (and the second run of a note
	// repair) churned the file anyway, which is both the fingerprint of the
	// non-converging repair and the reason a quiet doctor could never be told
	// apart from a working one. A hand-edited state is still re-serialized:
	// the RUNBOOK's torn-tail recovery (python indent=2, then doctor) leaves
	// bytes that differ from the canonical form the CLI writes.
	writeNeeded := len(pending) > 0 || artifactsRepaired > 0 || mirrorRebuilt
	if !writeNeeded {
		writeNeeded = string(raw) != validation.DumpIndented(st)+"\n"
	}
	raw = nil // the file bytes were only needed for the canonicality test
	if writeNeeded {
		if err := validation.WriteJson(path, st, ""); err != nil {
			return validation.VNull(), err
		}
	}
	after := int64(0)
	if fi, err := os.Stat(path); err == nil {
		after = fi.Size()
	}
	// r36b P2: the reported before/after are the REAL lengths. `before` was
	// measured on the note as it was read from the file; `after` is measured
	// on the note read BACK from the file this repair wrote — never on what
	// capNote returned. A number nobody can check against the file is how
	// "truncated note on stage X: 4,176 -> 4,176 chars" survived eight runs.
	afterLens := make([]int, len(pending))
	for i, p := range pending {
		afterLens[i] = utf8.RuneCountInString(p.capped)
	}
	if len(pending) > 0 {
		if persisted, perr := validation.ReadJson(path); perr == nil {
			stages := validation.ObjAt(persisted, "stages")
			for i, p := range pending {
				entry := validation.ObjAt(stages, p.stage)
				if entry.Kind != validation.Obj {
					continue
				}
				if note := validation.ObjAt(entry, "note"); note.Kind == validation.Str {
					afterLens[i] = runeLen(note)
				}
			}
		}
	}
	truncated := make([]validation.Value, 0, len(pending))
	for i, p := range pending {
		truncated = append(truncated, validation.VObj(
			validation.KV{K: "stage", V: validation.VStr(p.stage)},
			validation.KV{K: "before", V: validation.VInt(int64(p.before))},
			validation.KV{K: "after", V: validation.VInt(int64(afterLens[i]))},
		))
	}
	// r17: the rebuild's own trace must OUTLIVE the run. The JSON delta
	// printed once and vanished; verify then says green and `audit` says
	// PASS over whatever the log became. campaigns/<C>/doctor.json keeps
	// a durable (capped) journal of repairs — a truncation laundered to
	// green still leaves the record that it happened and what moved.
	if mirrorRebuilt || mirrorRefusal != "" {
		entry := validation.VObj(
			validation.KV{K: "at", V: validation.VStr(state.NowIso())},
			validation.KV{K: "rebuilt", V: validation.VBool(mirrorRebuilt)},
			validation.KV{K: "delta", V: mirrorDeltaNote},
			validation.KV{K: "refused",
				V: func() validation.Value {
					if mirrorRefusal == "" {
						return validation.VNull()
					}
					return validation.VStr(mirrorRefusal)
				}()},
		)
		journalPath := filepath.Join(campaign.Dir, "doctor.json")
		journal := []validation.Value{}
		corruptTo := ""
		if raw, jerr := os.ReadFile(journalPath); jerr == nil {
			if v, perr := validation.ParseOrdered(raw); perr == nil &&
				v.Kind == validation.Arr {
				journal = v.A
			} else {
				// r18 P2: corrupt-to-silence — an unreadable journal used
				// to be replaced by a fresh one, quietly deleting every
				// earlier disclosure while THIS rebuild laundered the
				// truncation it was supposed to record. The bytes are
				// rescued next to the journal and the salvage is named in
				// the entry that overwrites it.
				corruptTo = journalPath + ".corrupt"
				for n := 1; n < 100; n++ {
					if _, statErr := os.Stat(corruptTo); os.IsNotExist(statErr) {
						break
					}
					corruptTo = fmt.Sprintf("%s.corrupt-%d", journalPath, n)
				}
				if werr := os.WriteFile(corruptTo, raw, 0o644); werr != nil {
					corruptTo = "RESCUE FAILED: " + werr.Error()
				}
			}
		}
		if corruptTo != "" {
			entry.O = validation.SetOrAppend(entry.O, "journal_replaced",
				validation.VStr("previous doctor.json was unparseable; its "+
					"bytes rescued to "+filepath.Base(corruptTo)+
					" — repairs before this one are NOT in this journal"))
		}
		journal = append(journal, entry)
		if len(journal) > 50 { // capped journal, newest kept
			journal = journal[len(journal)-50:]
		}
		if jerr := validation.WriteJson(journalPath,
			validation.VArr(journal...), ""); jerr != nil {
			return validation.VNull(), jerr
		}
	}
	return validation.VObj(
		validation.KV{K: "state_path", V: validation.VStr(path)},
		validation.KV{K: "size_before", V: validation.VInt(before)},
		validation.KV{K: "size_after", V: validation.VInt(after)},
		validation.KV{K: "bytes_freed", V: validation.VInt(before - after)},
		validation.KV{K: "notes_truncated", V: validation.VArr(truncated...)},
		validation.KV{K: "repaired_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "events_mirror_rebuilt", V: validation.VBool(mirrorRebuilt)},
		validation.KV{K: "events_mirror_delta", V: mirrorDeltaNote},
		validation.KV{K: "events_mirror_refused",
			V: func() validation.Value {
				if mirrorRefusal == "" {
					return validation.VNull()
				}
				return validation.VStr(mirrorRefusal)
			}()},
	), nil
}

// runeLen is Python's len(str) for the note shapes doctor caps.
func runeLen(v validation.Value) int {
	if v.Kind == validation.Str {
		return utf8.RuneCountInString(v.S)
	}
	return 0
}

// SnapshotScope is snapshot_scope: what does the ACTIVE pin actually cover?
// Ground truth for scope drift.
func SnapshotScope(campaign *state.Campaign) (validation.Value, error) {
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	if sid == nil {
		cid := campaign.CampaignID
		if cid == "" {
			// A campaign in hand without an id keeps the documented
			// metavariable rather than rendering a command with an empty hole.
			cid = "<campaign>"
		}
		return validation.VObj(
			validation.KV{K: "active_snapshot", V: validation.VNull()},
			validation.KV{K: "note", V: validation.VStr("no snapshot pinned " +
				"— run `webv2 snap " + cid + " <target>`")},
		), nil
	}
	snapDir := filepath.Join(campaign.Dir, "snapshots", *sid)
	fi, serr := os.Stat(snapDir)
	if serr != nil && !os.IsNotExist(serr) {
		// r44b P3-a: this used to be one branch — `if fi, err :=
		// os.Stat(snapDir); err != nil || !fi.IsDir()` — so EVERY stat
		// error, EACCES included, rendered as exists:false + "snapshot
		// <id> directory missing". With `chmod 000 <c>/snapshots/` the
		// directory is there but unreadable (stat needs +x on the parent):
		// doctor said the pin was MISSING in both surfaces, which is a
		// claim about absence drawn from a read failure. Doctor's rc stays
		// 0 — its documented precedent: the bill discloses, it does not
		// fail — so the REASON has to be the truth, and the note retracts
		// the absence claim by name. A genuinely absent pin (NotExist)
		// keeps the r37b shape below, message-for-message.
		return validation.VObj(
			validation.KV{K: "active_snapshot", V: validation.VStr(*sid)},
			validation.KV{K: "exists", V: validation.VBool(false)},
			validation.KV{K: "read_error", V: validation.VStr(serr.Error())},
			validation.KV{K: "note", V: validation.VStr("the snapshot store " +
				snapDir + " could not be read: " + serr.Error() +
				" — a read failure is NOT proof the pin is absent; fix the " +
				"permissions on snapshots/ and re-run")},
		), nil
	}
	if serr != nil || !fi.IsDir() {
		// Genuinely missing (NotExist), or a path occupied by something
		// that is not a directory: the pin's directory is not there, which
		// is what this shape has always said.
		return validation.VObj(
			validation.KV{K: "active_snapshot", V: validation.VStr(*sid)},
			validation.KV{K: "exists", V: validation.VBool(false)},
			validation.KV{K: "note", V: validation.VStr("snapshot " + *sid +
				" directory missing")},
		), nil
	}
	metaPath := filepath.Join(snapDir, "snapshot.json")
	meta := validation.VObj()
	if _, metaErr := os.Stat(metaPath); metaErr == nil {
		meta, err = validation.ReadJson(metaPath)
		if err != nil {
			return validation.VNull(), err
		}
	} else if !os.IsNotExist(metaErr) {
		// r44b P3-a: this was `if pathExists(metaPath)`, and pathExists
		// folded EVERY stat error into false — an unsearchable pin dir
		// (mode 0400) read as "this pin has no manifest", so the report
		// carried source_root:null and the file walk below billed 0 files
		// over a tree nobody could read. A manifest that cannot be stat'ed
		// decides nothing: refuse with the path and the errno.
		return validation.VNull(), fmt.Errorf(
			"the snapshot store %s cannot be read: %v", metaPath, metaErr)
	}
	files, err := walkFiles(snapDir)
	if err != nil {
		return validation.VNull(), err
	}
	total := int64(0)
	counts := map[string]int{}
	order := []string{}
	for _, p := range files {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
		rel, err := filepath.Rel(snapDir, p)
		if err != nil {
			continue
		}
		parts := splitPath(rel)
		top := "."
		if len(parts) > 1 {
			top = parts[0]
		}
		if _, seen := counts[top]; !seen {
			order = append(order, top)
		}
		counts[top]++
	}
	sort.SliceStable(order, func(i, j int) bool {
		return counts[order[i]] > counts[order[j]]
	})
	if len(order) > 10 {
		order = order[:10]
	}
	topDirs := make([]validation.Value, 0, len(order))
	for _, name := range order {
		topDirs = append(topDirs, validation.VArr(validation.VStr(name),
			validation.VInt(int64(counts[name]))))
	}
	var warnV validation.Value = validation.VNull()
	if len(files) > SnapshotFileWarn {
		warnV = validation.VStr("pin covers " + itoa(len(files)) + " files — " +
			"if the target is a small source tree, this pin has scope drift " +
			"(it likely swallowed directories the target does not own); " +
			"re-pin with --exclude or a tighter target")
	}
	var rootV validation.Value = validation.VNull()
	if r := validation.ObjStr(validation.ObjAt(meta, "source"), "root"); r != "" {
		rootV = validation.VStr(r)
	}
	return validation.VObj(
		validation.KV{K: "active_snapshot", V: validation.VStr(*sid)},
		validation.KV{K: "source_root", V: rootV},
		validation.KV{K: "files", V: validation.VInt(int64(len(files)))},
		validation.KV{K: "bytes", V: validation.VInt(total)},
		validation.KV{K: "top_directories", V: validation.VArr(topDirs...)},
		validation.KV{K: "file_count_warning", V: warnV},
	), nil
}

// Doctor is doctor: the state repair, the snapshot scope report and the
// sandbox preflight (readiness BEFORE the first exec pays for it).
func Doctor(campaign *state.Campaign) (validation.Value, error) {
	st, err := StateHealth(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	scope, err := SnapshotScope(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	pre, err := envgo.SandboxPreflight(campaign, nil, nil)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "state", V: st},
		validation.KV{K: "snapshot", V: scope},
		validation.KV{K: "preflight", V: pre},
	), nil
}

// walkFiles is `[p for p in snap_dir.rglob("*") if p.is_file()]`.
func walkFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				// The entry vanished between the listing and the stat, or
				// the name is a broken symlink: absence, not a read failure.
				return nil
			}
			// r44b P3-a: this used to `return nil` on EVERY stat error, so a
			// pin dir that lists but cannot be searched (mode 0400 — the
			// names come back, the stat of each entry does not) made the
			// scope report "0 files, 0.0 MB": the r37b empty-but-present
			// lie, over a tree this run never read. It is the same fold as
			// the missing manifest above, and both refuse.
			return fmt.Errorf("the snapshot store %s cannot be read: %v", p, err)
		}
		if fi.Mode().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// splitPath is PurePath.parts for a relative path.
func splitPath(rel string) []string {
	var out []string
	cur := ""
	for _, r := range rel {
		if r == '/' || r == filepath.Separator {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// setKey replaces key in place (Python's dict assignment keeps position).
func setKey(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
}

// itoa is str(int).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// mirrorDelta compares the old projection tail against the rebuilt one
// by position: same-prefix counts (kept), positions present in both but
// unequal (changed — edited content under a chain that still verifies),
// extra old rows (dropped), extra new rows (added). Counts only; the
// human output prints the number, the JSON carries it.
func mirrorDelta(oldV, newV validation.Value) (kept, changed, dropped, added int64) {
	min := len(oldV.A)
	if len(newV.A) < min {
		min = len(newV.A)
	}
	for i := 0; i < min; i++ {
		if validation.CanonSpaced(oldV.A[i]) == validation.CanonSpaced(newV.A[i]) {
			kept++
		} else {
			changed++
		}
	}
	dropped = int64(len(oldV.A) - min)
	added = int64(len(newV.A) - min)
	return
}
