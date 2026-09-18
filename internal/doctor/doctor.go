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

// stateHealthPendingNote is one note this run actually SHORTENS: the stage
// key, the length read from the file before the write, and the capped text.
// doctor reports what it staged here and nothing else — the r36b P2 finding
// was a report of a repair that capNote's own over-cap output kept undoing.
type stateHealthPendingNote struct {
	stage  string
	before int
	capped string
}

// stateHealthCtx carries the shared context of one StateHealth run: the
// projection being repaired, the notes the repair staged, and what the
// events-mirror rebuild decided.
type stateHealthCtx struct {
	campaign          *state.Campaign
	path              string
	st                validation.Value
	before            int64
	after             int64
	pending           []stateHealthPendingNote
	artifactsRepaired int
	mirrorRebuilt     bool
	mirrorRefusal     string
	mirrorDeltaNote   validation.Value
}

// StateHealth is state_health: report the state file size and repair
// oversized stage notes. Rewrites the projection (campaign_state.json) with
// every note capped; the event log is untouched.
func StateHealth(campaign *state.Campaign) (validation.Value, error) {
	sh := &stateHealthCtx{campaign: campaign,
		mirrorDeltaNote: validation.VNull()}
	// r15: doctor WRITES campaign_state (note caps, mirror rebuild) —
	// it is a state writer like any other and takes the lock for its
	// whole load->repair->write window; the raw WriteJson at the bottom
	// is inside this span. Racing a repair against a `floors set` used
	// to lose the floor decision silently.
	if err := campaign.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer campaign.UnlockProcess()
	sh.path = campaign.StatePath
	sh.before = sh.stateHealthFileSize()
	// r36b P2: keep the bytes we parse. They answer "is this file already the
	// canonical projection?" without a second read of a state file that can
	// be gigabytes (the 1.7 GB state the note cap exists for), and that answer
	// is what decides whether a quiet run writes at all.
	raw, err := os.ReadFile(sh.path)
	if err != nil {
		return validation.VNull(), err
	}
	if sh.st, err = validation.ParseOrdered(raw); err != nil {
		return validation.VNull(), err
	}
	sh.stateHealthCapStages()
	sh.stateHealthCapArtifacts()
	sh.stateHealthRebuildMirror()
	if err := sh.stateHealthWriteIfChanged(raw); err != nil {
		return validation.VNull(), err
	}
	raw = nil // the file bytes were only needed for the canonicality test
	sh.after = sh.stateHealthFileSize()
	truncated := sh.stateHealthTruncated()
	if err := sh.stateHealthJournal(); err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "state_path", V: validation.VStr(sh.path)},
		validation.KV{K: "size_before", V: validation.VInt(sh.before)},
		validation.KV{K: "size_after", V: validation.VInt(sh.after)},
		validation.KV{K: "bytes_freed", V: validation.VInt(sh.before - sh.after)},
		validation.KV{K: "notes_truncated", V: validation.VArr(truncated...)},
		validation.KV{K: "repaired_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "events_mirror_rebuilt", V: validation.VBool(sh.mirrorRebuilt)},
		validation.KV{K: "events_mirror_delta", V: sh.mirrorDeltaNote},
		validation.KV{K: "events_mirror_refused", V: sh.stateHealthRefusedValue()},
	), nil
}

// stateHealthFileSize stats the state file; a failed stat folds to a size
// of 0, exactly as the inline stat did.
func (sh *stateHealthCtx) stateHealthFileSize() int64 {
	if fi, err := os.Stat(sh.path); err == nil {
		return fi.Size()
	}
	return 0
}

// stateHealthCapStages caps every oversized stage note in the projection.
func (sh *stateHealthCtx) stateHealthCapStages() {
	if stages := validation.ObjAt(sh.st, "stages"); stages.Kind == validation.Obj {
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
			sh.pending = append(sh.pending, stateHealthPendingNote{
				stage:  stages.O[i].K,
				before: runeLen(note),
				capped: capped,
			})
			setKey(&stages.O[i].V, "note", validation.VStr(capped))
		}
		setKey(&sh.st, "stages", stages)
	}
}

// stateHealthCapArtifacts caps the artifact notes.
//
// artifact notes ride the same rule (they are summaries too). They carry
// no stage key, so — as before — they stay out of the stage-keyed
// notes_truncated report; the fixed-point test is what keeps them from
// being re-capped on every run.
func (sh *stateHealthCtx) stateHealthCapArtifacts() {
	if arts := validation.ObjAt(sh.st, "artifacts"); arts.Kind == validation.Arr {
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
			sh.artifactsRepaired++
		}
		setKey(&sh.st, "artifacts", arts)
	}
}

// stateHealthRebuildMirror repairs the events mirror.
//
// r14: the events mirror is a PROJECTION of the log, and an unflocked
// era (or the r13 twin-package race) can strand it mid-file — verify
// goes red forever with no verb to fix it. Doctor owns repairs of
// projection-only damage: rebuild the tail from the log (the log is
// never touched; its chain is the truth). Reported, never silent.
func (sh *stateHealthCtx) stateHealthRebuildMirror() {
	fresh, merr := sh.campaign.EventsMirrorFromLog()
	if merr != nil {
		// r15: a refused rebuild is DISCLOSED, never silent — but it
		// does not veto the note-cap repair (an oversized note still
		// gets capped; the mirror stays as-is, visible to verify).
		sh.mirrorRefusal = merr.Error()
	} else if validation.CanonSpaced(validation.ObjAt(sh.st, "events")) !=
		validation.CanonSpaced(validation.Value{Kind: validation.Arr,
			A: fresh}) {
		// r16: capture the OLD mirror BEFORE cand is built —
		// SetOrAppend writes through the shared []KV backing array,
		// so st["events"] reads the NEW value once cand exists (and a
		// delta computed from st afterwards is zero by construction
		// — it was, until a pin caught it).
		oldMirror := validation.ObjAt(sh.st, "events")
		cand := sh.st
		cand.O = validation.SetOrAppend(cand.O, "events",
			validation.Value{Kind: validation.Arr, A: fresh})
		// The rebuild must not poison the file it repairs: if the
		// candidate state fails the schema (or the log could not be
		// read as a whole), skip the rebuild rather than write a state
		// NO verb can load afterward.
		if verr := validation.Validate(cand, "campaign_state", 1); verr != nil {
			sh.mirrorRefusal = fmt.Sprintf("rebuilt state would not "+
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
			sh.st = cand
			sh.mirrorRebuilt = true
			sh.mirrorDeltaNote = validation.VObj(
				validation.KV{K: "kept", V: validation.VInt(adopted)},
				validation.KV{K: "changed", V: validation.VInt(changed)},
				validation.KV{K: "dropped_from_projection", V: validation.VInt(dropped)},
				validation.KV{K: "added_from_log", V: validation.VInt(added)},
			)
		}
	}
}

// stateHealthWriteIfChanged rewrites the projection (campaign_state.json).
func (sh *stateHealthCtx) stateHealthWriteIfChanged(raw []byte) error {
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
	writeNeeded := len(sh.pending) > 0 || sh.artifactsRepaired > 0 || sh.mirrorRebuilt
	if !writeNeeded {
		writeNeeded = string(raw) != validation.DumpIndented(sh.st)+"\n"
	}
	if !writeNeeded {
		return nil
	}
	return validation.WriteJson(sh.path, sh.st, "")
}

// stateHealthTruncated builds the notes_truncated report for the notes this
// run actually shortened.
func (sh *stateHealthCtx) stateHealthTruncated() []validation.Value {
	// r36b P2: the reported before/after are the REAL lengths. `before` was
	// measured on the note as it was read from the file; `after` is measured
	// on the note read BACK from the file this repair wrote — never on what
	// capNote returned. A number nobody can check against the file is how
	// "truncated note on stage X: 4,176 -> 4,176 chars" survived eight runs.
	afterLens := make([]int, len(sh.pending))
	for i, p := range sh.pending {
		afterLens[i] = utf8.RuneCountInString(p.capped)
	}
	if len(sh.pending) > 0 {
		if persisted, perr := validation.ReadJson(sh.path); perr == nil {
			stages := validation.ObjAt(persisted, "stages")
			for i, p := range sh.pending {
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
	truncated := make([]validation.Value, 0, len(sh.pending))
	for i, p := range sh.pending {
		truncated = append(truncated, validation.VObj(
			validation.KV{K: "stage", V: validation.VStr(p.stage)},
			validation.KV{K: "before", V: validation.VInt(int64(p.before))},
			validation.KV{K: "after", V: validation.VInt(int64(afterLens[i]))},
		))
	}
	return truncated
}

// stateHealthRefusedValue renders the mirror-refusal disclosure: null when
// nothing was refused, the refusal text otherwise.
func (sh *stateHealthCtx) stateHealthRefusedValue() validation.Value {
	if sh.mirrorRefusal == "" {
		return validation.VNull()
	}
	return validation.VStr(sh.mirrorRefusal)
}

// stateHealthJournal appends this run's mirror-repair record to the durable
// doctor.json journal.
func (sh *stateHealthCtx) stateHealthJournal() error {
	// r17: the rebuild's own trace must OUTLIVE the run. The JSON delta
	// printed once and vanished; verify then says green and `audit` says
	// PASS over whatever the log became. campaigns/<C>/doctor.json keeps
	// a durable (capped) journal of repairs — a truncation laundered to
	// green still leaves the record that it happened and what moved.
	if sh.mirrorRebuilt || sh.mirrorRefusal != "" {
		entry := validation.VObj(
			validation.KV{K: "at", V: validation.VStr(state.NowIso())},
			validation.KV{K: "rebuilt", V: validation.VBool(sh.mirrorRebuilt)},
			validation.KV{K: "delta", V: sh.mirrorDeltaNote},
			validation.KV{K: "refused", V: sh.stateHealthRefusedValue()},
		)
		journalPath := filepath.Join(sh.campaign.Dir, "doctor.json")
		journal := []validation.Value{}
		corruptTo := ""
		if raw, jerr := os.ReadFile(journalPath); jerr == nil {
			if v, perr := validation.ParseOrdered(raw); perr == nil &&
				v.Kind == validation.Arr {
				journal = v.A
			} else {
				corruptTo = stateHealthJournalRescue(journalPath, raw)
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
			return jerr
		}
	}
	return nil
}

// stateHealthJournalRescue salvages the bytes of an unparseable doctor.json.
//
// r18 P2: corrupt-to-silence — an unreadable journal used
// to be replaced by a fresh one, quietly deleting every
// earlier disclosure while THIS rebuild laundered the
// truncation it was supposed to record. The bytes are
// rescued next to the journal and the salvage is named in
// the entry that overwrites it.
func stateHealthJournalRescue(journalPath string, raw []byte) string {
	corruptTo := journalPath + ".corrupt"
	for n := 1; n < 100; n++ {
		if _, statErr := os.Stat(corruptTo); os.IsNotExist(statErr) {
			break
		}
		corruptTo = fmt.Sprintf("%s.corrupt-%d", journalPath, n)
	}
	if werr := os.WriteFile(corruptTo, raw, 0o644); werr != nil {
		corruptTo = "RESCUE FAILED: " + werr.Error()
	}
	return corruptTo
}

// runeLen is Python's len(str) for the note shapes doctor caps.
func runeLen(v validation.Value) int {
	if v.Kind == validation.Str {
		return utf8.RuneCountInString(v.S)
	}
	return 0
}

// snapScopeCtx carries the shared context of one SnapshotScope report: the
// active pin, its manifest, and what the file walk found.
type snapScopeCtx struct {
	campaign *state.Campaign
	sid      *string
	meta     validation.Value
	files    []string
	total    int64
}

// SnapshotScope is snapshot_scope: what does the ACTIVE pin actually cover?
// Ground truth for scope drift.
func SnapshotScope(campaign *state.Campaign) (validation.Value, error) {
	sc := &snapScopeCtx{campaign: campaign}
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	sc.sid = sid
	if sid == nil {
		return sc.snapScopeNoPin(), nil
	}
	snapDir := filepath.Join(campaign.Dir, "snapshots", *sid)
	fi, serr := os.Stat(snapDir)
	if serr != nil && !os.IsNotExist(serr) {
		return sc.snapScopeUnreadable(snapDir, serr), nil
	}
	if serr != nil || !fi.IsDir() {
		return sc.snapScopeMissing(snapDir), nil
	}
	if err := sc.snapScopeLoadMeta(snapDir); err != nil {
		return validation.VNull(), err
	}
	topDirs, err := sc.snapScopeTally(snapDir)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "active_snapshot", V: validation.VStr(*sc.sid)},
		validation.KV{K: "source_root", V: sc.snapScopeRootV()},
		validation.KV{K: "files", V: validation.VInt(int64(len(sc.files)))},
		validation.KV{K: "bytes", V: validation.VInt(sc.total)},
		validation.KV{K: "top_directories", V: validation.VArr(topDirs...)},
		validation.KV{K: "file_count_warning", V: sc.snapScopeWarnV()},
	), nil
}

// snapScopeNoPin renders the shape used when no snapshot is pinned.
func (sc *snapScopeCtx) snapScopeNoPin() validation.Value {
	cid := sc.campaign.CampaignID
	if cid == "" {
		// A campaign in hand without an id keeps the documented
		// metavariable rather than rendering a command with an empty hole.
		cid = "<campaign>"
	}
	return validation.VObj(
		validation.KV{K: "active_snapshot", V: validation.VNull()},
		validation.KV{K: "note", V: validation.VStr("no snapshot pinned " +
			"— run `webv2 snap " + cid + " <target>`")},
	)
}

// snapScopeUnreadable renders the shape for a pin whose store cannot be read.
func (sc *snapScopeCtx) snapScopeUnreadable(snapDir string, serr error) validation.Value {
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
		validation.KV{K: "active_snapshot", V: validation.VStr(*sc.sid)},
		validation.KV{K: "exists", V: validation.VBool(false)},
		validation.KV{K: "read_error", V: validation.VStr(serr.Error())},
		validation.KV{K: "note", V: validation.VStr("the snapshot store " +
			snapDir + " could not be read: " + serr.Error() +
			" — a read failure is NOT proof the pin is absent; fix the " +
			"permissions on snapshots/ and re-run")},
	)
}

// snapScopeMissing renders the shape for a pin whose directory is absent.
func (sc *snapScopeCtx) snapScopeMissing(snapDir string) validation.Value {
	// Genuinely missing (NotExist), or a path occupied by something
	// that is not a directory: the pin's directory is not there, which
	// is what this shape has always said.
	return validation.VObj(
		validation.KV{K: "active_snapshot", V: validation.VStr(*sc.sid)},
		validation.KV{K: "exists", V: validation.VBool(false)},
		validation.KV{K: "note", V: validation.VStr("snapshot " + *sc.sid +
			" directory missing")},
	)
}

// snapScopeLoadMeta reads the pin's snapshot.json manifest when it is there.
func (sc *snapScopeCtx) snapScopeLoadMeta(snapDir string) error {
	metaPath := filepath.Join(snapDir, "snapshot.json")
	sc.meta = validation.VObj()
	if _, metaErr := os.Stat(metaPath); metaErr == nil {
		meta, err := validation.ReadJson(metaPath)
		if err != nil {
			return err
		}
		sc.meta = meta
	} else if !os.IsNotExist(metaErr) {
		// r44b P3-a: this was `if pathExists(metaPath)`, and pathExists
		// folded EVERY stat error into false — an unsearchable pin dir
		// (mode 0400) read as "this pin has no manifest", so the report
		// carried source_root:null and the file walk below billed 0 files
		// over a tree nobody could read. A manifest that cannot be stat'ed
		// decides nothing: refuse with the path and the errno.
		return fmt.Errorf(
			"the snapshot store %s cannot be read: %v", metaPath, metaErr)
	}
	return nil
}

// snapScopeTally walks the pin's files and accumulates the byte total and
// the per-top-directory counts; it returns the sorted top_directories rows.
func (sc *snapScopeCtx) snapScopeTally(snapDir string) ([]validation.Value, error) {
	files, err := walkFiles(snapDir)
	if err != nil {
		return nil, err
	}
	sc.files = files
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
	sc.total = total
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
	return topDirs, nil
}

// snapScopeWarnV builds the scope-drift warning (null when the pin is small
// enough).
func (sc *snapScopeCtx) snapScopeWarnV() validation.Value {
	var warnV validation.Value = validation.VNull()
	if len(sc.files) > SnapshotFileWarn {
		warnV = validation.VStr("pin covers " + itoa(len(sc.files)) + " files — " +
			"if the target is a small source tree, this pin has scope drift " +
			"(it likely swallowed directories the target does not own); " +
			"re-pin with --exclude or a tighter target")
	}
	return warnV
}

// snapScopeRootV reads source.root out of the manifest (null when absent).
func (sc *snapScopeCtx) snapScopeRootV() validation.Value {
	if r := validation.ObjStr(validation.ObjAt(sc.meta, "source"), "root"); r != "" {
		return validation.VStr(r)
	}
	return validation.VNull()
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
