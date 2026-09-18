// State-health concern: state_health — the state file size report, the
// projection-only note cap repair, the events-mirror rebuild, and the
// durable doctor.json repair journal.
package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"websec/internal/state"
	"websec/internal/validation"
)

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
