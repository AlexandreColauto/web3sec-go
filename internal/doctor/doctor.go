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
	st, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	truncated := []validation.Value{}
	if stages := objAt(st, "stages"); stages.Kind == validation.Obj {
		for i := range stages.O {
			entry := stages.O[i].V
			if entry.Kind != validation.Obj {
				continue
			}
			note := objAt(entry, "note")
			if note.Kind == validation.Null {
				continue
			}
			length := runeLen(note)
			if length <= state.NOTE_CAP {
				continue
			}
			capped := state.CapNote(note)
			truncated = append(truncated, validation.VObj(
				validation.KV{K: "stage", V: validation.VStr(stages.O[i].K)},
				validation.KV{K: "before", V: validation.VInt(int64(length))},
				validation.KV{K: "after", V: validation.VInt(
					int64(utf8.RuneCountInString(capped)))},
			))
			setKey(&stages.O[i].V, "note", validation.VStr(capped))
		}
		setKey(&st, "stages", stages)
	}
	// artifact notes ride the same rule (they are summaries too)
	if arts := objAt(st, "artifacts"); arts.Kind == validation.Arr {
		for i := range arts.A {
			art := arts.A[i]
			if art.Kind != validation.Obj {
				continue
			}
			note := objAt(art, "note")
			if note.Kind == validation.Null || runeLen(note) <= state.NOTE_CAP {
				continue
			}
			setKey(&arts.A[i], "note", validation.VStr(state.CapNote(note)))
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
	} else if validation.CanonSpaced(objAt(st, "events")) !=
		validation.CanonSpaced(validation.Value{Kind: validation.Arr,
			A: fresh}) {
		// r16: capture the OLD mirror BEFORE cand is built —
		// SetOrAppend writes through the shared []KV backing array,
		// so st["events"] reads the NEW value once cand exists (and a
		// delta computed from st afterwards is zero by construction
		// — it was, until a pin caught it).
		oldMirror := objAt(st, "events")
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
	if err := validation.WriteJson(path, st, ""); err != nil {
		return validation.VNull(), err
	}
	after := int64(0)
	if fi, err := os.Stat(path); err == nil {
		after = fi.Size()
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
	if fi, err := os.Stat(snapDir); err != nil || !fi.IsDir() {
		return validation.VObj(
			validation.KV{K: "active_snapshot", V: validation.VStr(*sid)},
			validation.KV{K: "exists", V: validation.VBool(false)},
			validation.KV{K: "note", V: validation.VStr("snapshot " + *sid +
				" directory missing")},
		), nil
	}
	metaPath := filepath.Join(snapDir, "snapshot.json")
	meta := validation.VObj()
	if pathExists(metaPath) {
		meta, err = validation.ReadJson(metaPath)
		if err != nil {
			return validation.VNull(), err
		}
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
	if r := objStr(objAt(meta, "source"), "root"); r != "" {
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
			return nil
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

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
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

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
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
