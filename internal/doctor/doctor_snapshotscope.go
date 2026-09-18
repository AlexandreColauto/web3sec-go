// Snapshot-scope concern: snapshot_scope — what the ACTIVE pin actually
// covers, ground truth for scope drift.
package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

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
