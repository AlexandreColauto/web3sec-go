// pin_source_snapshot: materialize an immutable copy of the target and pin
// all four layers (source now; deployment/chain/config attach in Task 12).
//
// Ports web3sec-final/src/webv2/snapshot.py::pin_source_snapshot plus the
// _prune_excludes / _excluded_names_in helpers, refresh_manifest (Task 12
// promotes it to manifest.go) and the _detect_toolchain fallback (Task 12
// promotes it to toolchain.go once the TOML dependency lands).
package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// resolveSnap is Path.resolve(): absolute with symlinks expanded.
// (Mirrors state.resolvePath; state internals are unexported.)
func resolveSnap(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

// snapNowIso is now_iso: UTC, 6-digit microseconds, +00:00 (never Z).
// (Mirrors state.nowIso; unexported there, and the staging-dir name needs
// the exact format.)
func snapNowIso() string {
	// WEBV2_NOW: the golden-suite clock pin (same contract as
	// state.nowIso — both twins honor it, unset = real clock).
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// sget is the snapshot-local objAt: the Null value when the key is absent
// or the value is not an object.
func sget(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// setOrAppendObj mirrors Python dict assignment: an existing key is
// replaced in place (position kept), a new key is appended at the end.
func setOrAppendObj(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i, kv := range o {
		if kv.K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// --- prune helpers ----------------------------------------------------------

// pruneExcludes is _prune_excludes: physically remove from staging every
// file or directory whose NAME is in excludes, at any depth. Returns the
// sorted top-level names affected, for the record. Required on the
// git-worktree path (which checks out the whole tree); a no-op on the
// copytree path where ignore already pruned.
func pruneExcludes(staging string, excludes map[string]struct{}) []string {
	if len(excludes) == 0 {
		return nil
	}
	var victims []string
	_ = filepath.WalkDir(staging, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == staging {
			return nil
		}
		if _, bad := excludes[d.Name()]; bad {
			victims = append(victims, p)
		}
		return nil
	})
	sort.Slice(victims, func(i, j int) bool {
		return len(victims[i]) > len(victims[j])
	})
	for _, p := range victims {
		st, err := os.Lstat(p)
		if err != nil {
			continue // a parent prune already took it (OSError -> pass)
		}
		if st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			_ = os.RemoveAll(p) // rmtree(ignore_errors=True)
		} else {
			_ = os.Remove(p) // unlink (fails on dirs -> ignored)
		}
	}
	top := map[string]struct{}{}
	for _, p := range victims {
		rel, err := filepath.Rel(staging, p)
		if err != nil || rel == "." {
			continue
		}
		top[strings.Split(rel, string(os.PathSeparator))[0]] = struct{}{}
	}
	out := make([]string, 0, len(top))
	for k := range top {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// excludedNamesIn is _excluded_names_in: the top-level names in target that
// the prune set will drop. Computed from the target (not the staging)
// because on the copytree path the exclusion already happened at copy time.
func excludedNamesIn(target string, names map[string]struct{}) []string {
	top := map[string]struct{}{}
	_ = filepath.WalkDir(target, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == target {
			return nil
		}
		if _, bad := names[d.Name()]; bad {
			rel, rerr := filepath.Rel(target, p)
			if rerr == nil && rel != "." && rel != "" {
				top[strings.Split(rel, string(os.PathSeparator))[0]] = struct{}{}
			}
		}
		return nil
	})
	out := make([]string, 0, len(top))
	for k := range top {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- copytree ----------------------------------------------------------------

// copyTree is shutil.copytree(target, staging, ignore=ignore_patterns(
// *excludes), dirs_exist_ok=True, symlinks=True): skip every entry whose
// NAME is in excludes (pruning matched dirs whole), copy symlinks as
// symlinks, create directories with their mode bits.
func copyTree(src, dst string, excludes map[string]struct{}) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == src {
			return nil
		}
		if _, bad := excludes[d.Name()]; bad {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		q := filepath.Join(dst, rel)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			_ = os.Remove(q)
			return os.Symlink(link, q)
		case info.IsDir():
			return os.MkdirAll(q, info.Mode().Perm())
		case info.Mode().IsRegular():
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(q), 0o755); err != nil {
				return err
			}
			_ = os.Remove(q)
			return os.WriteFile(q, raw, info.Mode().Perm())
		default:
			return nil // fifos/sockets: nothing to hash, not copied
		}
	})
}

// --- the pin ----------------------------------------------------------------

// PinSourceSnapshot is pin_source_snapshot: detect the ladder, stage the
// tree (git worktree on git-clean, copytree otherwise), physically prune
// the bulk/extra/store excludes, hash what remains, and pin the snapshot
// dict (schema-validated on write) as the campaign's active snapshot.
//
// snapshot_id forms (Python-exact; the plan's §Task 11 shorthand is wrong,
// see report): git-clean "src-"+commit[:12]; git-dirty
// "src-"+commit[:8]+"-"+content_hash[:12]; no-vcs
// "src-content-"+content_hash[:12].
func PinSourceSnapshot(c *state.Campaign, target string, config *validation.Value, extraExcludes []string) (validation.Value, error) {
	targetAbs := resolveSnap(target)
	ladder, commit, dirty, err := DetectLadder(targetAbs)
	if err != nil {
		return validation.VNull(), err
	}

	snapRoot := resolveSnap(filepath.Join(c.Dir, "snapshots"))
	if err := os.MkdirAll(snapRoot, 0o755); err != nil {
		return validation.VNull(), err
	}
	// Never copy the store into itself: when snap_root lives inside the
	// target, exclude the top-level entry that leads to it.
	excludes := map[string]struct{}{}
	for k := range SourceExcludes {
		excludes[k] = struct{}{}
	}
	for k := range BulkSourceExcludes {
		excludes[k] = struct{}{}
	}
	for _, k := range extraExcludes {
		excludes[k] = struct{}{}
	}
	if rel, rerr := filepath.Rel(targetAbs, snapRoot); rerr == nil && rel != "." &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		excludes[strings.Split(rel, string(os.PathSeparator))[0]] = struct{}{}
	}
	// The SCOPE this pin deliberately drops, computed from the target so it
	// is reported identically on every ladder path.
	pruneSet := map[string]struct{}{}
	for k := range excludes {
		if _, keep := SourceExcludes[k]; !keep {
			pruneSet[k] = struct{}{}
		}
	}
	prunedTop := excludedNamesIn(targetAbs, pruneSet)

	staging := snapRoot + string(os.PathSeparator) +
		"staging-" + strings.ReplaceAll(snapNowIso(), ":", "") +
		fmt.Sprintf("-%d", os.Getpid())
	worktreeAdded := false
	defer func() {
		// The worktree moved (rename) or was discarded (re-pin noop): only
		// a leftover staging dir needs rmtree + prune, exactly like the
		// Python finally block.
		if worktreeAdded {
			if dirExists(staging) {
				_ = os.RemoveAll(staging)
				Git(targetAbs, "worktree", "prune")
			}
		}
	}()

	if ladder == "git-clean" && commit != nil {
		Git(targetAbs, "worktree", "add", "--detach", staging, *commit)
		if dirExists(staging) {
			worktreeAdded = true
		} else {
			// git missing/raced: fall back to a copy.
			if err := copyTree(targetAbs, staging, excludes); err != nil {
				return validation.VNull(), err
			}
		}
	} else {
		if err := copyTree(targetAbs, staging, excludes); err != nil {
			return validation.VNull(), err
		}
	}

	// Physical prune: required on the worktree path (whole tree checked
	// out), a no-op on the copytree path (ignore already pruned).
	pruneExcludes(staging, pruneSet)

	contentHash, fileCount, err := ContentHash(staging)
	if err != nil {
		return validation.VNull(), err
	}
	var snapshotID string
	switch ladder {
	case "git-clean":
		snapshotID = "src-" + trunc(*commit, 12)
	case "git-dirty":
		snapshotID = "src-" + trunc(*commit, 8) + "-" + trunc(contentHash, 12)
	default: // no-vcs: the content hash is the only identity
		snapshotID = "src-content-" + trunc(contentHash, 12)
	}

	final := filepath.Join(snapRoot, snapshotID)
	if dirExists(final) {
		// Re-pin of identical content: verify the existing copy still
		// hashes to what was just computed, then discard staging.
		priorHash, _, err := ContentHash(final)
		if err != nil {
			return validation.VNull(), err
		}
		if priorHash != contentHash {
			return validation.VNull(), fmt.Errorf(
				"pinned snapshot %s no longer matches its recorded content hash "+
					"— the immutable copy was modified; delete it and re-pin", snapshotID)
		}
		_ = os.RemoveAll(staging)
	} else {
		if err := os.Rename(staging, final); err != nil {
			return validation.VNull(), err
		}
		if worktreeAdded {
			// The worktree moved; tell git where it went (best effort).
			Git(targetAbs, "worktree", "repair", final)
			worktreeAdded = false
		}
	}

	var cfg validation.Value
	if config == nil || (config.Kind == validation.Obj && len(config.O) == 0) {
		cfg = DetectToolchain(final)
	} else {
		cfg = *config
	}

	budget, err := c.Budget()
	if err != nil {
		return validation.VNull(), err
	}
	var gitCommit, gitDirty validation.Value
	gitCommit = validation.VNull()
	gitDirty = validation.VNull()
	if commit != nil {
		gitCommit = validation.VStr(*commit)
	}
	if dirty != nil {
		gitDirty = validation.VBool(*dirty)
	}
	source := validation.VObj(
		validation.KV{K: "ladder", V: validation.VStr(ladder)},
		validation.KV{K: "git_commit", V: gitCommit},
		validation.KV{K: "git_dirty", V: gitDirty},
		validation.KV{K: "content_hash", V: validation.VStr(contentHash)},
		validation.KV{K: "root", V: validation.VStr(final)},
		validation.KV{K: "file_count", V: validation.VInt(int64(fileCount))},
	)
	if len(prunedTop) > 0 {
		names := make([]validation.Value, len(prunedTop))
		for i, n := range prunedTop {
			names[i] = validation.VStr(n)
		}
		source.O = append(source.O, validation.KV{K: "excluded", V: validation.VArr(names...)})
	}
	snap := validation.VObj(
		validation.KV{K: "snapshot_id", V: validation.VStr(snapshotID)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "created_at", V: validation.VStr(snapNowIso())},
		validation.KV{K: "pass", V: sget(budget, "pass")},
		validation.KV{K: "pinned", V: validation.VBool(
			ladder == "git-clean" || ladder == "git-dirty" || ladder == "no-vcs")},
		validation.KV{K: "source", V: source},
		validation.KV{K: "deployment", V: validation.VNull()},
		validation.KV{K: "chain", V: validation.VNull()},
		validation.KV{K: "config", V: cfg},
	)
	if len(prunedTop) > 0 {
		// The prune is SCOPE: record which top-level names this pin
		// deliberately does NOT cover, in the snapshot and on the log.
		names := make([]validation.Value, len(prunedTop))
		for i, n := range prunedTop {
			names[i] = validation.VStr(n)
		}
		data := validation.VObj(
			validation.KV{K: "names", V: validation.VArr(names...)},
			validation.KV{K: "reason", V: validation.VStr(
				"bulk-default and/or --exclude prune set at pin time")},
		)
		if _, err := c.Log("snapshot.excluded", &snapshotID, &data); err != nil {
			return validation.VNull(), err
		}
	}
	// Self-describing manifest, then the schema-validated write, then pin.
	snap, err = RefreshManifest(snap, final)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(filepath.Join(final, "snapshot.json"), snap, "snapshot"); err != nil {
		return validation.VNull(), err
	}
	if _, err := c.PinSnapshot(snap); err != nil {
		return validation.VNull(), err
	}
	return snap, nil
}
