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
	// state.nowIso — honored verbatim, unset = real clock).
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

// ContainmentWarning is the one sentence the containment geometry prints:
// the campaign directory sits inside the target that was pinned, so the
// campaign's own notes, findings and logs are physically part of the tree
// an agent can read as target source. It is exported because both `snap`
// (which prints it as `warning: ` + this) and `scorecard` (which reads the
// recorded source.campaign_inside_target flag) must say the same thing;
// internal/snapshot must not import internal/cli for it.
const ContainmentWarning = "the campaign directory is inside the pinned target " +
	"tree; its own notes are part of what an agent could read as target source"

// insideTree reports whether dir is root itself or a strict descendant of
// it, comparing whole path components: "/a/target2" is not inside
// "/a/target", and neither is "/a/other". This is the only place the
// comparison lives now: `scorecard` used to keep a twin of it, but that
// comparison could never fire (it compared the staged copy against its own
// parent) and the section reads the recorded flag instead. It is not
// shared with internal/cli because sharing it would make internal/snapshot
// import internal/cli. Both paths are clean and absolute by the time they
// get here; filepath.Rel is the whole component-wise test.
func insideTree(root, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(dir))
	if err != nil {
		return false
	}
	return rel == "." ||
		(rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// --- prune helpers ----------------------------------------------------------

// pruneExcludes is _prune_excludes: physically remove from staging every
// file or directory whose NAME is in excludes, at any depth. Returns the
// sorted RELATIVE subpaths of the entries that matched, for the record
// (feedback-triage A10: the old code aggregated each match to its first
// path component, so a deep build-artifact dir inside an in-scope project
// made the whole top-level directory look excluded). Required on the
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
	// A10: report the actual matched subpath, not just the top-level
	// component, so a deep match inside an in-scope dir is not mistaken
	// for the whole dir being out of scope.
	paths := map[string]struct{}{}
	for _, p := range victims {
		rel, err := filepath.Rel(staging, p)
		if err != nil || rel == "." {
			continue
		}
		paths[filepath.ToSlash(rel)] = struct{}{}
	}
	return sortedKeys(paths)
}

// excludedNamesIn is _excluded_names_in: the paths in target that the prune
// set will drop, at whatever depth they match. Computed from the target
// (not the staging) because on the copytree path the exclusion already
// happened at copy time. A10: returns the full relative subpath of each
// match (a deep match under an in-scope dir must not be reported as the
// whole top-level dir being excluded).
func excludedNamesIn(target string, names map[string]struct{}) []string {
	paths := map[string]struct{}{}
	_ = filepath.WalkDir(target, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == target {
			return nil
		}
		if _, bad := names[d.Name()]; bad {
			rel, rerr := filepath.Rel(target, p)
			if rerr == nil && rel != "." && rel != "" {
				paths[filepath.ToSlash(rel)] = struct{}{}
			}
		}
		return nil
	})
	return sortedKeys(paths)
}

// MatchedExcludes reports, for each requested exclude NAME, whether the
// target tree carries an entry with that base name at any depth (exact base
// names — the ported ignore-pattern law is not glob). Exposed for the CLI's
// "matched nothing" note (critic r2).
func MatchedExcludes(target string, names []string) map[string]bool {
	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = false
	}
	_ = filepath.WalkDir(resolveSnap(target), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: conservative (not matched)
		}
		if _, bad := set[d.Name()]; bad {
			found[d.Name()] = true
		}
		return nil
	})
	return found
}

// sortedKeys returns the sorted string keys of a set.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
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
	// Python's copytree creates the destination root even when the source
	// is empty; the walk below returns at p==src without touching dst, so
	// the root must be made here or an empty-after-prune tree leaves no
	// staging at all and hashing fails with a raw lstat error (critic r2).
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
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
	// Containment is a fact about THIS pin: the campaign directory (its
	// notes, findings, logs) sitting inside the absolute target being
	// pinned. It is decided here, where the target is resolved, because
	// the recorded source.root is the staged COPY under the campaign dir —
	// from what lands on disk the geometry is unrepresentable, so a reader
	// downstream would be comparing a path against its own parent.
	campaignInsideTarget := insideTree(targetAbs, resolveSnap(c.Dir))
	snapRoot := resolveSnap(filepath.Join(c.Dir, "snapshots"))
	st, err := stageTree(targetAbs, snapRoot, extraExcludes)
	if err != nil {
		return validation.VNull(), err
	}
	ladder, commit, dirty := st.ladder, st.commit, st.dirty
	prunedPaths := st.prunedPaths
	staging := st.staging
	worktreeAdded := st.worktreeAdded
	contentHash, fileCount := st.contentHash, st.fileCount
	snapshotID := st.snapshotID
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
	// Presence-gated: the key exists only when the geometry actually
	// holds. An absent key means "not the containment case" — which is
	// also every snapshot pinned before this field existed, so old records
	// read correctly without a migration.
	if campaignInsideTarget {
		source.O = append(source.O, validation.KV{K: "campaign_inside_target",
			V: validation.VBool(true)})
	}
	if len(prunedPaths) > 0 {
		names := make([]validation.Value, len(prunedPaths))
		for i, n := range prunedPaths {
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
	if len(prunedPaths) > 0 {
		// The prune is SCOPE: record the subpaths this pin deliberately
		// does NOT cover (A10: the actual matched paths, at their real
		// depth — not an aggregated top-level name), in the snapshot and
		// on the log.
		names := make([]validation.Value, len(prunedPaths))
		for i, n := range prunedPaths {
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
	// Printed here, not by the caller, because the pin path is the only
	// place that still knows the TARGET: source.root is the staged copy,
	// so `scorecard` reads the recorded flag instead and a caller could
	// not reconstruct the geometry from the returned dict. stderr, not
	// stdout: the pin's own report is the machine-readable part, and the
	// `snap` verb has no stderr writer of its own to hand down.
	if campaignInsideTarget {
		fmt.Fprintln(os.Stderr, "warning: "+ContainmentWarning)
	}
	return snap, nil
}
