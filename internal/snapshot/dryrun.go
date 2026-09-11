package snapshot

// dryrun.go — M2/M5: `snap --dry-run` and the untracked-files warning.
//
// M2: the operator choosing a target cannot see the prune set before
// paying for the pin. DryRunPin stages, prunes and hashes through the
// same stageTree core as a real pin but records nothing: no snapshot dir,
// no manifest, no snapshot.json, no campaign events.
//
// M5: an operator running agents against a bounty target wants a warning
// when untracked files appear inside the pinned tree (a deliberately kept
// PoC test file is exactly the shape of an accidental scope change).
// UntrackedFiles lists them; the CLI warning also says whether this
// ladder's pin covers them (copytree paths do, the git-clean worktree
// does not).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// stagedTree is the halfway state of a pin: the source staged, pruned and
// hashed, before anything is recorded.
type stagedTree struct {
	targetAbs     string
	ladder        string
	commit        *string
	dirty         *bool
	excludes      map[string]struct{}
	pruneSet      map[string]struct{}
	prunedPaths   []string
	staging       string
	worktreeAdded bool
	contentHash   string
	fileCount     int
	snapshotID    string
}

// stageTree is the first half of PinSourceSnapshot, verbatim: detect the
// ladder, build the exclude set, stage the tree (git worktree on
// git-clean, copytree otherwise), prune and hash it, derive the snapshot
// id. snapRoot is the snapshot store ("" for a dry run: staging goes to a
// temp dir and the never-copy-the-store-into-itself exclusion is
// skipped). The caller owns cleanup: the real pin keeps its
// rename-or-discard defer; a dry run calls discardStaged.
func stageTree(targetAbs, snapRoot string, extraExcludes []string) (*stagedTree, error) {
	ladder, commit, dirty, err := DetectLadder(targetAbs)
	if err != nil {
		return nil, err
	}
	stagingParent := snapRoot
	if stagingParent == "" {
		stagingParent, err = os.MkdirTemp("", "webv2-snap-dryrun-")
		if err != nil {
			return nil, err
		}
	} else if err := os.MkdirAll(snapRoot, 0o755); err != nil {
		return nil, err
	}
	// Never copy the store into itself: when snap_root lives inside the
	// target, exclude the top-level entry that leads to it.
	excludes := excludeSet(extraExcludes)
	if snapRoot != "" {
		if rel, rerr := filepath.Rel(targetAbs, snapRoot); rerr == nil && rel != "." &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			excludes[strings.Split(rel, string(os.PathSeparator))[0]] = struct{}{}
		}
	}
	// The SCOPE this pin deliberately drops, computed from the target so it
	// is reported identically on every ladder path.
	pruneSet := map[string]struct{}{}
	for k := range excludes {
		if _, keep := SourceExcludes[k]; !keep {
			pruneSet[k] = struct{}{}
		}
	}
	prunedPaths := excludedNamesIn(targetAbs, pruneSet)

	staging := stagingParent + string(os.PathSeparator) +
		"staging-" + strings.ReplaceAll(snapNowIso(), ":", "") +
		fmt.Sprintf("-%d", os.Getpid())
	st := &stagedTree{targetAbs: targetAbs, ladder: ladder, commit: commit,
		dirty: dirty, excludes: excludes, pruneSet: pruneSet,
		prunedPaths: prunedPaths, staging: staging}

	if ladder == "git-clean" && commit != nil {
		Git(targetAbs, "worktree", "add", "--detach", staging, *commit)
		if dirExists(staging) {
			st.worktreeAdded = true
		} else {
			// git missing/raced: fall back to a copy.
			if err := copyTree(targetAbs, staging, excludes); err != nil {
				return nil, err
			}
		}
	} else {
		if err := copyTree(targetAbs, staging, excludes); err != nil {
			return nil, err
		}
	}

	// Physical prune: required on the worktree path (whole tree checked
	// out), a no-op on the copytree path (ignore already pruned).
	pruneExcludes(staging, pruneSet)

	contentHash, fileCount, err := ContentHash(staging)
	if err != nil {
		return nil, err
	}
	st.contentHash, st.fileCount = contentHash, fileCount
	switch ladder {
	case "git-clean":
		st.snapshotID = "src-" + trunc(*commit, 12)
	case "git-dirty":
		st.snapshotID = "src-" + trunc(*commit, 8) + "-" + trunc(contentHash, 12)
	default: // no-vcs: the content hash is the only identity
		st.snapshotID = "src-content-" + trunc(contentHash, 12)
	}
	return st, nil
}

// discardStaged undoes a DRY-RUN staging: remove the temp tree (and its
// temp parent) and prune a worktree registration if one was made.
func discardStaged(st *stagedTree) {
	_ = os.RemoveAll(st.staging)
	_ = os.RemoveAll(filepath.Dir(st.staging))
	if st.worktreeAdded {
		Git(st.targetAbs, "worktree", "prune")
	}
}

// Preview is the M2 dry-run report: everything the pin WOULD record,
// with nothing recorded.
type Preview struct {
	Target      string
	Ladder      string
	SnapshotID  string
	FileCount   int
	ContentHash string
	// PruneNames is the FULL effective exclude-name set (hash excludes +
	// bulk prune defaults + --exclude): the static answer to "what will
	// you drop". PrunedPaths is what actually matched in THIS target —
	// the scope-relevant subset the pin records as "excluded".
	PruneNames    []string
	PrunedPaths   []string
	Untracked     []string
	UntrackedMore int
}

// DryRunPin stages, prunes and hashes the target exactly like a real pin
// and reports the preview, then discards the staging. No snapshot dir,
// no manifest, no snapshot.json, no campaign events are written.
func DryRunPin(target string, extraExcludes []string) (*Preview, error) {
	targetAbs := resolveSnap(target)
	st, err := stageTree(targetAbs, "", extraExcludes)
	if err != nil {
		return nil, err
	}
	defer discardStaged(st)
	untracked, more := UntrackedFiles(targetAbs, st.excludes)
	return &Preview{
		Target:        target,
		Ladder:        st.ladder,
		SnapshotID:    st.snapshotID,
		FileCount:     st.fileCount,
		ContentHash:   st.contentHash,
		PruneNames:    sortedKeys(st.excludes),
		PrunedPaths:   st.prunedPaths,
		Untracked:     untracked,
		UntrackedMore: more,
	}, nil
}

// excludeSet is the effective exclude-name set for a pin: the hash
// excludes, the bulk prune defaults, and the operator's --exclude names.
func excludeSet(extraExcludes []string) map[string]struct{} {
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
	return excludes
}

// untrackedCap bounds the reported untracked list; the true count rides
// alongside so a cap never hides work.
const untrackedCap = 20

// UntrackedInTarget recomputes the effective exclude names for target (as
// the pin would) and lists untracked files under it. See UntrackedFiles.
func UntrackedInTarget(target string, extraExcludes []string) ([]string, int) {
	return UntrackedFiles(resolveSnap(target), excludeSet(extraExcludes))
}

// UntrackedFiles lists git-untracked entries under target (porcelain `??`),
// minus the pruned names. Empty for non-git targets, clean trees, or
// missing git — every one of those is silent: the warning is advisory,
// never an error. The second return is entries beyond the cap.
func UntrackedFiles(targetAbs string, skip map[string]struct{}) ([]string, int) {
	out := Git(targetAbs, "status", "--porcelain=v1",
		"--untracked-files=normal", "--", ".")
	if out == "" {
		return nil, 0
	}
	listed := []string{}
	more := 0
	for _, ln := range strings.Split(out, "\n") {
		if !strings.HasPrefix(ln, "??") {
			continue
		}
		p := strings.TrimSpace(strings.TrimPrefix(ln, "??"))
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			continue
		}
		if _, bad := skip[strings.Split(p, "/")[0]]; bad {
			continue
		}
		if len(listed) < untrackedCap {
			listed = append(listed, p)
		} else {
			more++
		}
	}
	return listed, more
}
