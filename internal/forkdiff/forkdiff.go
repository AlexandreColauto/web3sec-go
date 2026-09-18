// Package forkdiff is a 1:1 port of webv2/forkdiff.py: how far is this
// target from known-good reference protocols? A target that differs from a
// battle-tested baseline by a handful of selectors is where critical bugs
// hide: the diff is the search space. The fingerprint is built on the SAME
// parser as the structural index (one parser, no drift), and baselines are
// operator-supplied, version-pinned trees with content hashes — nothing here
// fetches them at runtime.
//
// Verdicts are advisory (strong/partial/none): they order attention, they do
// not gate findings. Baseline drift is an audit failure, because a drifted
// reference silently corrupts every diff.
package forkdiff

import (
	"os"
	"path/filepath"

	"websec/internal/audit/sections"
	"websec/internal/state"
	"websec/internal/validation"
)

// RepoRoot is REPO_ROOT: the tree the baselines directory hangs off. Python
// derives it from __file__ (an ABSOLUTE source-relative path); a Go binary
// has no source-relative root, so it defaults to the ABSOLUTE working
// directory — absolute so that the paths in diagnostics ("baseline source
// X overlaps the destination Y") render the same shape as Python's, and
// settable by the CLI/embedder.
var RepoRoot = "."

// BaselinesDir is BASELINES_DIR (REPO_ROOT/baselines).
var BaselinesDir = filepath.Join(RepoRoot, "baselines")

func init() {
	if wd, err := os.Getwd(); err == nil {
		RepoRoot = wd
		BaselinesDir = filepath.Join(wd, "baselines")
	}
}

// SetRepoRoot repoints REPO_ROOT and the derived baselines directory.
func SetRepoRoot(root string) {
	if root == "" {
		root = "."
	}
	RepoRoot = root
	BaselinesDir = filepath.Join(root, "baselines")
}

// SetBaselinesDir points the baselines directory at an explicit path.
func SetBaselinesDir(dir string) {
	if dir == "" {
		dir = filepath.Join(RepoRoot, "baselines")
	}
	BaselinesDir = dir
}

// Wire installs forkdiff into the audit's baselines section (section 10),
// which owns the drift check: a baseline whose src/ no longer matches its
// recorded fingerprint is an audit problem. Python has no wiring step — the
// section imports forkdiff directly — so this is the Go spelling of that
// import edge.
func Wire() {
	sections.SetForkdiff(seam{})
}

// seam implements sections.ForkdiffAPI over this package's globals.
type seam struct{}

// BaselinesDir is FD.BASELINES_DIR.
func (seam) BaselinesDir(*state.Campaign) string { return BaselinesDir }

// FingerprintTree is FD.fingerprint_tree.
func (seam) FingerprintTree(root string) (validation.Value, error) {
	return FingerprintTree(root)
}
