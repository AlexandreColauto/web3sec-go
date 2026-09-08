// Snapshot ladder detection: _git probe tolerance and _detect_ladder.
//
// Ports web3sec-final/src/webv2/snapshot.py::_git and _detect_ladder.
package snapshot

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// BulkSourceExcludes mirrors BULK_SOURCE_EXCLUDES: bulk / generated
// directory names pruned from a source pin by DEFAULT at copy time. The
// set only prunes what gets COPIED — SOURCE_EXCLUDES (in hashing.go) is
// left untouched because it drives the content/manifest hash.
// Verified against the Python constant 1:1.
var BulkSourceExcludes = map[string]struct{}{
	"data":            {},
	"datasets":        {},
	"data-raw":        {},
	".scratch":        {},
	"webv2-workspace": {},
	".pytest_cache":   {},
	".mypy_cache":     {},
	".ruff_cache":     {},
	".tox":            {},
	"build":           {},
	"dist":            {},
}

// Git is _git: run `git -C path args...` and return the stripped stdout.
// Any failure — missing binary, non-zero exit, timeout — returns ""
// exactly like Python returning "" on SubprocessError/FileNotFoundError,
// so a missing git degrades git-clean/git-dirty to the no-vcs path.
func Git(path string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	full := append([]string{"-C", path}, args...)
	out, err := exec.CommandContext(ctx, "git", full...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// DetectLadder is _detect_ladder: (ladder, git_commit, git_dirty). A
// missing target is an error (Python: raise FileNotFoundError(target)).
func DetectLadder(target string) (string, *string, *bool, error) {
	if _, err := os.Stat(target); err != nil {
		return "", nil, nil, err
	}
	commit := Git(target, "rev-parse", "HEAD")
	if commit != "" {
		dirty := Git(target, "status", "--porcelain") != ""
		cp := commit
		if dirty {
			return "git-dirty", &cp, &dirty, nil
		}
		return "git-clean", &cp, &dirty, nil
	}
	return "no-vcs", nil, nil, nil
}
