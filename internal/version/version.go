package version

// version.go — the binary's build identity (DEFECT-2 follow-up).
//
// The eval found no `webv2 --version` vs checkout-commit affordance: an
// operator running a stale binary cannot tell it is stale, so a fixed defect
// (DEFECT-1) gets re-litigated as a live one. The identity rides Go's own VCS
// stamping (runtime/debug.ReadBuildInfo: vcs.revision/vcs.time/vcs.modified,
// recorded automatically on builds Go stamps — -trimpath and CGO_ENABLED=0 do
// not remove it), so no ldflags wiring, no release-script change, and no CI
// change is needed.
//
// r43b (P3-1): "on every build from a git checkout" was itself a lie of the
// kind this file exists to avoid. Go's buildvcs emits NO stamp for some
// sanctioned builds — a git WORKTREE build is the reported one — so a
// stamped-when-possible binary that says "not built from a git checkout"
// asserts a cause it never verified. Absence of a stamp is the fact; the
// causes are possibilities. Describe() names them as such and nothing more.

import (
	"os"
	"runtime/debug"
)

// Unknown is the Commit value when the binary carries no VCS stamp and no
// override is set (see WEBV2_BUILD below).
const Unknown = "unknown"

// webv2BuildEnv is the deterministic override for UNSTAMPED builds only:
// test binaries never carry a VCS stamp (Go stamps main-package builds),
// so hermetic tests and the golden suite pin identity through the same
// WEBV2_* env mechanism the harness already uses for time and ids
// (WEBV2_NOW, WEBV2_UUID, WEBV2_FINDING_IDS). A stamped production binary
// ignores it — the environment must never be able to fake a release build.
const webv2BuildEnv = "WEBV2_BUILD"

// Commit is the 12-char build commit, the WEBV2_BUILD override on
// unstamped builds, or Unknown when neither knows.
func Commit() string {
	rev, _, _ := vcsInfo()
	if rev == "" {
		rev = os.Getenv(webv2BuildEnv)
	}
	if rev == "" {
		return Unknown
	}
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// Known reports whether the binary knows its own build commit.
func Known() bool { return Commit() != Unknown }

// BuildTime is the VCS timestamp of the build commit, or "" when unstamped.
func BuildTime() string {
	_, tm, _ := vcsInfo()
	return tm
}

// Dirty reports whether the build tree had uncommitted changes. False when
// unstamped (unknown, not clean — callers must check Known first).
func Dirty() bool {
	_, _, modified := vcsInfo()
	return modified
}

// Describe is the `webv2 --version` line.
//
// r43b: an unstamped binary states the fact (no VCS stamp in this binary) and,
// at most, the plausible causes — never one asserted cause. A worktree build
// is stamped-when-possible but carries no stamp, so claiming "not built from a
// git checkout" would be false exactly where the stamp matters.
func Describe() string {
	if !Known() {
		return "webv2 " + Unknown + " (no VCS stamp in this binary; " +
			"plausibly a git-worktree build, a -buildvcs=false build, " +
			"or a build from an exported tree)"
	}
	out := "webv2 " + Commit()
	if tm := BuildTime(); tm != "" {
		out += " (" + tm + ")"
	}
	if Dirty() {
		out += " +dirty"
	}
	return out
}

// vcsInfo is (revision, time, modified) from the build's VCS stamp.
func vcsInfo() (rev, tm string, modified bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", false
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			tm = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	return rev, tm, modified
}
