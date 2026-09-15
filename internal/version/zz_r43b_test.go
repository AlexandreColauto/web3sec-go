package version

// R43B (P3-1): an unstamped `webv2 --version` said "no VCS stamp: not built
// from a git checkout". Go's buildvcs emits NO stamp for a git WORKTREE
// build, so that sentence named a cause the binary had not verified — and it
// is exactly the sanctioned build in which the stamp matters. The line must
// state what is known (there is no VCS stamp in this binary) and, where it
// names causes at all, name the plausible ones without choosing between them.

import (
	"strings"
	"testing"
)

func TestR43bUnstampedVersionAssertsNoCause(t *testing.T) {
	t.Setenv(webv2BuildEnv, "")
	if Known() {
		t.Skip("this binary carries a VCS stamp; the unstamped line is unobservable")
	}
	d := Describe()
	t.Logf("Describe() = %q", d)
	if strings.Contains(d, "not built from a git checkout") {
		t.Fatalf("Describe() = %q asserts a cause it did not verify: a git "+
			"worktree build carries no VCS stamp either", d)
	}
	if !strings.Contains(d, "no VCS stamp") {
		t.Fatalf("Describe() = %q does not state the one fact it knows", d)
	}
	// The chosen wording names the plausible causes instead of picking one.
	for _, cause := range []string{"worktree", "-buildvcs=false", "exported"} {
		if !strings.Contains(d, cause) {
			t.Errorf("Describe() = %q names no plausible cause %q; the "+
				"operator is left guessing", d, cause)
		}
	}
}

// TestR43bStampedVersionIsUnchanged is the other half: the fix touches only
// the unstamped branch — a stamped build still names its commit.
func TestR43bStampedVersionIsUnchanged(t *testing.T) {
	if rev, _, _ := vcsInfo(); rev != "" {
		t.Skip("this binary carries a VCS stamp; the override path is unobservable")
	}
	t.Setenv(webv2BuildEnv, "0f0f0f0f0f0f")
	d := Describe()
	t.Logf("Describe() = %q", d)
	if !strings.Contains(d, "0f0f0f0f0f0f") {
		t.Fatalf("Describe() = %q does not name the pinned build", d)
	}
	if strings.Contains(d, "no VCS stamp") {
		t.Fatalf("Describe() = %q calls a known build unstamped", d)
	}
}
