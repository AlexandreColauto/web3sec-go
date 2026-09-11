package version

// version_test.go — DEFECT-2 follow-up: the binary always names a build
// identity, stamped from git or honestly "unknown".

import (
	"strings"
	"testing"
)

func TestCommitIsNeverEmpty(t *testing.T) {
	if Commit() == "" {
		t.Fatal("Commit() is empty: --version would print a blank build")
	}
}

func TestDescribeNamesBinaryAndCommit(t *testing.T) {
	d := Describe()
	if !strings.HasPrefix(d, "webv2 ") {
		t.Fatalf("Describe() = %q, want the `webv2 <build>` line", d)
	}
	if Known() && !strings.Contains(d, Commit()) {
		t.Fatalf("Describe() = %q, does not name Commit() %q", d, Commit())
	}
	if !Known() && !strings.Contains(d, Unknown) {
		t.Fatalf("Describe() = %q, an unstamped build must say so", d)
	}
}

func TestBuildOverrideCoversUnstampedBuilds(t *testing.T) {
	// Test binaries never carry a VCS stamp (Go stamps main-package
	// builds), so without the override every test process reads Unknown.
	// The override exists for exactly this case — and only this case: a
	// stamped production binary ignores the environment.
	t.Setenv("WEBV2_BUILD", "override-build-for-tests")
	if !Known() {
		t.Fatal("WEBV2_BUILD override did not apply on an unstamped build")
	}
	if got := Commit(); got != "override-bui" {
		t.Fatalf("Commit() = %q, want the override truncated to 12 chars",
			got)
	}
}
