package cli

// DEFECT-2 follow-up: `webv2 --version` names the binary's own build
// commit, so an operator can compare it against the checkout (and the
// snapshot pin) instead of discovering the skew from a crash.

import (
	"strings"
	"testing"
)

func TestVersionNamesBuildCommit(t *testing.T) {
	for _, flag := range []string{"--version", "-V"} {
		code, out, errS := run(t, flag)
		if code != 0 {
			t.Fatalf("%s exit %d: %q", flag, code, errS)
		}
		if !strings.HasPrefix(out, "webv2 ") {
			t.Fatalf("%s output = %q, want the `webv2 <build>` line", flag, out)
		}
		if errS != "" {
			t.Fatalf("%s wrote to stderr: %q", flag, errS)
		}
	}
}
