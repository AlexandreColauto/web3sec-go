package cli

// cmd_classify_toolabsent_test.go — Task 9 at the operator surface. The law
// (production-readiness plan §Task 9; RUNBOOK §0 toolchain provisioning and
// §6a) is that a MISSING TOOLCHAIN BINARY routes to ENVIRONMENT with a note
// that names the fix, because the box — not the hypothesis — lost the round.
// internal/envgo/classifier_toolabsent_test.go pins the classifier; this file
// drives the wired `classify` verb end-to-end, so the class the operator
// actually reads is pinned too.

import (
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
)

func TestClassifyVerbMissingToolchainIsEnvironment(t *testing.T) {
	root, cid := r38Camp(t)
	ensureSeams() // the production wiring (sandbox.SetClassifyFailure(envgo.…))
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	reg := func(name, text string) string {
		t.Helper()
		rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
			Profile: "docker-networkless", Command: "forge test",
			ReportedBy: "harness", ExitStatus: 1, StderrText: text})
		if err != nil {
			t.Fatal(err)
		}
		return objStr(rec, "exec_id")
	}
	cases := []struct {
		name     string
		text     string
		wantNote string
	}{
		{"missing-solc", "Error: solc 0.8.24 is not installed. Install it " +
			"with `svm install 0.8.24`\n", "WEBV2_SOLC_DIR"},
		{"missing-forge", "sh: 1: forge: not found\n", "foundryup"},
		{"missing-docker", "docker: command not found\n", "docker CLI"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			execID := reg(tc.name, tc.text)
			code, out, errS := run(t, "--root", root, "classify", cid, execID)
			if code != 0 {
				t.Fatalf("classify exit %d: out=%q err=%q", code, out, errS)
			}
			if !strings.Contains(out, "(exit 1): ENVIRONMENT") {
				t.Fatalf("class line = %q, want ENVIRONMENT", out)
			}
			if !strings.Contains(out, "toolchain binary absent") {
				t.Errorf("output lacks the absence signal: %q", out)
			}
			if !strings.Contains(out, tc.wantNote) {
				t.Errorf("note lacks the fix %q: %q", tc.wantNote, out)
			}
			if strings.Contains(out, "retry in a fresh context") {
				t.Errorf("a missing toolchain must not be routed to a "+
					"fresh-context retry: %q", out)
			}
		})
	}
}
