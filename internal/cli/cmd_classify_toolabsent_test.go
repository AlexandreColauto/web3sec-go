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
	"websec/internal/validation"

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
		return validation.ObjStr(rec, "exec_id")
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

// TestClassifyVerbToolAbsenceBoundaries pins the two task-9 review findings at
// the operator surface. F1: the foundry absence token needs a LEADING word
// boundary too, so "cast" inside "broadcast" is not the binary — a missing
// broadcast artifact is repository SETUP and keeps the fresh-context retry.
// F2: a hypothesis-space assertion outranks a merely-ECHOED subprocess
// not-found — LOGIC is the only class that argues the hypothesis, and it must
// not deny the retry.
func TestClassifyVerbToolAbsenceBoundaries(t *testing.T) {
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
		return validation.ObjStr(rec, "exec_id")
	}
	cases := []struct {
		name, text, wantClass, wantNote string
		forbid                          []string
	}{
		{"broadcast-not-found-stays-setup",
			"Error: broadcast not found for script deploy\n", "SETUP",
			"retry in a fresh context",
			[]string{"foundryup", "toolchain binary absent"}},
		{"echoed-not-found-with-assertion-stays-logic",
			"sh: 1: helper.sh: command not found\nassertion failed: x != y\n",
			"LOGIC", "only class that argues the finding",
			[]string{"do NOT spend a fresh-context retry"}},
		{"solc-colon-not-installed-stays-environment", "solc: not installed\n",
			"ENVIRONMENT", "WEBV2_SOLC_DIR",
			[]string{"retry in a fresh context"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			execID := reg(tc.name, tc.text)
			code, out, errS := run(t, "--root", root, "classify", cid, execID)
			if code != 0 {
				t.Fatalf("classify exit %d: out=%q err=%q", code, out, errS)
			}
			if !strings.Contains(out, "(exit 1): "+tc.wantClass) {
				t.Fatalf("class line = %q, want %s", out, tc.wantClass)
			}
			if !strings.Contains(out, tc.wantNote) {
				t.Errorf("note lacks %q: %q", tc.wantNote, out)
			}
			for _, bad := range tc.forbid {
				if strings.Contains(out, bad) {
					t.Errorf("output must not contain %q: %q", bad, out)
				}
			}
		})
	}
}
