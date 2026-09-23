package envgo

// classifier_toolabsent_test.go — Task 9 of the production-readiness plan
// (docs/archive/PORT-ERA-DIGEST.md §II (2026-09-17-trust-boundary-hardening) §Task 9):
// a MISSING TOOLCHAIN BINARY (solc, the foundry tools, the docker client) is
// an ENVIRONMENT failure, per the runbook's own vocabulary —
//
//	RUNBOOK §0 (toolchain): "With the network cut (networkless / gvisor /
//	vm-snapshot profiles), a missing solc binary is an environment failure,
//	not a harness bug."
//	RUNBOOK §6a: "A FAILED exec is classified on the spot: ENVIRONMENT
//	(daemon down, image missing, solc download cut — fix the environment, do
//	NOT spend a fresh-context retry), SETUP (retry in a fresh context with
//	the failure record), LOGIC (the only class that argues the hypothesis)."
//
// The classifier used to route "Error: solc 0.8.24 is not installed" and
// "sh: 1: forge: not found" (exit 1, no docker-level exit code) into
// setup/unknown — spending the finding's fresh-context retry on a box that
// simply lacks the binary. The rows above the boundary are that law; the rows
// below it are the hypothesis-space failures that must NOT move: a missing
// Solidity LIBRARY (forge-std, "module not found") is repository setup, not a
// missing toolchain, and a compile error / assertion is the hypothesis losing
// a round.

import (
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/validation"
)

// TestToolchainAbsenceClassifiesEnvironment is the Task 9 table: absent
// toolchain binaries route to ENVIRONMENT and their note names the fix; the
// hypothesis-space rows keep their class.
func TestToolchainAbsenceClassifiesEnvironment(t *testing.T) {
	cases := []struct {
		name         string
		profile      string
		stdout       string
		exit         int
		class        string
		noteContains []string
		noteWithout  []string
	}{
		// --- missing toolchain/dependency -> ENVIRONMENT -------------------
		{"missing-solc-not-installed", "docker-networkless",
			"Error: solc 0.8.24 is not installed. Install it with " +
				"`svm install 0.8.24`\n",
			1, "environment",
			[]string{"solc", "svm cache", "WEBV2_SOLC_DIR", "fresh-context"},
			[]string{"retry in a fresh context"}},
		{"missing-solc-not-found", "docker-networkless",
			"Error: solc not found\n", 1, "environment",
			[]string{"solc", "WEBV2_SOLC_DIR", "fresh-context"}, nil},
		{"missing-solc-missing-from-cache", "docker-networkless",
			"solc 0.8.24 pinned by foundry.toml but missing from the svm " +
				"cache /home/foundry/.svm\n",
			1, "environment",
			[]string{"solc", "WEBV2_SOLC_DIR"}, nil},
		{"missing-forge-not-found", "docker-networkless",
			"sh: 1: forge: not found\n", 1, "environment",
			[]string{"foundryup", "fresh-context"},
			[]string{"retry in a fresh context"}},
		{"missing-forge-command-not-found", "docker-networkless",
			"forge: command not found\n", 1, "environment",
			[]string{"foundryup", "fresh-context"}, nil},
		{"missing-docker-command-not-found", "host-readonly",
			"docker: command not found\n", 1, "environment",
			[]string{"docker", "fresh-context"},
			[]string{"retry in a fresh context"}},
		{"missing-docker-executable-file-not-found", "host-readonly",
			"exec: \"docker\": executable file not found in $PATH\n", 1,
			"environment", []string{"docker", "fresh-context"}, nil},
		// A docker IMAGE that is not there is the same environment family
		// (§6a "image missing"), but the note must not claim the CLI is
		// absent — it names both readings and the probe that settles it.
		{"missing-docker-image", "docker-networkless",
			"Error: docker image ghcr.io/foundry-rs/foundry:latest not " +
				"found\n",
			1, "environment",
			[]string{"image", "fresh-context"},
			[]string{"the docker CLI is not on this box's PATH — install " +
				"docker (or use the host-readonly profile"}},
		{"missing-tool-generic-shell", "docker-networkless",
			"sh: 1: jq: not found\n", 1, "environment",
			[]string{"install", "fresh-context"}, nil},
		// A colon delimiter (rather than whitespace) is still absence
		// evidence for the binary itself.
		{"missing-solc-colon-not-installed", "docker-networkless",
			"solc: not installed\n", 1, "environment",
			[]string{"solc", "WEBV2_SOLC_DIR", "fresh-context"}, nil},
		// The exit-code path already names a missing binary and must keep
		// doing so (r36/r38 behaviour, not re-litigated here).
		{"missing-forge-exit127-host", "host-readonly", "", 127,
			"environment", []string{"could not find the command"}, nil},

		// --- hypothesis space -> unchanged ---------------------------------
		{"hypothesis-compile-error", "docker-networkless",
			"Error: compilation failed\n", 1, "setup",
			[]string{"retry in a fresh context"}, nil},
		{"hypothesis-missing-solidity-library", "docker-networkless",
			"Error: Source \"forge-std/Test.sol\" not found: File not " +
				"found.\n",
			1, "setup",
			[]string{"retry in a fresh context"}, []string{"foundryup"}},
		{"hypothesis-module-not-found", "docker-networkless",
			"Error: module not found: forge-std\n", 1, "setup",
			[]string{"retry in a fresh context"}, nil},
		{"hypothesis-logic", "docker-networkless",
			"assertion failed: x != y\n", 1, "logic",
			[]string{"only class that argues the finding"}, nil},
		{"unclassified-stays-unknown", "docker-networkless",
			"something odd happened\n", 1, "unknown",
			[]string{"routed as setup"}, nil},
		// F1 (task-9 review, finding 1): the absence token needs a LEADING
		// word boundary as well as its trailing delimiter — "cast" inside
		// "broadcast"/"forecast" is not the foundry binary. A missing
		// broadcast ARTIFACT is repository setup and keeps the fresh-context
		// retry; a forecast word is not evidence of anything.
		{"broadcast-not-found-stays-setup", "docker-networkless",
			"Error: broadcast not found for script deploy\n", 1, "setup",
			[]string{"retry in a fresh context"}, []string{"foundryup"}},
		{"forecast-word-stays-unknown", "docker-networkless",
			"forecast data not found\n", 1, "unknown",
			[]string{"routed as setup"}, []string{"foundryup"}},
		// F2 (task-9 review, finding 2): a hypothesis-space assertion
		// outranks a merely-ECHOED subprocess not-found. LOGIC is the only
		// class that argues the hypothesis, and its note must not deny the
		// fresh-context retry.
		{"echoed-subprocess-not-found-with-assertion", "docker-networkless",
			"sh: 1: helper.sh: command not found\nassertion failed: x != y\n",
			1, "logic", []string{"only class that argues the finding"},
			[]string{"do NOT spend a fresh-context retry"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := r38Record(t, "t9-"+tc.name, tc.profile, tc.stdout, "",
				tc.exit)
			res := ClassifyFailure(rec)
			if got := validation.ObjStr(res, "class"); got != tc.class {
				t.Fatalf("class = %q, want %q (signals %s, note %q)", got,
					tc.class, strings.Join(strList(validation.ObjAt(res, "signals")), "|"),
					validation.ObjStr(res, "note"))
			}
			note := validation.ObjStr(res, "note")
			if note == "" {
				t.Fatalf("empty note")
			}
			for _, want := range tc.noteContains {
				if !strings.Contains(note, want) {
					t.Errorf("note %q lacks %q", note, want)
				}
			}
			for _, bad := range tc.noteWithout {
				if strings.Contains(note, bad) {
					t.Errorf("note %q must not contain %q", note, bad)
				}
			}
		})
	}
}

// TestToolchainAbsenceSignalIsRecorded pins the signal the operator reads on
// the `classify` line, so the class is never asserted without the evidence
// that produced it.
func TestToolchainAbsenceSignalIsRecorded(t *testing.T) {
	rec := r38Record(t, "t9-signal", "docker-networkless",
		"Error: solc 0.8.24 is not installed. Install it with "+
			"`svm install 0.8.24`\n", "", 1)
	res := ClassifyFailure(rec)
	signals := strings.Join(strList(validation.ObjAt(res, "signals")), "|")
	if !strings.Contains(signals, "toolchain binary absent") {
		t.Errorf("signals = %q, want the toolchain-absent signal", signals)
	}
	// The absence signal must not be invented for a hypothesis-space failure.
	lib := ClassifyFailure(r38Record(t, "t9-signal-lib", "docker-networkless",
		"Error: Source \"forge-std/Test.sol\" not found: File not found.\n",
		"", 1))
	if got := strings.Join(strList(validation.ObjAt(lib, "signals")), "|"); strings.Contains(
		got, "toolchain binary absent") {
		t.Errorf("library failure signals = %q, want no toolchain-absent signal",
			got)
	}
	// F1: "cast" inside "broadcast" is not the foundry binary, so the signal
	// must not be invented for a missing broadcast artifact either.
	bc := ClassifyFailure(r38Record(t, "t9-signal-broadcast", "docker-networkless",
		"Error: broadcast not found for script deploy\n", "", 1))
	if got := strings.Join(strList(validation.ObjAt(bc, "signals")), "|"); strings.Contains(
		got, "toolchain binary absent") {
		t.Errorf("broadcast failure signals = %q, want no toolchain-absent signal",
			got)
	}
}

// TestToolchainAbsenceIsMirroredInTheSandboxDefault extends the r38 rail to
// this law. sandbox.defaultClassifyFailure is the seam's fallback (what the
// verbs speak when envgo is not installed), and a stale second copy of the
// classifier is exactly the r36 bug class. The r38 differential table predates
// Task 9, so it cannot see a divergence on tool-absent text; this row set is
// what keeps the two transcriptions honest.
func TestToolchainAbsenceIsMirroredInTheSandboxDefault(t *testing.T) {
	sandbox.SetClassifyFailure(nil) // the transcribed sandbox default
	t.Cleanup(func() { sandbox.SetClassifyFailure(nil) })

	cases := []struct{ name, text string }{
		{"solc-not-installed", "Error: solc 0.8.24 is not installed. " +
			"Install it with `svm install 0.8.24`\n"},
		{"solc-not-found", "Error: solc not found\n"},
		{"forge-not-found", "sh: 1: forge: not found\n"},
		{"forge-command-not-found", "forge: command not found\n"},
		{"docker-command-not-found", "docker: command not found\n"},
		{"generic-shell-not-found", "sh: 1: jq: not found\n"},
		{"solc-colon-not-installed", "solc: not installed\n"},
		{"broadcast-not-found", "Error: broadcast not found for script deploy\n"},
		{"echoed-not-found-with-assertion",
			"sh: 1: helper.sh: command not found\nassertion failed: x != y\n"},
		{"library-not-found-stays-setup",
			"Error: Source \"forge-std/Test.sol\" not found: File not " +
				"found.\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := r38Record(t, "t9-mirror-"+tc.name, "docker-networkless",
				tc.text, "", 1)
			wired := ClassifyFailure(rec)
			def := sandbox.ClassifyFailure(rec)
			if validation.CanonCompact(wired) != validation.CanonCompact(def) {
				t.Errorf("envgo copy disagrees with the sandbox default\n"+
					"  envgo:   %s\n  default: %s",
					validation.CanonCompact(wired),
					validation.CanonCompact(def))
			}
		})
	}
}

// strList flattens a signals array of strings for failure messages.
func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, s := range v.A {
		out = append(out, s.S)
	}
	return out
}
