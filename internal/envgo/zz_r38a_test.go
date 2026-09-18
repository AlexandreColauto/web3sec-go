package envgo

// r38 pins for the WIRED classifier. ClassifyFailure in this package is
// what ensureSeams (internal/cli/cmd_dedup.go) and cmd/webv2/main.go both
// install OVER the sandbox seam, so this copy — not
// sandbox.defaultClassifyFailure — is what `webv2 exec` / `webv2 classify`
// actually speak. r36 fixed the sandbox default only, leaving this copy
// with the stale unconditional "docker itself failed before the command
// ran" text for every 125/126/127; these tests close that gap from two
// sides:
//
//   - TestR38WiredCopyMatchesSandboxDefault is the differential: this copy
//     must classify exactly like sandbox.ClassifyFailure at its r36
//     default (the seam is reset to the default here; no envgo test
//     installs anything over it). It cannot be a call instead of a
//     transcription — this package is installed OVER the seam, so calling
//     sandbox.ClassifyFailure would recurse into itself, and the honest
//     default is unexported — so the differential is what keeps the two
//     honest.
//   - TestR38WiredClassifierIsHonest pins the four shapes r36 established,
//     through this package's own entry point.

import (
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// r38Record registers one exec record in a fresh campaign.
func r38Record(t *testing.T, name, profile, stdout, stderr string,
	exit int) validation.Value {
	t.Helper()
	c, err := state.Init(t.TempDir(), name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: profile, Command: "x", ReportedBy: "harness",
		ExitStatus: exit, StdoutText: stdout, StderrText: stderr})
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestR38WiredCopyMatchesSandboxDefault(t *testing.T) {
	sandbox.SetClassifyFailure(nil) // the r36-honest sandbox default
	t.Cleanup(func() { sandbox.SetClassifyFailure(nil) })

	cases := []struct {
		name                string
		profile, stdout     string
		exit                int
		class, noteContains string
		noteWithout         string
	}{
		{"host-127-missing-command", "host-readonly", "", 127,
			"environment", "could not find the command", "docker itself failed"},
		{"host-126-not-executable", "host-readonly", "", 126,
			"environment", "not executable", "docker itself failed"},
		{"host-125-no-docker", "host-readonly", "", 125,
			"environment", "no docker is involved", "docker itself failed before"},
		{"container-127-command-ran", "docker-networkless",
			"sh: 1: nonexistent-cmd-xyz: not found\n", 127,
			"environment", "RAN inside the container", ""},
		{"container-127-no-output-inconclusive", "docker-networkless", "", 127,
			"environment", "inconclusive", "docker itself failed before"},
		{"container-125-docker-itself", "docker-networkless", "", 125,
			"environment", "docker itself failed", ""},
		{"container-127-docker-error-text", "docker-networkless",
			"Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n",
			127, "environment",
			"docker client/runtime failed", "RAN inside the container"},
		{"exit-1-docker-text", "docker-networkless",
			"Cannot connect to the Docker daemon\n", 1,
			"environment", "fresh-context", ""},
		{"exit-1-solc", "docker-networkless",
			"Failed to install solc 0.8.36: error sending request for url " +
				"(https://binaries.soliditylang.org/linux-amd64/list.json)\n",
			1, "environment", "WEBV2_SOLC_DIR", ""},
		{"exit-1-setup", "docker-networkless", "Error: compilation failed\n",
			1, "setup", "fresh context", ""},
		{"exit-1-logic", "docker-networkless", "assertion failed: x != y\n",
			1, "logic", "only class that argues the finding", ""},
		{"exit-1-unknown", "docker-networkless", "something odd happened\n",
			1, "unknown", "routed as setup", ""},
		{"exit-0", "docker-networkless", "ok\n", 0,
			"none", "nothing to classify", ""},
	}
	for _, tc := range cases {
		rec := r38Record(t, "r38diff-"+tc.name, tc.profile, tc.stdout, "", tc.exit)
		wired := ClassifyFailure(rec)
		def := sandbox.ClassifyFailure(rec)
		if validation.CanonCompact(wired) != validation.CanonCompact(def) {
			t.Errorf("%s: wired copy disagrees with the sandbox default\n"+
				"  wired:   %s\n  default: %s", tc.name,
				validation.CanonCompact(wired), validation.CanonCompact(def))
		}
		if got := validation.ObjStr(wired, "class"); got != tc.class {
			t.Errorf("%s: class = %q, want %q", tc.name, got, tc.class)
		}
		if got := validation.ObjStr(wired, "note"); !strings.Contains(got, tc.noteContains) {
			t.Errorf("%s: note %q lacks %q", tc.name, got, tc.noteContains)
		}
		if tc.noteWithout != "" {
			if got := validation.ObjStr(wired, "note"); strings.Contains(got, tc.noteWithout) {
				t.Errorf("%s: note %q must not contain %q", tc.name, got,
					tc.noteWithout)
			}
		}
	}
}

// TestR38WiredClassifierIsHonest pins the four shapes through THIS
// package's entry point — the copy the CLI seam actually carries. The note
// texts are the sandbox default's r36 pins (internal/sandbox/envseam_test.go
// pins the same bytes there), so a drift on either side fails one package.
func TestR38WiredClassifierIsHonest(t *testing.T) {
	host := ClassifyFailure(r38Record(t, "r38h1", "host-readonly", "", "", 127))
	note := validation.ObjStr(host, "note")
	if strings.Contains(note, "docker itself failed") {
		t.Errorf("host 127 note claims docker ran the command: %q", note)
	}
	if !strings.Contains(note, "could not find the command") ||
		!strings.Contains(note, "docker is not involved") {
		t.Errorf("host 127 note must name the missing command and no docker: %q",
			note)
	}
	if sig := validation.CanonCompact(validation.ObjAt(host, "signals")); !strings.Contains(
		sig, "no docker involved") {
		t.Errorf("host 127 signals must say no docker is involved: %s", sig)
	}

	host126 := ClassifyFailure(r38Record(t, "r38h2", "host-readonly", "", "", 126))
	if note := validation.ObjStr(host126, "note"); !strings.Contains(note,
		"not executable") || strings.Contains(note, "docker itself failed") {
		t.Errorf("host 126 note = %q", note)
	}

	ran := ClassifyFailure(r38Record(t, "r38c1", "docker-networkless",
		"sh: 1: nonexistent-cmd-xyz: not found\n", "", 127))
	if note := validation.ObjStr(ran, "note"); !strings.Contains(note,
		"RAN inside the container") {
		t.Errorf("container 127 with in-container 'not found' evidence must "+
			"say the command ran: %q", note)
	}

	inconclusive := ClassifyFailure(r38Record(t, "r38c2",
		"docker-networkless", "", "", 127))
	if note := validation.ObjStr(inconclusive, "note"); !strings.Contains(note,
		"inconclusive") {
		t.Errorf("container 127 with no output must be inconclusive: %q", note)
	}
}
