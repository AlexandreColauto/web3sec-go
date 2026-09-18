// Package envgo is webv2/env.py: the read-only environment doctor and the
// EXEC FAILURE CLASSIFIER.
//
// The doctor answers, deterministically: what execution infrastructure is
// present, is the fork reachable (and on which chain), and is the image
// digest-pinned. Plus a failure classifier that routes a failed exec to
// environment / setup / logic so an environment failure never burns the
// finding's fresh-context retry budget.
//
// The doctor is READ-ONLY: it probes, it reports, it never mutates the
// campaign (and never logs — a diagnostic that appends events would itself
// stale the report's state-head stamp). It is the REAL implementation behind
// internal/sandbox's seams (D17): cmd/webv2/main.go installs ClassifyFailure
// and SandboxPreflight over the transcription the P2 wave shipped.
package envgo

import (
	"time"

	"websec/internal/sandbox"
	"websec/internal/validation"
)

// Seams. Python's env.py reads these through module globals, and its tests
// monkeypatch ENV.docker_image_probe / ENV.docker_daemon_ok / ENV.solc_dir /
// ENV.subprocess.run. The Go port keeps the same indirection so the ported
// tests can do the same.
var (
	dockerDaemonOK = sandbox.DockerDaemonOK
	dockerImage    = sandbox.DockerImage
	solcDir        = sandbox.SolcDir
	dockerProbe    = DockerImageProbe
	runProc        = realRunProc
	httpDo         = realHTTPDo
)

// --- seam setters -----------------------------------------------------------
//
// The Python tests monkeypatch ENV.docker_image_probe / ENV.docker_daemon_ok /
// ENV.solc_dir / ENV.subprocess.run. These setters expose the same four
// indirections to other packages (the CLI-level tests live in package cli).
// A nil argument restores the real implementation.

// SetDockerImageProbe installs docker_image_probe.
func SetDockerImageProbe(f func(*string) validation.Value) {
	if f == nil {
		f = DockerImageProbe
	}
	dockerProbe = f
}

// SetDockerDaemonOK installs the docker_daemon_ok probe.
func SetDockerDaemonOK(f func() bool) {
	if f == nil {
		f = sandbox.DockerDaemonOK
	}
	dockerDaemonOK = f
}

// SetSolcDir installs the solc_dir lookup.
func SetSolcDir(f func() *string) {
	if f == nil {
		f = sandbox.SolcDir
	}
	solcDir = f
}

// SetRunProc installs the subprocess.run stand-in.
func SetRunProc(f func([]string, time.Duration) (procResult, error)) {
	if f == nil {
		f = realRunProc
	}
	runProc = f
}

// ProcResult is the exported view of subprocess.CompletedProcess.
type ProcResult = procResult
