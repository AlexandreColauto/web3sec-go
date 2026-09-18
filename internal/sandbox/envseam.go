// envseam.go: the seam to webv2.env's failure classifier and sandbox
// preflight (env.py).
//
// env.py is not ported in this wave and is not owned by T20; the P2 CLI
// verbs `exec` and `classify` cannot be byte-exact without it, so this file
// carries a FAITHFUL transcription as the seam DEFAULT. When internal/env
// lands, it installs the real implementation through SetClassifyFailure /
// SetSandboxPreflight (nil restores this default). The default is never the
// absent-module behavior of inventing a verdict: it is the reference
// algorithm, line for line.
package sandbox

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// classifyFn is the installed classifier (the env seam).
var classifyFn = defaultClassifyFailure

// SetDockerDaemonOK installs the docker_daemon_ok probe (the Python twin
// monkeypatches SB.docker_daemon_ok); nil restores the real probe.
func SetDockerDaemonOK(f func() bool) {
	if f == nil {
		f = probeDockerDaemon
	}
	dockerDaemonOK = f
}

// SetClassifyFailure installs the webv2.env.classify_failure implementation;
// nil restores the transcribed default.
func SetClassifyFailure(f func(validation.Value) validation.Value) {
	if f == nil {
		f = defaultClassifyFailure
	}
	classifyFn = f
}

// ClassifyFailure is classify_failure: classify a FAILED exec record (exit
// != 0) by cause. Classification signals are listed so the operator can
// disagree with the classifier — the class is a routing hint, not a verdict.
func ClassifyFailure(rec validation.Value) validation.Value {
	return classifyFn(rec)
}

// --- sandbox preflight ------------------------------------------------------

// preflightFn is the installed preflight (the env seam).
var preflightFn = defaultSandboxPreflight

// SetSandboxPreflight installs the webv2.env.sandbox_preflight
// implementation; nil restores the transcribed default.
func SetSandboxPreflight(f func(*state.Campaign, *string,
	*string) (validation.Value, error)) {
	if f == nil {
		f = defaultSandboxPreflight
	}
	preflightFn = f
}

// SandboxPreflight is sandbox_preflight: the sandbox's readiness as a
// CHECKABLE PRECONDITION. Severity: FAILs block (issues — every one names
// the exact fix); WARNs are advisory. profile nil means "container
// readiness" — what `webv2 doctor` reports.
func SandboxPreflight(c *state.Campaign, workdir, profile *string) (
	validation.Value, error) {
	return preflightFn(c, workdir, profile)
}

// dockerImageProbeFn is the installed image probe (the env seam, D17).
var dockerImageProbeFn = defaultDockerImageProbe

// SetDockerImageProbe installs the webv2.env.docker_image_probe
// implementation; nil restores the transcribed default.
func SetDockerImageProbe(f func(*string) validation.Value) {
	if f == nil {
		f = defaultDockerImageProbe
	}
	dockerImageProbeFn = f
}

// DockerImageProbe is env.docker_image_probe: the exact image the container
// profiles would run, plus whether the reference is digest-pinned.
func DockerImageProbe(image *string) validation.Value {
	return dockerImageProbeFn(image)
}
