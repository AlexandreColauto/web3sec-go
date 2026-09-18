// execute.go: running the payload (container argv or host shell) and the
// timeout / never-ran stderr wording.
package sandbox

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// defaultRunTimeout is Python's `Sandbox.run(timeout: int = 300)` default.
// Go's zero value for RunOpts.Timeout means "caller said nothing", and a
// zero-duration timer would kill the process instantly, so an unset timeout
// must take the reference's default rather than 0 (the P2 docker e2e caught
// `sequence run` dying with exit -1 because run_sequence passes no timeout).
const defaultRunTimeout = 300

// execute runs the container argv or the host shell command. It returns
// the exit status, the kept stdout/stderr, and the true capture accounting
// (r36 F6).
func (s *Sandbox) execute(containerArgv []string, command string,
	opts RunOpts) (int, string, string, captureStats) {
	secs := opts.Timeout
	if secs <= 0 {
		secs = defaultRunTimeout
	}
	timeout := time.Duration(secs) * time.Second
	var res ProcResult
	var err error
	if containerArgv != nil {
		// Container execution: the docker CLI runs on the host, the COMMAND
		// runs in the container. Only the explicit env is passed (via -e
		// above); no other host environment variable leaks in.
		res, err = runProc(containerArgv, "", nil, timeout)
	} else {
		full := append(os.Environ(), envStrings(opts.Env)...)
		dir := ""
		if opts.Workdir != nil {
			dir = *opts.Workdir
		}
		res, err = runProc([]string{"/bin/sh", "-c", command}, dir, full, timeout)
	}
	if err == errTimeout {
		// The never-ran path below appends its reason "so the exec record
		// explains itself"; a TIMEOUT must be no different (critic r3):
		// -1 alone cannot tell a killed sleeper from a wedged test suite.
		// r36 F1: when the kill could not be confirmed (a container or a
		// setsid survivor still running), the record must NOT claim
		// "was killed".
		stderr := res.Stderr
		if stderr != "" && !strings.HasSuffix(stderr, "\n") {
			stderr += "\n"
		}
		base := fmt.Sprintf("sandbox: timed out after %gs and was killed",
			timeout.Seconds())
		if res.KillUnconfirmed {
			base = fmt.Sprintf("sandbox: timed out after %gs — the kill "+
				"could not be fully confirmed", timeout.Seconds())
		}
		return -1, res.Stdout, stderr + base + res.TimeoutNote + "\n",
			capsOf(res)
	}
	if err != nil {
		// The process never ran — a missing workdir, no docker on PATH, an
		// exec failure. res.ReturnCode is the zero value on that path, so
		// returning it recorded a successful execution (exit_status 0) for
		// something that never happened. Report -1 and put the reason in
		// stderr so the exec record explains itself instead of looking like
		// a clean run of a command that produced no output. res.TimeoutNote
		// here carries the r36 F1 abnormal-death container note.
		stderr := res.Stderr
		if stderr != "" && !strings.HasSuffix(stderr, "\n") {
			stderr += "\n"
		}
		return -1, res.Stdout, stderr + "sandbox: " + err.Error() +
			res.TimeoutNote + "\n", capsOf(res)
	}
	if res.TimeoutNote != "" {
		// Abnormal-death cleanup note on an otherwise reaped child (r36
		// F1): the container's fate is part of the record.
		stderr := res.Stderr
		if stderr != "" && !strings.HasSuffix(stderr, "\n") {
			stderr += "\n"
		}
		res.Stderr = stderr + "sandbox: " +
			strings.TrimPrefix(res.TimeoutNote, "; ") + "\n"
	}
	return res.ReturnCode, res.Stdout, res.Stderr, capsOf(res)
}

func envStrings(env []EnvVar) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		out = append(out, e.Key+"="+e.Value)
	}
	return out
}
