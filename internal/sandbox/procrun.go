// procrun.go: subprocess execution — runProc (subprocess.run with
// capture_output=True), the timeout arm, and survivor reaping (r21/r36).
package sandbox

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const timeSecond = time.Second

// ProcResult is one finished subprocess (Python's CompletedProcess).
type ProcResult struct {
	ReturnCode int
	Stdout     string
	Stderr     string
	// TimeoutNote, when set, qualifies the timeout record: the
	// pathological "group signalled but a survivor escaped" arm says so
	// instead of the wrapper claiming a clean kill (r22 F1: a record
	// that says "was killed" when nothing died is a lie + destroyed
	// stdout). Faked/injected results leave it empty = plain wording.
	// r36 F1/F2: it also carries the container's fate (killed / still
	// running / unidentifiable) and the escaped-survivor pids.
	TimeoutNote string
	// KillUnconfirmed is set when a timeout/abnormal-death kill could not
	// be confirmed to have stopped every process and container — the
	// record then must NOT claim "and was killed" (r36 F1).
	KillUnconfirmed bool
	// OutputWithheld is set when captured bytes were not read because a
	// survivor was still writing them — the byte totals are unknown, not
	// zero (r36 F6: absence, never a fabricated count).
	OutputWithheld bool
	// StdoutCap/StderrCap describe exactly which bytes Stdout/Stderr hold.
	StdoutCap CaptureTotal
	StderrCap CaptureTotal
}

// Platform hooks for the timeout cleanup (procsig_unix.go installs the
// /proc-walking implementations; non-linux leaves them nil, which the
// timeout path reports honestly as "cannot enumerate survivors").
var (
	survivorsOfFn   func(root int) (pids []int, ok bool)
	killSurvivorFn  func(pid int) bool
	survivorAliveFn func(pid int) bool
)

// runFunc executes a subprocess. dir is the working directory ("" = inherit),
// env is the FULL environment (nil = inherit), and a timeout surfaces as
// errTimeout with whatever output was captured. A package var so tests can
// intercept docker (Python monkeypatches sandbox.subprocess.run).
type runFunc func(argv []string, dir string, env []string,
	timeout time.Duration) (ProcResult, error)

// errTimeout is subprocess.TimeoutExpired.
var errTimeout = fmt.Errorf("timed out")

var runProc runFunc

// realRunProc refers to runProc (stopContainer kills the payload
// container through the seam), so the seam is wired in init, not a var
// initializer.
func init() { runProc = realRunProc }

// realRunProc is subprocess.run(capture_output=True, text=True, timeout=...).
func realRunProc(argv []string, dir string, env []string,
	timeout time.Duration) (ProcResult, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	if dir != "" {
		cmd.Dir = dir
	}
	if env != nil {
		cmd.Env = env
	}
	out := newCappedWriter(outputCaptureLimitBytes)
	errB := newCappedWriter(outputCaptureLimitBytes)
	cmd.Stdout, cmd.Stderr = out, errB
	// r21 F1: own process group, so the timeout kill reaches wrapper
	// CHILDREN (the pipe-holders), not just the direct child.
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		return ProcResult{Stdout: out.String(), Stderr: errB.String()}, err
	}
	// r36 F1: pin the container name the killing side will use to stop
	// the payload container. (The process-tree snapshot happens at
	// TIMEOUT time, inside timeoutProcResult: at start time the payload
	// may not have forked its escapees yet, and while the direct child
	// still lives its ppid links are intact.)
	containerName := containerNameFromArgv(argv)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return finishedProcResult(err, out, errB, containerName), nil
	case <-timer.C:
		// r21 F1: kill the whole process GROUP. The direct child of a
		// probe is often a WRAPPER (uv shims are #!/bin/sh scripts);
		// killing only the shell leaves its child holding the stdout
		// pipe — Wait never returns, and the r19 grace-return read the
		// shared Builders while a copier goroutine still wrote: a DATA
		// RACE on top of a goroutine leak. Setpgid (at Start, above)
		// makes the group kill reach the survivors, so Wait lands and
		// the Builders are quiescent before we read them. r36 F1/F2:
		// the group kill alone is not enough — the container payload
		// (not our child) and setsid() escapees are handled by
		// timeoutProcResult, which reports exactly what was and was
		// not killed.
		return timeoutProcResult(cmd, done, containerName, out, errB)
	}
}

// finishedProcResult builds the result of a child that Wait reaped. When
// the death was ABNORMAL (a signal — e.g. something killed the `docker
// run` client out from under us), the payload container may have outlived
// its client: stop it by name and record the truth (r36 F1).
func finishedProcResult(err error, out, errB *cappedWriter,
	containerName string) ProcResult {
	res := ProcResult{ReturnCode: exitCode(err), Stdout: out.String(),
		Stderr: errB.String(), StdoutCap: out.cap(), StderrCap: errB.cap()}
	if err == nil || res.ReturnCode >= 0 || containerName == "" {
		return res
	}
	switch fate := stopContainer(containerName); fate.outcome {
	case "killed":
		res.TimeoutNote = "; the docker client died abnormally (signal) — " +
			"the payload container '" + containerName + "' was killed by " +
			"the cleanup"
	case "removed":
		// r39 P3: a container left in a non-running state (created by the
		// daemon after the client died, or exited) is debris --rm will
		// never clear; it was force-removed, and the record says so.
		res.TimeoutNote = "; the docker client died abnormally (signal) — " +
			"the payload container '" + containerName + "' was found in " +
			"docker state '" + fate.state + "' and was REMOVED (docker rm -f)"
	case "removed-late":
		res.TimeoutNote = "; the docker client died abnormally (signal) — " +
			"the payload container '" + containerName + "' appeared in " +
			"docker state '" + fate.state + "' only after the client died " +
			"(the daemon finished creating it for a dead client) and was " +
			"REMOVED (docker rm -f)"
	case "exists":
		res.TimeoutNote = "; the docker client died abnormally (signal) — " +
			"the payload container '" + containerName + "' still exists in " +
			"docker state '" + fate.state + "' and could NOT be removed: " +
			"docker debris is left behind (docker rm -f " + containerName + ")"
		res.KillUnconfirmed = true
	case "running":
		res.TimeoutNote = "; the docker client died abnormally (signal) — " +
			"the payload container '" + containerName + "' COULD NOT BE " +
			"KILLED and is STILL RUNNING (docker ps --filter name=" +
			containerName + ")"
		res.KillUnconfirmed = true
	case "unknown":
		res.TimeoutNote = "; the docker client died abnormally (signal) — " +
			"the state of payload container '" + containerName + "' could " +
			"not be determined; it may still be running"
		res.KillUnconfirmed = true
	}
	return res
}

// timeoutProcResult is the timer-fired arm: stop the payload container by
// name CONCURRENTLY with the host-side group kill (r36 F1 — the payload
// cannot outlive the record by waiting for us), then reap whatever
// escaped the group by pid (r36 F2), and build the honest note.
func timeoutProcResult(cmd *exec.Cmd, done <-chan error,
	containerName string, out, errB *cappedWriter) (ProcResult, error) {
	// r36 F2: snapshot the payload's process tree BEFORE the group kill —
	// at timeout time the payload has fully forked, and while the direct
	// child still lives its ppid links are intact. After the kill the
	// orphans are reparented and can no longer be attributed.
	var descendants []int
	enumerated := false
	if survivorsOfFn != nil {
		descendants, enumerated = survivorsOfFn(cmd.Process.Pid)
	}
	groupKilled := killGroup(cmd)
	killDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-killDone:
				return
			case <-ticker.C:
				killGroup(cmd)
			}
		}
	}()
	containerCh := make(chan containerFate, 1)
	go func() { containerCh <- stopContainer(containerName) }()
	grace := time.NewTimer(5 * time.Second)
	defer grace.Stop()
	waited := false
	select {
	case <-done:
		waited = true
	case <-grace.C:
	}
	close(killDone)
	// r36 F2: pid-level cleanup for survivors that re-forked OUT of the
	// group (setsid) — unreachable by the pgid kill, still our same-uid
	// descendants.
	killedPids, remaining := reapEscaped(descendants, enumerated)
	fate := <-containerCh

	var note strings.Builder
	unconfirmed := !groupKilled
	switch fate.outcome {
	case "":
		// No container in this argv (host profile) — nothing to say...
		// unless the argv WAS a docker run we could not read, which
		// containerNameFromArgv already signalled via "" — see the
		// "none" case below.
	case "killed":
		note.WriteString("; the container '" + containerName +
			"' was killed")
	case "removed":
		// r39 P3: the container existed in a NON-running state (`created`
		// because the daemon finished the create request after the client
		// was killed, or `exited`). --rm only auto-removes a container
		// that was STARTED, so this one would have stayed in `docker ps
		// -a` forever; it has been force-removed instead of merely
		// described.
		note.WriteString("; the container '" + containerName +
			"' was found in docker state '" + fate.state + "' and was " +
			"REMOVED (docker rm -f) — it is not left behind as debris")
	case "removed-late":
		note.WriteString("; the container '" + containerName +
			"' appeared (docker state '" + fate.state + "') only AFTER the " +
			"docker client died — the daemon finished creating it for a " +
			"client that was already gone, so --rm could never clear it; " +
			"it was REMOVED (docker rm -f) — no debris is left behind")
	case "absent":
		// r39 P3: "absent" is what docker said across the whole sweep
		// window — an OBSERVATION, not a proof. The record must not read
		// like a clean bill of health for a box the daemon could still
		// decorate later, so the window and the re-check are named.
		note.WriteString("; the container '" + containerName +
			"' is not running (docker reported no such container across a " +
			fmt.Sprintf("%gs", containerSweepWindow.Seconds()) + " sweep — " +
			"absence observed, never proven; re-check with docker ps -a " +
			"--filter name=" + containerName + " if this exec died early)")
	case "exists":
		// The removal did not land: say what is still there instead of
		// calling the box clean.
		note.WriteString("; the container '" + containerName +
			"' still exists in docker state '" + fate.state + "' and could " +
			"NOT be removed — docker debris is left behind (docker rm -f " +
			containerName + ")")
		unconfirmed = true
	case "running":
		note.WriteString("; the container '" + containerName +
			"' COULD NOT BE KILLED and is STILL RUNNING (docker ps --filter name=" +
			containerName + ")")
		unconfirmed = true
	case "unknown":
		note.WriteString("; the container '" + containerName +
			"' could not be identified/stopped — it may still be running")
		unconfirmed = true
	}
	if containerName != "" && fate.outcome == "" {
		note.WriteString("; the payload container could not be identified " +
			"from the docker argv — it may still be running")
		unconfirmed = true
	}
	if !waited {
		// The pathological arm, now only for survivors that RE-FORKED
		// OUT of the group (setsid) or a wedged kill: reading the
		// Builders would race a live copier, so bytes are withheld —
		// and the record says EXACTLY what happened instead of claiming
		// a kill that escaped.
		if !enumerated {
			note.WriteString("; its process group was SIGKILLed, but a " +
				"pipe-holding survivor escaped the group and may STILL BE " +
				"RUNNING (the platform cannot enumerate survivors to clean " +
				"up) (partial output withheld)")
		} else if len(remaining) > 0 {
			note.WriteString(fmt.Sprintf("; a process escaped the process "+
				"group and REMAINS RUNNING after the cleanup attempt "+
				"(pids %v) (partial output withheld)", remaining))
			unconfirmed = true
		} else if len(killedPids) > 0 {
			note.WriteString(fmt.Sprintf("; a pipe-holding survivor escaped "+
				"the process group — the cleanup SIGKILLed it by pid %v "+
				"(partial output withheld)", killedPids))
		} else {
			// Something still holds the output pipe (Wait never returned)
			// but no escapee could be attributed: report the unknown
			// honestly — a process IS still running, we just cannot name
			// it (r36 F2).
			note.WriteString("; its process group was SIGKILLed, but " +
				"something still holds the output pipe and could not be " +
				"identified — it may still be running (partial output " +
				"withheld)")
			unconfirmed = true
		}
		return ProcResult{ReturnCode: -1, KillUnconfirmed: unconfirmed,
			OutputWithheld: true, TimeoutNote: note.String()}, errTimeout
	}
	if len(remaining) > 0 {
		note.WriteString(fmt.Sprintf("; a process escaped the process group "+
			"and REMAINS RUNNING after the cleanup attempt (pids %v)",
			remaining))
		unconfirmed = true
	} else if len(killedPids) > 0 {
		note.WriteString(fmt.Sprintf("; a pipe-holding survivor escaped the "+
			"process group — the cleanup SIGKILLed it by pid %v", killedPids))
	}
	return ProcResult{ReturnCode: -1, Stdout: out.String(),
		Stderr: errB.String(), StdoutCap: out.cap(), StderrCap: errB.cap(),
		KillUnconfirmed: unconfirmed, TimeoutNote: note.String()}, errTimeout
}

// reapEscaped SIGKILLs the snapshot survivors still alive after the group
// kill (r36 F2: the setsid escapee is unreachable by the pgid kill but is
// still our same-uid descendant) and reports the outcome.
func reapEscaped(descendants []int, enumerated bool) (killed, remaining []int) {
	if !enumerated {
		return nil, nil
	}
	var alive []int
	for _, pid := range descendants {
		if pid > 1 && survivorAliveFn != nil && survivorAliveFn(pid) {
			alive = append(alive, pid)
		}
	}
	if len(alive) == 0 {
		return nil, nil
	}
	for _, pid := range alive {
		if killSurvivorFn != nil {
			killSurvivorFn(pid)
		}
	}
	// Give the reaper a beat, then re-check liveness.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		still := 0
		for _, pid := range alive {
			if survivorAliveFn(pid) {
				still++
			}
		}
		if still == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, pid := range alive {
		if survivorAliveFn(pid) {
			remaining = append(remaining, pid)
		} else {
			killed = append(killed, pid)
		}
	}
	return killed, remaining
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if ok := asExitError(err, &ee); ok {
		return ee.ExitCode()
	}
	return -1
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}
