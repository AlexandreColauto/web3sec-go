// exec.go: the sandbox ledger — Sandbox.run, Sandbox.preview, register_exec,
// load_exec, all_execs (webv2.sandbox).
//
// Every execution is recorded: policy verdict, environment, hashes, captured
// output. Evidence minted elsewhere MUST reference the exec_id's profile.
package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

const timeSecond = time.Second

// CaptureTotal is the true byte accounting of one capped capture (r36 F6).
type CaptureTotal struct {
	// Total is every byte the process wrote to the stream.
	Total int64
	// Kept is the number of bytes retained under the cap.
	Kept int64
}

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

// outputCaptureLimitBytes is the DELIBERATE cap on captured stdout/stderr,
// per stream (r36 F6: the exec path used to keep everything — a 200MB
// write put ~817MB peak RSS on webv2 with no truncation marker and no
// size accounting). 10MiB per stream (20MiB worst case) is far above any
// meaningful build/test log and keeps memory bounded. The TRUE byte counts
// and the truncation land in the record's `output_capture` object, and the
// in-file marker line means a truncated log can never pass as complete.
// A package var (not a const) so tests can lower it to stay fast; the
// recorded cap_bytes always reflects the value in force.
var outputCaptureLimitBytes int64 = 10 << 20

// cappedWriter captures at most limit bytes while COUNTING everything
// written: the child is never throttled or blocked, excess bytes are
// dropped from memory only.
type cappedWriter struct {
	limit int64
	buf   bytes.Buffer
	total int64
}

func newCappedWriter(limit int64) *cappedWriter { return &cappedWriter{limit: limit} }

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	if room := w.limit - int64(w.buf.Len()); room > 0 {
		if int64(len(p)) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil // dropping the excess is not an error for the child
}

func (w *cappedWriter) String() string { return w.buf.String() }

func (w *cappedWriter) cap() CaptureTotal {
	return CaptureTotal{Total: w.total, Kept: int64(w.buf.Len())}
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

// containerFate is what the cleanup found and did to the payload container
// (r39 P3): the OUTCOME plus the docker state it was found in, so the record
// can name both instead of collapsing every non-running container into
// "exited".
type containerFate struct {
	// outcome is one of "killed", "removed", "removed-late", "absent",
	// "running", "exists", "unknown" — "" when the exec had no container.
	outcome string
	// state is docker's own {{.State.Status}} when one was observed
	// ("created", "exited", "running", ...), "" otherwise.
	state string
}

// containerSweepWindow bounds the late-appearance sweep (r39 P3). When the
// docker CLIENT dies, the daemon may still commit the create request it had
// already accepted: measured on the r39 box, the container appeared from
// ~0.5s to ~13s after the kill (the delay is the daemon's own work — image
// layers, load). The window is therefore seconds, not milliseconds, but it
// is FINITE and it is disclosed in the record: the sweep observes absence,
// it never proves it. A package var so tests do not pay it.
var containerSweepWindow = 15 * time.Second

// stopContainer is the killing side's container reaper (r36 F1, r39 P3). It
// reports docker's own view of the outcome AND leaves no container behind in
// ANY state: `docker kill` cannot clean a container the daemon created AFTER
// the client died (a `--rm` container that was never started is never
// auto-removed — it sits in state 'created' forever), so a container found
// in a non-running state is force-removed, and one that appears only after
// the first look (the create request still in flight when the client died)
// is swept. Bounded: the inner docker calls carry their own timeouts and the
// sweep has a deadline. An empty name returns the zero fate (no container
// involved).
func stopContainer(name string) containerFate {
	if name == "" {
		return containerFate{}
	}
	if res, err := runProc([]string{"docker", "kill", name}, "", nil,
		15*timeSecond); err == nil && res.ReturnCode == 0 {
		// The kill landed. `--rm` makes the daemon remove a container when
		// it stops, but that is the daemon's asynchronous work: force the
		// removal too (advisory — "killed" is already true) so a killed
		// payload cannot linger as debris either.
		removeContainer(name)
		return containerFate{outcome: "killed"}
	}
	st := containerState(name)
	if st == "absent" {
		// The docker CLIENT is already dead (the group kill precedes this
		// call), so a create request still in flight server-side can
		// materialize a container nothing will ever start or remove. Sweep
		// for it before declaring the box clean.
		if late := waitForContainer(name); late != "" {
			if removeContainer(name) {
				return containerFate{outcome: "removed-late", state: late}
			}
			return containerFate{outcome: "exists", state: late}
		}
		return containerFate{outcome: "absent"}
	}
	if st == "unknown" {
		return containerFate{outcome: "unknown", state: st}
	}
	// created / exited / dead / paused / restarting / removing / running:
	// `docker rm -f` is the one operation that cleans a container in EVERY
	// state — it kills a running one and removes any other.
	if removeContainer(name) {
		if st == "running" {
			// docker kill failed but the force-remove killed it.
			return containerFate{outcome: "killed", state: st}
		}
		return containerFate{outcome: "removed", state: st}
	}
	// The removal did not report success: re-read docker's own state rather
	// than assume, and let the record say what is really left.
	switch st2 := containerState(name); st2 {
	case "absent":
		return containerFate{outcome: "removed", state: st}
	case "running":
		return containerFate{outcome: "running", state: st2}
	case "unknown":
		return containerFate{outcome: "unknown", state: st}
	default:
		return containerFate{outcome: "exists", state: st2}
	}
}

// removeContainer is `docker rm -f` (bounded) and reports whether docker
// confirmed the container is gone — an already absent container counts as
// success, because absence is the goal.
func removeContainer(name string) bool {
	res, err := runProc([]string{"docker", "rm", "-f", name}, "", nil,
		20*timeSecond)
	if err == nil && res.ReturnCode == 0 {
		return true
	}
	if err == nil && strings.Contains(strings.ToLower(res.Stderr),
		"no such container") {
		return true
	}
	return containerState(name) == "absent"
}

// waitForContainer sweeps, until containerSweepWindow elapses, for a
// container the daemon creates after our first look (the killed client's
// create request was already in flight). Such a container can never be
// started and never be removed by --rm, so it must be seen and removed
// here. The poll backs off (250ms doubling to 2s) so a long window costs a
// handful of docker calls, not dozens. Returns the state it appeared in, or
// "" if it never appeared inside the window.
func waitForContainer(name string) string {
	deadline := time.Now().Add(containerSweepWindow)
	wait := 250 * time.Millisecond
	for {
		time.Sleep(wait)
		if st := containerState(name); st != "absent" {
			return st
		}
		if !time.Now().Before(deadline) {
			return ""
		}
		if wait < 2*time.Second {
			wait *= 2
		}
	}
}

// containerState asks docker for the container's state in ANY state
// ("created", "exited", "running", ...), distinguishing a container that is
// not running from one docker could not see at all ("absent") and from one
// whose state could not be determined ("unknown") — the record may claim the
// former two, only ever suspect the last (absence is inconclusive, never
// evidence).
func containerState(name string) string {
	ins, err := runProc([]string{"docker", "inspect", "-f",
		"{{.State.Status}}", name}, "", nil, 10*timeSecond)
	if err != nil {
		return "unknown"
	}
	if ins.ReturnCode != 0 {
		// docker 29 answers 'error: no such object: <name>' (lowercase) and
		// older clients capitalized it — absence must be recognised either
		// way, because it is exactly the trigger for the late-appearance
		// sweep (r39 P3): pre-r39 this fell through to "unknown" and the
		// container the daemon was about to create was never swept.
		low := strings.ToLower(ins.Stderr)
		if strings.Contains(low, "no such object") ||
			strings.Contains(low, "no such container") {
			return "absent"
		}
		return "unknown"
	}
	switch st := strings.TrimSpace(ins.Stdout); st {
	case "created", "running", "paused", "restarting", "removing",
		"exited", "dead":
		return st
	// The legacy `{{.State.Running}}` shape (the in-package fake docker
	// speaks it): a coarser answer must not collapse into "unknown".
	case "true":
		return "running"
	case "false":
		return "exited"
	}
	return "unknown"
}

// containerNameFromArgv extracts the --name value of a `docker run` argv
// ("" when absent — the container cannot then be identified).
func containerNameFromArgv(argv []string) string {
	for i, a := range argv {
		if a == "--name" && i+1 < len(argv) {
			return argv[i+1]
		}
		if strings.HasPrefix(a, "--name=") {
			return strings.TrimPrefix(a, "--name=")
		}
	}
	return ""
}

// withContainerName pins a deterministic container name onto a `docker
// run` argv so the killing side can stop the payload by name (r36 F1: a
// timeout used to kill only the host-side docker client, leaving the
// container running the full command, unseen and unrecorded).
func withContainerName(argv []string, name string) []string {
	if len(argv) < 2 || argv[0] != "docker" || argv[1] != "run" {
		return argv
	}
	if containerNameFromArgv(argv) != "" {
		return argv // already pinned
	}
	out := make([]string, 0, len(argv)+2)
	out = append(out, argv[:2]...)
	out = append(out, "--name", name)
	return append(out, argv[2:]...)
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

// RefusedError is Python's PermissionError from a policy refusal.
type RefusedError struct{ Message string }

func (e *RefusedError) Error() string { return e.Message }

// UnavailableError is Python's RuntimeError for a missing runtime.
type UnavailableError struct{ Message string }

func (e *UnavailableError) Error() string { return e.Message }

// Sandbox records every execution. Container profiles require the real
// runtime (a live docker daemon) and run through a real `docker run`;
// otherwise execution is refused rather than faked.
type Sandbox struct {
	Campaign *state.Campaign
	Profile  string
}

// NewSandbox is Sandbox.__init__.
func NewSandbox(c *state.Campaign, profile string) (*Sandbox, error) {
	if !inProfiles(profile) {
		return nil, fmt.Errorf("unknown profile %s", validation.PyReprStr(profile))
	}
	if !ProfileAvailable(profile) {
		return nil, &UnavailableError{Message: fmt.Sprintf(
			"profile %s requires runtime infrastructure not present on this "+
				"host — use 'host-readonly' or install the runtime; evidence "+
				"produced un-sandboxed cannot be minted at E4+",
			validation.PyReprStr(profile))}
	}
	return &Sandbox{Campaign: c, Profile: profile}, nil
}

// RunOpts mirrors run()'s keyword-only arguments.
type RunOpts struct {
	Workdir    *string
	FindingID  *string
	ArtifactID *string
	Timeout    int
	Env        []EnvVar
}

// Run is Sandbox.run: execute with the profile's constraints, capture
// stdout/stderr/hashes/exit status, and record a sandbox_execution record.
func (s *Sandbox) Run(command string, opts RunOpts) (validation.Value, error) {
	execID := "EXEC-" + shortID(10)
	verdict, err := PolicyCheck(command, s.Profile)
	if err != nil {
		return validation.VNull(), err
	}
	started := nowIso()

	var containerArgv []string
	var container validation.Value = validation.VNull()
	if !HostProfile(s.Profile) {
		argv, meta, err := BuildContainerArgv(s.Profile, command, opts.Workdir,
			opts.Env)
		if err != nil {
			return validation.VNull(), err
		}
		containerArgv, container = argv, meta.Container
		// r36 F1: pin a deterministic container name so the killing side
		// (timeout or abnormal client death) can stop the payload
		// container by name instead of killing only the docker client.
		// (Preview's argv keeps the reference shape; the name is a
		// per-exec runtime detail.)
		containerArgv = withContainerName(containerArgv,
			"webv2-exec-"+strings.ToLower(execID))
	}

	outDir := filepath.Join(s.Campaign.ExecsDir, execID)
	// r39 F2: the exec dir and everything in it is written BEFORE the
	// ledger event exists. A refused c.Log must therefore unwind — see the
	// execDirTxn comment for why the payload cannot be deferred.
	txn, err := beginExecDir(outDir)
	if err != nil {
		return validation.VNull(), err
	}
	stdoutPath := filepath.Join(outDir, "stdout.log")
	stderrPath := filepath.Join(outDir, "stderr.log")
	path := filepath.Join(outDir, "exec_record.json")
	txn.note(stdoutPath, stderrPath, path)

	record := s.record(execID, command, opts, verdict, container, started,
		stdoutPath, stderrPath)
	if err := validation.WriteJson(path, record, "sandbox_execution"); err != nil {
		return validation.VNull(), txn.fail(err)
	}

	if !truthy(verdict, "allowed") {
		violations := objAt(verdict, "violations")
		extended := append(append([]validation.Value(nil), violations.A...),
			validation.VStr("execution-refused"))
		record = setKey(record, "policy_verdict", validation.VObj(
			validation.KV{K: "allowed", V: objAt(verdict, "allowed")},
			validation.KV{K: "violations", V: validation.VArr(extended...)},
			validation.KV{K: "checked_rules", V: objAt(verdict, "checked_rules")},
		))
		record = setKey(record, "finished_at", validation.VStr(nowIso()))
		if err := validation.WriteJson(path, record, "sandbox_execution"); err != nil {
			return validation.VNull(), txn.fail(err)
		}
		ref := execID
		data := validation.VObj(validation.KV{K: "violations",
			V: objAt(verdict, "violations")})
		if _, err := s.Campaign.Log("sandbox.refused", &ref, &data); err != nil {
			// The refused act (a policy refusal) must not leave debris
			// behind either, and it must not hide what already happened:
			// the command did NOT run, and the refusal itself is not in
			// the ledger now — the operator has to know both (r39 F2).
			return validation.VNull(), txn.fail(fmt.Errorf(
				"the command was REFUSED by sandbox policy (%s) and did NOT "+
					"run, but the refusal event was refused as well — no "+
					"record was kept and the exec dir %s was removed, so "+
					"nothing about this refusal is in the ledger (ledger "+
					"refusal: %v)", pyListRepr(violations), outDir, err))
		}
		return validation.VNull(), &RefusedError{Message: fmt.Sprintf(
			"command refused by sandbox policy: %s",
			pyListRepr(violations))}
	}

	exitStatus, stdout, stderr, caps := s.execute(containerArgv, command, opts)
	// r36 F6: stdout.log/stderr.log hold the KEPT bytes; when a stream was
	// truncated, the in-file marker line is appended so no consumer can
	// mistake a truncated capture for a complete one. artifact_hashes
	// cover exactly the bytes on disk (capped payload + marker line).
	stdoutBytes := []byte(stdout)
	if caps.stdoutTruncated() {
		stdoutBytes = append(stdoutBytes, truncationMarker("stdout",
			caps.StdoutKept, caps.StdoutTotal)...)
	}
	stderrBytes := []byte(stderr)
	if caps.stderrTruncated() {
		stderrBytes = append(stderrBytes, truncationMarker("stderr",
			caps.StderrKept, caps.StderrTotal)...)
	}
	if err := os.WriteFile(stdoutPath, stdoutBytes, 0o644); err != nil {
		return validation.VNull(), txn.fail(err)
	}
	if err := os.WriteFile(stderrPath, stderrBytes, 0o644); err != nil {
		return validation.VNull(), txn.fail(err)
	}
	hashes := validation.VObj(
		validation.KV{K: "stdout.log", V: validation.VStr(shaFile(stdoutPath))},
		validation.KV{K: "stderr.log", V: validation.VStr(shaFile(stderrPath))},
	)
	record = setKey(record, "finished_at", validation.VStr(nowIso()))
	record = setKey(record, "exit_status", validation.VInt(int64(exitStatus)))
	record = setKey(record, "artifact_hashes", hashes)
	record = setKey(record, "output_capture", outputCaptureValue(caps))
	if err := validation.WriteJson(path, record, "sandbox_execution"); err != nil {
		return validation.VNull(), txn.fail(err)
	}
	ref := execID
	data := validation.VObj(
		validation.KV{K: "profile", V: validation.VStr(s.Profile)},
		validation.KV{K: "exit", V: validation.VInt(int64(exitStatus))},
		validation.KV{K: "finding", V: optStrValue(opts.FindingID)},
	)
	if _, err := s.Campaign.Log("sandbox.exec", &ref, &data); err != nil {
		// r39 F2: the payload has ALREADY RUN (execute() is above), so the
		// honest answer is not "nothing happened". Restore the pre-write
		// state — the exec dir goes away, so `webv2 execs` can never list
		// a run the ledger does not hold, the projection audit has no
		// residue to be green over, and a retry adds no second corpse —
		// and say in the returned error exactly which half happened: the
		// command EXECUTED, its record was NOT KEPT.
		return validation.VNull(), txn.fail(fmt.Errorf(
			"the command EXECUTED (exit status %d, %d stdout / %d stderr "+
				"byte(s) captured) but its record was NOT KEPT: the ledger "+
				"refused the sandbox.exec event and the exec dir %s was "+
				"removed — nothing about this run is in the ledger, and "+
				"re-running will execute the command AGAIN (ledger refusal: "+
				"%v)", exitStatus, len(stdoutBytes), len(stderrBytes),
			outDir, err))
	}
	return record, nil
}

// execDirTxn is the r39 F2 unwind-on-refusal dance for the per-exec ledger
// directory. Run and RegisterExec both create <execs>/<EXEC-id>/, write
// stdout.log, stderr.log and exec_record.json into it, and only THEN call
// c.Log — the event that anchors the whole thing. A refused Log left that
// directory behind as a THIRD kind of half-write: an exec record with no
// event, listed by `webv2 execs` as a normal run, invisible to verify, and
// (after doctor heals the ledger) the residue an audit goes green over —
// while the CLI never even said the payload had run.
//
// The law in this tree (findings.SaveThenLog, state.AppendJsonlThenLog) is
// snapshot-before-write and restore-on-refusal. The exec id is minted fresh,
// so the pre-write state of the directory IS absence and the restore is a
// removal; should a directory already exist at that (astronomically
// unlikely) id, only the files this call writes are removed, never a byte
// the call did not create.
//
// Why not refuse BEFORE running the payload: the ledger's health is only
// knowable from the write itself (the mirror check reads events.jsonl AND
// the projection under the campaign lock), and a second, pre-flight copy of
// that predicate is the two-predicates bug this tree forbids — a stale
// "OK" from it would let the very half-write this fixes through. So the
// payload does run first; the refusal is discovered at the log, and the
// contract is: restore the artifacts AND tell the operator plainly that the
// command executed but its record was not kept.
type execDirTxn struct {
	dir     string
	existed bool
	created []string
}

// beginExecDir creates the exec directory, remembering whether this call
// created it (the pre-write state), or returns the mkdir error untouched.
func beginExecDir(dir string) (*execDirTxn, error) {
	_, statErr := os.Stat(dir)
	existed := statErr == nil
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &execDirTxn{dir: dir, existed: existed}, nil
}

// note records paths this transaction writes, so an unwind of a pre-existing
// directory removes only them.
func (t *execDirTxn) note(paths ...string) {
	t.created = append(t.created, paths...)
}

// unwind restores the pre-write state exactly: a directory this call created
// is removed whole; a pre-existing one keeps every byte it had and loses only
// the files this call wrote.
func (t *execDirTxn) unwind() error {
	if t == nil {
		return nil
	}
	if !t.existed {
		return os.RemoveAll(t.dir)
	}
	var first error
	for _, p := range t.created {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) &&
			first == nil {
			first = err
		}
	}
	return first
}

// fail unwinds and returns err, naming BOTH failures when the unwind itself
// failed — a silent failed restore is the half-land this law exists to
// prevent (the same shape as SaveThenLog's UNWIND ALSO FAILED).
func (t *execDirTxn) fail(err error) error {
	if rerr := t.unwind(); rerr != nil {
		return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s may hold "+
			"post-write bytes with no ledger event; remove it by hand "+
			"before continuing)", err, rerr, t.dir)
	}
	return err
}

// record builds the sandbox_execution record in Python's key order.
func (s *Sandbox) record(execID, command string, opts RunOpts,
	verdict, container validation.Value, started, stdoutPath,
	stderrPath string) validation.Value {
	keys := make([]validation.Value, 0, len(opts.Env))
	for _, e := range opts.Env {
		keys = append(keys, validation.VStr(e.Key))
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].S < keys[j].S })
	var workdir validation.Value = validation.VNull()
	var workdirResolved validation.Value = validation.VNull()
	if opts.Workdir != nil {
		workdir = validation.VStr(*opts.Workdir)
		// r36 F4: the record must also name the RESOLVED directory the
		// process actually ran in — the operator's string is kept in
		// `workdir` (pinned shape), `workdir_resolved` is additive.
		workdirResolved = validation.VStr(resolvedPath(*opts.Workdir))
	}
	return validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(s.Campaign.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr(s.Profile)},
		validation.KV{K: "finding_id", V: optStrValue(opts.FindingID)},
		validation.KV{K: "artifact_id", V: optStrValue(opts.ArtifactID)},
		validation.KV{K: "command", V: validation.VStr(command)},
		validation.KV{K: "workdir", V: workdir},
		validation.KV{K: "workdir_resolved", V: workdirResolved},
		validation.KV{K: "policy_verdict", V: verdict},
		validation.KV{K: "environment", V: environmentValue(
			toolVersions(), keys, s.Profile)},
		validation.KV{K: "container", V: container},
		validation.KV{K: "origin", V: validation.VStr("locally-executed")},
		validation.KV{K: "reported_by", V: validation.VNull()},
		validation.KV{K: "input_hashes", V: hashDir(opts.Workdir)},
		validation.KV{K: "started_at", V: validation.VStr(started)},
		validation.KV{K: "finished_at", V: validation.VNull()},
		validation.KV{K: "exit_status", V: validation.VNull()},
		validation.KV{K: "stdout_path", V: validation.VStr(stdoutPath)},
		validation.KV{K: "stderr_path", V: validation.VStr(stderrPath)},
		validation.KV{K: "artifact_hashes", V: validation.VObj()},
	)
}

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

// captureStats is the true byte accounting of one execution's captured
// output (r36 F6). Withheld means the bytes were never read (a live
// copier held them) — the totals are unknown, never zero.
type captureStats struct {
	StdoutTotal, StderrTotal int64
	StdoutKept, StderrKept   int64
	Withheld                 bool
}

func (c captureStats) stdoutTruncated() bool {
	return !c.Withheld && c.StdoutTotal > c.StdoutKept
}

func (c captureStats) stderrTruncated() bool {
	return !c.Withheld && c.StderrTotal > c.StderrKept
}

// capsOf maps a ProcResult's capture accounting; faked proc results carry
// no accounting, so the kept strings themselves become the totals (that
// IS what was captured).
func capsOf(res ProcResult) captureStats {
	caps := captureStats{
		StdoutTotal: res.StdoutCap.Total, StdoutKept: res.StdoutCap.Kept,
		StderrTotal: res.StderrCap.Total, StderrKept: res.StderrCap.Kept,
		Withheld: res.OutputWithheld,
	}
	if caps.StdoutTotal == 0 && caps.StdoutKept == 0 && res.Stdout != "" {
		caps.StdoutTotal, caps.StdoutKept =
			int64(len(res.Stdout)), int64(len(res.Stdout))
	}
	if caps.StderrTotal == 0 && caps.StderrKept == 0 && res.Stderr != "" {
		caps.StderrTotal, caps.StderrKept =
			int64(len(res.Stderr)), int64(len(res.Stderr))
	}
	return caps
}

// truncationMarker is the in-file truncation marker: a consumer reading
// stdout.log/stderr.log directly can never mistake a truncated capture
// for a complete one (r36 F6).
func truncationMarker(stream string, kept, total int64) []byte {
	return []byte(fmt.Sprintf(
		"\n[sandbox: %s TRUNCATED — kept the first %d of %d bytes (cap %d); "+
			"the record's output_capture carries the true counts]\n",
		stream, kept, total, outputCaptureLimitBytes))
}

// outputCaptureValue renders the additive `output_capture` object (r36
// F6): the deliberate cap, the TRUE byte counts, and whether any stream
// was truncated. When output was withheld (a live copier held it), the
// totals are null — absence, never a fabricated count.
func outputCaptureValue(caps captureStats) validation.Value {
	stdoutTotal := validation.VInt(caps.StdoutTotal)
	stderrTotal := validation.VInt(caps.StderrTotal)
	if caps.Withheld {
		stdoutTotal = validation.VNull()
		stderrTotal = validation.VNull()
	}
	return validation.VObj(
		validation.KV{K: "cap_bytes", V: validation.VInt(outputCaptureLimitBytes)},
		validation.KV{K: "stdout_total_bytes", V: stdoutTotal},
		validation.KV{K: "stdout_truncated", V: validation.VBool(caps.stdoutTruncated())},
		validation.KV{K: "stderr_total_bytes", V: stderrTotal},
		validation.KV{K: "stderr_truncated", V: validation.VBool(caps.stderrTruncated())},
		validation.KV{K: "output_withheld", V: validation.VBool(caps.Withheld)},
		validation.KV{K: "note", V: validation.VStr(
			"artifact_hashes cover exactly the stdout.log/stderr.log bytes " +
				"kept on disk (the capped payload plus, when truncated, the " +
				"marker line)")},
	)
}

func envStrings(env []EnvVar) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		out = append(out, e.Key+"="+e.Value)
	}
	return out
}

// Preview is Sandbox.preview: what run WOULD do — argv, env keys, network,
// workdir mode — without running, without an EXEC record, and without
// requiring the profile to be available.
func Preview(profile, command string, workdir *string,
	env []EnvVar) (validation.Value, error) {
	if !inProfiles(profile) {
		return validation.VNull(), fmt.Errorf("unknown profile %s",
			validation.PyReprStr(profile))
	}
	keys := envKeyValues(env)
	var wd validation.Value = validation.VNull()
	if workdir != nil {
		wd = validation.VStr(*workdir)
	}
	base := []validation.KV{
		{K: "profile", V: validation.VStr(profile)},
		{K: "available", V: validation.VBool(ProfileAvailable(profile))},
		{K: "command", V: validation.VStr(command)},
		{K: "env_keys", V: validation.VArr(keys...)},
		{K: "workdir", V: wd},
		{K: "network", V: validation.VStr(profileNetwork[profile])},
	}
	if HostProfile(profile) {
		base = append(base, validation.KV{K: "note", V: validation.VStr(
			"runs on the HOST (no container): this exec can never back E4+ " +
				"evidence — use a container profile (docker-networkless, " +
				"fork-runner, ...) for reproduction evidence")})
		return validation.VObj(base...), nil
	}
	argv, meta, err := BuildContainerArgv(profile, command, workdir, env)
	if err != nil {
		return validation.VNull(), err
	}
	argvVals := make([]validation.Value, 0, len(argv))
	for _, a := range argv {
		argvVals = append(argvVals, validation.VStr(a))
	}
	out := validation.VObj(base...)
	// Python assigns base["env_keys"] = meta["env_keys"], which REPLACES the
	// value in place (the key keeps its position).
	out = setKey(out, "env_keys",
		validation.VArr(envKeyValues2(meta.EnvKeys)...))
	out.O = append(out.O,
		validation.KV{K: "argv", V: validation.VArr(argvVals...)},
		validation.KV{K: "image", V: validation.VStr(meta.Image)},
		validation.KV{K: "workdir_mode", V: validation.VStr(meta.Workdir)},
		validation.KV{K: "svm_mount", V: optStrValue(meta.SvmMount)},
		validation.KV{K: "note", V: validation.VStr(
			"entrypoint is pinned to /bin/sh -c (the image's entrypoint is " +
				"never used) — the command runs verbatim as a shell string")},
	)
	return out, nil
}

// EvidenceProfile is Sandbox.evidence_profile.
func (s *Sandbox) EvidenceProfile() string { return s.Profile }

// RegisterOpts mirrors register_exec's keyword-only arguments.
type RegisterOpts struct {
	Profile    string
	Command    string
	ReportedBy string
	ExitStatus int
	FindingID  *string
	ArtifactID *string
	Workdir    *string
	StdoutText string
	StderrText string
	StartedAt  *string
	FinishedAt *string
}

// RegisterExec is register_exec: the ledger entry for an execution that
// happened OUTSIDE this process. It is honest about its own status:
// origin="externally-reported" and reported_by names who claims it happened.
func RegisterExec(c *state.Campaign, opts RegisterOpts) (validation.Value, error) {
	if !inProfiles(opts.Profile) {
		return validation.VNull(), fmt.Errorf("unknown profile %s",
			validation.PyReprStr(opts.Profile))
	}
	if opts.ReportedBy == "" {
		return validation.VNull(), fmt.Errorf(
			"externally-reported executions need a reported_by identity")
	}
	verdict, err := PolicyCheck(opts.Command, opts.Profile)
	if err != nil {
		return validation.VNull(), err
	}
	execID := "EXEC-" + shortID(10)
	outDir := filepath.Join(c.ExecsDir, execID)
	txn, err := beginExecDir(outDir)
	if err != nil {
		return validation.VNull(), err
	}
	stdoutPath := filepath.Join(outDir, "stdout.log")
	stderrPath := filepath.Join(outDir, "stderr.log")
	recordPath := filepath.Join(outDir, "exec_record.json")
	txn.note(stdoutPath, stderrPath, recordPath)
	if err := os.WriteFile(stdoutPath, []byte(opts.StdoutText), 0o644); err != nil {
		return validation.VNull(), txn.fail(err)
	}
	if err := os.WriteFile(stderrPath, []byte(opts.StderrText), 0o644); err != nil {
		return validation.VNull(), txn.fail(err)
	}
	started, finished := nowIso(), nowIso()
	if opts.StartedAt != nil {
		started = *opts.StartedAt
	}
	if opts.FinishedAt != nil {
		finished = *opts.FinishedAt
	}
	var workdir validation.Value = validation.VNull()
	var workdirResolved validation.Value = validation.VNull()
	if opts.Workdir != nil {
		workdir = validation.VStr(*opts.Workdir)
		// r36 F4: additive resolved path (the operator's string is kept).
		workdirResolved = validation.VStr(resolvedPath(*opts.Workdir))
	}
	record := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr(opts.Profile)},
		validation.KV{K: "finding_id", V: optStrValue(opts.FindingID)},
		validation.KV{K: "artifact_id", V: optStrValue(opts.ArtifactID)},
		validation.KV{K: "command", V: validation.VStr(opts.Command)},
		validation.KV{K: "workdir", V: workdir},
		validation.KV{K: "workdir_resolved", V: workdirResolved},
		validation.KV{K: "policy_verdict", V: verdict},
		validation.KV{K: "environment", V: environmentValue(
			validation.VObj(), nil, opts.Profile)},
		validation.KV{K: "container", V: validation.VNull()},
		validation.KV{K: "origin", V: validation.VStr("externally-reported")},
		validation.KV{K: "reported_by", V: validation.VStr(opts.ReportedBy)},
		validation.KV{K: "input_hashes", V: hashDir(opts.Workdir)},
		validation.KV{K: "started_at", V: validation.VStr(started)},
		validation.KV{K: "finished_at", V: validation.VStr(finished)},
		validation.KV{K: "exit_status", V: validation.VInt(int64(opts.ExitStatus))},
		validation.KV{K: "stdout_path", V: validation.VStr(stdoutPath)},
		validation.KV{K: "stderr_path", V: validation.VStr(stderrPath)},
		validation.KV{K: "artifact_hashes", V: validation.VObj(
			validation.KV{K: "stdout.log", V: validation.VStr(shaFile(stdoutPath))},
			validation.KV{K: "stderr.log", V: validation.VStr(shaFile(stderrPath))})},
	)
	if err := validation.WriteJson(filepath.Join(outDir, "exec_record.json"),
		record, "sandbox_execution"); err != nil {
		return validation.VNull(), txn.fail(err)
	}
	ref := execID
	data := validation.VObj(
		validation.KV{K: "profile", V: validation.VStr(opts.Profile)},
		validation.KV{K: "exit", V: validation.VInt(int64(opts.ExitStatus))},
		validation.KV{K: "reported_by", V: validation.VStr(opts.ReportedBy)},
		validation.KV{K: "finding", V: optStrValue(opts.FindingID)},
	)
	if _, err := c.Log("sandbox.exec.registered", &ref, &data); err != nil {
		// r39 F2: same unwinding as Run. The execution happened OUTSIDE this
		// process (origin=externally-reported), so nothing here can undo it —
		// what must not survive is the registration the ledger refused: the
		// dir goes, and the error says the registration was not kept rather
		// than reporting a clean write.
		return validation.VNull(), txn.fail(fmt.Errorf(
			"the externally-reported execution by %s was NOT REGISTERED: the "+
				"ledger refused the sandbox.exec.registered event and the "+
				"exec dir %s was removed — no exec record exists, so the "+
				"reported execution cannot back any evidence (ledger "+
				"refusal: %v)", validation.PyReprStr(opts.ReportedBy), outDir,
			err))
	}
	return record, nil
}

// environmentValue renders the environment sub-dict.
func environmentValue(tools validation.Value, envKeys []validation.Value,
	profile string) validation.Value {
	if envKeys == nil {
		envKeys = []validation.Value{}
	}
	return validation.VObj(
		validation.KV{K: "tool_versions", V: tools},
		validation.KV{K: "env_keys", V: validation.VArr(envKeys...)},
		validation.KV{K: "network_access",
			V: validation.VStr(profileNetwork[profile])},
		validation.KV{K: "filesystem",
			V: validation.VStr(profileFilesystemLabel(profile))},
	)
}

// profileFilesystemLabel is the HONEST filesystem label for a profile
// (r36 F5): a host profile executes UNCONFINED on this host — nothing
// enforces readonly (the deny rules are static tripwires, not a
// boundary) — so the record must not assert "readonly" while the run
// writes the host filesystem. Container profiles keep their label (the
// container IS the enforcement mechanism).
func profileFilesystemLabel(profile string) string {
	if HostProfile(profile) {
		return "host (unconfined — nothing enforces readonly; deny-rule " +
			"tripwires only)"
	}
	return profileFilesystem[profile]
}

// LoadExec is load_exec: the stored exec record, or the FileNotFoundError
// text Python's read_json raises (cmd_mint's generic handler prints it).
func LoadExec(c *state.Campaign, execID string) (validation.Value, error) {
	path := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Errorf(
			"[Errno 2] No such file or directory: %s",
			validation.PyReprStr(path))
	}
	return validation.ReadJson(path)
}

// AllExecs is all_execs: every EXEC record, sorted by path.
func AllExecs(c *state.Campaign) ([]validation.Value, error) {
	if _, err := os.Stat(c.ExecsDir); err != nil {
		return nil, nil
	}
	matches := validation.ListSubPrefixed(c.ExecsDir, "EXEC-",
		"exec_record.json")
	sort.Strings(matches)
	out := make([]validation.Value, 0, len(matches))
	for _, p := range matches {
		v, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// shaFile is _sha.
func shaFile(path string) string {
	digest, _ := shaFileErr(path)
	return digest
}

// shaFileErr is shaFile with the error surfaced, so a hash that cannot be
// computed can be reported instead of silently digesting nothing.
func shaFileErr(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashDir is _hash_dir: relative path -> sha256 for every file under the
// RESOLVED directory d, in sorted relative-path order ([] when d is nil
// or absent). r36 F4: the root is resolved first, so a symlink workdir
// hashes the directory the process actually ran in instead of producing
// the fabricated {'.': ”} the old Lstat-on-symlink path emitted; and a
// digest that cannot be computed is recorded EXPLICITLY as
// "sha256-unavailable (...)" — never as an empty string, which a
// consumer could mistake for a real digest (an empty digest is a
// fabrication; absence or an explicit failure, nothing else).
func hashDir(d *string) validation.Value {
	if d == nil {
		return validation.VObj()
	}
	root := resolvedPath(*d)
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return validation.VObj()
	}
	var rels []string
	_ = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr == nil {
			rels = append(rels, rel)
		}
		return nil
	})
	sort.Strings(rels)
	o := make([]validation.KV, 0, len(rels))
	for _, rel := range rels {
		digest, err := shaFileErr(filepath.Join(root, rel))
		if err != nil {
			o = append(o, validation.KV{K: rel, V: validation.VStr(
				"sha256-unavailable (" + err.Error() + ")")})
			continue
		}
		o = append(o, validation.KV{K: rel, V: validation.VStr(digest)})
	}
	return validation.VObj(o...)
}

// toolVersions is _tool_versions: the host toolchain, probed once per exec.
// halmos and minicertora ride the same host LookPath + `--version`
// first-line probe as slither/aderyn (fail-open: a missing binary is
// omitted, a failed probe records "present (version probe failed)").
func toolVersions() validation.Value {
	out := []validation.KV{}
	for _, tool := range []string{"forge", "cast", "slither", "aderyn",
		"halmos", "minicertora", "miniprover", "solc", "python3", "docker"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		res, err := runProc([]string{tool, "--version"}, "", nil, 15*time.Second)
		if err != nil && err != errTimeout {
			out = append(out, validation.KV{K: tool, V: validation.VStr(
				"present (version probe failed)")})
			continue
		}
		text := res.Stdout
		if text == "" {
			text = res.Stderr
		}
		line := pyFirstLine80(text)
		if tool == "solc" {
			// solc's FIRST line is a banner; its version rides the
			// "Version: X" line (r18: the harness toolchain check
			// consumes this row, so it stores the VERSION, not the
			// banner).
			line = solcVersionLine(res.Stdout + res.Stderr)
		}
		out = append(out, validation.KV{K: tool, V: validation.VStr(line)})
	}
	return validation.VObj(out...)
}

// pyFirstLine80 is `(stdout or stderr).strip().splitlines()[0][:80]`.
func pyFirstLine80(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	line := strings.SplitN(text, "\n", 2)[0]
	rs := []rune(line)
	if len(rs) > 80 {
		line = string(rs[:80])
	}
	return line
}

// shortID is Python's `new_id("x", n).split("-")[1]`: n hex chars.
func shortID(n int) string {
	parts := strings.SplitN(state.NewID("x", n), "-", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// nowIso is now_iso (mirrors state.nowIso, unexported there). WEBV2_NOW is
// honoured identically.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// --- small value helpers ---------------------------------------------------

func truthy(v validation.Value, key string) bool {
	f := objAt(v, key)
	return f.Kind == validation.Bool && f.B
}

func optStrValue(p *string) validation.Value {
	if p == nil {
		return validation.VNull()
	}
	return validation.VStr(*p)
}

func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := validation.Value{Kind: validation.Obj, O: append(
		[]validation.KV(nil), v.O...)}
	for i := range out.O {
		if out.O[i].K == key {
			out.O[i].V = val
			return out
		}
	}
	out.O = append(out.O, validation.KV{K: key, V: val})
	return out
}

// pyListRepr renders Python's repr of a list of strings ("['a', 'b']").
func pyListRepr(v validation.Value) string {
	items := make([]validation.Value, 0, len(v.A))
	items = append(items, v.A...)
	return validation.PyRepr(validation.VArr(items...))
}

func envKeyValues(env []EnvVar) []validation.Value {
	keys := make([]string, 0, len(env))
	for _, e := range env {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return envKeyValues2(keys)
}

func envKeyValues2(keys []string) []validation.Value {
	out := make([]validation.Value, 0, len(keys))
	for _, k := range keys {
		out = append(out, validation.VStr(k))
	}
	return out
}

// SolcVersionFromText exports the extractor for the verify-side pin
// probe (same parsing, one law).
func SolcVersionFromText(text string) string { return solcVersionLine(text) }

// solcVersionLine extracts "0.8.36" from solc --version output
// ("Version: 0.8.36+commit..."). "" when no version line exists.
func solcVersionLine(text string) string {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "Version:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(ln, "Version:"))
		if i := strings.IndexAny(v, "+ "); i >= 0 {
			v = v[:i]
		}
		return v
	}
	return ""
}
