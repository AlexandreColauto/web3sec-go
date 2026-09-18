// container.go: the payload-container reaper (r36 F1, r39 P3) — stop,
// force-remove and sweep the `docker run` container an exec created.
package sandbox

import (
	"strings"
	"time"
)

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
