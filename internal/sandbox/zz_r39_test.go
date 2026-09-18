package sandbox

// r39 hostile-audit pins for this package's two findings:
//
//	F2  the sandbox exec writers are outside the unwind-on-refusal law
//	P3  a timed-out container is left in docker state 'created'
//
// Each pin is written against the PRE-FIX surface (Run / RegisterExec /
// stopContainer / the exec_record.json on disk) so it can be shown FAILING
// on the unfixed code and passing after the repair.
//
// F2: the campaign's state mirror is cut SHORTER than its ledger (the
// honest refusal any operator can hit), the payload runs, c.Log refuses —
// and pre-fix the exec dir (exec_record.json / stdout.log / stderr.log)
// survived with NO sandbox.exec event, still listed by AllExecs as a normal
// run, and the CLI never said the command had executed.
//
// P3: `docker kill` cannot clean a container the daemon created after the
// client was killed (a --rm container that was never STARTED is never
// auto-removed). Pre-fix the record called it "not running (exited)" while
// it stayed in `docker ps -a` as Created forever; now it is force-removed
// and the record names the state it was found in.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// lagLedger cuts the campaign ledger's LAST record away while the state
// mirror keeps it — the refusal shape any operator can hit after a partial
// restore or a crash (mirror LONGER than the log). Every c.Log in that
// campaign then refuses, which is exactly what the F2 pins need.
func lagLedger(t *testing.T, c *state.Campaign) {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("ledger holds %d line(s); the fixture needs >= 2 to cut one",
			len(lines))
	}
	kept := lines[:len(lines)-1]
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("cut ledger: %v", err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatalf("read mirror: %v", err)
	}
	mirror := validation.ObjAt(st, "events")
	if mirror.Kind != validation.Arr || len(mirror.A) <= len(kept) {
		t.Fatalf("mirror holds %d event(s) and the ledger now %d — the "+
			"fixture must leave the MIRROR longer", len(mirror.A), len(kept))
	}
	if _, err := c.Log("fixture-must-refuse", nil, nil); err == nil {
		t.Fatal("c.Log accepted a write with the mirror longer than the " +
			"ledger — the fixture did not arm the refusal")
	}
}

// execDirs lists the per-exec directories a campaign currently holds (what
// `webv2 execs` resolves): a corpse left by a refused write shows up here.
func execDirs(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	ents, err := os.ReadDir(c.ExecsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read execs dir: %v", err)
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// --- F2: a refused c.Log must unwind the exec dir ----------------------

// TestR39ExecRunUnwindsOnRefusedLog is the reported repro: mirror longer
// than the ledger, then `exec`. The payload RAN; the record must NOT
// survive without its event, and the operator must be told which half
// happened. Pre-fix: the dir (with the captured stdout) is left behind, is
// listed by AllExecs, and the error is only the ledger's complaint.
func TestR39ExecRunUnwindsOnRefusedLog(t *testing.T) {
	withDaemon(t, false)
	c := newCampaign(t, "r39-f2")
	if _, err := c.Log("probe", nil, nil); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	lagLedger(t, c)
	before := execDirs(t, c)
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	withProc(t, func(_ []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		return ProcResult{ReturnCode: 0, Stdout: "GHOST-RUN\n"}, nil
	})
	_, err = sb.Run("echo GHOST-RUN", RunOpts{Timeout: 5})
	if err == nil {
		t.Fatalf("Run accepted a record the ledger refused — an exec " +
			"record with no sandbox.exec event is the F2 half-write")
	}
	msg := err.Error()
	for _, want := range []string{"EXECUTED", "NOT KEPT", "removed",
		"mirrors"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must say which part happened (missing "+
				"%q): %v", want, msg)
		}
	}
	if got := execDirs(t, c); len(got) != len(before) {
		t.Fatalf("a refused log left an exec corpse behind: %v (want %v)",
			got, before)
	}
	execs, err := AllExecs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(execs) != 0 {
		t.Fatalf("`webv2 execs` would list %d run(s) the ledger does not "+
			"hold: %s", len(execs), validation.CanonCompact(
			validation.VArr(execs...)))
	}
	// The retry after the refusal must not leave a SECOND corpse for the
	// one run, and it must say again that the payload ran.
	_, err2 := sb.Run("echo GHOST-RUN", RunOpts{Timeout: 5})
	if err2 == nil {
		t.Fatal("the retry succeeded where the ledger still refuses")
	}
	if !strings.Contains(err2.Error(), "AGAIN") {
		t.Fatalf("the retry must warn that the command runs again: %v",
			err2.Error())
	}
	if got := execDirs(t, c); len(got) != len(before) {
		t.Fatalf("the retry left a second corpse: %v (want %v)", got, before)
	}
}

// TestR39RegisterExecUnwindsOnRefusedLog is the sibling writer: an
// externally-reported execution whose sandbox.exec.registered event is
// refused must not leave the registration artifacts behind either.
func TestR39RegisterExecUnwindsOnRefusedLog(t *testing.T) {
	c := newCampaign(t, "r39-f2-reg")
	if _, err := c.Log("probe", nil, nil); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	lagLedger(t, c)
	before := execDirs(t, c)
	_, err := RegisterExec(c, RegisterOpts{Profile: "host-readonly",
		Command: "echo hi", ReportedBy: "harness", ExitStatus: 0,
		StdoutText: "hi\n"})
	if err == nil {
		t.Fatal("RegisterExec accepted a registration the ledger refused")
	}
	msg := err.Error()
	for _, want := range []string{"NOT REGISTERED", "removed", "mirrors"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must say the registration was not kept "+
				"(missing %q): %v", want, msg)
		}
	}
	if got := execDirs(t, c); len(got) != len(before) {
		t.Fatalf("a refused registration left an exec corpse: %v (want %v)",
			got, before)
	}
}

// TestR39PolicyRefusalUnwindsOnRefusedLog pins the other arm: a policy
// refusal whose sandbox.refused event is ALSO refused must not leave the
// record behind, and must say that the command did not run and that the
// refusal itself is not in the ledger.
func TestR39PolicyRefusalUnwindsOnRefusedLog(t *testing.T) {
	withDaemon(t, false)
	c := newCampaign(t, "r39-f2-pol")
	if _, err := c.Log("probe", nil, nil); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	lagLedger(t, c)
	before := execDirs(t, c)
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	// The refused command must never reach execute(): the seam fails every
	// probe, and a `/bin/sh -c` argv here would mean the payload RAN.
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		if len(argv) > 0 && argv[0] == "/bin/sh" {
			t.Errorf("the policy-refused command was EXECUTED: %v", argv)
		}
		return ProcResult{ReturnCode: 1}, nil
	})
	_, err = sb.Run("rm -rf /var", RunOpts{Timeout: 5})
	if err == nil {
		t.Fatal("a destructive command was accepted")
	}
	msg := err.Error()
	for _, want := range []string{"REFUSED by sandbox policy", "did NOT " +
		"run", "refusal event was refused", "removed"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal must say the command did not run and "+
				"that the refusal is unrecorded (missing %q): %v", want, msg)
		}
	}
	if got := execDirs(t, c); len(got) != len(before) {
		t.Fatalf("a refused policy write left an exec corpse: %v (want %v)",
			got, before)
	}
}

// --- P3: a container in ANY state must be removed, not just described ---

// dockerCallSeen reports whether the cleanup issued exactly this docker argv.
func dockerCallSeen(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

// TestR39StopContainerRemovesCreatedContainer is the reported state: the
// daemon created the container after the client was killed, so `docker kill`
// fails and `docker inspect` says 'created'. Pre-fix stopContainer returned
// "exited" and NOBODY removed it (--rm never applies to a container that was
// never started): it stayed in `docker ps -a` forever.
func TestR39StopContainerRemovesCreatedContainer(t *testing.T) {
	var calls []string
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		calls = append(calls, strings.Join(argv, " "))
		switch argv[1] {
		case "kill":
			return ProcResult{ReturnCode: 1, Stderr: "Error response from " +
				"daemon: container webv2-exec-x is not running"}, nil
		case "inspect":
			return ProcResult{ReturnCode: 0, Stdout: "created\n"}, nil
		case "rm":
			return ProcResult{ReturnCode: 0, Stdout: "webv2-exec-x\n"}, nil
		}
		t.Fatalf("unexpected docker argv: %v", argv)
		return ProcResult{ReturnCode: 1}, nil
	})
	fate := stopContainer("webv2-exec-x")
	if fate.outcome != "removed" || fate.state != "created" {
		t.Fatalf("fate = %+v, want the created container REMOVED (found "+
			"in state created)", fate)
	}
	if !dockerCallSeen(calls, "docker rm -f webv2-exec-x") {
		t.Fatalf("the cleanup never force-removed the container: %v", calls)
	}
}

// TestR39StopContainerSweepsLateCreatedContainer pins the race the eight
// leftovers on the box came from: at the first look docker says the
// container does not exist (the create request is still in flight), and it
// materializes a moment later. It must be swept, not missed.
func TestR39StopContainerSweepsLateCreatedContainer(t *testing.T) {
	inspects := 0
	var calls []string
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		calls = append(calls, strings.Join(argv, " "))
		switch argv[1] {
		case "kill":
			return ProcResult{ReturnCode: 1, Stderr: "Error response from " +
				"daemon: No such container: webv2-exec-late"}, nil
		case "inspect":
			inspects++
			if inspects <= 2 {
				return ProcResult{ReturnCode: 1, Stderr: "Error: No such " +
					"object: webv2-exec-late"}, nil
			}
			return ProcResult{ReturnCode: 0, Stdout: "created\n"}, nil
		case "rm":
			return ProcResult{ReturnCode: 0, Stdout: "webv2-exec-late\n"}, nil
		}
		t.Fatalf("unexpected docker argv: %v", argv)
		return ProcResult{ReturnCode: 1}, nil
	})
	fate := stopContainer("webv2-exec-late")
	if fate.outcome != "removed-late" || fate.state != "created" {
		t.Fatalf("fate = %+v, want the LATE container removed (it cannot "+
			"be missed just because docker had not finished creating it)",
			fate)
	}
	if !dockerCallSeen(calls, "docker rm -f webv2-exec-late") {
		t.Fatalf("the sweep never removed the late container: %v", calls)
	}
}

// TestR39AbsenceIsRecognisedWhateverDockerCapitalises pins the TRIGGER for
// the late-container sweep: docker 29 answers `error: no such object: NAME`
// (lowercase) while older clients capitalize it. The pre-r39 exact-case
// check saw "unknown" instead of "absent" for a truly missing container, so
// the sweep never armed and the container the daemon was about to create was
// never looked for again.
func TestR39AbsenceIsRecognisedWhateverDockerCapitalises(t *testing.T) {
	for _, stderr := range []string{
		"error: no such object: webv2-exec-x",
		"Error: No such object: webv2-exec-x",
		"Error response from daemon: No such container: webv2-exec-x",
	} {
		withProc(t, func(_ []string, _ string, _ []string,
			_ time.Duration) (ProcResult, error) {
			return ProcResult{ReturnCode: 1, Stderr: stderr}, nil
		})
		if got := containerState("webv2-exec-x"); got != "absent" {
			t.Fatalf("containerState(%q) = %q, want absent", stderr, got)
		}
	}
}

// TestR39StopContainerStillKilled keeps the r36 F1 shape: a kill that lands
// still reports "killed" (the wording the r36 pins forward), with the
// removal attempted as belt-and-braces.
func TestR39StopContainerStillKilled(t *testing.T) {
	var calls []string
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		calls = append(calls, strings.Join(argv, " "))
		switch argv[1] {
		case "kill":
			return ProcResult{ReturnCode: 0}, nil
		case "rm":
			return ProcResult{ReturnCode: 1, Stderr: "Error: removal of " +
				"container webv2-exec-y is already in progress"}, nil
		case "inspect":
			return ProcResult{ReturnCode: 0, Stdout: "running\n"}, nil
		}
		t.Fatalf("unexpected docker argv: %v", argv)
		return ProcResult{ReturnCode: 1}, nil
	})
	fate := stopContainer("webv2-exec-y")
	if fate.outcome != "killed" {
		t.Fatalf("fate = %+v, want killed (the kill was observed to succeed)",
			fate)
	}
	if !dockerCallSeen(calls, "docker rm -f webv2-exec-y") {
		t.Fatalf("a killed container must not be assumed removed: %v", calls)
	}
}

// TestR39UnremovableContainerIsNamedNotHidden pins the honest failure arm:
// when the removal does NOT land, the record must name the debris instead of
// reporting a clean box.
func TestR39UnremovableContainerIsNamedNotHidden(t *testing.T) {
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		switch argv[1] {
		case "kill":
			return ProcResult{ReturnCode: 1, Stderr: "Error response from " +
				"daemon: container webv2-exec-z is not running"}, nil
		case "inspect":
			return ProcResult{ReturnCode: 0, Stdout: "created\n"}, nil
		case "rm":
			return ProcResult{ReturnCode: 1, Stderr: "Error response from " +
				"daemon: cannot remove container"}, nil
		}
		t.Fatalf("unexpected docker argv: %v", argv)
		return ProcResult{ReturnCode: 1}, nil
	})
	fate := stopContainer("webv2-exec-z")
	if fate.outcome != "exists" || fate.state != "created" {
		t.Fatalf("fate = %+v, want exists/created (the debris must be "+
			"reported, never hidden)", fate)
	}
}

// createdDebrisDocker writes a fake docker CLI that emulates the reported
// race: the daemon has created the container (state 'created') but the
// client dies before it is ever started, so `docker kill` fails and only
// `docker rm -f` can clear it. mode=="absent" emulates the other half of the
// race: the daemon has not committed the create yet, so the first looks find
// nothing. rmFail (env) makes the removal fail so the debris arm can be
// pinned too. Every argv is appended to $FAKE_DOCKER_LOG.
func createdDebrisDocker(t *testing.T, bin, mode string) {
	t.Helper()
	inspect := "echo created; exit 0"
	if mode == "absent" {
		inspect = "echo 'error: no such object: webv2-exec' >&2; exit 1"
	}
	script := "#!/bin/sh\n" +
		"log() { [ -n \"$FAKE_DOCKER_LOG\" ] && echo \"$*\" >> " +
		"\"$FAKE_DOCKER_LOG\"; }\n" +
		"log \"$@\"\n" +
		"case \"$1\" in\n" +
		"  --version) echo 'fake docker 0.0'; exit 0;;\n" +
		"  run) /bin/sleep 30;;\n" +
		"  kill) echo 'Error response from daemon: container is not running' " +
		">&2; exit 1;;\n" +
		"  inspect) " + inspect + ";;\n" +
		"  rm) [ -n \"$FAKE_DOCKER_RM_FAIL\" ] && exit 1; exit 0;;\n" +
		"esac\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script),
		0o755); err != nil {
		t.Fatal(err)
	}
}

// shortSweep lowers the late-appearance sweep window for a test (the real
// one is seconds; a pin must not pay it) and restores it afterwards.
func shortSweep(t *testing.T) {
	t.Helper()
	prev := containerSweepWindow
	containerSweepWindow = 300 * time.Millisecond
	t.Cleanup(func() { containerSweepWindow = prev })
}

// TestR39TimedOutCreatedContainerLeavesNoDebris is the P3 end-to-end pin
// through the real timeout path (a fake docker on PATH): after a timed-out
// container exec the record must name the state the container was found in
// and its removal, and `docker rm -f` must actually have been issued. The
// pre-fix record said "is not running (exited)" and issued no rm at all.
func TestR39TimedOutCreatedContainerLeavesNoDebris(t *testing.T) {
	bin := t.TempDir()
	createdDebrisDocker(t, bin, "created")
	logPath := filepath.Join(bin, "docker.log")
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_DOCKER_LOG", logPath)
	t.Setenv("WEBV2_DOCKER_IMAGE", "fake:1")
	withDaemon(t, true)
	c := newCampaign(t, "r39-p3")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("sleep 45", RunOpts{Timeout: 2})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	name := "webv2-exec-" + strings.ToLower(execID)
	stderrLog, err := os.ReadFile(filepath.Join(c.ExecsDir, execID,
		"stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(stderrLog)
	if !strings.Contains(got, "docker state 'created'") ||
		!strings.Contains(got, "REMOVED") {
		t.Fatalf("the timeout record must name the created container and "+
			"its removal: %q", got)
	}
	if strings.Contains(got, "is not running (exited)") {
		t.Fatalf("the record called a created container 'exited' — the "+
			"pre-fix lie this pin exists for: %q", got)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "rm -f "+name) {
		t.Fatalf("no `docker rm -f %s` was issued — the container would "+
			"stay in `docker ps -a` as Created: %q", name, string(calls))
	}
}

// TestR39UnremovableDebrisIsDisclosed is the same path with a failing
// removal: the record must say the container is STILL THERE.
func TestR39UnremovableDebrisIsDisclosed(t *testing.T) {
	bin := t.TempDir()
	createdDebrisDocker(t, bin, "created")
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_DOCKER_RM_FAIL", "1")
	t.Setenv("WEBV2_DOCKER_IMAGE", "fake:1")
	withDaemon(t, true)
	c := newCampaign(t, "r39-p3-fail")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("sleep 45", RunOpts{Timeout: 2})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	stderrLog, err := os.ReadFile(filepath.Join(c.ExecsDir, execID,
		"stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(stderrLog)
	if !strings.Contains(got, "could NOT be removed") ||
		!strings.Contains(got, "debris") {
		t.Fatalf("an unremovable container must be disclosed as debris, "+
			"not passed over: %q", got)
	}
}

// TestR39AbsentContainerIsDisclosedNotProven is the honest absence arm: when
// the sweep ends without ever seeing the container, docker's "absent" is an
// OBSERVATION in a bounded window, and the record says so (plus the exact
// re-check) instead of reading like a clean bill of health.
func TestR39AbsentContainerIsDisclosedNotProven(t *testing.T) {
	shortSweep(t)
	bin := t.TempDir()
	createdDebrisDocker(t, bin, "absent")
	t.Setenv("PATH", bin)
	t.Setenv("WEBV2_DOCKER_IMAGE", "fake:1")
	withDaemon(t, true)
	c := newCampaign(t, "r39-p3-absent")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("sleep 45", RunOpts{Timeout: 2})
	if err != nil {
		t.Fatal(err)
	}
	execID := validation.ObjStr(rec, "exec_id")
	name := "webv2-exec-" + strings.ToLower(execID)
	stderrLog, err := os.ReadFile(filepath.Join(c.ExecsDir, execID,
		"stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(stderrLog)
	for _, want := range []string{"no such container", "absence observed, " +
		"never proven", "docker ps -a --filter name=" + name} {
		if !strings.Contains(got, want) {
			t.Fatalf("the absent arm must disclose the bounded observation "+
				"and the re-check (missing %q): %q", want, got)
		}
	}
}

// TestR39AbsenceSweepIsBounded pins that the sweep is finite and backed off:
// with a window that has already elapsed the sweep makes a single look and
// returns (no unbounded waiting on docker).
func TestR39AbsenceSweepIsBounded(t *testing.T) {
	prev := containerSweepWindow
	containerSweepWindow = 0
	t.Cleanup(func() { containerSweepWindow = prev })
	inspects := 0
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		inspects++
		return ProcResult{ReturnCode: 1, Stderr: "error: no such object: x"}, nil
	})
	start := time.Now()
	if got := waitForContainer("webv2-exec-none"); got != "" {
		t.Fatalf("waitForContainer = %q, want no container inside the window",
			got)
	}
	if inspects != 1 {
		t.Fatalf("sweep made %d look(s) inside a zero window, want exactly 1",
			inspects)
	}
	if elapsed := time.Since(start); elapsed > containerSweepWindow+
		2*time.Second {
		t.Fatalf("the sweep ran for %s — it must be bounded", elapsed)
	}
}
