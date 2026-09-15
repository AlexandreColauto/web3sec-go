package sandbox

// r36 hostile-audit pins: six findings on `webv2 exec` / this package.
//
// Each pin is written against the PRE-FIX public surface only (existing
// ProcResult fields, the exec_record.json on disk, ClassifyFailure) so it
// can be shown FAILING on the unfixed code and passing after the repair:
//
//	F1  TestR36ContainerRunArgvPinsName / TestR36ContainerTimeoutHonesty
//	    TestR36RealDockerTimeoutKillsContainer
//	F2  TestR36TimeoutSurvivorIsReportedAndCleaned
//	F3  TestR36ExitCodeClassificationIsHonest
//	F4  TestR36WorkdirResolvedAndNoFabricatedHash
//	F5  TestR36HostReadonlyFilesystemLabelIsHonest
//	F6  TestR36OutputCaptureCapAndAccounting
//
// Docker-dependent assertions skip cleanly when the daemon/image is absent.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"websec/internal/validation"
)

// pidAlive reads /proc — the unprivileged liveness probe for pins.
func pidAlive(pid int) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	i := strings.LastIndex(string(raw), ")")
	if i < 0 || i+2 >= len(raw) {
		return false
	}
	fields := strings.Fields(string(raw[i+2:]))
	return len(fields) > 0 && fields[0] != "Z"
}

// --- F1: a container timeout must kill the CONTAINER, and the record must
// not claim a kill that did not happen -------------------------------

// TestR36ContainerRunArgvPinsName pins the deterministic container name:
// every container-profile `docker run` argv must carry --name so the
// killing side can stop the payload by id. (Pre-fix: no --name at all.)
func TestR36ContainerRunArgvPinsName(t *testing.T) {
	withDaemon(t, true)
	var got []string
	withProc(t, func(argv []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		got = argv
		return ProcResult{ReturnCode: 0}, nil
	})
	c := newCampaign(t, "r36")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Run("echo hi", RunOpts{Timeout: 5}); err != nil {
		t.Fatal(err)
	}
	for i, a := range got {
		if a == "--name" && i+1 < len(got) && got[i+1] != "" {
			return
		}
	}
	t.Fatalf("docker run argv carries no --name (the container cannot be "+
		"identified by the killing side): %v", got)
}

// fakeDockerScript emulates just enough of the docker CLI for the timeout
// pin: `run` starts the payload in a NEW SESSION (so a host-side group
// kill cannot reach it — exactly a container's relationship to the docker
// client), `kill`/`inspect` operate on that payload by name.
func fakeDockerScript(t *testing.T, bin, clientPidFile, containerPidFile string) {
	t.Helper()
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  --version) echo 'fake docker 0.0'; exit 0;;\n" +
		"  run)\n" +
		"    shift\n" +
		"    while [ $# -gt 0 ]; do\n" +
		"      case \"$1\" in\n" +
		"        --name) shift 2;;\n" +
		"        --network|--add-host|--tmpfs|-e|-v|-w|--entrypoint) shift 2;;\n" +
		"        -c) payload=\"$2\"; shift 2;;\n" +
		"        *) shift;;\n" +
		"      esac\n" +
		"    done\n" +
		"    echo $$ > \"" + clientPidFile + "\"\n" +
		"    /usr/bin/setsid /bin/sh -c \"$payload\" &\n" +
		"    echo $! > \"" + containerPidFile + "\"\n" +
		"    /bin/sleep 30\n" + // the client streams until the container exits
		"    ;;\n" +
		"  kill)\n" +
		"    kill -9 \"$(cat \"" + containerPidFile + "\")\" 2>/dev/null\n" +
		"    exit 0;;\n" +
		"  inspect)\n" +
		"    if kill -0 \"$(cat \"" + containerPidFile + "\")\" 2>/dev/null; then\n" +
		"      echo true\n" +
		"    else\n" +
		"      echo false\n" +
		"    fi\n" +
		"    exit 0;;\n" +
		"esac\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script),
		0o755); err != nil {
		t.Fatal(err)
	}
}

// TestR36ContainerTimeoutHonesty is the F1 law, pinned without docker:
// after a container-profile timeout either the payload is dead, or the
// record must NOT claim it was killed. Pre-fix the record says
// "timed out after 2s and was killed" while the payload (a setsid'd
// process a group kill cannot reach) runs on.
func TestR36ContainerTimeoutHonesty(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	bin := t.TempDir()
	clientPidFile := filepath.Join(bin, "client.pid")
	containerPidFile := filepath.Join(bin, "container.pid")
	fakeDockerScript(t, bin, clientPidFile, containerPidFile)
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_DOCKER_PIDFILE", containerPidFile)
	t.Setenv("WEBV2_DOCKER_IMAGE", "fake:1")
	withDaemon(t, true)
	c := newCampaign(t, "r36")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("/bin/sleep 40; echo NEVER", RunOpts{Timeout: 2})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	stderrLog := string(raw)
	pidRaw, err := os.ReadFile(containerPidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if err != nil {
		t.Fatal(err)
	}
	alive := pidAlive(pid)
	if alive && strings.Contains(stderrLog, "and was killed") {
		t.Fatalf("the record claims a kill while payload pid %d is still "+
			"alive — a lying record: %q", pid, stderrLog)
	}
	if alive {
		t.Fatalf("payload pid %d outlived the timeout record (stderr: %q)",
			pid, stderrLog)
	}
	if !strings.Contains(stderrLog, "timed out after 2s") {
		t.Fatalf("timeout record must explain itself: %q", stderrLog)
	}
	stdoutLog, err := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stdoutLog), "NEVER") {
		t.Fatalf("the payload ran to completion: %q", stdoutLog)
	}
}

// TestR36RealDockerTimeoutKillsContainer is the F1 repro against a real
// daemon: `sleep 40` under --timeout 4 must leave NO running container,
// and the record's note must be true.
func TestR36RealDockerTimeoutKillsContainer(t *testing.T) {
	image := "ghcr.io/foundry-rs/foundry:latest"
	if v := os.Getenv("WEBV2_TEST_IMAGE"); v != "" {
		image = v
	}
	if !dockerReady(image) {
		t.Skipf("no live docker daemon with image %q on this host", image)
	}
	t.Setenv("WEBV2_DOCKER_IMAGE", image)
	c := newCampaign(t, "r36real")
	sb, err := NewSandbox(c, "docker-networkless")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("sleep 40; echo NEVER", RunOpts{Timeout: 4})
	if err != nil {
		t.Fatal(err)
	}
	name := "webv2-exec-" + strings.ToLower(objStr(rec, "exec_id"))
	stderrLog, err := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stderrLog),
		"the container '"+name+"'") {
		t.Fatalf("the timeout record must state the container's fate "+
			"(name %s): %q", name, stderrLog)
	}
	// No running container afterwards (poll: the kill is signalled before
	// the record is written, but the reap/removal is docker's async work).
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, err := exec.Command("docker", "ps", "--filter",
			"ancestor="+image, "--filter", "status=running", "-q").Output()
		if err != nil {
			t.Fatalf("docker ps: %v", err)
		}
		if strings.TrimSpace(string(out)) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("container %s (or a sibling payload) still running "+
				"after the timeout record: %q", name, string(out))
		}
		time.Sleep(250 * time.Millisecond)
	}
	stdoutLog, err := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stdoutLog), "NEVER") {
		t.Fatalf("the payload ran to completion: %q", stdoutLog)
	}
}

// --- F2: a survivor that escapes the group must be reported as RUNNING
// (with pids) and cleaned up as far as an unprivileged parent can ------

func TestR36TimeoutSurvivorIsReportedAndCleaned(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "survived.txt")
	start := time.Now()
	res, err := realRunProc([]string{"/bin/sh", "-c",
		"setsid sh -c 'sleep 12; echo SURVIVED > " + file + "' & sleep 60"},
		"", nil, 1*time.Second)
	if err != errTimeout {
		t.Fatalf("want errTimeout, got %v", err)
	}
	// The note must record WHAT survived, by pid, and must never pretend
	// the escaped process was group-killed into oblivion.
	if !strings.Contains(res.TimeoutNote, "pid [") {
		t.Fatalf("the survivor note must record pids, got %q", res.TimeoutNote)
	}
	if strings.Contains(res.TimeoutNote, "survivor escaped") &&
		!strings.Contains(res.TimeoutNote, "REMAINS RUNNING") &&
		!strings.Contains(res.TimeoutNote, "cleanup") {
		t.Fatalf("survivor note neither reports it remains running nor a "+
			"cleanup: %q", res.TimeoutNote)
	}
	// The cleanup must have fired: wait past the survivor's write deadline
	// (t+12s) and require the file to be absent.
	time.Sleep(13*time.Second - time.Since(start))
	if _, err := os.Stat(file); err == nil {
		t.Fatalf("the escaped survivor ran to completion unsupervised: %s exists",
			file)
	}
}

// --- F3: exit 125/126/127 must be classified by profile and evidence ----

func TestR36ExitCodeClassificationIsHonest(t *testing.T) {
	c := newCampaign(t, "r36")
	mk := func(profile, stdout string, exit int) validation.Value {
		t.Helper()
		rec, err := RegisterExec(c, RegisterOpts{Profile: profile,
			Command: "x", ReportedBy: "harness", ExitStatus: exit,
			StdoutText: stdout})
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	host := ClassifyFailure(mk("host-readonly", "", 127))
	if strings.Contains(strAt(host, "note"), "docker itself failed") {
		t.Fatalf("host 127 note claims docker ran the command: %q",
			strAt(host, "note"))
	}
	if !strings.Contains(strings.ToLower(strAt(host, "note")), "not find") {
		t.Fatalf("host 127 note must name the missing command: %q",
			strAt(host, "note"))
	}
	ran := ClassifyFailure(mk("docker-networkless", "PWD-OUTPUT\n", 127))
	if !strings.Contains(strAt(ran, "note"), "RAN inside the container") {
		t.Fatalf("container 127 with captured output must say the command "+
			"ran: %q", strAt(ran, "note"))
	}
	dockerItself := ClassifyFailure(mk("docker-networkless", "", 125))
	if !strings.Contains(strAt(dockerItself, "note"), "docker itself failed") {
		t.Fatalf("container 125 must name docker itself: %q",
			strAt(dockerItself, "note"))
	}
	inconclusive := ClassifyFailure(mk("docker-networkless", "", 127))
	if !strings.Contains(strings.ToLower(strAt(inconclusive, "note")),
		"inconclusive") {
		t.Fatalf("container 127 with no output must be inconclusive: %q",
			strAt(inconclusive, "note"))
	}
}

// --- F4: the record must name the resolved workdir and never emit an
// empty (fabricated) digest ----------------------------------------------

func TestR36WorkdirResolvedAndNoFabricatedHash(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "hello.txt"), []byte("hi"),
		0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "wdlink")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	withDaemon(t, false)
	c := newCampaign(t, "r36")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	withProc(t, func(_ []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		return ProcResult{ReturnCode: 0}, nil
	})
	wd := link
	rec, err := sb.Run("pwd", RunOpts{Workdir: &wd, Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "exec_record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	resolved, ok := m["workdir_resolved"]
	if !ok {
		t.Fatalf("record has no workdir_resolved key (the record cannot say "+
			"where the command really ran): %s", raw)
	}
	if resolved != real {
		t.Fatalf("workdir_resolved = %v, want the resolved target %s", resolved,
			real)
	}
	hashes, ok := m["input_hashes"].(map[string]any)
	if !ok {
		t.Fatalf("input_hashes missing: %s", raw)
	}
	for k, v := range hashes {
		if v == "" {
			t.Fatalf("input_hashes[%q] is an EMPTY digest — a fabrication", k)
		}
		if k == "." {
			t.Fatalf("input_hashes contains the symlink-root '.' entry: %v",
				hashes)
		}
	}
	if _, ok := hashes["hello.txt"]; !ok {
		t.Fatalf("input_hashes missing hello.txt: %v", hashes)
	}
	sum := sha256.Sum256([]byte("hi"))
	if hashes["hello.txt"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("input_hashes[hello.txt] = %v, want %s", hashes["hello.txt"],
			hex.EncodeToString(sum[:]))
	}
}

// --- F5: host-readonly must not label the run `readonly` ----------------

func TestR36HostReadonlyFilesystemLabelIsHonest(t *testing.T) {
	withDaemon(t, false)
	c := newCampaign(t, "r36")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	withProc(t, func(_ []string, _ string, _ []string,
		_ time.Duration) (ProcResult, error) {
		return ProcResult{ReturnCode: 0}, nil
	})
	rec, err := sb.Run("echo hi", RunOpts{Timeout: 5})
	if err != nil {
		t.Fatal(err)
	}
	fs := strAt(objAt(rec, "environment"), "filesystem")
	if fs == "readonly" {
		t.Fatalf("host-readonly record claims filesystem %q while the run "+
			"writes the host filesystem unconfined", fs)
	}
	if !strings.Contains(fs, "host") {
		t.Fatalf("filesystem label %q must name the real mechanism (host, "+
			"unconfined, tripwires only)", fs)
	}
}

// --- F6: the exec path must cap captured output and account for it ------

func TestR36OutputCaptureCapAndAccounting(t *testing.T) {
	c := newCampaign(t, "r36")
	sb, err := NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("head -c 30000000 /dev/zero | tr '\\0' 'x'",
		RunOpts{Timeout: 60})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.ExecsDir,
		objStr(rec, "exec_id"), "exec_record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	oc, ok := m["output_capture"].(map[string]any)
	if !ok {
		t.Fatalf("record has no output_capture (no cap, no accounting): %s",
			raw)
	}
	if oc["stdout_truncated"] != true {
		t.Fatalf("stdout_truncated = %v, want true (a truncated capture must "+
			"be visible)", oc["stdout_truncated"])
	}
	total, ok := oc["stdout_total_bytes"].(float64)
	if !ok || total < 30000000 {
		t.Fatalf("stdout_total_bytes = %v, want the true count >= 30000000",
			oc["stdout_total_bytes"])
	}
	stdoutPath := objStr(rec, "stdout_path")
	st, err := os.Stat(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 10<<20+512 {
		t.Fatalf("stdout.log kept %d bytes — above the 10MiB cap", st.Size())
	}
	data, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "TRUNCATED") {
		t.Fatalf("stdout.log lacks the truncation marker — a consumer could " +
			"mistake it for a complete capture")
	}
	hashes := m["artifact_hashes"].(map[string]any)
	sum := sha256.Sum256(data)
	if hashes["stdout.log"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("artifact_hashes[stdout.log] = %v, want the digest of the "+
			"kept bytes %s", hashes["stdout.log"], hex.EncodeToString(sum[:]))
	}
	_ = fmt.Sprint()
}
