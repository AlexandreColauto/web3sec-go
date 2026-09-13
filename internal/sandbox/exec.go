// exec.go: the sandbox ledger — Sandbox.run, Sandbox.preview, register_exec,
// load_exec, all_execs (webv2.sandbox).
//
// Every execution is recorded: policy verdict, environment, hashes, captured
// output. Evidence minted elsewhere MUST reference the exec_id's profile.
package sandbox

import (
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

// ProcResult is one finished subprocess (Python's CompletedProcess).
type ProcResult struct {
	ReturnCode int
	Stdout     string
	Stderr     string
}

// runFunc executes a subprocess. dir is the working directory ("" = inherit),
// env is the FULL environment (nil = inherit), and a timeout surfaces as
// errTimeout with whatever output was captured. A package var so tests can
// intercept docker (Python monkeypatches sandbox.subprocess.run).
type runFunc func(argv []string, dir string, env []string,
	timeout time.Duration) (ProcResult, error)

// errTimeout is subprocess.TimeoutExpired.
var errTimeout = fmt.Errorf("timed out")

var runProc runFunc = realRunProc

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
	var out, errB strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errB
	if err := cmd.Start(); err != nil {
		return ProcResult{Stdout: out.String(), Stderr: errB.String()}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return ProcResult{ReturnCode: exitCode(err), Stdout: out.String(),
			Stderr: errB.String()}, nil
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-done
		return ProcResult{ReturnCode: -1, Stdout: out.String(),
			Stderr: errB.String()}, errTimeout
	}
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
	}

	outDir := filepath.Join(s.Campaign.ExecsDir, execID)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return validation.VNull(), err
	}
	stdoutPath := filepath.Join(outDir, "stdout.log")
	stderrPath := filepath.Join(outDir, "stderr.log")

	record := s.record(execID, command, opts, verdict, container, started,
		stdoutPath, stderrPath)
	path := filepath.Join(outDir, "exec_record.json")
	if err := validation.WriteJson(path, record, "sandbox_execution"); err != nil {
		return validation.VNull(), err
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
			return validation.VNull(), err
		}
		ref := execID
		data := validation.VObj(validation.KV{K: "violations",
			V: objAt(verdict, "violations")})
		if _, err := s.Campaign.Log("sandbox.refused", &ref, &data); err != nil {
			return validation.VNull(), err
		}
		return validation.VNull(), &RefusedError{Message: fmt.Sprintf(
			"command refused by sandbox policy: %s",
			pyListRepr(violations))}
	}

	exitStatus, stdout, stderr := s.execute(containerArgv, command, opts)
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		return validation.VNull(), err
	}
	if err := os.WriteFile(stderrPath, []byte(stderr), 0o644); err != nil {
		return validation.VNull(), err
	}
	hashes := validation.VObj(
		validation.KV{K: "stdout.log", V: validation.VStr(shaFile(stdoutPath))},
		validation.KV{K: "stderr.log", V: validation.VStr(shaFile(stderrPath))},
	)
	record = setKey(record, "finished_at", validation.VStr(nowIso()))
	record = setKey(record, "exit_status", validation.VInt(int64(exitStatus)))
	record = setKey(record, "artifact_hashes", hashes)
	if err := validation.WriteJson(path, record, "sandbox_execution"); err != nil {
		return validation.VNull(), err
	}
	ref := execID
	data := validation.VObj(
		validation.KV{K: "profile", V: validation.VStr(s.Profile)},
		validation.KV{K: "exit", V: validation.VInt(int64(exitStatus))},
		validation.KV{K: "finding", V: optStrValue(opts.FindingID)},
	)
	if _, err := s.Campaign.Log("sandbox.exec", &ref, &data); err != nil {
		return validation.VNull(), err
	}
	return record, nil
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
	if opts.Workdir != nil {
		workdir = validation.VStr(*opts.Workdir)
	}
	return validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(s.Campaign.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr(s.Profile)},
		validation.KV{K: "finding_id", V: optStrValue(opts.FindingID)},
		validation.KV{K: "artifact_id", V: optStrValue(opts.ArtifactID)},
		validation.KV{K: "command", V: validation.VStr(command)},
		validation.KV{K: "workdir", V: workdir},
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

// execute runs the container argv or the host shell command.
func (s *Sandbox) execute(containerArgv []string, command string,
	opts RunOpts) (int, string, string) {
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
		stderr := res.Stderr
		if stderr != "" && !strings.HasSuffix(stderr, "\n") {
			stderr += "\n"
		}
		return -1, res.Stdout, stderr +
			fmt.Sprintf("sandbox: timed out after %gs and was killed\n",
				timeout.Seconds())
	}
	if err != nil {
		// The process never ran — a missing workdir, no docker on PATH, an
		// exec failure. res.ReturnCode is the zero value on that path, so
		// returning it recorded a successful execution (exit_status 0) for
		// something that never happened. Report -1 and put the reason in
		// stderr so the exec record explains itself instead of looking like
		// a clean run of a command that produced no output.
		stderr := res.Stderr
		if stderr != "" && !strings.HasSuffix(stderr, "\n") {
			stderr += "\n"
		}
		return -1, res.Stdout, stderr + "sandbox: " + err.Error() + "\n"
	}
	return res.ReturnCode, res.Stdout, res.Stderr
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
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return validation.VNull(), err
	}
	stdoutPath := filepath.Join(outDir, "stdout.log")
	stderrPath := filepath.Join(outDir, "stderr.log")
	if err := os.WriteFile(stdoutPath, []byte(opts.StdoutText), 0o644); err != nil {
		return validation.VNull(), err
	}
	if err := os.WriteFile(stderrPath, []byte(opts.StderrText), 0o644); err != nil {
		return validation.VNull(), err
	}
	started, finished := nowIso(), nowIso()
	if opts.StartedAt != nil {
		started = *opts.StartedAt
	}
	if opts.FinishedAt != nil {
		finished = *opts.FinishedAt
	}
	var workdir validation.Value = validation.VNull()
	if opts.Workdir != nil {
		workdir = validation.VStr(*opts.Workdir)
	}
	record := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr(opts.Profile)},
		validation.KV{K: "finding_id", V: optStrValue(opts.FindingID)},
		validation.KV{K: "artifact_id", V: optStrValue(opts.ArtifactID)},
		validation.KV{K: "command", V: validation.VStr(opts.Command)},
		validation.KV{K: "workdir", V: workdir},
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
		return validation.VNull(), err
	}
	ref := execID
	data := validation.VObj(
		validation.KV{K: "profile", V: validation.VStr(opts.Profile)},
		validation.KV{K: "exit", V: validation.VInt(int64(opts.ExitStatus))},
		validation.KV{K: "reported_by", V: validation.VStr(opts.ReportedBy)},
		validation.KV{K: "finding", V: optStrValue(opts.FindingID)},
	)
	if _, err := c.Log("sandbox.exec.registered", &ref, &data); err != nil {
		return validation.VNull(), err
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
			V: validation.VStr(profileFilesystem[profile])},
	)
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
	fh, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashDir is _hash_dir: relative path -> sha256 for every file under d,
// in sorted relative-path order ([] when d is nil or absent).
func hashDir(d *string) validation.Value {
	if d == nil {
		return validation.VObj()
	}
	fi, err := os.Stat(*d)
	if err != nil || !fi.IsDir() {
		return validation.VObj()
	}
	var rels []string
	_ = filepath.WalkDir(*d, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(*d, p)
		if relErr == nil {
			rels = append(rels, rel)
		}
		return nil
	})
	sort.Strings(rels)
	o := make([]validation.KV, 0, len(rels))
	for _, rel := range rels {
		o = append(o, validation.KV{K: rel,
			V: validation.VStr(shaFile(filepath.Join(*d, rel)))})
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
		"halmos", "minicertora", "python3", "docker"} {
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
		out = append(out, validation.KV{K: tool,
			V: validation.VStr(pyFirstLine80(text))})
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
