// exec.go: the sandbox ledger — Sandbox.run, Sandbox.preview, register_exec,
// load_exec, all_execs (webv2.sandbox).
//
// Every execution is recorded: policy verdict, environment, hashes, captured
// output. Evidence minted elsewhere MUST reference the exec_id's profile.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

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
	// Expect is the PRE-RUN declaration expected_outcome ("pass" or
	// "fail"; "" leaves the key off the record, which reads as pass).
	// ExpectFailure is the declared failure signature, required under
	// "fail" and forbidden under "pass" — both land in the record's FIRST
	// write, before the payload executes (v16 §5.3 route 2).
	Expect        string
	ExpectFailure string
}

// Run is Sandbox.run: execute with the profile's constraints, capture
// stdout/stderr/hashes/exit status, and record a sandbox_execution record.
func (s *Sandbox) Run(command string, opts RunOpts) (validation.Value, error) {
	f := &runFlow{s: s, command: command, opts: opts,
		execID: "EXEC-" + shortID(10), container: validation.VNull()}
	if err := f.runPolicyCheck(); err != nil {
		return validation.VNull(), err
	}
	if err := f.runBuildContainerArgv(); err != nil {
		return validation.VNull(), err
	}
	if err := f.runOpenExecDir(); err != nil {
		return validation.VNull(), err
	}
	if err := f.runWriteInitialRecord(); err != nil {
		return validation.VNull(), err
	}
	if err := f.runRefusalPath(); err != nil {
		return validation.VNull(), err
	}
	if err := f.runExecuteAndLog(); err != nil {
		return validation.VNull(), err
	}
	return f.record, nil
}

// runFlow carries the shared state of one Sandbox.run across the runXxx
// helpers below — the former Run locals, verbatim, in the former order.
type runFlow struct {
	s             *Sandbox
	command       string
	opts          RunOpts
	execID        string
	verdict       validation.Value
	started       string
	containerArgv []string
	container     validation.Value
	outDir        string
	txn           *execDirTxn
	stdoutPath    string
	stderrPath    string
	path          string
	record        validation.Value
}

// runPolicyCheck is Run's opening gate: the policy verdict, then the
// started timestamp.
func (f *runFlow) runPolicyCheck() error {
	verdict, err := PolicyCheck(f.command, f.s.Profile)
	if err != nil {
		return err
	}
	f.verdict = verdict
	f.started = state.NowIso()
	return nil
}

// runBuildContainerArgv is Run's container arm: a non-container profile
// leaves containerArgv nil and the container value null.
func (f *runFlow) runBuildContainerArgv() error {
	if HostProfile(f.s.Profile) {
		return nil
	}
	argv, meta, err := BuildContainerArgv(f.s.Profile, f.command, f.opts.Workdir,
		f.opts.Env)
	if err != nil {
		return err
	}
	f.containerArgv, f.container = argv, meta.Container
	// r36 F1: pin a deterministic container name so the killing side
	// (timeout or abnormal client death) can stop the payload
	// container by name instead of killing only the docker client.
	// (Preview's argv keeps the reference shape; the name is a
	// per-exec runtime detail.)
	f.containerArgv = withContainerName(f.containerArgv,
		"webv2-exec-"+strings.ToLower(f.execID))
	return nil
}

// runOpenExecDir creates the per-exec directory transaction and fixes the
// artifact paths (Run's former outDir/txn block).
func (f *runFlow) runOpenExecDir() error {
	f.outDir = filepath.Join(f.s.Campaign.ExecsDir, f.execID)
	// r39 F2: the exec dir and everything in it is written BEFORE the
	// ledger event exists. A refused c.Log must therefore unwind — see the
	// execDirTxn comment for why the payload cannot be deferred.
	txn, err := beginExecDir(f.outDir)
	if err != nil {
		return err
	}
	f.txn = txn
	f.stdoutPath = filepath.Join(f.outDir, "stdout.log")
	f.stderrPath = filepath.Join(f.outDir, "stderr.log")
	f.path = filepath.Join(f.outDir, "exec_record.json")
	f.txn.note(f.stdoutPath, f.stderrPath, f.path)
	return nil
}

// runWriteInitialRecord builds and writes the sandbox_execution record
// with its pre-execution fields.
func (f *runFlow) runWriteInitialRecord() error {
	f.record = f.s.record(f.execID, f.command, f.opts, f.verdict, f.container,
		f.started, f.stdoutPath, f.stderrPath)
	f.record = applyExecExpectation(f.record, f.opts)
	if err := validation.WriteJson(f.path, f.record, "sandbox_execution"); err != nil {
		return f.txn.fail(err)
	}
	return nil
}

// runRefusalPath handles a not-allowed verdict: it extends the record's
// policy_verdict, rewrites it, logs the refusal and returns the
// RefusedError. nil means the command is allowed and Run proceeds.
func (f *runFlow) runRefusalPath() error {
	if truthy(f.verdict, "allowed") {
		return nil
	}
	violations := validation.ObjAt(f.verdict, "violations")
	extended := append(append([]validation.Value(nil), violations.A...),
		validation.VStr("execution-refused"))
	f.record = setKey(f.record, "policy_verdict", validation.VObj(
		validation.KV{K: "allowed", V: validation.ObjAt(f.verdict, "allowed")},
		validation.KV{K: "violations", V: validation.VArr(extended...)},
		validation.KV{K: "checked_rules", V: validation.ObjAt(f.verdict, "checked_rules")},
	))
	f.record = setKey(f.record, "finished_at", validation.VStr(state.NowIso()))
	if err := validation.WriteJson(f.path, f.record, "sandbox_execution"); err != nil {
		return f.txn.fail(err)
	}
	ref := f.execID
	data := validation.VObj(validation.KV{K: "violations",
		V: validation.ObjAt(f.verdict, "violations")})
	if _, err := f.s.Campaign.Log("sandbox.refused", &ref, &data); err != nil {
		// The refused act (a policy refusal) must not leave debris
		// behind either, and it must not hide what already happened:
		// the command did NOT run, and the refusal itself is not in
		// the ledger now — the operator has to know both (r39 F2).
		return f.txn.fail(fmt.Errorf(
			"the command was REFUSED by sandbox policy (%s) and did NOT "+
				"run, but the refusal event was refused as well — no "+
				"record was kept and the exec dir %s was removed, so "+
				"nothing about this refusal is in the ledger (ledger "+
				"refusal: %v)", pyListRepr(violations), f.outDir, err))
	}
	return &RefusedError{Message: fmt.Sprintf(
		"command refused by sandbox policy: %s",
		pyListRepr(violations))}
}

// runExecuteAndLog runs the payload, writes the captured logs, finalizes
// the record and anchors the sandbox.exec ledger event.
func (f *runFlow) runExecuteAndLog() error {
	exitStatus, stdout, stderr, caps := f.s.execute(f.containerArgv, f.command,
		f.opts)
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
	if err := os.WriteFile(f.stdoutPath, stdoutBytes, 0o644); err != nil {
		return f.txn.fail(err)
	}
	if err := os.WriteFile(f.stderrPath, stderrBytes, 0o644); err != nil {
		return f.txn.fail(err)
	}
	hashes := validation.VObj(
		validation.KV{K: "stdout.log", V: validation.VStr(shaFile(f.stdoutPath))},
		validation.KV{K: "stderr.log", V: validation.VStr(shaFile(f.stderrPath))},
	)
	f.record = setKey(f.record, "finished_at", validation.VStr(state.NowIso()))
	f.record = setKey(f.record, "exit_status", validation.VInt(int64(exitStatus)))
	f.record = setKey(f.record, "artifact_hashes", hashes)
	f.record = setKey(f.record, "output_capture", outputCaptureValue(caps))
	if err := validation.WriteJson(f.path, f.record, "sandbox_execution"); err != nil {
		return f.txn.fail(err)
	}
	ref := f.execID
	data := validation.VObj(
		validation.KV{K: "profile", V: validation.VStr(f.s.Profile)},
		validation.KV{K: "exit", V: validation.VInt(int64(exitStatus))},
		validation.KV{K: "finding", V: optStrValue(f.opts.FindingID)},
	)
	if _, err := f.s.Campaign.Log("sandbox.exec", &ref, &data); err != nil {
		// r39 F2: the payload has ALREADY RUN (execute() is above), so the
		// honest answer is not "nothing happened". Restore the pre-write
		// state — the exec dir goes away, so `webv2 execs` can never list
		// a run the ledger does not hold, the projection audit has no
		// residue to be green over, and a retry adds no second corpse —
		// and say in the returned error exactly which half happened: the
		// command EXECUTED, its record was NOT KEPT.
		return f.txn.fail(fmt.Errorf(
			"the command EXECUTED (exit status %d, %d stdout / %d stderr "+
				"byte(s) captured) but its record was NOT KEPT: the ledger "+
				"refused the sandbox.exec event and the exec dir %s was "+
				"removed — nothing about this run is in the ledger, and "+
				"re-running will execute the command AGAIN (ledger refusal: "+
				"%v)", exitStatus, len(stdoutBytes), len(stderrBytes),
			f.outDir, err))
	}
	return nil
}
