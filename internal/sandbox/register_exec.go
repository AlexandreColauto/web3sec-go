// register_exec.go: register_exec — the ledger entry for an execution that
// happened OUTSIDE this process (origin=externally-reported).
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"websec/internal/state"
	"websec/internal/validation"
)

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
	f := &registerExecFlow{c: c, opts: opts}
	if err := f.regExecValidate(); err != nil {
		return validation.VNull(), err
	}
	if err := f.regExecPrepare(); err != nil {
		return validation.VNull(), err
	}
	if err := f.regExecWriteRecord(); err != nil {
		return validation.VNull(), err
	}
	if err := f.regExecLog(); err != nil {
		return validation.VNull(), err
	}
	return f.record, nil
}

// registerExecFlow carries the shared state of one register_exec across
// the regExecXxx helpers below — the former RegisterExec locals, verbatim,
// in the former order.
type registerExecFlow struct {
	c          *state.Campaign
	opts       RegisterOpts
	execID     string
	outDir     string
	txn        *execDirTxn
	stdoutPath string
	stderrPath string
	started    string
	finished   string
	verdict    validation.Value
	record     validation.Value
}

// regExecValidate is RegisterExec's argument gate: known profile, a
// reported_by identity, and the policy verdict.
func (f *registerExecFlow) regExecValidate() error {
	if !inProfiles(f.opts.Profile) {
		return fmt.Errorf("unknown profile %s",
			validation.PyReprStr(f.opts.Profile))
	}
	if f.opts.ReportedBy == "" {
		return fmt.Errorf(
			"externally-reported executions need a reported_by identity")
	}
	verdict, err := PolicyCheck(f.opts.Command, f.opts.Profile)
	if err != nil {
		return err
	}
	f.verdict = verdict
	return nil
}

// regExecPrepare mints the exec id, opens the directory transaction and
// writes the captured stdout/stderr text into it.
func (f *registerExecFlow) regExecPrepare() error {
	f.execID = "EXEC-" + shortID(10)
	f.outDir = filepath.Join(f.c.ExecsDir, f.execID)
	txn, err := beginExecDir(f.outDir)
	if err != nil {
		return err
	}
	f.txn = txn
	f.stdoutPath = filepath.Join(f.outDir, "stdout.log")
	f.stderrPath = filepath.Join(f.outDir, "stderr.log")
	recordPath := filepath.Join(f.outDir, "exec_record.json")
	f.txn.note(f.stdoutPath, f.stderrPath, recordPath)
	if err := os.WriteFile(f.stdoutPath, []byte(f.opts.StdoutText), 0o644); err != nil {
		return f.txn.fail(err)
	}
	if err := os.WriteFile(f.stderrPath, []byte(f.opts.StderrText), 0o644); err != nil {
		return f.txn.fail(err)
	}
	f.started, f.finished = state.NowIso(), state.NowIso()
	if f.opts.StartedAt != nil {
		f.started = *f.opts.StartedAt
	}
	if f.opts.FinishedAt != nil {
		f.finished = *f.opts.FinishedAt
	}
	return nil
}

// regExecWriteRecord builds the sandbox_execution record in Python's key
// order and writes it into the exec dir.
func (f *registerExecFlow) regExecWriteRecord() error {
	var workdir validation.Value = validation.VNull()
	var workdirResolved validation.Value = validation.VNull()
	if f.opts.Workdir != nil {
		workdir = validation.VStr(*f.opts.Workdir)
		// r36 F4: additive resolved path (the operator's string is kept).
		workdirResolved = validation.VStr(resolvedPath(*f.opts.Workdir))
	}
	f.record = validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(f.execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(f.c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr(f.opts.Profile)},
		validation.KV{K: "finding_id", V: optStrValue(f.opts.FindingID)},
		validation.KV{K: "artifact_id", V: optStrValue(f.opts.ArtifactID)},
		validation.KV{K: "command", V: validation.VStr(f.opts.Command)},
		validation.KV{K: "workdir", V: workdir},
		validation.KV{K: "workdir_resolved", V: workdirResolved},
		validation.KV{K: "policy_verdict", V: f.verdict},
		validation.KV{K: "environment", V: environmentValue(
			validation.VObj(), nil, f.opts.Profile)},
		validation.KV{K: "container", V: validation.VNull()},
		validation.KV{K: "origin", V: validation.VStr("externally-reported")},
		validation.KV{K: "reported_by", V: validation.VStr(f.opts.ReportedBy)},
		validation.KV{K: "input_hashes", V: hashDir(f.opts.Workdir)},
		validation.KV{K: "started_at", V: validation.VStr(f.started)},
		validation.KV{K: "finished_at", V: validation.VStr(f.finished)},
		validation.KV{K: "exit_status", V: validation.VInt(int64(f.opts.ExitStatus))},
		validation.KV{K: "stdout_path", V: validation.VStr(f.stdoutPath)},
		validation.KV{K: "stderr_path", V: validation.VStr(f.stderrPath)},
		validation.KV{K: "artifact_hashes", V: validation.VObj(
			validation.KV{K: "stdout.log", V: validation.VStr(shaFile(f.stdoutPath))},
			validation.KV{K: "stderr.log", V: validation.VStr(shaFile(f.stderrPath))})},
	)
	if err := validation.WriteJson(filepath.Join(f.outDir, "exec_record.json"),
		f.record, "sandbox_execution"); err != nil {
		return f.txn.fail(err)
	}
	return nil
}

// regExecLog anchors the sandbox.exec.registered event; a refused log
// unwinds the exec dir.
func (f *registerExecFlow) regExecLog() error {
	ref := f.execID
	// v1.6: the same anchor as Run's sandbox.exec — the record is already on
	// disk (regExecWriteRecord), and anchoring only the Run path would leave
	// the same hand-edit open through this writer (exec_record_anchor.go).
	data := validation.VObj(append([]validation.KV{
		{K: "profile", V: validation.VStr(f.opts.Profile)},
		{K: "exit", V: validation.VInt(int64(f.opts.ExitStatus))},
		{K: "reported_by", V: validation.VStr(f.opts.ReportedBy)},
		{K: "finding", V: optStrValue(f.opts.FindingID)},
	}, ExecRecordAnchorKVs(f.record)...)...)
	if _, err := f.c.Log("sandbox.exec.registered", &ref, &data); err != nil {
		// r39 F2: same unwinding as Run. The execution happened OUTSIDE this
		// process (origin=externally-reported), so nothing here can undo it —
		// what must not survive is the registration the ledger refused: the
		// dir goes, and the error says the registration was not kept rather
		// than reporting a clean write.
		return f.txn.fail(fmt.Errorf(
			"the externally-reported execution by %s was NOT REGISTERED: the "+
				"ledger refused the sandbox.exec.registered event and the "+
				"exec dir %s was removed — no exec record exists, so the "+
				"reported execution cannot back any evidence (ledger "+
				"refusal: %v)", validation.PyReprStr(f.opts.ReportedBy), f.outDir,
			err))
	}
	return nil
}
