// postpatch.go: Task 8 (G11) — the post-patch verdict.
//
// `verify --post-patch FINDING --exec EXEC` re-runs the finding's original
// reproduction after a patch and compares exit-vectors (exit status +
// stdout hash) between the NEW exec and the ORIGINAL repro exec the
// finding's minted evidence cites (MintReproEvidence wrote the exec id as
// the evidence item's artifact_id; the recorded stdout hash lives in the
// exec record's artifact_hashes["stdout.log"], the same ledger hash G15's
// rerun comparison uses).
//
// Verdict law (exact):
//   - no minted repro evidence on the finding ⇒ indeterminate,
//     "no baseline repro exec on the finding";
//   - still_reproducible: new exit == 0 AND original exit == 0 AND stdout
//     hashes equal;
//   - fixed: original exit == 0 AND new exit != 0;
//   - indeterminate: everything else (new exit 0 with different stdout;
//     original non-zero; timeout markers; missing stdout file).
//
// Fail-open: the verdict never changes finding status and never blocks
// anything — it is metadata (verification.patch_regression) plus a report
// line. Promotion rides triage reading the record, same law as the harness
// rungs. PostPatchVerdict itself is pure-ish: it reads the campaign store
// and exec dirs and writes nothing.
package reproduction

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// Post-patch verdicts.
const (
	PostPatchStillReproducible = "still_reproducible"
	PostPatchFixed             = "fixed"
	PostPatchIndeterminate     = "indeterminate"
)

// NoBaselineDetail is the indeterminate detail when the finding carries no
// minted repro evidence to regress against.
const NoBaselineDetail = "no baseline repro exec on the finding"

// UnknownIDError is an unknown --post-patch / --exec id. The CLI maps it
// to exit 2 naming the id (the PyReprStr style the harness path uses).
type UnknownIDError struct {
	Kind string // "finding" or "exec"
	ID   string
}

func (e *UnknownIDError) Error() string {
	return fmt.Sprintf("no %s %s", e.Kind, e.ID)
}

// BaselineReproExec is the finding's original repro exec: the first
// evidence item whose artifact_id names an EXEC record. False when the
// finding carries no minted repro evidence.
func BaselineReproExec(f validation.Value) (string, bool) {
	for _, e := range validation.ObjAt(f, "evidence").A {
		if aid := validation.ObjStr(e, "artifact_id"); strings.HasPrefix(aid,
			"EXEC-") {
			return aid, true
		}
	}
	return "", false
}

// PostPatchVerdict compares the NEW post-patch exec against the finding's
// baseline repro exec and returns the verdict plus a one-line detail.
// Unknown finding/new-exec ids are *UnknownIDError; everything else that
// cannot be compared resolves to indeterminate (fail-open), never to an
// error.
func PostPatchVerdict(c *state.Campaign, findingID,
	newExecID string) (verdict, detail string, err error) {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return "", "", &UnknownIDError{Kind: "finding", ID: findingID}
	}
	baseExecID, ok := BaselineReproExec(f)
	if !ok {
		return PostPatchIndeterminate, NoBaselineDetail, nil
	}
	newRec, err := sandbox.LoadExec(c, newExecID)
	if err != nil {
		if isMissingExec(c, newExecID) {
			return "", "", &UnknownIDError{Kind: "exec", ID: newExecID}
		}
		return "", "", err
	}
	baseRec, err := sandbox.LoadExec(c, baseExecID)
	if err != nil {
		return PostPatchIndeterminate, fmt.Sprintf(
			"baseline exec %s has no exec record on disk", baseExecID), nil
	}
	newExit, ok := execExit(newRec)
	if !ok {
		return PostPatchIndeterminate, fmt.Sprintf(
			"exec %s has no recorded exit status", newExecID), nil
	}
	baseExit, ok := execExit(baseRec)
	if !ok {
		return PostPatchIndeterminate, fmt.Sprintf(
			"exec %s has no recorded exit status", baseExecID), nil
	}
	// Timeout markers first: exit -1 is the sandbox's "the run did not
	// complete" (timeout or never-started) — never a fix signal.
	if newExit == -1 || baseExit == -1 {
		timed := newExecID
		if newExit != -1 {
			timed = baseExecID
		}
		return PostPatchIndeterminate, fmt.Sprintf(
			"timeout marker on %s (exit -1) — the run did not complete",
			timed), nil
	}
	newRaw, err := postPatchStdout(c, newExecID, newRec)
	if err != nil {
		return PostPatchIndeterminate, err.Error(), nil
	}
	baseRaw, err := postPatchStdout(c, baseExecID, baseRec)
	if err != nil {
		return PostPatchIndeterminate, err.Error(), nil
	}
	if baseExit != 0 {
		return PostPatchIndeterminate, fmt.Sprintf(
			"baseline %s exits %d — not a successful reproduction",
			baseExecID, baseExit), nil
	}
	if newExit != 0 {
		return PostPatchFixed, fmt.Sprintf(
			"baseline %s exits 0; post-patch %s exits %d",
			baseExecID, newExecID, newExit), nil
	}
	if execStdoutHash(newRec, newRaw) != execStdoutHash(baseRec, baseRaw) {
		return PostPatchIndeterminate, fmt.Sprintf(
			"post-patch %s exits 0 but stdout differs from baseline %s",
			newExecID, baseExecID), nil
	}
	return PostPatchStillReproducible, fmt.Sprintf(
		"post-patch %s exits 0 with stdout matching baseline %s",
		newExecID, baseExecID), nil
}

// PatchRegressionRecord builds the verification.patch_regression object in
// the brief's key order (verdict, exec, base_exec) plus the detail Task 9's
// scope rows append to and the advisory snapshot pin (null when the flag
// was absent).
func PatchRegressionRecord(verdict, exec, baseExec, detail,
	snapshot string) validation.Value {
	var snap validation.Value = validation.VNull()
	if snapshot != "" {
		snap = validation.VStr(snapshot)
	}
	return validation.VObj(
		validation.KV{K: "verdict", V: validation.VStr(verdict)},
		validation.KV{K: "exec", V: validation.VStr(exec)},
		validation.KV{K: "base_exec", V: validation.VStr(baseExec)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
		validation.KV{K: "snapshot", V: snap},
	)
}

// execExit is the record's exit status, or false when absent/non-integer.
func execExit(rec validation.Value) (int, bool) {
	if v := validation.ObjAt(rec, "exit_status"); v.Kind == validation.Int &&
		v.Big == "" {
		return int(v.I), true
	}
	return 0, false
}

// postPatchStdout reads the record's stdout file, resolving a relative
// stdout_path against the exec dir (the same resolution the harness path
// uses). A missing file is an indeterminate detail, not an error.
func postPatchStdout(c *state.Campaign, execID string,
	rec validation.Value) ([]byte, error) {
	p := validation.ObjStr(rec, "stdout_path")
	if p == "" {
		return nil, fmt.Errorf("missing stdout file for %s", execID)
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(c.ExecsDir, execID, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("missing stdout file for %s", execID)
	}
	return raw, nil
}

// isMissingExec reports whether the exec record file is absent (as opposed
// to a malformed record, which is a genuine error).
func isMissingExec(c *state.Campaign, execID string) bool {
	_, err := os.Stat(filepath.Join(c.ExecsDir, execID, "exec_record.json"))
	return os.IsNotExist(err)
}
