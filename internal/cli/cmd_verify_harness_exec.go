package cli

// cmd_verify_harness_exec: exec-record readers — the record itself, its
// captured stdout, the T17 scaffold bytes, and the invocation-bound and
// timeout bits (moved verbatim from cmd_verify_harness.go).

import (
	"errors"
	"path/filepath"
	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessExecRecord loads execs/<execID>/exec_record.json (state.AllExecs,
// the reader cmd_execs uses) and reports the exec dir for relative
// stdout_path resolution.
func harnessExecRecord(c *state.Campaign, execID string) (validation.Value,
	string, error) {
	execs, err := state.AllExecs(c)
	if err != nil {
		return validation.VNull(), "", err
	}
	for _, e := range execs {
		if validation.ObjStr(e, "exec_id") == execID {
			return e, filepath.Join(c.ExecsDir, execID), nil
		}
	}
	return validation.VNull(), "", t14ExitErr(2,
		"verify: no exec %s in this campaign's exec ledger\n",
		validation.PyReprStr(execID))
}

// harnessExecStdout reads the run's captured stdout through the ONE reader
// the audit uses too (harness.ReadExecStdout — the r13 candidate order, the
// 1MB cap and the truncation semantics live there; r29b F2), and keeps this
// command's own refusal text for the two failure shapes it distinguishes:
// an empty record field means nothing was captured, an open failure says
// unreadable with the errno (r13).
//
// r13: a record written under `--root .` stores a CWD-relative stdout_path;
// joining it back against execDir double-nests the path and a
// plainly-present capture was reported as "no captured stdout to map". The
// canonical location — <execDir>/stdout.log — is the audit's law (execs.go
// derives it the same way); the reader prefers an ABSOLUTE stored path and
// falls back to the canonical one, exactly as this command always has.
func harnessExecStdout(execDir string, rec validation.Value) ([]byte, error) {
	raw, err := harness.ReadExecStdout(execDir, rec)
	if err == nil {
		return raw, nil
	}
	if errors.Is(err, harness.ErrNoCapturedStdout) {
		return nil, t14ExitErr(2,
			"verify: exec %s has no captured stdout to map\n",
			validation.PyReprStr(validation.ObjStr(rec, "exec_id")))
	}
	var ue *harness.StdoutUnreadableError
	if errors.As(err, &ue) {
		return nil, t14ExitErr(2,
			"verify: exec %s stdout file unreadable (%v)\n",
			validation.PyReprStr(validation.ObjStr(rec, "exec_id")), ue.Err)
	}
	return nil, err
}

// harnessScaffoldBytes loads the T17 scaffold artifact bytes: the latest
// harness_scaffold event for HARNESS-<INV>-<kind> names the registered
// artifact as its ref; the bytes come back through the artifacts API.
func harnessScaffoldBytes(c *state.Campaign, invID string,
	kind harness.Kind) ([]byte, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	want := "HARNESS-" + invID + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = validation.ObjStr(ev, "ref")
	}
	if ref == "" {
		return nil, t14ExitErr(2, "verify: no harness scaffold for %s "+
			"(scaffold it first with verify --scaffold %s --invariant %s)\n",
			validation.PyReprStr(invID), string(kind),
			validation.PyReprStr(invID))
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: harness scaffold artifact %s is not registered\n",
			validation.PyReprStr(ref))
	}
	// r29b F3(c): the read itself is harness.ArtifactFileBytes — the row's
	// recorded path joined against the campaign root and read raw (no sha
	// re-check: the bind does not make one). Section 11's unbound arm reads
	// the same file the same way, so the bytes the bind Validated and the
	// bytes the audit Validates cannot be two different artifacts.
	raw, err := harness.ArtifactFileBytes(c.Root, validation.ObjStr(art, "path"))
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: harness scaffold artifact %s has no readable file\n",
			validation.PyReprStr(ref))
	}
	return raw, nil
}

// harnessTimedOut is the MapRun timedOut bit: the sandbox records exit
// -1 both when the timeout kills the run and when the process never
// started, and a signal death (128+N, the shell's convention) means the
// process was killed rather than completed. Either way the run did not
// complete, so its bytes map to inconclusive, never to a rung — a
// "killed by signal" status is exactly as much a non-result as -1.
//
// r28b F2: the reading itself lives in package harness
// (harness.RecordTimedOut over harness.RecordExitStatus) so the bind and
// section 11 can never disagree about an absent exit_status — the audit
// arm read `es := 0` while this bit read "not timed out", and the two
// together blessed a record that named no exit at all.
func harnessTimedOut(rec validation.Value) bool {
	return harness.RecordTimedOut(rec)
}

// harnessCommand is the exec record's command string ("" when absent).
func harnessCommand(rec validation.Value) string {
	return validation.ObjStr(rec, "command")
}

// invocationBound parses the invocation bound out of an exec command —
// harness.InvocationBoundKind owns the parse, and the KIND is part of it.
//
// r32 F1/F2: this wrapper used to take the kind and throw it away
// (`_ = kind`), so ONE Python-flavoured reading was applied to three tools
// with three command-line languages: `forge test --fuzz-runs 4_000` (real
// forge: "error: invalid value '4_000' … invalid digit found in string")
// read as 4000, a repeated --fuzz-runs read last-wins although clap
// refuses it, and a LONE foreign bound flag (`forge test --loop 3`) was
// bound as if forge had a --loop. Carrying the kind makes the value
// semantics the owning tool's and floors a foreign bound flag as the
// invocation the tool would refuse.
//
// The production call site reads the record through
// harness.RecordInvocationBound instead of composing this with
// harnessCommand, because the record's command field must be read with its
// SHAPE (r32 F8: a `command` that is an ARRAY or a NUMBER is a stated
// invocation, not an absent one). This wrapper stays for callers that hold
// a command string (and for the S2 regression table), and it is the
// string-level half of exactly that reader.
func invocationBound(command string, kind harness.Kind) int {
	return harness.InvocationBoundKind(kind, command)
}
