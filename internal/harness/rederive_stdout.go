package harness

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"websec/internal/validation"
)

// StdoutCap is the 1MB read cap on an exec stdout capture — the bind's own
// constant, now the ONE cap both halves obey.
const StdoutCap = 1 << 20

// ErrNoCapturedStdout is the sentinel ReadExecStdout returns when the record
// names no stdout_path AND the canonical <execDir>/stdout.log is not there
// either: nothing was captured to map (the bind refuses it with exit 2).
var ErrNoCapturedStdout = errors.New("no captured stdout")

// StdoutUnreadableError carries the last candidate's open error, so the
// bind's own "stdout file unreadable (<errno>)" refusal keeps naming the
// errno it observed through the shared reader.
type StdoutUnreadableError struct{ Err error }

func (e *StdoutUnreadableError) Error() string { return e.Err.Error() }

// Unwrap exposes the os error for errors.Is/As users.
func (e *StdoutUnreadableError) Unwrap() error { return e.Err }

// ReadExecStdout is THE reader of a run's captured stdout — the bytes the
// bind maps and the bytes every audit re-derivation must map, so there is
// exactly one answer to "what did this run print?" (r29b F2).
//
// Before this home: the bind read through its own candidate list
// (harnessExecStdout: the record's stdout_path first when it is ABSOLUTE,
// then <execDir>/stdout.log, with the relative stdout_path last) and capped
// the read at 1MB, while all three audit sites called os.ReadFile on
// <execs>/<id>/stdout.log — uncapped. A 1,048,638-byte capture whose
// attributed PROVEN line came before byte 1,048,576 and whose DUPLICATE
// attributed line came after it therefore bound "proved-bounded (k=4)" and
// audited "inconclusive (duplicate verdict lines for rule)": two halves of
// one law reading two different files (or the same file twice at two
// different lengths). Same candidate order, same cap, same truncation
// semantics — one function.
//
// The truncated tail may cut a line in half; that is the bind's law too, and
// MapMinicertora's "output is not JSONL" floor is the honest reading of a
// capture that was bigger than the cap.
func ReadExecStdout(execDir string, rec validation.Value) ([]byte, error) {
	p := recordStr(rec, "stdout_path")
	candidates := []string{filepath.Join(execDir, "stdout.log")}
	if p != "" {
		if filepath.IsAbs(p) {
			candidates = []string{p, candidates[0]}
		} else {
			candidates = append(candidates, filepath.Join(execDir, p))
		}
	}
	var openErr error
	for _, cand := range candidates {
		fh, err := os.Open(cand)
		if err != nil {
			openErr = err
			continue
		}
		defer fh.Close()
		return io.ReadAll(io.LimitReader(fh, StdoutCap))
	}
	if p == "" {
		return nil, ErrNoCapturedStdout
	}
	return nil, &StdoutUnreadableError{Err: openErr}
}

// ArtifactFileBytes reads a registered artifact's FILE the way the bind's
// harnessScaffoldBytes reads a harness scaffold: the registry row's own
// path, made absolute against the campaign root when it is relative, read
// whole — and with NO sha re-check, because the bind makes none.
//
// r29b F3(c): the audit's evidence reader (section 11's
// harnessScaffoldArtifactBytes) goes through state.ArtifactBytes, which
// REFUSES a file whose bytes no longer hash to the row's pinned sha (the
// r25 F2 discipline for re-derivation). That is the right reader for the
// hash arm — but the bind's UNBOUND arm Validates the file it read from
// disk regardless, so an audit that only had the pinned reader saw "bytes
// unobtainable" over a file the bind would have judged, and blessed a
// drifted claim. This is that same file, read the same way.
func ArtifactFileBytes(root, path string) ([]byte, error) {
	p := path
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	return os.ReadFile(p)
}
