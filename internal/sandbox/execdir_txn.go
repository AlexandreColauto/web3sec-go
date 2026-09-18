// execdir_txn.go: the r39 F2 unwind-on-refusal transaction for a per-exec
// ledger directory.
package sandbox

import (
	"fmt"
	"os"
)

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
