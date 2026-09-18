// The r18/r42 ladder snapshot class: capture BOTH files before a verb's first write and restore them together on refusal.
package maximization

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
)

// r18 P1-2: the LADDER class — StartLadder wrote the ladder doc and the
// finding's maximization block BEFORE logging; a refused Log left the
// projection rows standing, the event absent, and the retry path takes
// the idempotent early-return (finding already has ladder_id) so the
// missing ladder.started can NEVER be emitted — the r9 PinSnapshot
// permanent-burn shape reborn, with `verify` GREEN throughout. Same
// discipline, generalized: capture BOTH file bytes before the first
// write of a verb; restore them together when the ledger refuses.
//
// r42 P1: that snapshot used to collapse EVERY read error into "the file
// did not exist" and the restore honored the lie with os.Remove — so an
// existing-but-UNREADABLE finding was DELETED by the very unwind that
// exists to protect it. The message ('open ...: permission denied') never
// said the tool had done the deleting, the ladder was left pointing at a
// record that no longer existed, and verify/audit stayed GREEN over the
// loss. Three pre-call states, never two:
//
//	absent     — ReadFile said ENOENT: the restore removes what this verb
//	             may have created, and only that.
//	readable   — the exact pre-call bytes are in raw: the restore puts them
//	             back byte for byte.
//	unreadable — the file is there (or a read failure leaves its absence
//	             UNPROVEN) and its bytes are unknown: the restore must not
//	             touch it, and must SAY SO.
type ladderFileSnap struct {
	path       string
	raw        []byte
	had        bool  // ReadFile succeeded: raw holds the exact pre-call bytes
	unreadable bool  // present (or absence unproven) and NOT readable
	rerr       error // why the bytes are unknown, when unreadable
}

// prevFile is the ladder family's only reader. It returns the read error
// UNCOLLAPSED — os.IsNotExist(err) is the one "the file was absent"
// signal — and classifies the path into the three states above, the same
// three-state discipline findings.prevBytes and state.appendJsonlThenLog
// follow. A caller that sees unreadable must ABORT the verb BEFORE its
// first write; that abort is what keeps the r42 deletion unreachable.
func prevFile(path string) ladderFileSnap {
	raw, err := os.ReadFile(path)
	if err == nil {
		return ladderFileSnap{path: path, raw: raw, had: true}
	}
	if os.IsNotExist(err) {
		// Genuinely absent: the verb may create it, and the unwind may
		// remove what the verb created. Nothing to guess at.
		return ladderFileSnap{path: path}
	}
	// Not "absent": the file is there and unreadable, or a read failure
	// leaves its absence UNPROVEN (absence is inconclusive). Either way
	// its bytes are unknown, so no restore may conclude they were gone.
	_, serr := os.Stat(path)
	return ladderFileSnap{path: path, had: serr == nil, unreadable: true,
		rerr: err}
}

// ladderPair is the two files one ladder verb may touch, both captured
// before its first write.
type ladderPair struct {
	lad ladderFileSnap
	fnd ladderFileSnap
}

// snapshotLadderFiles is the ONE snapshot door of the ladder family: read
// BOTH files before the verb's first write and REFUSE the verb when either
// one exists but cannot be read. A verb that never starts writing has
// nothing to unwind, so the r42 deletion becomes unreachable — and the
// restore refuses the unreadable state on its own too (see restore).
func snapshotLadderFiles(c *state.Campaign, findingID string) (ladderPair, error) {
	lad := prevFile(ladderPath(c, findingID))
	if lad.unreadable {
		return ladderPair{}, ladderSnapshotRefusal("ladder", findingID, lad)
	}
	fnd := prevFile(findings.FindingPath(c, findingID))
	if fnd.unreadable {
		return ladderPair{}, ladderSnapshotRefusal("finding", findingID, fnd)
	}
	return ladderPair{lad: lad, fnd: fnd}, nil
}

// ladderSnapshotRefusal names the read failure, the file and the choice:
// the verb stops BEFORE any write, so nothing was changed and nothing
// needs unwinding. The retry after the file is readable is a real verb —
// not the "no finding in campaign" the old deletion answered with.
func ladderSnapshotRefusal(kind, findingID string, s ladderFileSnap) error {
	why := "is present but unreadable"
	if !s.had {
		why = "cannot be read and its absence cannot be proven"
	}
	return fmt.Errorf("cannot snapshot the %s %s before writing (%w): it %s — "+
		"refusing before any write, so its bytes are neither overwritten nor "+
		"removed; make it readable and retry", kind, findingID, s.rerr, why)
}

// restore puts this file back exactly as it was, or REPORTS that it could
// not — a failed restore is never swallowed again (restoreLadderPair used
// to return void while every other door in the tree names its failures).
func (s ladderFileSnap) restore() error {
	if s.unreadable {
		// The pre-call bytes were never readable: removing would be the
		// r42 bug (deleting a record we never saw), writing would invent
		// them. Leave the file ALONE and say so.
		return fmt.Errorf("the pre-call bytes were never readable (%v), so "+
			"%s could not be restored and was NOT touched", s.rerr,
			filepath.Base(s.path))
	}
	if !s.had {
		if rerr := os.Remove(s.path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	return os.WriteFile(s.path, s.raw, 0o644)
}

// restoreLadderPair undoes one verb's writes, file by file, and NAMES every
// file it could not put back (the same voice as findings.SaveThenLog,
// sandbox's execDirTxn.fail and the link/JSONL siblings). A silent failed
// restore is the half-land this law exists to prevent: state ahead of event
// is exactly what verify's projection hunt burns red over.
func restoreLadderPair(p ladderPair) error {
	var failed []string
	for _, s := range []ladderFileSnap{p.lad, p.fnd} {
		if rerr := s.restore(); rerr != nil {
			failed = append(failed, fmt.Sprintf("%s: %v",
				filepath.Base(s.path), rerr))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not restore %s", strings.Join(failed, "; "))
	}
	return nil
}

// unwindLadderPair restores the pair and returns the verb's refusal, naming
// BOTH failures when the restore itself failed — the same wording as
// findings.SaveThenLog's '(UNWIND ALSO FAILED: ...)'.
func unwindLadderPair(p ladderPair, refused error) error {
	if rerr := restoreLadderPair(p); rerr != nil {
		return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the ladder pair may "+
			"hold post-write bytes with no event; repair the named file(s) "+
			"by hand before continuing)", refused, rerr)
	}
	return refused
}
