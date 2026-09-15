package state

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/validation"
)

// AppendJsonlThenLog is the r36 UNWIND-ON-REFUSAL dance for a writer that
// pairs an append-only JSONL ROW with a c.Log event. It lives here (r38 P2-2)
// because the pairing is not one package's business: learning's
// learnings.jsonl / planner_hints.jsonl / benchmarks.jsonl, costs.jsonl and
// waivers.jsonl all write a row and then anchor it in the ledger, and a copy
// of the dance per package is how two of them came to be missing it.
//
// A row that lands while its event is REFUSED (torn ledger, mirror lag or
// hole, held lock, unreadable ledger) is a half-write: it is a campaign
// artifact with no event, which verify cannot see, which the projection audit
// red-lines as ghost spend / a waiver without its event, and over which the
// retry after the heal appends a SECOND row for the one event. So the write is
// atomic in the only sense available to two stores with no shared commit: the
// whole snapshot -> append -> log -> restore window is held under the campaign
// lock the inner Log re-enters by depth, the file's bytes are snapshotted
// before the append, and a refused append OR a refused log restores those
// exact bytes — or removes a file that did not exist yet, never creating an
// empty one.
//
// appendFn names the row's writer (validation.AppendJsonl for the raw UTF-8
// logs, AppendJsonlAsciiThenLog for the ASCII-framed ones), so the discipline
// exists once and the JSONL split policy is not restated here.
func AppendJsonlThenLog(c *Campaign, path, line string, log func() error) error {
	return appendJsonlThenLog(c, path, line, validation.AppendJsonl, log)
}

// AppendJsonlAsciiThenLog is AppendJsonlThenLog for the ASCII-framed logs
// (events/costs): same dance, same unwind, the ASCII-only row writer.
func AppendJsonlAsciiThenLog(c *Campaign, path, line string, log func() error) error {
	return appendJsonlThenLog(c, path, line, validation.AppendJsonlAscii, log)
}

// appendJsonlThenLog is the one implementation the two exported doors share.
func appendJsonlThenLog(c *Campaign, path, line string,
	appendFn func(path, line string) error, log func() error) error {
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	prevRaw, perr := os.ReadFile(path)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	// restore puts the file back exactly as it was: the pre-write bytes when
	// it existed, nothing at all when it did not. A missing file that the
	// failed append never created is a successful restore, not a broken one.
	restore := func() error {
		if had {
			return os.WriteFile(path, prevRaw, 0o644)
		}
		if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	// A FAILED restore means the row bytes are still AHEAD of the refused
	// event — the exact half-land this helper exists to prevent. Name both
	// failures so no caller can report a clean unwind that never happened.
	fail := func(err error) error {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s holds "+
				"post-write bytes with no event; repair by hand before "+
				"continuing)", err, rerr, filepath.Base(path))
		}
		return err
	}
	if err := appendFn(path, line); err != nil {
		// A refused or short append can still have put bytes on disk
		// (O_APPEND + a failing fsync): the row would be there with the
		// error returned, the same half-land as a refused event.
		return fail(err)
	}
	if err := log(); err != nil {
		return fail(err)
	}
	return nil
}
