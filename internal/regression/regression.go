// Package regression is the v1.6 Part 3a regression suite's record layer: one
// campaign per target, one target record, its pin, its runs, and (from Task 3
// onward) its derived labels, mirror bookkeeping, contamination grep, answer
// keys and commit-before-reveal record.
//
// Every durable side effect is one schema-validated file plus exactly one
// hash-chained ledger event, written together or not at all (writeThenLog).
// The records live in the campaign (campaigns/<cid>/regression/) rather than
// in a repo-level store so they inherit the ledger, the determinism pins, the
// single-writer lock and the audit — the same reason execs/ and chains/ do.
// The one repo-level artefact is the suite COMPOSITION (internal/regression/
// suite.go, Task 10), because a suite spans campaigns.
package regression

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// Dir is the campaign-scoped home of every regression record.
func Dir(c *state.Campaign) string { return filepath.Join(c.Dir, "regression") }

// TargetsDir is the directory of target records (one per target).
func TargetsDir(c *state.Campaign) string { return filepath.Join(Dir(c), "targets") }

// RunsDir is the directory of run records.
func RunsDir(c *state.Campaign) string { return filepath.Join(Dir(c), "runs") }

func targetPath(c *state.Campaign, id string) string {
	return filepath.Join(TargetsDir(c), id+".json")
}

func runPath(c *state.Campaign, id string) string {
	return filepath.Join(RunsDir(c), id+".json")
}

// kv is the vet-clean keyed KV constructor (unkeyed cross-package literals are
// rejected by go vet).
func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// contains reports membership in a small closed vocabulary.
func contains(vocab []string, s string) bool {
	for _, v := range vocab {
		if v == s {
			return true
		}
	}
	return false
}

// optionalStr is one optional string key of a record. An absent key and an
// empty value are different facts in these records (the dataset's commit field
// is legitimately the empty string), so absence is expressed by the writer
// omitting the key, never by writing "".
type optionalStr struct{ key, val string }

// withOptional appends every non-empty optional key, in the order given (the
// ordered-JSON discipline: a rewrite must not reorder a record).
func withOptional(o []validation.KV, opts ...optionalStr) []validation.KV {
	for _, opt := range opts {
		if opt.val != "" {
			o = validation.SetOrAppend(o, opt.key, validation.VStr(opt.val))
		}
	}
	return o
}

// readRecord reads one JSON record, reporting absence rather than an error.
func readRecord(path string) (validation.Value, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return validation.VNull(), false, nil
		}
		return validation.VNull(), false, err
	}
	doc, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), false, err
	}
	return doc, true, nil
}

// loadRecords is every <prefix>*.json record in dir, in file order.
// validation.ListPrefixedOptional returns full paths, already sorted.
func loadRecords(dir, prefix string) ([]validation.Value, error) {
	names, err := validation.ListPrefixedOptional(dir, prefix, ".json")
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(names))
	for _, p := range names {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, doc)
	}
	return out, nil
}

// writeThenLog is the ledger law for a file-backed record: the record file and
// its one ledger event land together or not at all. The file is written first
// (it is the projection), the event second (it is the audit trail), and a
// failed log write RESTORES the file to its pre-write bytes, so no unrecorded
// projection can survive.
//
// The restore is not a plain remove, and the difference is the whole point of
// the law. Two writers reach this helper with different histories:
//
//   - a NEW record (AddTarget, RecordRun): no file existed, so undoing the
//     write means removing the file it just created;
//   - a REWRITE of a committed record (PinTarget): a file existed, and
//     removing it would destroy the record the campaign already ledgered —
//     data loss on an error path, the exact half-land this law exists to
//     prevent. It is written back byte-for-byte instead.
//
// This mirrors internal/findings/storage.go's SaveThenLog/prevBytes/
// restoreBytes, the repo's existing implementation of the same law (small
// helpers are duplicated, not exported — the house rule).
//
// Every writer in this package goes through here; there is no second path.
func writeThenLog(c *state.Campaign, path string, doc validation.Value, schema,
	eventType string, ref *string, data validation.Value) (validation.Value, error) {
	if err := validation.Validate(doc, schema, 1); err != nil {
		return validation.VNull(), err
	}
	prevRaw, hadPrev, err := prevBytes(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(path, doc, ""); err != nil {
		return validation.VNull(), err
	}
	if _, err := c.Log(eventType, ref, &data); err != nil {
		if rErr := restoreBytes(path, prevRaw, hadPrev); rErr != nil {
			// The findings package's own wording (r18 P2): a FAILED
			// restore means the projection is still AHEAD of the
			// refused event. Returning only the ledger error would
			// launder that half-land into a clean unwind that never
			// happened.
			return validation.VNull(), fmt.Errorf(
				"ledger write failed (%w) (UNWIND ALSO FAILED: %v — the "+
					"projection may hold post-write bytes with no event; "+
					"the campaign store needs a manual clean)", err, rErr)
		}
		return validation.VNull(), err
	}
	return doc, nil
}

// prevBytes snapshots a record's bytes before it is rewritten, reporting
// absence rather than an error so "there was no file" is a fact the restore
// can act on. The findings package's SaveThenLog keeps the same snapshot
// (internal/findings/storage.go:193).
func prevBytes(path string) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return raw, true, nil
}

// restoreBytes undoes a projection write: a file that existed before is
// written back byte-for-byte, a file that did not is removed. Deleting a
// PRE-EXISTING record because a later rewrite's event was refused is data
// loss, not an unwind — the failing writer is PinTarget, whose record
// AddTarget already committed and ledgered.
func restoreBytes(path string, raw []byte, had bool) error {
	if !had {
		return os.Remove(path)
	}
	return os.WriteFile(path, raw, 0o644)
}
