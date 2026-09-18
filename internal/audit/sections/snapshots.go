// Section 6: snapshots — the pinned copies are immutable by design; the
// audit verifies that claim instead of trusting it. Every pinned tree is
// re-hashed with the same length-prefixed digest used at pin time
// (snapshot.json itself is excluded) and compared to the recorded content
// hash; the self-describing manifest (where present) is recomputed from
// disk. Message-for-message with audit.py section 6.
package sections

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// snapshotStoreRefusal is the ONE wording this section uses when the snapshot
// store, or anything inside it, cannot be READ. Only os.IsNotExist is absence
// (the callers handle it: a campaign that never pinned has no snapshots/, and
// a pin dir that vanished between the listing and the stat is gone); every
// other error — EACCES, ENOTDIR, EIO — is a refusal that names the path and
// the errno, because a count taken over a store nobody read is a false
// certification, not an empty store.
func snapshotStoreRefusal(verb, path string, err error) error {
	return fmt.Errorf("the snapshot store %s cannot be %s: %v", path, verb, err)
}

// Snapshots is audit.py section 6. checked counts the pin dirs with a
// readable source.content_hash.
func Snapshots(c *state.Campaign) (validation.Value, error) {
	var problems []validation.Value
	checked := 0
	snapsRoot := filepath.Join(c.Dir, "snapshots")
	// r44b P1-b: this was `if _, err := os.Stat(snapsRoot); err == nil {
	// entries, _ := os.ReadDir(snapsRoot) }` — the ReadDir error was
	// DISCARDED, so a snapshots/ store that could not be listed was
	// indistinguishable from an empty one: `chmod 000 <c>/snapshots/`
	// turned {"checked":1,"ok":true} into {"checked":0,"ok":true} and the
	// section whose docstring promises to verify immutability "instead of
	// trusting it" verified ZERO pins and passed, exit 0. Absence stays a
	// fact (a campaign that never pinned has no store and audits green);
	// a store that cannot be listed refuses, naming the path and the errno.
	entries, rerr := os.ReadDir(snapsRoot)
	if rerr != nil {
		if !os.IsNotExist(rerr) {
			return validation.Value{}, snapshotStoreRefusal("listed", snapsRoot,
				rerr)
		}
		entries = nil // absent store: an empty campaign, not a refusal
	}
	// Python sorts the child Paths (full path string) ascending.
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		paths = append(paths, filepath.Join(snapsRoot, e.Name()))
	}
	sort.Strings(paths)
	for _, snapDir := range paths {
		st, sterr := os.Stat(snapDir)
		if sterr != nil {
			if os.IsNotExist(sterr) {
				// Listed, then gone: absence.
				continue
			}
			// r44b: this used to `continue` on ANY stat error, so a pin
			// dir this run could not inspect was silently dropped from
			// `checked` — the same fold as the store itself.
			return validation.Value{}, snapshotStoreRefusal("read", snapDir,
				sterr)
		}
		if !st.IsDir() {
			continue // the layout filter: snapshots/ holds pin dirs
		}
		name := filepath.Base(snapDir)
		meta := filepath.Join(snapDir, "snapshot.json")
		if _, merr := os.Stat(meta); merr != nil {
			if !os.IsNotExist(merr) {
				// r44b: an unreadable pin dir (mode 000 on snapshots/<id>,
				// EIO) made os.Stat(meta) fail with EACCES and the section
				// reported "missing snapshot.json" — a claim about the
				// file's ABSENCE drawn from a read failure.
				return validation.Value{}, snapshotStoreRefusal("read", meta,
					merr)
			}
			problems = append(problems, validation.VStr(
				fmt.Sprintf("%s: missing snapshot.json", name)))
			continue
		}
		snap, perr := validation.ReadJson(meta)
		recorded := validation.ObjAt(validation.ObjAt(snap, "source"), "content_hash")
		if perr != nil || recorded.Kind != validation.Str {
			// r44b: an I/O failure on the manifest is a READ failure, not
			// a content verdict — Python's os errors are uncaught there
			// and the port must not turn EACCES into "unusable content".
			// Only the not-exist shape (the file vanished between the stat
			// and the read) keeps the message below.
			var pe *os.PathError
			if perr != nil && !os.IsNotExist(perr) &&
				errors.As(perr, &pe) {
				return validation.Value{}, snapshotStoreRefusal("read", meta,
					perr)
			}
			// Python catches (KeyError, ValueError): a missing
			// source/content_hash is a KeyError; invalid JSON is a
			// JSONDecodeError (a ValueError). Both -> unreadable.
			problems = append(problems, validation.VStr(
				fmt.Sprintf("%s: unreadable snapshot.json (missing or invalid content_hash)", name)))
			continue
		}
		checked++
		actual, _, err := snapshot.ContentHash(snapDir)
		if err != nil {
			return validation.Value{}, err
		}
		if actual != recorded.S {
			problems = append(problems, validation.VStr(
				fmt.Sprintf("%s: content hash mismatch (stored %s..., actual %s...) — the pinned copy was modified after pinning",
					name, trunc12(recorded.S), actual[:12])))
		}
		// The self-describing manifest (where present).
		manifest := validation.ObjAt(snap, "manifest")
		if manifest.Kind == validation.Obj && len(manifest.O) > 0 {
			actualRoot, err := snapshot.SourceMerkleRoot(snapDir)
			if err != nil {
				return validation.Value{}, err
			}
			manifestRoot := validation.ObjStr(manifest, "source_merkle_root")
			if actualRoot != manifestRoot {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: manifest source_merkle_root mismatch (stored %s..., actual %s...)",
						name, trunc12(manifestRoot), actualRoot[:12])))
			}
			manifestMH := validation.ObjStr(manifest, "manifest_hash")
			// Recompute metal hash over the manifest's own fields
			// (excluding manifest_hash itself).
			fields := withoutKey(manifest, "manifest_hash")
			actualMH := snapshot.ManifestHash(fields)
			if actualMH != manifestMH {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: manifest_hash does not match the manifest's own fields — the manifest was edited after pinning",
						name)))
			}
		}
	}
	// r4 (critic): an active_snapshot the projection names but the store
	// does not hold is a ghost pin — every later integrity read trusts it.
	// Corrupt CONTENT was caught; a missing DIRECTORY was not. The
	// round-3 law applies: disclose loudly (audit goes RED; doctor
	// already says exists:false), do not block ingest over a deleted dir
	// the operator may be mid-recovery from.
	if st, serr := c.State(); serr == nil {
		active := validation.ObjStr(st, "active_snapshot_id")
		for _, name := range referencedSnapshotIDs(st) {
			pinPath := filepath.Join(snapsRoot, name)
			_, derr := os.Stat(pinPath)
			if derr == nil {
				continue
			}
			if !os.IsNotExist(derr) {
				// r44b: this existence check read the store too, and it
				// answered "no ghost" for every stat error — a pin whose
				// presence could not be decided is not a pin the section
				// may call present.
				return validation.Value{}, snapshotStoreRefusal("read",
					pinPath, derr)
			}
			// r13: one message must not claim "active" for an
			// inactive ghost row — activeness is a fact the check
			// knows, so it speaks it.
			role := "lists"
			if name == active {
				role = "names as active"
			}
			problems = append(problems, validation.VStr(
				name+": the campaign "+role+" this snapshot but "+
					"snapshots/"+name+" does not exist — re-pin (`webv2 "+
					"snap`) or the ledger pins are ghosts"))
		}
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(checked))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// referencedSnapshotIDs is the set of snapshot ids the campaign's
// projection actively trusts right now: state.active_snapshot plus every
// finding's snapshot_ids.source that is not the "unpinned" sentinel.
func referencedSnapshotIDs(st validation.Value) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s == "" || s == "unpinned" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(validation.ObjStr(st, "active_snapshot_id"))
	// r12: the projection check reads EVERY row of state.snapshots, and
	// the brief/learning layers trust non-active rows too — a deleted
	// directory for an INACTIVE row was a ghost pin the message already
	// named ("the ledger pins are ghosts") but no check covered. Every
	// referenced row must exist, active or not.
	for _, r := range validation.ObjAt(st, "snapshots").A {
		add(validation.ObjStr(r, "snapshot_id"))
	}
	sort.Strings(out)
	return out
}

// withoutKey returns a copy of an object value without the named key
// (Python {k: v for k, v in manifest.items() if k != "manifest_hash"}).
func withoutKey(v validation.Value, key string) validation.Value {
	o := make([]validation.KV, 0, len(v.O))
	for _, kv := range v.O {
		if kv.K == key {
			continue
		}
		o = append(o, kv)
	}
	return validation.VObj(o...)
}

// trunc12 is Python str(x)[:12] (the stored-prefix truncation).
func trunc12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
