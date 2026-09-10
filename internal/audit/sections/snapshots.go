// Section 6: snapshots — the pinned copies are immutable by design; the
// audit verifies that claim instead of trusting it. Every pinned tree is
// re-hashed with the same length-prefixed digest used at pin time
// (snapshot.json itself is excluded) and compared to the recorded content
// hash; the self-describing manifest (where present) is recomputed from
// disk. Message-for-message with audit.py section 6.
package sections

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// Snapshots is audit.py section 6. checked counts the pin dirs with a
// readable source.content_hash.
func Snapshots(c *state.Campaign) (validation.Value, error) {
	var problems []validation.Value
	checked := 0
	snapsRoot := filepath.Join(c.Dir, "snapshots")
	if _, err := os.Stat(snapsRoot); err == nil {
		entries, _ := os.ReadDir(snapsRoot)
		// Python sorts the child Paths (full path string) ascending.
		paths := make([]string, 0, len(entries))
		for _, e := range entries {
			paths = append(paths, filepath.Join(snapsRoot, e.Name()))
		}
		sort.Strings(paths)
		for _, snapDir := range paths {
			if st, err := os.Stat(snapDir); err != nil || !st.IsDir() {
				continue
			}
			name := filepath.Base(snapDir)
			meta := filepath.Join(snapDir, "snapshot.json")
			if _, err := os.Stat(meta); err != nil {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: missing snapshot.json", name)))
				continue
			}
			snap, perr := validation.ReadJson(meta)
			recorded := objAt(objAt(snap, "source"), "content_hash")
			if perr != nil || recorded.Kind != validation.Str {
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
			manifest := objAt(snap, "manifest")
			if manifest.Kind == validation.Obj && len(manifest.O) > 0 {
				actualRoot, err := snapshot.SourceMerkleRoot(snapDir)
				if err != nil {
					return validation.Value{}, err
				}
				manifestRoot := objStr(manifest, "source_merkle_root")
				if actualRoot != manifestRoot {
					problems = append(problems, validation.VStr(
						fmt.Sprintf("%s: manifest source_merkle_root mismatch (stored %s..., actual %s...)",
							name, trunc12(manifestRoot), actualRoot[:12])))
				}
				manifestMH := objStr(manifest, "manifest_hash")
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
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(checked))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
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
