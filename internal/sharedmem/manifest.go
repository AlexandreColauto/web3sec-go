// The hash-chained manifest, tier concatenation/dedup and the public read
// side of every store.

package sharedmem

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"websec/internal/validation"
)

// recordHash is _record_hash: sha256 over the sorted-keys, ASCII-safe JSON
// of the record body (record_hash itself excluded).
func recordHash(record validation.Value) string {
	body := validation.VObj()
	for _, kv := range record.O {
		if kv.K == "record_hash" {
			continue
		}
		body.O = append(body.O, kv)
	}
	sum := sha256.Sum256([]byte(validation.CanonSpaced(body)))
	return hex.EncodeToString(sum[:])
}

// manifestAppend is _manifest_append: append a HASH-CHAINED record.
func manifestAppend(store string, record validation.Value) (validation.Value, error) {
	manifest, err := tierManifest(store)
	if err != nil {
		return validation.VNull(), err
	}
	prev := strings.Repeat("0", 64)
	for i := len(manifest) - 1; i >= 0; i-- {
		if h, ok := fieldAt(manifest[i], "record_hash"); ok {
			prev = pyStr(h)
			break
		}
	}
	rec := validation.VObj()
	rec.O = append(rec.O, record.O...)
	rec.O = append(rec.O, kv("prev_hash", validation.VStr(prev)))
	rec.O = append(rec.O, kv("record_hash", validation.VStr(recordHash(rec))))
	manifest = append(manifest, rec)
	if err := validation.WriteJson(manifestPath(store),
		validation.VArr(manifest...), ""); err != nil {
		return validation.VNull(), err
	}
	return rec, nil
}

// merge is _merge: concatenate tiers in precedence order, dedupe by key;
// with preferGlobal a scope=global copy wins over a scope=program one.
func merge(rows [][]validation.Value, keyOf func(validation.Value) string,
	preferGlobal bool) []validation.Value {
	out := []validation.Value{}
	index := map[string]int{}
	for _, rowset := range rows {
		for _, r := range rowset {
			k := keyOf(r)
			if i, ok := index[k]; ok {
				if preferGlobal && validation.ObjStr(r, "scope") == "global" &&
					validation.ObjStr(out[i], "scope") != "global" {
					out[i] = r
				}
				continue
			}
			index[k] = len(out)
			out = append(out, r)
		}
	}
	return out
}

// LoadSignatures is load_signatures: capability signatures across every
// tier this campaign can see.
func LoadSignatures(root string) ([]validation.Value, error) {
	sets := [][]validation.Value{}
	for _, d := range StoreDirs(root) {
		ts, err := tierSignatures(d)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ts)
	}
	return merge(sets, sigKey, true), nil
}

// LoadSharedMemory is load_shared_memory: approved memory rows across every
// tier, deduped by memory_id. It is the corpus/findings seam target.
func LoadSharedMemory(root string) ([]validation.Value, error) {
	sets := [][]validation.Value{}
	for _, d := range StoreDirs(root) {
		tm, err := tierMemory(d)
		if err != nil {
			return nil, err
		}
		sets = append(sets, tm)
	}
	return merge(sets, func(w validation.Value) string {
		return validation.ObjStr(validation.ObjAt(w, "row"), "memory_id")
	}, true), nil
}

// LoadManifest is load_manifest: publish/scope records across every tier,
// ordered by time.
func LoadManifest(root string) ([]validation.Value, error) {
	merged := []validation.Value{}
	for _, d := range StoreDirs(root) {
		tm, err := tierManifest(d)
		if err != nil {
			return nil, err
		}
		merged = append(merged, tm...)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		ai, aj := validation.ObjStr(merged[i], "at"), validation.ObjStr(merged[j], "at")
		if ai != aj {
			return ai < aj
		}
		return validation.ObjStr(merged[i], "record_id") < validation.ObjStr(merged[j], "record_id")
	})
	return merged, nil
}
