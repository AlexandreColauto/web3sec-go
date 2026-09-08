// memory.go: visible_memory_rows / _canonical_row_hash / compute_row_digest /
// record_memory_check / memory_check_fails (webv2.findings).
//
// The graph-memory check replaces the dead corpus-check: a finding reaches
// CONFIRMED only with a recorded consultation whose stamp (row_digest over
// the referenced rows) still verifies against the live store. Unknown ids
// cannot be recorded; a store that changes after recording makes the check
// stale, and the gate says so instead of passing on faith.
package findings

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- store seams (learning / shared_memory own the real loaders). The
// ---- defaults see an empty store, which makes every check fail closed.

// sharedMemoryRowsFunc is shared_memory.load_shared_memory(root): the merged
// approved rows across every tier, each wrapped as {..., "row": row}.
var sharedMemoryRowsFunc = func(root string) ([]validation.Value, error) {
	return nil, nil
}

// SetSharedMemoryRows wires shared_memory.load_shared_memory.
func SetSharedMemoryRows(f func(string) ([]validation.Value, error)) {
	if f == nil {
		panic("findings: nil shared-memory loader")
	}
	sharedMemoryRowsFunc = f
}

// learningAllMemoryFunc is learning.all_memory(campaign): within-campaign
// learning memory rows.
var learningAllMemoryFunc = func(*state.Campaign) ([]validation.Value, error) {
	return nil, nil
}

// SetLearningAllMemory wires learning.all_memory.
func SetLearningAllMemory(f func(*state.Campaign) ([]validation.Value, error)) {
	if f == nil {
		panic("findings: nil learning-memory loader")
	}
	learningAllMemoryFunc = f
}

// VisibleMemoryRows is visible_memory_rows: memory_id -> row over everything
// this campaign may consult — the shared store (both tiers; its publish
// discipline already restricts to approved rows) plus within-campaign
// learning memory.
func VisibleMemoryRows(campaign *state.Campaign) (map[string]validation.Value, error) {
	out := map[string]validation.Value{}
	// campaign.root (a path), NOT the Campaign object: passing the object
	// resolves the root tier to <campaign.dir>/shared-memory, where
	// publish_campaign never writes — root-tier rows would be invisible and
	// every recorded check referencing one would verify stale forever.
	shared, err := sharedMemoryRowsFunc(campaign.Root)
	if err != nil {
		return nil, err
	}
	for _, w := range shared {
		row := w
		if w.Kind == validation.Obj {
			if inner, ok := fieldAt(w, "row"); ok {
				row = inner
			}
		}
		if id := objStr(row, "memory_id"); id != "" {
			out[id] = row
		}
	}
	learned, err := learningAllMemoryFunc(campaign)
	if err != nil {
		return nil, err
	}
	for _, row := range learned {
		if id := objStr(row, "memory_id"); id != "" {
			if _, exists := out[id]; !exists {
				out[id] = row
			}
		}
	}
	return out, nil
}

// canonicalRowHash is _canonical_row_hash:
// sha256(json.dumps(row, sort_keys=True, ensure_ascii=True)).
func canonicalRowHash(row validation.Value) string {
	return validation.Sha256Hex([]byte(validation.CanonSpaced(row)))
}

// ComputeRowDigest is compute_row_digest: sha256 of the sorted JSON pair list
// [(memory_id, canonical-row-hash), ...]. Deterministic; an empty list gives
// the digest of [].
func ComputeRowDigest(memoryIDs []string,
	rowsByID map[string]validation.Value) string {
	type pair struct{ mid, hash string }
	pairs := make([]pair, 0, len(memoryIDs))
	for _, mid := range memoryIDs {
		if row, ok := rowsByID[mid]; ok {
			pairs = append(pairs, pair{mid, canonicalRowHash(row)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].mid != pairs[j].mid {
			return pairs[i].mid < pairs[j].mid
		}
		return pairs[i].hash < pairs[j].hash
	})
	items := make([]validation.Value, len(pairs))
	for i, p := range pairs {
		items[i] = validation.VArr(validation.VStr(p.mid),
			validation.VStr(p.hash))
	}
	return validation.Sha256Hex([]byte(validation.CanonSpaced(
		validation.VArr(items...))))
}

// memoryCheckKey is Python's (frozenset(memory_ids), mode) dedupe key.
func memoryCheckKey(ids []string, mode validation.Value) string {
	uniq := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			uniq = append(uniq, id)
		}
	}
	sort.Strings(uniq)
	return strings.Join(uniq, "\x00") + "\x01" + validation.PyRepr(mode)
}

// RecordMemoryCheck is record_memory_check: record graph-memory consultations
// for a finding (the CONFIRMED gate's required evidence). Appends; dedupes on
// (frozenset(memory_ids), mode); never rewrites prior entries.
func RecordMemoryCheck(campaign *state.Campaign, findingID string,
	checks []validation.Value) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	prov := objAt(finding, "provenance")
	if prov.Kind != validation.Obj {
		prov = validation.VObj()
	}
	existing := objAt(prov, "memory_checks")
	if existing.Kind != validation.Arr {
		existing = validation.VArr()
	}
	seen := map[string]struct{}{}
	for _, r := range existing.A {
		if r.Kind != validation.Obj {
			continue
		}
		seen[memoryCheckKey(valueStrings(objAt(r, "memory_ids")),
			objAt(r, "mode"))] = struct{}{}
	}
	rowsByID, err := VisibleMemoryRows(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	added := 0
	for _, c := range checks {
		key, entry, err := memoryCheckEntry(c, rowsByID)
		if err != nil {
			return validation.VNull(), err
		}
		if _, dup := seen[key]; dup {
			continue
		}
		existing.A = append(existing.A, entry)
		seen[key] = struct{}{}
		added++
	}
	prov.O = setOrAppend(prov.O, "memory_checks", existing)
	finding.O = setOrAppend(finding.O, "provenance", prov)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "added", V: validation.VInt(int64(added))},
		validation.KV{K: "modes", V: strArr(checkModes(checks))},
	)
	if _, err := campaign.Log("finding.memory_checked", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// memoryCheckEntry validates one check against the visible store and builds
// its dedup key + stamped entry (Python's in-loop body).
func memoryCheckEntry(c validation.Value, rowsByID map[string]validation.Value) (
	string, validation.Value, error) {
	ids := valueStrings(objAt(c, "memory_ids"))
	mode := objAt(c, "mode")
	if mode.Kind != validation.Str ||
		(mode.S != "negative" && mode.S != "comparative") {
		return "", validation.VNull(), fmtUnknownMode(mode)
	}
	var unknown []string
	for _, mid := range ids {
		if _, ok := rowsByID[mid]; !ok {
			unknown = append(unknown, mid)
		}
	}
	if len(unknown) > 0 {
		return "", validation.VNull(), fmtUnknownMemoryIDs(unknown)
	}
	entry := validation.VObj(
		validation.KV{K: "memory_ids", V: strArr(sortedStrings(ids))},
		validation.KV{K: "mode", V: mode},
		validation.KV{K: "consulted_at", V: validation.VStr(nowIso())},
		validation.KV{K: "row_digest",
			V: validation.VStr(ComputeRowDigest(ids, rowsByID))},
	)
	if note := objAt(c, "note"); pyTruthy(note) {
		entry.O = append(entry.O, validation.KV{K: "note", V: note})
	}
	return memoryCheckKey(ids, mode), entry, nil
}

func fmtUnknownMode(mode validation.Value) error {
	return fmt.Errorf("memory check mode must be negative|comparative, got %s",
		validation.PyRepr(mode))
}

func fmtUnknownMemoryIDs(unknown []string) error {
	return fmt.Errorf("unknown memory id(s) %s — not in the visible store",
		listRepr(unknown))
}

// checkModes is sorted({c.get("mode") or "-" for c in checks}).
func checkModes(checks []validation.Value) []string {
	seen := map[string]struct{}{}
	for _, c := range checks {
		m := objAt(c, "mode")
		if m.Kind == validation.Str && m.S != "" {
			seen[m.S] = struct{}{}
			continue
		}
		seen["-"] = struct{}{}
	}
	return sortedSetKeys(seen)
}

func sortedStrings(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

// MemoryCheckFails is memory_check_fails: the gate's memory-check portion.
// Returns nil when a recorded check verifies, else the failure message.
// Verification: mode valid; every referenced id still in the visible store;
// recomputed digest matches the stamp. A hand-written legacy corpus-reference
// list in provenance is NOT a memory check.
func MemoryCheckFails(campaign *state.Campaign,
	findingID string) (*string, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return nil, err
	}
	checks := objAt(asDict(objAt(finding, "provenance")), "memory_checks")
	if checks.Kind != validation.Arr {
		checks = validation.VArr()
	}
	rowsByID, err := VisibleMemoryRows(campaign)
	if err != nil {
		return nil, err
	}
	for _, c := range checks.A {
		if c.Kind != validation.Obj {
			continue
		}
		mode := objAt(c, "mode")
		if mode.Kind != validation.Str ||
			(mode.S != "negative" && mode.S != "comparative") {
			continue
		}
		ids := valueStrings(objAt(c, "memory_ids"))
		stale := false
		for _, mid := range ids {
			if _, ok := rowsByID[mid]; !ok {
				stale = true // stale: referenced row gone
				break
			}
		}
		if stale {
			continue
		}
		if ComputeRowDigest(ids, rowsByID) != objStr(c, "row_digest") {
			continue // stale: row content changed since recording
		}
		return nil, nil
	}
	msg := "no verified graph-memory recall recorded — none recorded, or " +
		"every recorded check is stale (a referenced row changed or left " +
		"the store) — run `webv2 recall --finding " + findingID + "`"
	return &msg, nil
}
