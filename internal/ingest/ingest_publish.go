// Shared-store operations: first-class program-key replace and the batched
// publish of ingest_record outputs, both manifest-logged.
package ingest

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/evalstore"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// resolveStore is _resolve_store: the tier directory + its manifest tier
// label. "global" is the user-global tier; anything else with a path
// separator is taken as an explicit store dir.
func resolveStore(tier string) (string, string, error) {
	if tier == "global" {
		return sharedmem.GlobalStoreDir(), "global", nil
	}
	if strings.Contains(tier, string(filepath.Separator)) ||
		strings.Contains(tier, "/") {
		return tier, "global", nil
	}
	return "", "", fmt.Errorf("unknown tier %s: use 'global' or an explicit "+
		"store directory", validation.PyReprStr(tier))
}

// ReplaceProgramKey is replace_program_key: first-class replace — drop every
// wrapper with program_key, add newWrappers, log ONE chained manifest record.
func ReplaceProgramKey(programKey string, newWrappers []validation.Value,
	tier string) (validation.Value, error) {
	if programKey == "" {
		return validation.VNull(), errors.New(
			"program_key must be a non-empty string")
	}
	store, tierLabel, err := resolveStore(tier)
	if err != nil {
		return validation.VNull(), err
	}
	wrappers := append([]validation.Value(nil), newWrappers...)
	for _, w := range wrappers {
		if err := validation.Validate(w, "shared_memory_row", 1); err != nil {
			return validation.VNull(), err
		}
		row := validation.ObjAt(w, "row")
		if err := validation.Validate(row, "memory", 1); err != nil {
			return validation.VNull(), err
		}
		// Leakage guard (constraint 4): replace_program_key is a first-class
		// store mutation — a non-dev row must not enter the shared store.
		if orDev(validation.ObjStr(row, "partition")) != "dev" {
			return validation.VNull(), fmt.Errorf("row %s: partition %s is "+
				"not 'dev' — non-dev rows must not enter the shared store",
				validation.PyRepr(validation.ObjAt(row, "memory_id")),
				validation.PyRepr(validation.ObjAt(row, "partition")))
		}
	}
	existing, err := sharedmem.TierMemory(store)
	if err != nil {
		return validation.VNull(), err
	}
	mems := []validation.Value{}
	removed := []string{}
	for _, w := range existing {
		if validation.ObjStr(w, "program_key") == programKey {
			if mid := validation.ObjStr(validation.ObjAt(w, "row"), "memory_id"); mid != "" {
				removed = append(removed, mid)
			}
			continue
		}
		mems = append(mems, w)
	}
	sort.Strings(removed)
	mems = append(mems, wrappers...)
	sigs, err := sharedmem.TierSignatures(store)
	if err != nil {
		return validation.VNull(), err
	}
	if err := sharedmem.WriteStore(store, sigs, mems); err != nil {
		return validation.VNull(), err
	}
	added := make([]string, 0, len(wrappers))
	for _, w := range wrappers {
		added = append(added, validation.ObjStr(validation.ObjAt(w, "row"), "memory_id"))
	}
	sort.Strings(added)
	record := validation.VObj(
		validation.KV{K: "record_id", V: validation.VStr("RPK-" +
			validation.Sha12Hex([]byte(programKey+"|"+state.NowIso())))},
		validation.KV{K: "action", V: validation.VStr("program_key.replaced")},
		validation.KV{K: "program_key", V: validation.VStr(programKey)},
		validation.KV{K: "tier", V: validation.VStr(tierLabel)},
		validation.KV{K: "at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "removed_count", V: validation.VInt(int64(len(removed)))},
		validation.KV{K: "added_count", V: validation.VInt(int64(len(wrappers)))},
		validation.KV{K: "removed_ids_sha256", V: validation.VStr(idsSha(removed))},
		validation.KV{K: "added_ids_sha256", V: validation.VStr(idsSha(added))},
		validation.KV{K: "signatures_sha256", V: validation.VStr(
			sharedmem.FileSha256(sharedmem.SignaturesPath(store)))},
		validation.KV{K: "memory_sha256", V: validation.VStr(
			sharedmem.FileSha256(sharedmem.MemoryPath(store)))})
	return sharedmem.ManifestAppend(store, record)
}

// PublishSummary is publish_ingested's return dict.
type PublishSummary struct {
	CasesAdded     int
	RowsAdded      int
	ManifestRecord *validation.Value
}

// Value renders the summary as Python's dict.
func (s PublishSummary) Value() validation.Value {
	rec := validation.VNull()
	if s.ManifestRecord != nil {
		rec = *s.ManifestRecord
	}
	return validation.VObj(
		validation.KV{K: "cases_added", V: validation.VInt(int64(s.CasesAdded))},
		validation.KV{K: "rows_added", V: validation.VInt(int64(s.RowsAdded))},
		validation.KV{K: "manifest_record", V: rec})
}

// PublishIngested is publish_ingested: batch-publish ingest_record outputs —
// eval cases into the eval store, memory rows (grouped by program key, scope
// global) via ReplaceProgramKey. Non-dev rows are EVAL-ONLY.
func PublishIngested(results []Result, dataset string, programKey *string,
	tier string) (PublishSummary, error) {
	summary := PublishSummary{}
	type group struct {
		key      string
		wrappers []validation.Value
	}
	var order []string
	byKey := map[string]*group{}
	for i := range results {
		result := results[i]
		if err := addCaseIfAny(result, &summary); err != nil {
			return summary, err
		}
		key := ""
		if programKey != nil {
			key = *programKey
		} else {
			k, _, err := sharedmem.ProgramKey(validation.ObjAt(result.EvalCase, "program"))
			if err != nil {
				return summary, err
			}
			key = k
		}
		for _, row := range result.MemoryRows {
			if orDev(validation.ObjStr(row, "partition")) != "dev" {
				continue // eval-only: the case is stored, the row is not
			}
			g, ok := byKey[key]
			if !ok {
				g = &group{key: key}
				byKey[key] = g
				order = append(order, key)
			}
			g.wrappers = append(g.wrappers, validation.VObj(
				validation.KV{K: "program_key", V: validation.VStr(key)},
				validation.KV{K: "published_at", V: validation.VStr(state.NowIso())},
				validation.KV{K: "scope", V: validation.VStr("global")},
				validation.KV{K: "row", V: row}))
		}
	}
	for _, key := range order {
		rec, err := ReplaceProgramKey(key, byKey[key].wrappers, tier)
		if err != nil {
			return summary, err
		}
		summary.ManifestRecord = &rec
		summary.RowsAdded += len(byKey[key].wrappers)
	}
	return summary, nil
}

// addCaseIfAny stores the result's eval case (always present in Result).
func addCaseIfAny(result Result, summary *PublishSummary) error {
	if result.EvalCase.Kind == validation.Null {
		return nil
	}
	if _, err := evalstore.AddCase(result.EvalCase); err != nil {
		return err
	}
	summary.CasesAdded++
	return nil
}

// idsSha is _ids_sha: sha256(json.dumps(ids, sort_keys=True)).
func idsSha(ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, s := range ids {
		parts = append(parts, validation.PyReprStr(s))
	}
	return validation.Sha256Hex([]byte("[" + strings.Join(parts, ", ") + "]"))
}

// orDev is `row.get("partition") or "dev"`.
func orDev(s string) string {
	if s == "" {
		return "dev"
	}
	return s
}
