// report.go: build_report and the two bundle blocks (shared_memory_block,
// corpus_surface_block). Advisory throughout — no status changes, no
// hypotheses, no pipeline gating.
package corpus

import (
	"errors"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// CorpusSurfaceFile is the sweep artifact name.
const CorpusSurfaceFile = "corpus_surface.json"

// BuildReport is build_report: the full corpus-surface report.
//
// Deterministic: same inputs -> byte-identical report modulo generated_at
// (explicit ordering everywhere downstream). An ABSENT corpus root is a
// legitimate input state for this advisory sweep — the shape leg degrades to
// {} and attribution/poc_missing to ({}, 0). A PRESENT-but-non-git checkout
// still fails loud (the shape-cache contract): guessing staleness is worse
// than stopping.
func BuildReport(c *state.Campaign, pocRoot *string) (validation.Value, error) {
	root := PocRoot
	if pocRoot != nil {
		root = *pocRoot
	}
	snapRoot, err := ActiveSnapshotRoot(c)
	if err != nil {
		return validation.VNull(), err
	}
	index, err := structidx.EnsureFreshIndex(c, snapRoot)
	if err != nil {
		return validation.VNull(), err
	}
	inventory, err := ClassInventory(c)
	if err != nil {
		return validation.VNull(), err
	}
	probed := ProbeClasses(index)
	exposure := ExposureRows(inventory, probed)
	shapes := ShapeIndex{}
	if isDir(root) {
		doc, derr := LoadOrBuildPocShapes(c, &root)
		if derr != nil {
			return validation.VNull(), derr
		}
		shapes = doc.Shapes
	}
	matches := MatchShapes(index, shapes)
	attribution, pocMissing, err := pocAttribution(&root)
	if err != nil {
		return validation.VNull(), err
	}
	if err := attachMemory(c, attribution); err != nil {
		return validation.VNull(), err
	}
	for i, m := range matches {
		attr, ok := attribution[objStr(m, "file")]
		if !ok {
			continue
		}
		matches[i] = appendKV(m,
			validation.KV{K: "record_id", V: attr.recordID},
			validation.KV{K: "memory_ids", V: attr.memoryIDs},
			validation.KV{K: "bug_class", V: attr.bugClass},
		)
	}
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "generated_at", V: validation.VStr(nowIso())},
		validation.KV{K: "inventory", V: inventory},
		validation.KV{K: "class_exposure", V: validation.VArr(exposure...)},
		validation.KV{K: "shape_matches", V: validation.VArr(matches...)},
		validation.KV{K: "unprobed_classes", V: unprobedValue()},
		validation.KV{K: "poc_missing", V: validation.VInt(pocMissing)},
	), nil
}

// appendKV returns v with the extra keys appended (the report mutates its
// shape-match rows in place after attribution).
func appendKV(v validation.Value, kvs ...validation.KV) validation.Value {
	out := validation.VObj(append(append([]validation.KV{}, v.O...), kvs...)...)
	return out
}

// unprobedValue is dict(UNPROBED) in declaration order.
func unprobedValue() validation.Value {
	return validation.VObj(
		validation.KV{K: "precision-rounding", V: validation.VStr(
			Unprobed["precision-rounding"])},
		validation.KV{K: "signature-replay", V: validation.VStr(
			Unprobed["signature-replay"])},
	)
}

// attribution is one PoC path's record linkage.
type attribution struct {
	recordID  validation.Value
	memoryIDs validation.Value
	bugClass  validation.Value
}

// pocAttribution is _poc_attribution: poc_path -> {record_id, memory_ids,
// bug_class} via the dataset loader. Absent explorer -> ({}, 0): attribution
// is simply absent, shapes are still reported, poc_missing is 0.
func pocAttribution(pocRoot *string) (map[string]*attribution, int64, error) {
	records, err := LoadPocRecords(nil, pocRoot)
	if err != nil {
		if errors.Is(err, ErrDatasetAbsent) || errors.Is(err, os.ErrNotExist) {
			return map[string]*attribution{}, 0, nil
		}
		return nil, 0, err
	}
	byPath := map[string]*attribution{}
	missing := int64(0)
	for _, rec := range records {
		poc := objStr(objAt(rec, "exploit"), "poc_path")
		if poc == "" {
			missing++
			continue
		}
		byPath[poc] = &attribution{
			recordID:  objAt(rec, "id"),
			memoryIDs: validation.VArr(),
			bugClass:  validation.VNull(),
		}
	}
	return byPath, missing, nil
}

// attachMemory is _attach_memory: fill in memory_ids + bug_class from the
// shared-memory rows published under ingest:defihacklabs:<record_id> (first
// row wins for the class — one incident, one taxonomy class).
func attachMemory(c *state.Campaign, byPath map[string]*attribution) error {
	rows, err := LoadSharedMemory(c.Root)
	if err != nil {
		return err
	}
	byCampaign := map[string][]validation.Value{}
	for _, w := range rows {
		row := wrappedRow(w)
		cid := objStr(row, "campaign_id")
		if len(cid) >= len("ingest:defihacklabs:") &&
			cid[:len("ingest:defihacklabs:")] == "ingest:defihacklabs:" {
			byCampaign[cid] = append(byCampaign[cid], row)
		}
	}
	for _, entry := range byPath {
		if entry.recordID.Kind != validation.Str || entry.recordID.S == "" {
			continue
		}
		matched := byCampaign["ingest:defihacklabs:"+entry.recordID.S]
		ids := make([]string, 0, len(matched))
		for _, r := range matched {
			if id := objAt(r, "memory_id"); id.Kind == validation.Str {
				ids = append(ids, id.S)
			}
		}
		sort.Strings(ids)
		entry.memoryIDs = strArr(ids)
		if len(matched) > 0 {
			entry.bugClass = objAt(matched[0], "bug_class")
		}
	}
	return nil
}

// SharedMemoryBlock is shared_memory_block: cross-campaign prior knowledge
// made visible to the proposer. nil when the store is empty.
func SharedMemoryBlock(c *state.Campaign, bugClass *string,
	limit int) (validation.Value, error) {
	raw, err := LoadSharedMemory(c.Root)
	if err != nil {
		return validation.VNull(), err
	}
	type wrapped struct {
		row   validation.Value
		scope validation.Value
	}
	items := make([]wrapped, 0, len(raw))
	for _, w := range raw {
		items = append(items, wrapped{row: wrappedRow(w), scope: scopeOf(w)})
	}
	if len(items) == 0 {
		return validation.VNull(), nil
	}
	inv, err := ClassInventory(c)
	if err != nil {
		return validation.VNull(), err
	}
	weight := map[string]int64{}
	for _, kv := range objAt(inv, "classes").O {
		weight[kv.K] = intAt(kv.V, "memory_rows") + intAt(kv.V, "eval_cases")
	}
	pool := items
	filtered := false
	if bugClass != nil && *bugClass != "" {
		same := make([]wrapped, 0, len(items))
		for _, it := range items {
			if objStr(it.row, "bug_class") == *bugClass {
				same = append(same, it)
				filtered = true
			}
		}
		if len(same) > 0 {
			pool = same
		}
	}
	sort.SliceStable(pool, func(i, j int) bool {
		wi := weight[objStr(pool[i].row, "bug_class")]
		wj := weight[objStr(pool[j].row, "bug_class")]
		if wi != wj {
			return wi > wj
		}
		return objStr(pool[i].row, "memory_id") < objStr(pool[j].row, "memory_id")
	})
	if limit >= 0 && len(pool) > limit {
		pool = pool[:limit]
	}
	rows := make([]validation.Value, 0, len(pool))
	for _, it := range pool {
		summary := clipRunes(objStr(it.row, "evidence_summary"), 300)
		rows = append(rows, validation.VObj(
			validation.KV{K: "memory_id", V: objAt(it.row, "memory_id")},
			validation.KV{K: "scope", V: it.scope},
			validation.KV{K: "bug_class", V: objAt(it.row, "bug_class")},
			validation.KV{K: "pattern", V: objAt(it.row, "pattern")},
			validation.KV{K: "evidence_summary", V: validation.VStr(summary)},
		))
	}
	return validation.VObj(
		validation.KV{K: "rows", V: validation.VArr(rows...)},
		validation.KV{K: "total_visible", V: validation.VInt(int64(len(items)))},
		validation.KV{K: "filtered_by_bug_class", V: validation.VBool(filtered)},
	), nil
}

// clipRunes is Python's `s[:n]` for a string: a CHARACTER slice. The
// reference clips shared-memory evidence summaries with `[:300]`, so a
// multi-byte rune straddling the budget must not shorten the row relative to
// the reference (golden v5 surfaced this on the P4 fixture's ingest rows,
// whose descriptions carry em dashes and en dashes).
func clipRunes(s string, n int) string {
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n])
	}
	return s
}

// CorpusSurfaceBlock is corpus_surface_block: the compact bundle view of the
// sweep. nil when no artifact exists — the sweep is optional input, not a
// dependency.
func CorpusSurfaceBlock(c *state.Campaign, maxExposure,
	maxMatches int) (validation.Value, error) {
	path := filepath.Join(c.ArtifactsDir, CorpusSurfaceFile)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return validation.VNull(), nil
		}
		return validation.VNull(), err
	}
	rep, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	exposure := listAt(rep, "class_exposure")
	if len(exposure) > maxExposure {
		exposure = exposure[:maxExposure]
	}
	top := make([]validation.Value, 0, len(exposure))
	for _, r := range exposure {
		hits := listAt(r, "hits")
		if len(hits) > 5 {
			hits = hits[:5]
		}
		top = append(top, validation.VObj(
			validation.KV{K: "bug_class", V: objAt(r, "bug_class")},
			validation.KV{K: "exposed", V: objAt(r, "exposed")},
			validation.KV{K: "score", V: objAt(r, "score")},
			validation.KV{K: "confidence", V: objAt(r, "confidence")},
			validation.KV{K: "corpus_weight", V: objAt(r, "corpus_weight")},
			validation.KV{K: "hits", V: validation.VArr(hits...)},
		))
	}
	matches := listAt(rep, "shape_matches")
	if len(matches) > maxMatches {
		matches = matches[:maxMatches]
	}
	shapeRows := make([]validation.Value, 0, len(matches))
	for _, m := range matches {
		ids := strListAt(m, "memory_ids")
		if len(ids) > 3 {
			ids = ids[:3]
		}
		shapeRows = append(shapeRows, validation.VObj(
			validation.KV{K: "file", V: objAt(m, "file")},
			validation.KV{K: "exact", V: validation.VInt(int64(len(listAt(m, "exact_hits"))))},
			validation.KV{K: "near", V: validation.VInt(int64(len(listAt(m, "near_misses"))))},
			validation.KV{K: "bug_class", V: objAt(m, "bug_class")},
			validation.KV{K: "memory_ids", V: strArr(ids)},
		))
	}
	unprobed := make([]string, 0)
	for _, kv := range objAt(rep, "unprobed_classes").O {
		unprobed = append(unprobed, kv.K)
	}
	sort.Strings(unprobed)
	return validation.VObj(
		validation.KV{K: "advisory", V: validation.VBool(true)},
		validation.KV{K: "top_exposure", V: validation.VArr(top...)},
		validation.KV{K: "shape_matches", V: validation.VArr(shapeRows...)},
		validation.KV{K: "unprobed_classes", V: strArr(unprobed)},
	), nil
}

// strArr builds a JSON array of strings.
func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}
