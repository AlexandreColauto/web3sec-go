// Package corpus ports webv2.corpus_surface: the deterministic sweep of the
// ingested exploit corpus against a campaign's structural surface. Two probe
// layers, one report:
//
//  1. class probes — per-bug-class applicability predicates over the
//     structural index, corpus-weighted by historical frequency and loss;
//  2. PoC shape-match — call-shape signatures extracted from the local
//     DeFiHackLabs PoCs, matched against the target's exported surface.
//
// Contract (architecture law): NO model calls anywhere in this package or
// its CLI path. Deterministic: same inputs -> byte-identical report (explicit
// ordering everywhere). Advisory: results never set finding status, mint
// hypotheses, or block the pipeline — they tell the proposer what the corpus
// says this surface resembles.
package corpus

import (
	"errors"
	"math"

	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"websec/internal/classweights"
	"websec/internal/state"
	"websec/internal/validation"
)

// lossRe is LOSS_RE.
var lossRe = regexp.MustCompile(`Reported loss: ([\d,]+(?:\.\d+)?)\s*USD`)

// ErrDatasetAbsent is Python's FileNotFoundError from
// datasets.defihacklabs.load_records when the explorer clone is absent: the
// seam's documented absent-data signal.
var ErrDatasetAbsent = errors.New("defihacklabs explorer clone absent")

// LoadSharedMemory is shared_memory.load_shared_memory: the wrapped rows
// ({"row": {...}, "scope": ..., "program_key": ..., "published_at": ...})
// visible to a campaign root, both tiers. internal/sharedmem is not ported
// yet, so the default is Python's absent-store behavior (no rows). When it
// lands it calls SetLoadSharedMemory(sharedmem.LoadSharedMemory).
var LoadSharedMemory = func(root string) ([]validation.Value, error) {
	return nil, nil
}

// SetLoadSharedMemory installs the shared-memory store reader; nil restores
// the absent-store default.
func SetLoadSharedMemory(f func(root string) ([]validation.Value, error)) {
	if f == nil {
		LoadSharedMemory = func(root string) ([]validation.Value, error) {
			return nil, nil
		}
		return
	}
	LoadSharedMemory = f
}

// ListEvalCases is eval_store.list_cases: every evaluation case, in store
// order. internal/evalstore is not ported yet, so the default is Python's
// empty-store behavior. The setter is the wiring point when it lands.
var ListEvalCases = func() ([]validation.Value, error) { return nil, nil }

// SetListEvalCases installs the eval-store reader; nil restores the
// empty-store default.
func SetListEvalCases(f func() ([]validation.Value, error)) {
	if f == nil {
		ListEvalCases = func() ([]validation.Value, error) { return nil, nil }
		return
	}
	ListEvalCases = f
}

// LoadPocRecords is datasets.defihacklabs.load_records(explorer_dir,
// poc_root): the incident records, each carrying exploit.poc_path and id. The
// dataset module is not ported yet, so the default reports the clone absent
// (ErrDatasetAbsent) — attribution is then simply absent, shapes are still
// reported and poc_missing is 0, exactly Python's absent-clone path.
var LoadPocRecords = func(explorerDir, pocRoot *string) ([]validation.Value, error) {
	return nil, ErrDatasetAbsent
}

// SetLoadPocRecords installs the dataset record loader; nil restores the
// absent-clone default.
func SetLoadPocRecords(f func(explorerDir, pocRoot *string) ([]validation.Value, error)) {
	if f == nil {
		LoadPocRecords = func(explorerDir, pocRoot *string) ([]validation.Value, error) {
			return nil, ErrDatasetAbsent
		}
		return
	}
	LoadPocRecords = f
}

// PocRoot is DfH.POC_ROOT. Python resolves it against REPO_ROOT (the tree
// above src/webv2); a Go binary has no source-relative root, so it is the
// same path relative to the process working directory. An absent directory is
// a legitimate input state for this advisory sweep: the shape leg degrades to
// [] and attribution/poc_missing to ({}, 0).
var PocRoot = "data/datasets/DeFiHackLabs"

// SetPocRoot points the default PoC corpus at dir.
func SetPocRoot(dir string) { PocRoot = dir }

// ClassInventory is class_inventory: per-bug-class corpus stats from both
// prior-knowledge stores — the shared-memory store (both tiers; approved rows
// only by publish discipline) and the hash-verified eval store filtered to
// outcome=confirmed-exploitable with a mapped bug_class. Unmapped
// confirmed-exploitable cases are counted, not silently dropped.
func ClassInventory(c *state.Campaign) (validation.Value, error) {
	inv := map[string]*classEntry{}
	rows, err := LoadSharedMemory(c.Root)
	if err != nil {
		return validation.VNull(), err
	}
	addMemoryRows(inv, rows)
	cases, err := ListEvalCases()
	if err != nil {
		return validation.VNull(), err
	}
	unmapped := addEvalCases(inv, cases)
	return inventoryValue(inv, unmapped), nil
}

// classEntry is one taxonomy class's aggregated inventory.
type classEntry struct {
	memoryRows int64
	evalCases  int64
	lossSum    float64
	severity   map[string]int64
}

// classEntryFor returns (creating if needed) the class's accumulator.
func classEntryFor(inv map[string]*classEntry, cls string) *classEntry {
	e, ok := inv[cls]
	if !ok {
		e = &classEntry{severity: map[string]int64{}}
		inv[cls] = e
	}
	return e
}

// addMemoryRows folds the shared-memory store into the inventory: rows with
// no class (or "unmapped") are skipped, and a "Reported loss: N USD" summary
// adds N to the class's loss sum.
func addMemoryRows(inv map[string]*classEntry, rows []validation.Value) {
	for _, w := range rows {
		row := wrappedRow(w)
		cls := validation.ObjStr(row, "bug_class")
		if cls == "" || cls == "unmapped" {
			continue
		}
		e := classEntryFor(inv, cls)
		e.memoryRows++
		if m := lossRe.FindStringSubmatch(validation.ObjStr(row, "evidence_summary")); m != nil {
			if v, perr := parsePyFloat(strings.ReplaceAll(m[1], ",", "")); perr == nil {
				e.lossSum += v
			}
		}
	}
}

// addEvalCases folds the hash-verified eval store in, counting the
// confirmed-exploitable cases whose class is missing or "unmapped".
func addEvalCases(inv map[string]*classEntry, cases []validation.Value) int64 {
	unmapped := int64(0)
	for _, cse := range cases {
		g := validation.ObjAt(cse, "gold")
		if g.Kind != validation.Obj {
			continue
		}
		if validation.ObjStr(g, "outcome") != "confirmed-exploitable" {
			continue
		}
		cls := validation.ObjStr(g, "bug_class")
		if cls == "" || cls == "unmapped" {
			unmapped++
			continue
		}
		e := classEntryFor(inv, cls)
		e.evalCases++
		sev := validation.ObjStr(g, "severity")
		if sev == "" {
			sev = "unknown"
		}
		e.severity[sev]++
	}
	return unmapped
}

// inventoryValue renders the inventory: classes sorted by name, severity
// counts sorted within each class (byte-stable ordering).
func inventoryValue(inv map[string]*classEntry, unmapped int64) validation.Value {
	classes := make([]string, 0, len(inv))
	for cls := range inv {
		classes = append(classes, cls)
	}
	sort.Strings(classes)
	classVals := make([]validation.KV, 0, len(classes))
	for _, cls := range classes {
		e := inv[cls]
		sevs := make([]string, 0, len(e.severity))
		for s := range e.severity {
			sevs = append(sevs, s)
		}
		sort.Strings(sevs)
		sevKVs := make([]validation.KV, 0, len(sevs))
		for _, s := range sevs {
			sevKVs = append(sevKVs, validation.KV{K: s,
				V: validation.VInt(e.severity[s])})
		}
		classVals = append(classVals, validation.KV{K: cls, V: validation.VObj(
			validation.KV{K: "memory_rows", V: validation.VInt(e.memoryRows)},
			validation.KV{K: "eval_cases", V: validation.VInt(e.evalCases)},
			validation.KV{K: "loss_usd_sum", V: validation.VFloat(e.lossSum)},
			validation.KV{K: "severity_counts", V: validation.VObj(sevKVs...)},
		)})
	}
	return validation.VObj(
		validation.KV{K: "classes", V: validation.VObj(classVals...)},
		validation.KV{K: "unmapped_confirmed_exploitable", V: validation.VInt(unmapped)},
	)
}

// wrappedRow is `w["row"] if isinstance(w, dict) and "row" in w else w`.
func wrappedRow(w validation.Value) validation.Value {
	if w.Kind == validation.Obj {
		for _, kv := range w.O {
			if kv.K == "row" {
				return kv.V
			}
		}
	}
	return w
}

// scopeOf is `w.get("scope") if isinstance(w, dict) else None`.
func scopeOf(w validation.Value) validation.Value {
	if w.Kind == validation.Obj {
		return validation.ObjAt(w, "scope")
	}
	return validation.VNull()
}

// ConfidenceFactor is CONFIDENCE_FACTOR.
var ConfidenceFactor = map[string]float64{"high": 1.0, "medium": 0.5, "low": 0.25}

// searchFactor is the test seam over classweights.SearchFactor, and the ONLY
// graduation door: G3 may move numbers only in the JSON table, never in code.
var searchFactor = classweights.SearchFactor

// ExposureRows is exposure_rows: join corpus weights with probe results into
// a ranked exposure list.
//
// score = hit_count * log2(1 + corpus_weight) * CONFIDENCE_FACTOR[confidence]
// (rounded to 6 decimals). The confidence factor keeps loose/catch-all
// predicates from dominating the top slot: a low-confidence class needs
// proportionally more structural hits to outrank a tight one. Aliased classes
// score with their own inventory weight — they are distinct corpus entries
// sharing a predicate. Sorted by (-score, -loss_usd_sum, bug_class).
//
// The corpus weight deliberately counts shared rows WITHOUT program-key or
// partition filtering: the weight measures how much confirmed evidence exists
// that a bug CLASS is real and recurring anywhere in the corpus, not how
// relevant it is to this campaign's program.
func ExposureRows(inventory validation.Value, probed []validation.Value) []validation.Value {
	type row struct {
		val   validation.Value
		score float64
		loss  float64
		cls   string
	}
	rows := make([]row, 0, len(probed))
	for _, p := range probed {
		cls := validation.ObjStr(p, "bug_class")
		inv := validation.ObjAt(validation.ObjAt(inventory, "classes"), cls)
		weight := intAt(inv, "memory_rows") + intAt(inv, "eval_cases")
		hits := listAt(p, "hits")
		score := float64(len(hits)) * math.Log2(1+float64(weight)) *
			ConfidenceFactor[validation.ObjStr(p, "confidence")] * searchFactor(cls)
		score = validation.PythonRound(score, 6)
		loss := floatAt(inv, "loss_usd_sum")
		rows = append(rows, row{
			cls:   cls,
			score: score,
			loss:  loss,
			val: validation.VObj(
				validation.KV{K: "bug_class", V: validation.VStr(cls)},
				validation.KV{K: "exposed", V: validation.ObjAt(p, "exposed")},
				validation.KV{K: "hits", V: validation.ObjAt(p, "hits")},
				validation.KV{K: "confidence", V: validation.ObjAt(p, "confidence")},
				validation.KV{K: "corpus_weight", V: validation.VInt(int64(weight))},
				validation.KV{K: "loss_usd_sum", V: validation.VFloat(loss)},
				validation.KV{K: "score", V: validation.VFloat(score)},
			),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		if rows[i].loss != rows[j].loss {
			return rows[i].loss > rows[j].loss
		}
		return rows[i].cls < rows[j].cls
	})
	out := make([]validation.Value, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.val)
	}
	return out
}

// CoverageGaps is coverage_gaps: corpus classes with no probe, alias, or
// unprobed entry.
func CoverageGaps(inventory validation.Value) []string {
	known := map[string]bool{}
	for cls := range Probes {
		known[cls] = true
	}
	for alias := range Aliases {
		known[alias] = true
	}
	for cls := range Unprobed {
		known[cls] = true
	}
	var out []string
	for _, kv := range validation.ObjAt(inventory, "classes").O {
		if !known[kv.K] {
			out = append(out, kv.K)
		}
	}
	sort.Strings(out)
	return out
}

// ActiveSnapshotRoot is _active_snapshot_root: the root of the ACTIVE pin,
// read from the pinned manifest — the same resolution the orchestrator uses
// (state.active_snapshot() returns only the summary row; the full manifest
// with source.root lives in the pin dir's snapshot.json).
func ActiveSnapshotRoot(c *state.Campaign) (string, error) {
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return "", err
	}
	if sid == nil {
		return "", &NoActiveSnapshotError{CampaignID: c.CampaignID}
	}
	meta, err := validation.ReadJson(snapshotManifestPath(c, *sid))
	if err != nil {
		return "", err
	}
	root := validation.ObjStr(validation.ObjAt(meta, "source"), "root")
	return root, nil
}

// NoActiveSnapshotError is the ValueError `_active_snapshot_root` raises.
type NoActiveSnapshotError struct{ CampaignID string }

func (e *NoActiveSnapshotError) Error() string {
	return "campaign " + e.CampaignID + " has no active snapshot — " +
		"pin one (webv2 snap) before running the corpus sweep"
}

func snapshotManifestPath(c *state.Campaign, sid string) string {
	return filepath.Join(c.Dir, "snapshots", sid, "snapshot.json")
}

// ---- helpers -------------------------------------------------------------

func listAt(v validation.Value, key string) []validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}

func strListAt(v validation.Value, key string) []string {
	var out []string
	for _, e := range listAt(v, key) {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func intAt(v validation.Value, key string) int64 {
	x := validation.ObjAt(v, key)
	switch x.Kind {
	case validation.Int:
		if x.Big != "" {
			return 0
		}
		return x.I
	case validation.Flt:
		return int64(x.F)
	}
	return 0
}

func floatAt(v validation.Value, key string) float64 {
	x := validation.ObjAt(v, key)
	switch x.Kind {
	case validation.Flt:
		return x.F
	case validation.Int:
		return float64(x.I)
	}
	return 0.0
}

// sortedKeys is sorted(map keys) for a membership set.

// parsePyFloat is Python's float(str) for a plain decimal (the LOSS_RE group
// always is one), keeping the error path the caller swallows.
func parsePyFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}
