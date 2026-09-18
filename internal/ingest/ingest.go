// Package ingest ports webv2.ingest: the adapter contract's framework side.
//
// WHY: public datasets (ScaBench, DeFiHackLabs, FORGE) label the same bug with
// different vocabularies and different outcome words. Adapters pre-digest raw
// records into ONE common shape; this module turns that shape into
// framework-owned structures — a validated evaluation case, v2 memory rows,
// and a campaign seed — plus the two shared-store operations the sprint needs
// (first-class program-key replace, batched publish). Adapters own parsing;
// THIS module owns normalization, identity, and store writes, so a bad label
// or a leaky partition is stopped in exactly one place.
//
// Everything here is framework-decided (no model calls). IngestRecord is PURE
// (no IO); only ReplaceProgramKey / PublishIngested touch the stores, and only
// through manifest-logged operations.
package ingest

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/evalstore"
	"websec/internal/learning"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// Outcomes is the six adjudicated ground-truth outcomes (evaluation_case
// gold.outcome).
var Outcomes = []string{
	"confirmed-exploitable",
	"confirmed-not-exploitable",
	"disproved",
	"out-of-scope",
	"duplicate",
	"economic-no-go",
}

// datasets is the adapter registry's dataset vocabulary.
var datasets = []string{
	"scabench", "defihacklabs", "defihacklabs-explorer", "forge",
	"forge-curated", "c4audit", "sherlock", "immunefi-resolved",
	"smartbugs-curated", "manual",
}

// negativeByOutcome is _NEGATIVE_BY_OUTCOME: outcome -> (status,
// rejection_class) for NEGATIVE rows. "confirmed-exploitable" is absent on
// purpose — a confirmed-exploitable finding is not a non-issue, so
// negative=True with that outcome is a caller bug.
var negativeByOutcome = map[string]struct {
	Status    string
	Rejection *string
}{
	"disproved":                 {"DISPROVED", strPtr("invalid-hypothesis")},
	"confirmed-not-exploitable": {"UNREACHABLE", strPtr("not-exploitable")},
	"economic-no-go":            {"NON-ECONOMIC", strPtr("below-threshold")},
	"out-of-scope":              {"OUT_OF_SCOPE", strPtr("invalid-hypothesis")},
	"duplicate":                 {"DUPLICATE", nil},
}

// Result is ingest_record's return dict. CampaignSeed nil is Python's None.
type Result struct {
	EvalCase     validation.Value
	MemoryRows   []validation.Value
	CampaignSeed *validation.Value
	Canonical    string
	Mapped       bool
}

// Value renders the result as Python's dict (taxonomy as a 2-tuple).
func (r Result) Value() validation.Value {
	seed := validation.VNull()
	if r.CampaignSeed != nil {
		seed = *r.CampaignSeed
	}
	return validation.VObj(
		validation.KV{K: "eval_case", V: r.EvalCase},
		validation.KV{K: "memory_rows", V: validation.VArr(r.MemoryRows...)},
		validation.KV{K: "campaign_seed", V: seed},
		validation.KV{K: "taxonomy", V: validation.VArr(
			validation.VStr(r.Canonical), validation.VBool(r.Mapped))})
}

// IngestRecord is ingest_record: turn one common-shape adapter record into
// framework structures. PURE. maps nil loads every repo map file.
func IngestRecord(record validation.Value, maps *validation.Value) (Result, error) {
	if record.Kind != validation.Obj {
		return Result{}, errors.New("an ingestion record must be a dict")
	}
	dataset := validation.ObjStr(record, "dataset")
	if !slices.Contains(datasets, dataset) {
		return Result{}, fmt.Errorf("record %s: unknown dataset %s",
			validation.PyRepr(validation.ObjAt(record, "id")),
			validation.PyRepr(validation.ObjAt(record, "dataset")))
	}
	rid := validation.ObjAt(record, "id")
	if rid.Kind != validation.Str || rid.S == "" {
		return Result{}, errors.New("record 'id' must be a non-empty string")
	}
	outcome := validation.ObjStr(record, "outcome")
	if !slices.Contains(Outcomes, outcome) {
		return Result{}, fmt.Errorf("record %s: unknown outcome %s; expected "+
			"one of %s", validation.PyReprStr(rid.S),
			validation.PyRepr(validation.ObjAt(record, "outcome")), pyTuple(Outcomes))
	}
	partition := validation.ObjStr(record, "partition")
	if !slices.Contains([]string{"dev", "held-out", "training"}, partition) {
		return Result{}, fmt.Errorf("record %s: unknown partition %s",
			validation.PyReprStr(rid.S),
			validation.PyRepr(validation.ObjAt(record, "partition")))
	}
	title, err := requireStr(record, "title", 5, 500)
	if err != nil {
		return Result{}, err
	}
	description, err := requireStr(record, "description", 20, 10000)
	if err != nil {
		return Result{}, err
	}
	rootCause, err := requireStr(record, "root_cause", 10, 2000)
	if err != nil {
		return Result{}, err
	}
	negative := truthy(validation.ObjAt(record, "negative"))
	prior := truthy(validation.ObjAt(record, "prior"))
	if negative && prior {
		return Result{}, fmt.Errorf(
			"record %s: 'negative' and 'prior' are mutually exclusive",
			validation.PyReprStr(rid.S))
	}
	pattern := validation.ObjAt(record, "pattern")
	if negative || prior {
		n := utf8.RuneCountInString(pattern.S)
		if pattern.Kind != validation.Str || n < 10 || n > 500 {
			return Result{}, fmt.Errorf(
				"record %s: 'pattern' (10-500 chars) is required when "+
					"'negative' or 'prior' is set", validation.PyReprStr(rid.S))
		}
	}
	program := validation.ObjAt(record, "program")
	programName := validation.ObjStr(program, "program")
	if programName == "" {
		return Result{}, fmt.Errorf(
			"record %s: program.program must be non-empty",
			validation.PyReprStr(rid.S))
	}
	label := strOrNil(validation.ObjAt(record, "bug_class_label"))
	canonical, mapped, err := taxonomy.NormalizeClass(label, maps)
	if err != nil {
		return Result{}, err
	}
	caseID := "CASE-" + validation.Sha12Hex([]byte(dataset+"|"+rid.S))
	source := []validation.KV{
		{K: "dataset", V: validation.VStr(dataset)},
		{K: "record_id", V: validation.VStr(rid.S)},
	}
	if u := validation.ObjAt(record, "url"); truthy(u) {
		source = append(source, validation.KV{K: "url", V: u})
	}
	locations, err := buildLocations(record, rid.S)
	if err != nil {
		return Result{}, err
	}
	codeIn := validation.ObjAt(record, "code")
	repo := validation.ObjStr(codeIn, "repo")
	if repo == "" {
		return Result{}, fmt.Errorf("record %s: code.repo must be non-empty",
			validation.PyReprStr(rid.S))
	}
	code, err := buildCode(codeIn, repo)
	if err != nil {
		return Result{}, err
	}
	evalCase := buildEvalCase(evalCaseArgs{
		caseID: caseID, source: source, partition: partition,
		program: program, programName: programName, outcome: outcome,
		canonical: canonical, severity: validation.ObjAt(record, "severity"),
		rootCause: rootCause, locations: locations, code: code,
		notes: truncRunes(title+"\n\n"+description, 1000),
	})
	if err := validation.Validate(evalCase, "evaluation_case", 1); err != nil {
		return Result{}, err
	}
	rows, err := memoryRows(record, memoryArgs{
		rid: rid.S, dataset: dataset, caseID: caseID, negative: negative,
		prior: prior, canonical: canonical, partition: partition,
		pattern: pattern, description: description, outcome: outcome})
	if err != nil {
		return Result{}, err
	}
	var seed *validation.Value
	if strings.TrimSpace(repo) != "" {
		s := validation.VObj(
			validation.KV{K: "case_id", V: validation.VStr(caseID)},
			validation.KV{K: "repo", V: validation.VStr(repo)},
			validation.KV{K: "commit", V: nullIfAbsent(codeIn, "commit")},
			validation.KV{K: "focus_files", V: validation.VArr(
				valsOf(validation.ObjAt(codeIn, "files"))...)},
			validation.KV{K: "expected", V: validation.VObj(
				validation.KV{K: "outcome", V: validation.VStr(outcome)},
				validation.KV{K: "bug_class", V: validation.VStr(canonical)},
				validation.KV{K: "root_cause", V: validation.VStr(rootCause)})})
		seed = &s
	}
	return Result{EvalCase: evalCase, MemoryRows: rows, CampaignSeed: seed,
		Canonical: canonical, Mapped: mapped}, nil
}

// ---- ingest_record helpers ----------------------------------------------

func buildLocations(record validation.Value, rid string) ([]validation.Value, error) {
	out := []validation.Value{}
	for _, loc := range valsOf(validation.ObjAt(record, "locations")) {
		file := validation.ObjStr(loc, "file")
		if loc.Kind != validation.Obj || file == "" {
			return nil, fmt.Errorf("record %s: each location needs a 'file'",
				validation.PyReprStr(rid))
		}
		entry := []validation.KV{{K: "file", V: validation.VStr(file)}}
		if line := validation.ObjAt(loc, "line"); line.Kind != validation.Null {
			entry = append(entry, validation.KV{K: "line", V: line})
		}
		out = append(out, validation.VObj(entry...))
	}
	return out, nil
}

func buildCode(codeIn validation.Value, repo string) (validation.Value, error) {
	out := []validation.KV{{K: "repo", V: validation.VStr(repo)}}
	if v := validation.ObjAt(codeIn, "commit"); truthy(v) {
		out = append(out, validation.KV{K: "commit", V: v})
	}
	if v := validation.ObjAt(codeIn, "files"); truthy(v) {
		out = append(out, validation.KV{K: "files", V: validation.VArr(
			valsOf(v)...)})
	}
	if v := validation.ObjAt(codeIn, "snapshot_note"); truthy(v) {
		out = append(out, validation.KV{K: "snapshot_note", V: v})
	}
	return validation.VObj(out...), nil
}

type evalCaseArgs struct {
	caseID      string
	source      []validation.KV
	partition   string
	program     validation.Value
	programName string
	outcome     string
	canonical   string
	severity    validation.Value
	rootCause   string
	locations   []validation.Value
	code        validation.Value
	notes       string
}

func buildEvalCase(a evalCaseArgs) validation.Value {
	return validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(a.caseID)},
		validation.KV{K: "source", V: validation.VObj(a.source...)},
		validation.KV{K: "partition", V: validation.VStr(a.partition)},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr(a.programName)},
			validation.KV{K: "platform", V: nullIfAbsent(a.program, "platform")},
			validation.KV{K: "chains", V: validation.VArr(
				valsOf(validation.ObjAt(a.program, "chains"))...)})},
		validation.KV{K: "gold", V: validation.VObj(
			validation.KV{K: "outcome", V: validation.VStr(a.outcome)},
			validation.KV{K: "bug_class", V: validation.VStr(a.canonical)},
			validation.KV{K: "severity", V: a.severity},
			validation.KV{K: "root_cause", V: validation.VStr(a.rootCause)},
			validation.KV{K: "locations", V: validation.VArr(a.locations...)})},
		validation.KV{K: "code", V: a.code},
		// The schema has no title/description fields; keep them reachable
		// through notes (truncated to the schema's limit) instead of
		// dropping them — source.record_id stays the bridge back.
		validation.KV{K: "notes", V: validation.VStr(a.notes)},
		validation.KV{K: "created_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "schema_version", V: validation.VInt(2)})
}

type memoryArgs struct {
	rid         string
	dataset     string
	caseID      string
	negative    bool
	prior       bool
	canonical   string
	partition   string
	pattern     validation.Value
	description string
	outcome     string
}

func memoryRows(record validation.Value, a memoryArgs) ([]validation.Value, error) {
	rows := []validation.Value{}
	stamp := state.NowIso()
	if a.negative {
		if a.outcome == "confirmed-exploitable" {
			return nil, fmt.Errorf("record %s: outcome "+
				"'confirmed-exploitable' is not a non-issue — negative=True "+
				"contradicts it", validation.PyReprStr(a.rid))
		}
		spec := negativeByOutcome[a.outcome]
		row, err := memoryRow(memoryRowArgs{
			recordID: a.rid, dataset: a.dataset, caseID: a.caseID,
			kind: "disproved", status: spec.Status,
			rejectionClass: spec.Rejection, pattern: a.pattern.S,
			bugClass: a.canonical, partition: a.partition,
			evidence: a.description, at: stamp})
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	} else if a.prior && a.canonical != taxonomy.UNMAPPED {
		// A classless prior is useless as a prior (nothing to match on).
		row, err := memoryRow(memoryRowArgs{
			recordID: a.rid, dataset: a.dataset, caseID: a.caseID,
			kind: "confirmed", status: "CONFIRMED", pattern: a.pattern.S,
			bugClass: a.canonical, partition: a.partition,
			evidence: a.description, at: stamp})
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

type memoryRowArgs struct {
	recordID       string
	dataset        string
	caseID         string
	kind           string
	status         string
	rejectionClass *string
	pattern        string
	bugClass       string
	partition      string
	evidence       string
	at             string
}

// memoryRow is _memory_row: one v2 memory row, validated. Provenance rides
// the schema's own source fields: campaign_id names the ingestion origin.
func memoryRow(a memoryRowArgs) (validation.Value, error) {
	rejection := validation.VNull()
	if a.rejectionClass != nil {
		rejection = validation.VStr(*a.rejectionClass)
	}
	row := validation.VObj(
		validation.KV{K: "memory_id", V: validation.VStr("MEM-" +
			validation.Sha12Hex([]byte(a.caseID+"|"+a.kind+"|"+a.status)))},
		validation.KV{K: "campaign_id", V: validation.VStr(
			"ingest:" + a.dataset + ":" + a.recordID)},
		validation.KV{K: "finding_id", V: validation.VNull()},
		validation.KV{K: "snapshot_id", V: validation.VNull()},
		validation.KV{K: "created_at", V: validation.VStr(a.at)},
		validation.KV{K: "kind", V: validation.VStr(a.kind)},
		validation.KV{K: "status", V: validation.VStr(a.status)},
		validation.KV{K: "pattern", V: validation.VStr(a.pattern)},
		validation.KV{K: "bug_class", V: validation.VStr(a.bugClass)},
		validation.KV{K: "cwe", V: validation.VNull()},
		validation.KV{K: "evidence_summary", V: validation.VStr(a.evidence)},
		validation.KV{K: "partition", V: validation.VStr(a.partition)},
		validation.KV{K: "schema_version", V: validation.VInt(
			learning.MemorySchemaVersion)},
		validation.KV{K: "rejection_class", V: rejection},
		// Ingested rows carry class/pattern matching only — proposition
		// matching is for campaign-learned rows.
		validation.KV{K: "deciding_propositions", V: validation.VArr()},
		validation.KV{K: "promotion_status", V: validation.VStr("promoted")},
		validation.KV{K: "approved_by", V: validation.VStr("dataset-ingestion")},
		validation.KV{K: "approved_at", V: validation.VStr(a.at)})
	if err := validation.Validate(row, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// ---- shared-store operations --------------------------------------------

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

// ---- small helpers -------------------------------------------------------

func strPtr(s string) *string { return &s }

// truthy is Python's bool() over the JSON values the records carry.
func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0 || v.Big != "" && v.Big != "0"
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func valsOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

func nullIfAbsent(v validation.Value, key string) validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Null {
		return validation.VNull()
	}
	return x
}

// strOrNil is a nullable string read (None when absent or not a string).
func strOrNil(v validation.Value) *string {
	if v.Kind != validation.Str {
		return nil
	}
	return &v.S
}

// requireStr is _require_str.
func requireStr(record validation.Value, key string, lo, hi int) (string, error) {
	value := validation.ObjAt(record, key)
	if value.Kind != validation.Str {
		return "", fmt.Errorf("record %s: %s must be a string of %d-%d chars",
			validation.PyRepr(validation.ObjAt(record, "id")), validation.PyReprStr(key),
			lo, hi)
	}
	n := utf8.RuneCountInString(value.S)
	if n < lo || n > hi {
		return "", fmt.Errorf("record %s: %s must be a string of %d-%d chars",
			validation.PyRepr(validation.ObjAt(record, "id")), validation.PyReprStr(key),
			lo, hi)
	}
	return value.S, nil
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// pyTuple is Python's tuple repr for the outcome-vocabulary error message.
func pyTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
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
