// Package immunefi is the Wave G G3 adapter: Immunefi resolved-report
// verdicts into the Outcomes vocabulary, written through evalstore.AddCase.
//
// WHY (verbatim intent): a resolved triage verdict is adjudicated public
// ground truth — never training fuel for self-test — so every loaded row
// lands held-out unless the caller overrides the partition, and every
// ingested case keeps its provenance (source.dataset immunefi-resolved,
// source.record_id the row id, source.url the record url). The status
// dialect is small but sharp: accepted (paid or not), downgraded and split
// are all acceptances, hence confirmed-exploitable; rejected is disproved.
// A downgrade keeps its history in the notes string ("downgraded from X",
// X = the row's downgraded_from when present else its severity); the paid
// fact rides the notes string verbatim ("paid_usd=<amount>") and NEVER a
// hand-added gold.paid key — gold has additionalProperties:false, so AddCase
// would reject it. Severity passes through per the policy bands
// (critical/high/medium/low, case-insensitive); critical folds to high with
// a notes marker because the evaluation_case severity enum carries no
// critical band; anything else (Informational, absent) is null. An unknown
// status string is a loud LoadRecords error naming the row id — never a
// silent default.
//
// Code pointers are synthetic by design (G7 honesty): resolved Immunefi data
// ships no pinned snapshot, so code.repo is immunefi://<program> with an
// empty files list and a snapshot_note saying exactly that; the record url
// in source.url is the cite. No commit is stamped: the evaluation_case
// schema only accepts ^[0-9a-f]{7,64}$ there, so anything but a real pinned
// hash would fail validation.
//
// program.platform is "immunefi" (not null): the platform IS known here —
// the schema's platform is an optional free string with no enum (Step 0
// confirmed: type ["string","null"], immunefi/cantina/sherlock live only in
// the description), so no legend-pin dance is needed.
//
// Style mirrors internal/datasets/c4audit+sherlock: strict parse,
// deterministic (file-order) output, validation.Value docs throughout, no
// new dependencies.
package immunefi

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"websec/internal/evalstore"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

const (
	// Dataset is the registry name (added to the ingest datasets list and
	// the evaluation_case source.dataset enum by this task).
	Dataset = "immunefi-resolved"
	// DefaultPartition is this loader's law: adjudicated public data is
	// ground truth, never training fuel for self-test.
	DefaultPartition = "held-out"
	// Platform is the program.platform stamp: known, free-string, no enum.
	Platform = "immunefi"
	// RootCauseMin / RootCauseMax are the evaluation_case schema's
	// root_cause bounds (minLength 10, maxLength 2000).
	RootCauseMin = 10
	RootCauseMax = 2000
)

// statusToOutcome is the brief's verbatim status-mapping table as a named map
// (the drift test reads this symbol). accepted+paid and accepted+!paid share
// one entry — the paid fact rides notes, never the outcome — and the
// downgrade/split entries carry note law applied in mapOutcome, documented
// here so the table stays the single source of truth:
//
//	accepted (+paid or not) -> confirmed-exploitable (acceptance is
//	                             acceptance; paid_usd rides notes verbatim)
//	rejected                -> disproved
//	downgraded              -> confirmed-exploitable + notes "downgraded
//	                             from X" (a downgrade is still an acceptance)
//	split                   -> confirmed-exploitable, one row per report
var statusToOutcome = map[string]string{
	"accepted":   "confirmed-exploitable",
	"rejected":   "disproved",
	"downgraded": "confirmed-exploitable",
	"split":      "confirmed-exploitable",
}

// severityToGold maps the row severity to the gold severity vocabulary per
// the policy bands. High/medium/low pass through lowercased; critical folds
// to high (the evaluation_case enum has no critical band — the fold is
// marked in notes); anything else (Informational, absent) is null: the row
// states no adjudicated severity the schema can carry.
var severityToGold = map[string]string{
	"critical": "high",
	"high":     "high",
	"medium":   "medium",
	"low":      "low",
}

// Partitions is the evaluation_case partition vocabulary (mirrors the schema
// enum so Ingest can reject a bad override loudly).
var Partitions = []string{"dev", "held-out", "training"}

// mapOutcome applies statusToOutcome. The paid fact does NOT reach the
// outcome by design — it rides the notes string (see buildCase) — so this
// function is deliberately not given it (H11: the parameter was accepted and
// immediately discarded, which read as if payment could change the outcome).
// rowID names the row in the unknown-status error.
func mapOutcome(status, rowID string) (string, error) {
	base, ok := statusToOutcome[status]
	if !ok {
		return "", fmt.Errorf("immunefi: unknown status %s for row %s",
			validation.PyReprStr(status), validation.PyReprStr(rowID))
	}
	return base, nil
}

// mapSeverity is severityToGold (case-insensitive) with a null default.
func mapSeverity(severity string) validation.Value {
	if gold, ok := severityToGold[strings.ToLower(severity)]; ok {
		return validation.VStr(gold)
	}
	return validation.VNull()
}

// severityFolded reports whether the row severity folds to a different gold
// band (today: only critical -> high).
func severityFolded(severity string) bool {
	gold, ok := severityToGold[strings.ToLower(severity)]
	return ok && !strings.EqualFold(severity, gold)
}

// shapeRootCause clips the root cause to the schema maximum and pads a short
// one to the schema minimum with the row id (deterministic; mirrors the
// c4audit/sherlock title padding — an adjudicated row is never dropped over
// a terse root cause).
func shapeRootCause(rootCause, rowID string) string {
	text := strings.TrimSpace(rootCause)
	if utf8.RuneCountInString(text) > RootCauseMax {
		text = string([]rune(text)[:RootCauseMax])
	}
	for utf8.RuneCountInString(text) < RootCauseMin {
		text += " [" + rowID + "]"
	}
	return text
}

// LoadRecords parses one normalized JSONL file into common-shape records in
// deterministic file order (blank lines skipped). Strict: every non-blank
// line must be a JSON object; id, status, root_cause, url and program must
// be non-empty strings; paid must be a bool when present; paid_usd,
// downgraded_from and severity strings when present; class falls back
// honestly (unmapped / null).
// The record shape:
//
//	{id, dataset, url, program, title (=root_cause), bug_class (canonical),
//	 outcome (mapped), severity (gold string or null),
//	 severity_raw (pre-mapping label, for the critical-fold marker),
//	 root_cause (shaped), partition (held-out),
//	 status, paid, paid_usd, downgraded_from (preserved for audit)}
func LoadRecords(path string) ([]validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records []validation.Value
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		doc, err := validation.ParseOrdered([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("immunefi: %s line %d: %v", path, i+1, err)
		}
		if doc.Kind != validation.Obj {
			return nil, fmt.Errorf("immunefi: %s line %d: must be a JSON object",
				path, i+1)
		}
		rec, err := buildRecord(doc)
		if err != nil {
			return nil, fmt.Errorf("immunefi: %s line %d: %v", path, i+1, err)
		}
		records = append(records, rec)
	}
	if records == nil {
		records = []validation.Value{}
	}
	return records, nil
}

// buildRecord validates one row object into a record (errors name the row id
// when one is present; in practice id is required first, so unknown-status
// errors always name the id).
func buildRecord(doc validation.Value) (validation.Value, error) {
	id := objStr(doc, "id")
	if id == "" {
		return validation.VNull(), fmt.Errorf("record 'id' must be a non-empty string")
	}
	status := objStr(doc, "status")
	if objAt(doc, "status").Kind != validation.Str || status == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'status' must be a non-empty string", validation.PyReprStr(id))
	}
	rootCause := objStr(doc, "root_cause")
	if rootCause == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'root_cause' must be a non-empty string", validation.PyReprStr(id))
	}
	url := objStr(doc, "url")
	if url == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'url' must be a non-empty string", validation.PyReprStr(id))
	}
	program := objStr(doc, "program")
	if program == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'program' must be a non-empty string", validation.PyReprStr(id))
	}
	paid := false
	if kv := objAt(doc, "paid"); kv.Kind != validation.Null {
		if kv.Kind != validation.Bool {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'paid' must be a bool", validation.PyReprStr(id))
		}
		paid = kv.B
	}
	paidUSD := ""
	if kv := objAt(doc, "paid_usd"); kv.Kind != validation.Null {
		if kv.Kind != validation.Str {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'paid_usd' must be a string", validation.PyReprStr(id))
		}
		paidUSD = kv.S
	}
	downgradedFrom := ""
	if kv := objAt(doc, "downgraded_from"); kv.Kind != validation.Null {
		if kv.Kind != validation.Str {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'downgraded_from' must be a string", validation.PyReprStr(id))
		}
		downgradedFrom = kv.S
	}
	severityRaw := ""
	if kv := objAt(doc, "severity"); kv.Kind != validation.Null {
		if kv.Kind != validation.Str {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'severity' must be a string", validation.PyReprStr(id))
		}
		severityRaw = kv.S
	}
	outcome, err := mapOutcome(status, id)
	if err != nil {
		return validation.VNull(), err
	}
	var label *string
	if c := objAt(doc, "class"); c.Kind == validation.Str && strings.TrimSpace(c.S) != "" {
		s := c.S
		label = &s
	}
	canonical, _, err := taxonomy.NormalizeClass(label, nil)
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"row %s: %v", validation.PyReprStr(id), err)
	}
	return validation.VObj(
		kv("id", validation.VStr(id)),
		kv("dataset", validation.VStr(Dataset)),
		kv("url", validation.VStr(url)),
		kv("program", validation.VStr(program)),
		kv("title", validation.VStr(rootCause)),
		kv("bug_class", validation.VStr(canonical)),
		kv("outcome", validation.VStr(outcome)),
		kv("severity", mapSeverity(severityRaw)),
		kv("severity_raw", validation.VStr(severityRaw)),
		kv("root_cause", validation.VStr(shapeRootCause(rootCause, id))),
		kv("partition", validation.VStr(DefaultPartition)),
		kv("status", validation.VStr(status)),
		kv("paid", validation.VBool(paid)),
		kv("paid_usd", validation.VStr(paidUSD)),
		kv("downgraded_from", validation.VStr(downgradedFrom)),
	), nil
}

// IngestOptions are Ingest's options. Partition overrides the rows'
// held-out default (the loader's law); Maps are the taxonomy maps used when
// a row carries a raw class label (nil loads the repo defaults — rows from
// LoadRecords already carry the canonical bug_class, which Ingest trusts and
// AddCase re-validates).
type IngestOptions struct {
	Partition *string
	Maps      *validation.Value
}

// Ingest writes rows as evaluation cases through evalstore.AddCase (which
// validates each case against the evaluation_case schema). store repoints the
// eval store at a directory for the call (tests pass a temp dir); empty
// means the ambient WEBV2_EVAL_DIR / cwd-relative default. Returns the stored
// case docs in row order. case_id is deterministic
// (CASE-<sha12 of "immunefi-resolved|"+row id> — validation.Sha12Hex, the
// SAME derivation ingest uses (H11 removed the private twin))
// so a replay over the same rows yields the same ids; created_at stamps
// state.NowIso() (the WEBV2_NOW pin), so determinism lives in the row
// CONTENT, not the timestamp.
func Ingest(store string, rows []validation.Value, opts IngestOptions) ([]validation.Value, error) {
	if store != "" {
		evalstore.SetEvalDir(store)
	}
	partition := ""
	if opts.Partition != nil {
		partition = *opts.Partition
		if !inList(partition, Partitions) {
			return nil, fmt.Errorf("immunefi: unknown partition %s",
				validation.PyReprStr(partition))
		}
	}
	out := make([]validation.Value, 0, len(rows))
	for i, row := range rows {
		doc, err := buildCase(row, i, partition, opts.Maps)
		if err != nil {
			return nil, err
		}
		stored, err := evalstore.AddCase(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, stored)
	}
	return out, nil
}

// buildCase renders one loaded record as an evaluation_case doc (pre-stamp;
// AddCase owns case_id/partition/schema_version/created_at defaults, but the
// caller-visible fields are set here so the doc is complete and deterministic
// before validation).
func buildCase(row validation.Value, index int, partitionOverride string, maps *validation.Value) (validation.Value, error) {
	if row.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("immunefi: row %d must be a dict", index)
	}
	id := objStr(row, "id")
	if id == "" {
		return validation.VNull(), fmt.Errorf("immunefi: row %d: 'id' must be a non-empty string", index)
	}
	program := objStr(row, "program")
	if program == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'program' must be a non-empty string", validation.PyReprStr(id))
	}
	outcome := objStr(row, "outcome")
	if !inList(outcome, Outcomes) {
		return validation.VNull(), fmt.Errorf(
			"row %s: unknown outcome %s", validation.PyReprStr(id),
			validation.PyRepr(objAt(row, "outcome")))
	}
	partition := objStr(row, "partition")
	if partition == "" {
		partition = DefaultPartition
	}
	if partitionOverride != "" {
		partition = partitionOverride
	}
	if !inList(partition, Partitions) {
		return validation.VNull(), fmt.Errorf(
			"row %s: unknown partition %s", validation.PyReprStr(id),
			validation.PyReprStr(partition))
	}
	rootCause := objStr(row, "root_cause")
	if rootCause == "" {
		rootCause = shapeRootCause(objStr(row, "title"), id)
	}
	// Rows from LoadRecords already carry the canonical bug_class; a row
	// carrying a raw class label instead is resolved through the taxonomy
	// maps here (unmapped fallback, never an error).
	bugClass := objStr(row, "bug_class")
	if raw := objStr(row, "class"); raw != "" {
		canonical, _, err := taxonomy.NormalizeClass(&raw, maps)
		if err != nil {
			return validation.VNull(), fmt.Errorf(
				"row %s: %v", validation.PyReprStr(id), err)
		}
		bugClass = canonical
	}
	source := []validation.KV{
		kv("dataset", validation.VStr(Dataset)),
		kv("record_id", validation.VStr(id)),
	}
	if u := objStr(row, "url"); u != "" {
		source = append(source, kv("url", validation.VStr(u)))
	}
	// Notes carry the paid/downgrade facts verbatim (never smuggled keys:
	// gold has additionalProperties:false, so a hand-added gold.paid would
	// fail AddCase validation).
	status := objStr(row, "status")
	paidAt := objAt(row, "paid")
	paid := paidAt.Kind == validation.Bool && paidAt.B
	notes := fmt.Sprintf("immunefi-resolved %s: status=%s paid=%v",
		id, status, paid)
	if paidUSD := objStr(row, "paid_usd"); paidUSD != "" {
		notes += " paid_usd=" + paidUSD
	}
	if status == "downgraded" {
		from := objStr(row, "downgraded_from")
		if from == "" {
			from = objStr(row, "severity_raw")
			if from == "" {
				from = "unknown"
			}
		}
		notes += " downgraded from " + from
	}
	if raw := objStr(row, "severity_raw"); severityFolded(raw) {
		notes += " reported severity " + raw + " folded to high (schema has no critical band)"
	}
	return validation.VObj(
		kv("case_id", validation.VStr("CASE-"+validation.Sha12Hex([]byte(Dataset+"|"+id)))),
		kv("source", validation.VObj(source...)),
		kv("partition", validation.VStr(partition)),
		kv("program", validation.VObj(
			kv("program", validation.VStr(program)),
			kv("platform", validation.VStr(Platform)),
			kv("chains", validation.VArr()))),
		kv("gold", validation.VObj(
			kv("outcome", validation.VStr(outcome)),
			kv("bug_class", validation.VStr(bugClass)),
			kv("severity", objAt(row, "severity")),
			kv("root_cause", validation.VStr(rootCause)),
			kv("locations", validation.VArr()))),
		// Synthetic pointer: no commit is stamped on purpose — the schema
		// only accepts ^[0-9a-f]{7,64}$ there, and inventing a hash would be
		// a lie. files stays empty for the same reason.
		kv("code", validation.VObj(
			kv("repo", validation.VStr("immunefi://"+program)),
			kv("files", validation.VArr()),
			kv("snapshot_note", validation.VStr(
				"adjudicated public data without a pinned snapshot; see source.url")))),
		kv("notes", validation.VStr(notes)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(2)),
	), nil
}

// Outcomes is the evaluation_case outcome vocabulary (mirrors the schema
// enum so buildCase rejects a bad row outcome before AddCase does).
var Outcomes = []string{
	"confirmed-exploitable",
	"confirmed-not-exploitable",
	"disproved",
	"out-of-scope",
	"duplicate",
	"economic-no-go",
}

func inList(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- local ordered-object helpers (same pattern as internal/dedup) -------

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, e := range v.O {
		if e.K == key {
			return e.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	if s := objAt(v, key); s.Kind == validation.Str {
		return s.S
	}
	return ""
}
