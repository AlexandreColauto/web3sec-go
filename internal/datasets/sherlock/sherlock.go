// Package sherlock is the Wave G G3 adapter: Sherlock audit-judge verdicts
// into the Outcomes vocabulary, written through evalstore.AddCase.
//
// WHY (verbatim intent): a judge verdict is adjudicated public ground truth —
// never training fuel for self-test — so every loaded row lands held-out
// unless the caller overrides the partition, and every ingested case keeps
// its provenance (source.dataset sherlock, source.record_id the row id,
// source.url the record url). The judge dialect is small but sharp: High,
// Medium and Low mean paid findings ONLY when the finding was not previously
// known (known=true is out-of-scope, not an acceptance); a Low with
// griefing=true is a valid finding no one will pay to exploit, hence
// economic-no-go; QA is informational-valid, hence out-of-scope and never
// confirmed-not-exploitable; Invalid is disproved; Duplicate needs a
// non-empty duplicate_of pointer; the Griefing judge IS the griefing class,
// hence economic-no-go when fresh (known=true stays out-of-scope by the same
// rule as every other judge). An unknown judge string is a loud
// LoadRecords error naming the row id — never a silent default.
//
// Code pointers are synthetic by design (G7 honesty): adjudicated Sherlock data
// ships no pinned snapshot, so code.repo is sherlock://<program> with an empty
// files list and a snapshot_note saying exactly that; the record url in
// source.url is the cite. No commit is stamped: the evaluation_case schema
// only accepts ^[0-9a-f]{7,64}$ there, so anything but a real pinned hash
// would fail validation.
//
// Style mirrors internal/datasets/defihacklabs: strict parse, deterministic
// (file-order) output, validation.Value docs throughout, no new dependencies.
package sherlock

import (
	"crypto/sha256"
	"encoding/hex"
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
	// Dataset is the registry name (the ingest datasets list already
	// carries "sherlock").
	Dataset = "sherlock"
	// DefaultPartition is this loader's law: adjudicated public data is
	// ground truth, never training fuel for self-test.
	DefaultPartition = "held-out"
	// RootCauseMin / RootCauseMax are the evaluation_case schema's
	// root_cause bounds (minLength 10, maxLength 2000).
	RootCauseMin = 10
	RootCauseMax = 2000
)

// judgeToOutcome is the brief's verbatim judge-mapping table as a named map
// (the drift test reads this symbol). Two entries carry flag law applied in
// mapOutcome, documented here so the table stays the single source of truth:
//
//	High/Medium/Low + known=false (+griefing=false for Low) ->
//	 confirmed-exploitable (the table default)
//	High/Medium/Low + known=true  -> out-of-scope (previously known = not a
//	                                 paid acceptance)
//	Low + griefing=true           -> economic-no-go (valid but no one pays to
//	                                 exploit it; only meaningful for Low)
//	QA                            -> out-of-scope (informational-valid: never
//	                                 confirmed-not-exploitable)
//	Invalid                       -> disproved
//	Duplicate                     -> duplicate (requires non-empty duplicate_of)
//	Griefing + known=false        -> economic-no-go (the Griefing judge IS the
//	                                 griefing class)
//	Griefing + known=true         -> out-of-scope (same known rule as every
//	                                 other judge)
var judgeToOutcome = map[string]string{
	"High":      "confirmed-exploitable",
	"Medium":    "confirmed-exploitable",
	"Low":       "confirmed-exploitable",
	"QA":        "out-of-scope",
	"Invalid":   "disproved",
	"Duplicate": "duplicate",
	"Griefing":  "economic-no-go",
}

// severityToGold maps the row severity to the gold severity vocabulary.
// Sherlock never inflates bands: High->high, Medium->medium, Low->low pass
// through lowercased; anything else is null.
var severityToGold = map[string]string{
	"High":   "high",
	"Medium": "medium",
	"Low":    "low",
}

// Partitions is the evaluation_case partition vocabulary (mirrors the schema
// enum so Ingest can reject a bad override loudly).
var Partitions = []string{"dev", "held-out", "training"}

// mapOutcome applies judgeToOutcome plus the flag law (known, griefing).
// griefing is only meaningful for Low; rowID names the row in every error
// (unknown judge, Duplicate without a pointer).
func mapOutcome(judge string, known, griefing bool, duplicateOf, rowID string) (string, error) {
	base, ok := judgeToOutcome[judge]
	if !ok {
		return "", fmt.Errorf("sherlock: unknown judge %s for row %s",
			validation.PyReprStr(judge), validation.PyReprStr(rowID))
	}
	switch judge {
	case "High", "Medium":
		if known {
			return "out-of-scope", nil
		}
		return base, nil
	case "Low":
		if known {
			return "out-of-scope", nil
		}
		if griefing {
			return "economic-no-go", nil
		}
		return base, nil
	case "Griefing":
		if known {
			return "out-of-scope", nil
		}
		return base, nil
	case "Duplicate":
		if strings.TrimSpace(duplicateOf) == "" {
			return "", fmt.Errorf(
				"sherlock: row %s judges Duplicate without duplicate_of",
				validation.PyReprStr(rowID))
		}
		return base, nil
	}
	return base, nil
}

// mapSeverity is severityToGold with a null default.
func mapSeverity(severity string) validation.Value {
	if gold, ok := severityToGold[severity]; ok {
		return validation.VStr(gold)
	}
	return validation.VNull()
}

// shapeRootCause clips the title to the schema maximum and pads a short one
// to the schema minimum with the row id (deterministic; mirrors defihacklabs'
// recordTitle padding — an adjudicated row is never dropped over a terse
// title).
func shapeRootCause(title, rowID string) string {
	text := strings.TrimSpace(title)
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
// line must be a JSON object; id, judge, title, url and program must be
// non-empty strings; known and griefing must be bools when present
// (griefing is only meaningful for Low); duplicate_of a string when
// present; class/severity fall back honestly (unmapped / null).
// The record shape:
//
//	{id, dataset, url, program, title, bug_class (canonical),
//	 outcome (mapped), severity (gold string or null),
//	 root_cause (shaped title), partition (held-out),
//	 judge, known, griefing, duplicate_of (preserved for audit)}
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
			return nil, fmt.Errorf("sherlock: %s line %d: %v", path, i+1, err)
		}
		if doc.Kind != validation.Obj {
			return nil, fmt.Errorf("sherlock: %s line %d: must be a JSON object",
				path, i+1)
		}
		rec, err := buildRecord(doc)
		if err != nil {
			return nil, fmt.Errorf("sherlock: %s line %d: %v", path, i+1, err)
		}
		records = append(records, rec)
	}
	if records == nil {
		records = []validation.Value{}
	}
	return records, nil
}

// buildRecord validates one row object into a record (errors name the row id
// when one is present, else the raw judge for an unknown-judge row without
// an id... in practice id is required first, so unknown-judge errors always
// name the id).
func buildRecord(doc validation.Value) (validation.Value, error) {
	id := objStr(doc, "id")
	if id == "" {
		return validation.VNull(), fmt.Errorf("record 'id' must be a non-empty string")
	}
	judge := objStr(doc, "judge")
	if objAt(doc, "judge").Kind != validation.Str || judge == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'judge' must be a non-empty string", validation.PyReprStr(id))
	}
	title := objStr(doc, "title")
	if title == "" {
		return validation.VNull(), fmt.Errorf(
			"row %s: 'title' must be a non-empty string", validation.PyReprStr(id))
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
	known := false
	if kv := objAt(doc, "known"); kv.Kind != validation.Null {
		if kv.Kind != validation.Bool {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'known' must be a bool", validation.PyReprStr(id))
		}
		known = kv.B
	}
	duplicateOf := ""
	if kv := objAt(doc, "duplicate_of"); kv.Kind != validation.Null {
		if kv.Kind != validation.Str {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'duplicate_of' must be a string", validation.PyReprStr(id))
		}
		duplicateOf = kv.S
	}
	griefing := false
	if kv := objAt(doc, "griefing"); kv.Kind != validation.Null {
		if kv.Kind != validation.Bool {
			return validation.VNull(), fmt.Errorf(
				"row %s: 'griefing' must be a bool", validation.PyReprStr(id))
		}
		griefing = kv.B
	}
	outcome, err := mapOutcome(judge, known, griefing, duplicateOf, id)
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
	severity := validation.VNull()
	if s := objAt(doc, "severity"); s.Kind == validation.Str {
		severity = mapSeverity(s.S)
	}
	return validation.VObj(
		kv("id", validation.VStr(id)),
		kv("dataset", validation.VStr(Dataset)),
		kv("url", validation.VStr(url)),
		kv("program", validation.VStr(program)),
		kv("title", validation.VStr(title)),
		kv("bug_class", validation.VStr(canonical)),
		kv("outcome", validation.VStr(outcome)),
		kv("severity", severity),
		kv("root_cause", validation.VStr(shapeRootCause(title, id))),
		kv("partition", validation.VStr(DefaultPartition)),
		kv("judge", validation.VStr(judge)),
		kv("known", validation.VBool(known)),
		kv("griefing", validation.VBool(griefing)),
		kv("duplicate_of", validation.VStr(duplicateOf)),
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
// (CASE-sha12("sherlock|"+row id), mirroring ingest's derivation) so a replay
// over the same rows yields the same ids; created_at stamps state.NowIso()
// (the WEBV2_NOW pin), so determinism lives in the row CONTENT, not the
// timestamp.
func Ingest(store string, rows []validation.Value, opts IngestOptions) ([]validation.Value, error) {
	if store != "" {
		evalstore.SetEvalDir(store)
	}
	partition := ""
	if opts.Partition != nil {
		partition = *opts.Partition
		if !inList(partition, Partitions) {
			return nil, fmt.Errorf("sherlock: unknown partition %s",
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
		return validation.VNull(), fmt.Errorf("sherlock: row %d must be a dict", index)
	}
	id := objStr(row, "id")
	if id == "" {
		return validation.VNull(), fmt.Errorf("sherlock: row %d: 'id' must be a non-empty string", index)
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
	judge, known, griefing, duplicateOf := objStr(row, "judge"), objAt(row, "known"), objAt(row, "griefing"), objStr(row, "duplicate_of")
	notes := fmt.Sprintf("sherlock %s: judge=%s known=%v griefing=%v",
		id, judge, known.Kind == validation.Bool && known.B,
		griefing.Kind == validation.Bool && griefing.B)
	if duplicateOf != "" {
		notes += " duplicate_of=" + duplicateOf
	}
	notes += "; synthetic code pointer (no pinned snapshot) — ground truth at source.url"
	return validation.VObj(
		kv("case_id", validation.VStr("CASE-"+sha12Hex(Dataset+"|"+id))),
		kv("source", validation.VObj(source...)),
		kv("partition", validation.VStr(partition)),
		kv("program", validation.VObj(
			kv("program", validation.VStr(program)),
			kv("platform", validation.VNull()),
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
			kv("repo", validation.VStr("sherlock://"+program)),
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

// sha12Hex is ingest.sha12's twin (unexported there): first 12 hex chars of
// sha256 — the deterministic case-id derivation.
func sha12Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:12]
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
