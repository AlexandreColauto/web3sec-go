// Package scabench ports webv2.datasets.scabench: the ScaBench adapter,
// curated audit findings into the common ingest shape.
//
// WHY (verbatim intent): ScaBench ships 555 curated, confirmed findings nested
// one level down (project["vulnerabilities"]) with no category label, no
// outcome field, no per-finding code pointers, PDF-scraped U+FFFE/U+FFFF
// noncharacters in some sherlock/cantina descriptions, and unreliable commit
// pins (empty, "main", short SHAs). This module owns every one of those dialect
// quirks so webv2.ingest only ever sees clean common-shape records: opaque
// <project_id>-<finding_id> ids, honest "unmapped" classes,
// confirmed-exploitable outcomes, schema-safe commit refs, and the held-out
// partition (the contamination-free benchmark — eval only, never memory).
package scabench

import (
	"fmt"
	"regexp"
	"strings"

	"websec/internal/ingest"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

const (
	// Dataset is DATASET.
	Dataset = "scabench"
	// Partition is PARTITION: the contamination-free benchmark slice.
	Partition = "held-out"
)

// SourceFile is SOURCE_FILE: the only shipped ground-truth snapshot.
var SourceFile = "data/datasets/scabench/datasets/curated-2025-08-18/curated-2025-08-18.json"

// SetSourceFile repoints the snapshot path (harness/test override).
func SetSourceFile(path string) { SourceFile = path }

// Severities is SEVERITIES: the curated file's whole severity vocabulary; it
// already matches the evaluation_case gold.severity enum, so the map is direct.
var Severities = []string{"high", "medium", "low", "informational"}

var (
	// _NONCHARACTERS: the PDF-scraping noncharacters (recon §10.4), U+FFFF
	// x574 over two sherlock projects; U+FFFE is stripped too.
	noncharactersRe = regexp.MustCompile("[\ufffe\uffff]")
	// _FULL_SHA: a commit that pins an exact tree.
	fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// _SCHEMA_COMMIT: the evaluation_case schema only accepts hex commits
	// (7-64 chars), so only hex refs travel as commit.
	schemaCommitRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
)

// StripNoncharacters removes U+FFFE/U+FFFF PDF-scraping damage.
// Deterministic, idempotent.
func StripNoncharacters(text string) string {
	return noncharactersRe.ReplaceAllString(text, "")
}

// FitTitle is fit_title: fit a finding title into the common shape's 5-500
// chars. Strip noncharacters and surrounding whitespace; a too-short title is
// suffixed with its (globally unique, always long) finding id; a too-long title
// is cut to 497 chars plus "...".
func FitTitle(title, findingID string) string {
	text := strings.TrimSpace(StripNoncharacters(title))
	if runeLen(text) < 5 {
		text = strings.TrimSpace(strings.Trim(text+" — "+findingID, " —"))
		for runeLen(text) < 5 {
			text = text + " " + findingID
		}
	}
	if runeLen(text) > 500 {
		text = runeSlice(text, 0, 497) + "..."
	}
	return text
}

// FitDescription is fit_description: fit a finding description into the common
// shape's 20-10000 chars. Strip noncharacters first (so lengths are measured on
// clean text), then strip surrounding whitespace. A too-short body is composed
// up from the (already fitted) title; a too-long body is cut on a paragraph
// boundary (blank-line split, paragraphs kept whole while they fit); a single
// over-long first paragraph is hard-cut to 10000.
func FitDescription(description, title, findingID string) string {
	text := strings.TrimSpace(StripNoncharacters(description))
	if runeLen(text) < 20 {
		text = strings.TrimSpace(title + "\n\n" + text)
		if runeLen(text) < 20 {
			text = text + "\n\nFinding " + findingID + "."
		}
		for runeLen(text) < 20 {
			text = text + " " + title
		}
	}
	if runeLen(text) > 10000 {
		paras := strings.Split(text, "\n\n")
		var kept []string
		total := 0
		for _, para := range paras {
			if strings.TrimSpace(para) == "" {
				continue
			}
			add := runeLen(para)
			if len(kept) > 0 {
				add += 2
			}
			if len(kept) > 0 && total+add > 10000 {
				break
			}
			if len(kept) == 0 && runeLen(para) > 10000 {
				kept = []string{runeSlice(para, 0, 10000)}
				total = 10000
				break
			}
			kept = append(kept, para)
			total += add
		}
		if len(kept) > 0 {
			text = strings.Join(kept, "\n\n")
		} else {
			text = runeSlice(text, 0, 10000)
		}
	}
	return text
}

// ComposeRootCause is compose_root_cause: compose the 10-2000 char root cause
// from title + first paragraph. Take the first non-empty paragraph of the
// (fitted) description and prefix the fitted title — "<title>. <para>"; extend
// with the title while under 10 chars; hard-cut to 2000 chars when over.
func ComposeRootCause(title, description string) string {
	first := ""
	for _, p := range strings.Split(description, "\n\n") {
		if strings.TrimSpace(p) != "" {
			first = strings.TrimSpace(p)
			break
		}
	}
	// Python strips only spaces and dots here (not whitespace): a trailing
	// newline in the first paragraph survives into root_cause.
	cause := strings.Trim(title+". "+first, " .")
	for runeLen(cause) < 10 {
		cause = cause + " " + title
	}
	if runeLen(cause) > 2000 {
		cause = runeSlice(cause, 0, 2000)
	}
	return cause
}

// BuildCode is build_code: build the common-shape code block from the first
// codebase. repo is the published repo_url; commit travels only when it is
// schema-safe hex (full or short SHA) — empty/"main" are omitted, not
// laundered. Any commit that is not a full 40-hex pin earns the brief's
// snapshot_note. files is always [] (no per-finding file data).
func BuildCode(codebase validation.Value) (validation.Value, error) {
	if codebase.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf(
			"scabench codebase must be a dict, got %s", validation.PyRepr(codebase))
	}
	repo := pyStrOrEmpty(at(codebase, "repo_url"))
	if repo == "" {
		return validation.VNull(), fmt.Errorf("scabench codebase has no repo_url")
	}
	code := validation.VObj(
		validation.KV{K: "repo", V: validation.VStr(repo)},
		validation.KV{K: "files", V: validation.VArr()})
	commit := pyStrOrEmpty(at(codebase, "commit"))
	if commit != "" && schemaCommitRe.MatchString(commit) {
		code = setKey(code, "commit", validation.VStr(commit))
	}
	if !(commit != "" && fullSHARe.MatchString(commit)) {
		code = setKey(code, "snapshot_note",
			validation.VStr("commit as published in dataset; not a verified ref"))
	}
	return code, nil
}

// BuildRecord is build_record: build one common-shape record from a
// (project, finding) pair. Pinned mapping (brief §Task 3):
// <project_id>-<finding_id> id, program from the enclosing project (chains
// always [] — the dataset has no chain field), "unmapped" class (no labels,
// honest), confirmed-exploitable (curated confirmed ground truth), direct
// severity, no memory content (negative/prior False, pattern None), no
// locations, no exploit, held-out partition.
func BuildRecord(project, finding validation.Value) (validation.Value, error) {
	for _, key := range []string{"project_id", "name", "platform"} {
		if pyStrOrEmpty(at(project, key)) == "" {
			return validation.VNull(), fmt.Errorf(
				"scabench project is missing %s: %s",
				validation.PyReprStr(key),
				validation.PyRepr(at(project, "project_id")))
		}
	}
	for _, key := range []string{"finding_id", "severity", "title", "description"} {
		if at(finding, key).Kind == validation.Null {
			return validation.VNull(), fmt.Errorf(
				"scabench finding is missing %s in project %s",
				validation.PyReprStr(key),
				validation.PyRepr(at(project, "project_id")))
		}
	}
	severity := at(finding, "severity")
	sevText := pyStrOrEmpty(severity)
	if !inList(sevText, Severities) {
		return validation.VNull(), fmt.Errorf(
			"scabench finding %s: unknown severity %s",
			validation.PyRepr(at(finding, "finding_id")),
			validation.PyRepr(severity))
	}
	findingID := pyStrOrEmpty(at(finding, "finding_id"))
	recordID := pyStrOrEmpty(at(project, "project_id")) + "-" + findingID
	title := FitTitle(pyStrOrEmpty(at(finding, "title")), findingID)
	description := FitDescription(pyStrOrEmpty(at(finding, "description")),
		title, findingID)
	codebases := at(project, "codebases")
	if codebases.Kind != validation.Arr || len(codebases.A) == 0 {
		return validation.VNull(), fmt.Errorf(
			"scabench project %s has no codebases",
			validation.PyRepr(at(project, "project_id")))
	}
	code, err := BuildCode(codebases.A[0])
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(recordID)},
		validation.KV{K: "dataset", V: validation.VStr(Dataset)},
		validation.KV{K: "url", V: validation.VNull()},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr(
				pyStrOrEmpty(at(project, "name")))},
			validation.KV{K: "platform", V: validation.VStr(
				pyStrOrEmpty(at(project, "platform")))},
			validation.KV{K: "chains", V: validation.VArr()})},
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "description", V: validation.VStr(description)},
		validation.KV{K: "bug_class_label", V: validation.VStr("unmapped")},
		validation.KV{K: "outcome", V: validation.VStr("confirmed-exploitable")},
		validation.KV{K: "severity", V: validation.VStr(sevText)},
		validation.KV{K: "negative", V: validation.VBool(false)},
		validation.KV{K: "prior", V: validation.VBool(false)},
		validation.KV{K: "pattern", V: validation.VNull()},
		validation.KV{K: "root_cause", V: validation.VStr(
			ComposeRootCause(title, description))},
		validation.KV{K: "locations", V: validation.VArr()},
		validation.KV{K: "code", V: code},
		validation.KV{K: "exploit", V: validation.VNull()},
		validation.KV{K: "partition", V: validation.VStr(Partition)},
	), nil
}

// LoadRecords is load_records: load the curated snapshot into common-shape
// records (pure file read). source overrides the shipped snapshot path (tests
// point it at a synthetic sample in the exact source format). Returns one
// record per finding (555 on the snapshot).
func LoadRecords(source *string) ([]validation.Value, error) {
	path := SourceFile
	if source != nil {
		path = *source
	}
	projects, err := validation.ReadJson(path)
	if err != nil {
		return nil, err
	}
	if projects.Kind != validation.Arr {
		return nil, fmt.Errorf("scabench source %s must be a JSON list", path)
	}
	var records []validation.Value
	for _, project := range projects.A {
		if project.Kind != validation.Obj {
			return nil, fmt.Errorf("scabench project must be a dict, got %s",
				validation.PyRepr(project))
		}
		vulns := at(project, "vulnerabilities")
		if vulns.Kind != validation.Arr {
			continue // absent or null -> the dataset publishes no findings
		}
		for _, finding := range vulns.A {
			rec, err := BuildRecord(project, finding)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	return records, nil
}

// IngestOptions are ingest's keyword arguments.
type IngestOptions struct {
	Maps *validation.Value
	Tier string
}

// Ingest is ingest: load, ingest_record each, publish. All 555 records are
// eval-only (prior/negative are both False, so no memory rows exist) and
// held-out, so even the real run only adds evaluation cases — the shared store
// is untouched. tier selects the publish target.
func Ingest(opts IngestOptions) (validation.Value, error) {
	maps := opts.Maps
	if maps == nil {
		m, err := taxonomy.LoadMaps([]string{"scabench"})
		if err != nil {
			return validation.VNull(), err
		}
		maps = &m
	}
	tier := opts.Tier
	if tier == "" {
		tier = "global"
	}
	records, err := LoadRecords(nil)
	if err != nil {
		return validation.VNull(), err
	}
	results := make([]ingest.Result, 0, len(records))
	for _, record := range records {
		res, err := ingest.IngestRecord(record, maps)
		if err != nil {
			return validation.VNull(), err
		}
		results = append(results, res)
	}
	summary, err := ingest.PublishIngested(results, Dataset, nil, tier)
	if err != nil {
		return validation.VNull(), err
	}
	return summary.Value(), nil
}

// ---- helpers ---------------------------------------------------------------

func at(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, p := range v.O {
		if p.K == key {
			return p.V
		}
	}
	return validation.VNull()
}

func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, p := range v.O {
		if p.K == key {
			out = append(out, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out = append(out, p)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: val})
	}
	v.O = out
	return v
}

func pyStrOrEmpty(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return ""
	case validation.Bool:
		if !v.B {
			return ""
		}
		return "True"
	case validation.Int:
		if v.I == 0 && v.Big == "" {
			return ""
		}
		return validation.IntText(v)
	case validation.Flt:
		if v.F == 0 {
			return ""
		}
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	case validation.Arr:
		if len(v.A) == 0 {
			return ""
		}
		return validation.PyRepr(v)
	case validation.Obj:
		if len(v.O) == 0 {
			return ""
		}
		return validation.PyRepr(v)
	}
	return ""
}

func runeLen(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

func runeSlice(s string, from, to int) string {
	r := []rune(s)
	if from < 0 {
		from = 0
	}
	if to > len(r) {
		to = len(r)
	}
	if from > to {
		return ""
	}
	return string(r[from:to])
}

func inList(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}
