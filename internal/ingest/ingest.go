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
	"slices"
	"strings"
	"unicode/utf8"

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
	s := &ingestState{record: record, maps: maps}
	if err := s.ingestValidateFields(); err != nil {
		return Result{}, err
	}
	if err := s.ingestValidateFlags(); err != nil {
		return Result{}, err
	}
	if err := s.ingestNormalizeClass(); err != nil {
		return Result{}, err
	}
	if err := s.ingestBuildCaseParts(); err != nil {
		return Result{}, err
	}
	evalCase, err := s.ingestBuildEvalCase()
	if err != nil {
		return Result{}, err
	}
	rows, err := s.ingestBuildRows()
	if err != nil {
		return Result{}, err
	}
	return Result{EvalCase: evalCase, MemoryRows: rows,
		CampaignSeed: s.ingestBuildSeed(), Canonical: s.canonical,
		Mapped: s.mapped}, nil
}

// ingestState carries one record through the sections of IngestRecord.
type ingestState struct {
	record validation.Value
	maps   *validation.Value

	rid         validation.Value
	dataset     string
	outcome     string
	partition   string
	title       string
	description string
	rootCause   string
	negative    bool
	prior       bool
	pattern     validation.Value

	program     validation.Value
	programName string

	canonical string
	mapped    bool

	caseID    string
	source    []validation.KV
	locations []validation.Value
	codeIn    validation.Value
	repo      string
	code      validation.Value
}

// ingestValidateFields checks the record's identity and text fields and
// captures their values.
func (s *ingestState) ingestValidateFields() error {
	dataset := validation.ObjStr(s.record, "dataset")
	if !slices.Contains(datasets, dataset) {
		return fmt.Errorf("record %s: unknown dataset %s",
			validation.PyRepr(validation.ObjAt(s.record, "id")),
			validation.PyRepr(validation.ObjAt(s.record, "dataset")))
	}
	rid := validation.ObjAt(s.record, "id")
	if rid.Kind != validation.Str || rid.S == "" {
		return errors.New("record 'id' must be a non-empty string")
	}
	outcome := validation.ObjStr(s.record, "outcome")
	if !slices.Contains(Outcomes, outcome) {
		return fmt.Errorf("record %s: unknown outcome %s; expected "+
			"one of %s", validation.PyReprStr(rid.S),
			validation.PyRepr(validation.ObjAt(s.record, "outcome")), pyTuple(Outcomes))
	}
	partition := validation.ObjStr(s.record, "partition")
	if !slices.Contains([]string{"dev", "held-out", "training"}, partition) {
		return fmt.Errorf("record %s: unknown partition %s",
			validation.PyReprStr(rid.S),
			validation.PyRepr(validation.ObjAt(s.record, "partition")))
	}
	title, err := requireStr(s.record, "title", 5, 500)
	if err != nil {
		return err
	}
	description, err := requireStr(s.record, "description", 20, 10000)
	if err != nil {
		return err
	}
	rootCause, err := requireStr(s.record, "root_cause", 10, 2000)
	if err != nil {
		return err
	}
	s.dataset, s.rid, s.outcome, s.partition = dataset, rid, outcome, partition
	s.title, s.description, s.rootCause = title, description, rootCause
	return nil
}

// ingestValidateFlags checks the negative/prior/pattern and program fields.
func (s *ingestState) ingestValidateFlags() error {
	negative := truthy(validation.ObjAt(s.record, "negative"))
	prior := truthy(validation.ObjAt(s.record, "prior"))
	if negative && prior {
		return fmt.Errorf(
			"record %s: 'negative' and 'prior' are mutually exclusive",
			validation.PyReprStr(s.rid.S))
	}
	pattern := validation.ObjAt(s.record, "pattern")
	if negative || prior {
		n := utf8.RuneCountInString(pattern.S)
		if pattern.Kind != validation.Str || n < 10 || n > 500 {
			return fmt.Errorf(
				"record %s: 'pattern' (10-500 chars) is required when "+
					"'negative' or 'prior' is set", validation.PyReprStr(s.rid.S))
		}
	}
	program := validation.ObjAt(s.record, "program")
	programName := validation.ObjStr(program, "program")
	if programName == "" {
		return fmt.Errorf(
			"record %s: program.program must be non-empty",
			validation.PyReprStr(s.rid.S))
	}
	s.negative, s.prior, s.pattern = negative, prior, pattern
	s.program, s.programName = program, programName
	return nil
}

// ingestNormalizeClass resolves the optional bug_class_label through the
// taxonomy maps.
func (s *ingestState) ingestNormalizeClass() error {
	label := strOrNil(validation.ObjAt(s.record, "bug_class_label"))
	canonical, mapped, err := taxonomy.NormalizeClass(label, s.maps)
	if err != nil {
		return err
	}
	s.canonical, s.mapped = canonical, mapped
	return nil
}

// ingestBuildCaseParts derives the case id, source block, locations and
// code block.
func (s *ingestState) ingestBuildCaseParts() error {
	s.caseID = "CASE-" + validation.Sha12Hex([]byte(s.dataset+"|"+s.rid.S))
	source := []validation.KV{
		{K: "dataset", V: validation.VStr(s.dataset)},
		{K: "record_id", V: validation.VStr(s.rid.S)},
	}
	if u := validation.ObjAt(s.record, "url"); truthy(u) {
		source = append(source, validation.KV{K: "url", V: u})
	}
	s.source = source
	locations, err := buildLocations(s.record, s.rid.S)
	if err != nil {
		return err
	}
	s.locations = locations
	s.codeIn = validation.ObjAt(s.record, "code")
	s.repo = validation.ObjStr(s.codeIn, "repo")
	if s.repo == "" {
		return fmt.Errorf("record %s: code.repo must be non-empty",
			validation.PyReprStr(s.rid.S))
	}
	code, err := buildCode(s.codeIn, s.repo)
	if err != nil {
		return err
	}
	s.code = code
	return nil
}

// ingestBuildEvalCase assembles and validates the evaluation case.
func (s *ingestState) ingestBuildEvalCase() (validation.Value, error) {
	evalCase := buildEvalCase(evalCaseArgs{
		caseID: s.caseID, source: s.source, partition: s.partition,
		program: s.program, programName: s.programName, outcome: s.outcome,
		canonical: s.canonical, severity: validation.ObjAt(s.record, "severity"),
		rootCause: s.rootCause, locations: s.locations, code: s.code,
		notes: truncRunes(s.title+"\n\n"+s.description, 1000),
	})
	if err := validation.Validate(evalCase, "evaluation_case", 1); err != nil {
		return validation.Value{}, err
	}
	return evalCase, nil
}

// ingestBuildRows renders the record's v2 memory rows.
func (s *ingestState) ingestBuildRows() ([]validation.Value, error) {
	return memoryRows(s.record, memoryArgs{
		rid: s.rid.S, dataset: s.dataset, caseID: s.caseID, negative: s.negative,
		prior: s.prior, canonical: s.canonical, partition: s.partition,
		pattern: s.pattern, description: s.description, outcome: s.outcome})
}

// ingestBuildSeed builds the campaign seed (nil when the repo is blank).
func (s *ingestState) ingestBuildSeed() *validation.Value {
	if strings.TrimSpace(s.repo) == "" {
		return nil
	}
	seed := validation.VObj(
		validation.KV{K: "case_id", V: validation.VStr(s.caseID)},
		validation.KV{K: "repo", V: validation.VStr(s.repo)},
		validation.KV{K: "commit", V: nullIfAbsent(s.codeIn, "commit")},
		validation.KV{K: "focus_files", V: validation.VArr(
			valsOf(validation.ObjAt(s.codeIn, "files"))...)},
		validation.KV{K: "expected", V: validation.VObj(
			validation.KV{K: "outcome", V: validation.VStr(s.outcome)},
			validation.KV{K: "bug_class", V: validation.VStr(s.canonical)},
			validation.KV{K: "root_cause", V: validation.VStr(s.rootCause)})})
	return &seed
}
