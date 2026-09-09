// Package forge ports webv2.datasets.forge: the FORGE-Curated adapter,
// verified audit findings into the common ingest shape.
//
// WHY (verbatim intent): FORGE-Curated ships 3,590 LLM-extracted audit findings
// across 323 per-report JSONs (findings/ with resolved source + 115
// findings-without-source/ reports) with NO verdict field — every row is a
// positive audit finding, so negative memory is NOT derivable (documented plan
// deviation). Severity is the only validity proxy (Medium+ is FORGE's own
// exploitable cut): Critical/High/Medium become CONFIRMED positive priors, Low
// becomes confirmed-not-exploitable, Informational/null becomes out-of-scope.
// Labels are CWE-tree dicts (level "1" pillar first, deepest level when "1" is
// absent, None when empty); locations mix File::func anchors with prose and PR
// URLs; files entries carry a <40hex>/<org>/<repo>/ prefix; url/commit_id are
// str|list|None with occasional non-hex commits. This module owns all of those
// quirks so webv2.ingest only ever sees clean common-shape records, all
// partition dev.
package forge

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"websec/internal/ingest"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

const (
	// Dataset is DATASET.
	Dataset = "forge-curated"
	// Partition is PARTITION: every FORGE row is dev (no leakage cut exists).
	Partition = "dev"
	// ProgramKey is PROGRAM_KEY: one shared key for the prior-knowledge rows.
	ProgramKey = "forge-prior-knowledge|other|-"
)

// DatasetDir is DATASET_DIR: the read-only clone (recon-forge.md §2).
var DatasetDir = filepath.Join("data", "datasets", "FORGE-Curated",
	"dataset-curated")

// SetDatasetDir repoints the clone path (harness/test override).
func SetDatasetDir(path string) { DatasetDir = path }

// ReportSubdirs is REPORT_SUBDIRS.
var ReportSubdirs = []string{"findings", "findings-without-source"}

// PriorSeverities is PRIOR_SEVERITIES: Medium+ is FORGE's own exploitable cut.
var PriorSeverities = []string{"Critical", "High", "Medium"}

// severityMap is _SEVERITY_MAP.
var severityMap = map[string]string{
	"Critical":      "high",
	"High":          "high",
	"Medium":        "medium",
	"Low":           "low",
	"Informational": "informational",
}

// outcomeMap is _OUTCOME_MAP (keyed by the mapped severity; "" is Python None).
var outcomeMap = map[string]string{
	"high":          "confirmed-exploitable",
	"medium":        "confirmed-exploitable",
	"low":           "confirmed-not-exploitable",
	"informational": "out-of-scope",
	"":              "out-of-scope",
}

var (
	// _ANCHOR_LINE_RE: first line number in a location anchor fragment.
	anchorLineRe = regexp.MustCompile(`#\D*(\d+)`)
	// _HEX_LIKE_RE / _SCHEMA_COMMIT_RE: a files-entry commit prefix (40 chars
	// usually; short SHAs occur) — the evaluation_case schema accepts hex 7-64.
	hexLikeRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
	// causeLabelRe / causeStopRe emulate the Python _CAUSE_RE (Go's RE2 has no
	// lookahead, so the section end is scanned by line instead).
	causeLabelRe = regexp.MustCompile(`(?i)^cause\s*:`)
	causeStopRe  = regexp.MustCompile(
		`(?i)^\s*(exploitation|impact|recommendation|fix|mitigation|likelihood|references)\s*:`)
	// causeSplitRe is re.split(r"\n\s*\n").
	causeSplitRe = regexp.MustCompile(`\n\s*\n`)
)

// absentTokens is _ABSENT_TOKENS.
var absentTokens = map[string]bool{"": true, "n/a": true, "none": true, "null": true}

// ExtractLabel is extract_label: the finding's bug-class label, the level-"1"
// CWE first. Pinned mapping: category["1"][0] when present and non-empty, else
// the first CWE of the deepest non-empty numeric level (the specific class
// beats the pillar); empty/absent -> nil. Returns raw CWE ids — taxonomy
// mapping happens downstream in ingest_record.
func ExtractLabel(category validation.Value) *string {
	if category.Kind != validation.Obj || len(category.O) == 0 {
		return nil
	}
	if items := valsOf(at(category, "1")); len(items) > 0 {
		s := pyStrOrEmpty(items[0])
		return &s
	}
	type level struct {
		n    int
		name string
	}
	var levels []level
	for _, p := range category.O {
		key := strings.TrimSpace(p.K)
		if key == "" {
			continue
		}
		n, err := strconv.Atoi(key)
		if err != nil || n < 0 {
			continue
		}
		if !truthy(p.V) {
			continue
		}
		levels = append(levels, level{n, p.K})
	}
	if len(levels) == 0 {
		return nil
	}
	sort.SliceStable(levels, func(i, j int) bool { return levels[i].n < levels[j].n })
	items := valsOf(at(category, levels[len(levels)-1].name))
	if len(items) == 0 {
		return nil
	}
	s := pyStrOrEmpty(items[0])
	return &s
}

// MapSeverity is map_severity: FORGE severity -> the common severity enum.
// None stays nil (null is a legitimate band: 148 findings).
func MapSeverity(severity *string) (*string, error) {
	if severity == nil {
		return nil, nil
	}
	mapped, ok := severityMap[*severity]
	if !ok {
		return nil, fmt.Errorf("forge-curated finding: unknown severity %s",
			validation.PyReprStr(*severity))
	}
	return &mapped, nil
}

// MapOutcome is map_outcome: mapped severity -> outcome. Informational/null is
// out-of-scope (not a security issue, not disproved); Low is
// confirmed-not-exploitable (audited and judged non-exploitable);
// Critical/High/Medium are confirmed-exploitable (FORGE's own cut).
func MapOutcome(severity *string) (string, error) {
	mapped, err := MapSeverity(severity)
	if err != nil {
		return "", err
	}
	key := ""
	if mapped != nil {
		key = *mapped
	}
	return outcomeMap[key], nil
}

// ExtractRootCause is extract_root_cause: the "Cause: ..." labeled section
// when present, else the first paragraph; whitespace-collapsed and hard-capped
// at 2000 chars.
func ExtractRootCause(description string) string {
	text := strings.TrimSpace(description)
	cause := ""
	if start, end, ok := causeSection(text); ok {
		cause = collapseWS(text[start:end])
	}
	if cause == "" {
		paras := splitNonEmpty(text)
		first := text
		if len(paras) > 0 {
			first = paras[0]
		}
		cause = collapseWS(first)
	}
	if runeLen(cause) > 2000 {
		cause = strings.TrimRightFunc(runeSlice(cause, 0, 2000), unicode.IsSpace)
	}
	if runeLen(cause) < 10 {
		cause = runeSlice(collapseWS(text), 0, 2000)
	}
	return cause
}

// causeSection locates the Python _CAUSE_RE match without lookahead: the
// earliest line starting (case-insensitively) with "cause:" and the earliest
// following line start whose text (after optional whitespace, which may span
// blank lines) begins a labeled stop section — or end of text.
func causeSection(text string) (start, end int, ok bool) {
	lineStart := -1
	for i := 0; i <= len(text); i++ {
		if i > 0 && text[i-1] != '\n' {
			continue
		}
		if lineStart < 0 && causeLabelRe.FindStringIndex(text[i:]) != nil &&
			causeLabelRe.FindStringIndex(text[i:])[0] == 0 {
			lineStart = i
			break
		}
	}
	if lineStart < 0 {
		return 0, 0, false
	}
	colon := strings.Index(text[lineStart:], ":")
	if colon < 0 {
		return 0, 0, false
	}
	start = lineStart + colon + 1
	for start < len(text) && isSpaceByte(text[start]) {
		start++
	}
	end = len(text)
	for p := start; p < len(text); p++ {
		if p > 0 && text[p-1] != '\n' {
			continue
		}
		if m := causeStopRe.FindStringIndex(text[p:]); m != nil && m[0] == 0 {
			end = p
			break
		}
	}
	return start, end, true
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// splitNonEmpty is [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()].
func splitNonEmpty(text string) []string {
	var out []string
	for _, p := range causeSplitRe.Split(text, -1) {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// collapseWS is " ".join(text.split()).
func collapseWS(text string) string { return strings.Join(strings.Fields(text), " ") }

// ParseLocation is parse_location: a "File::symbol#anchor" entry into
// {"file": ...} (+ "line" when an anchor number is present). Prose, URLs, and
// symbol-only fragments without a file extension resolve to nil.
func ParseLocation(item validation.Value) (validation.Value, bool) {
	if item.Kind != validation.Str {
		return validation.VNull(), false
	}
	idx := strings.Index(item.S, "::")
	if idx < 0 {
		return validation.VNull(), false
	}
	head := strings.TrimSpace(item.S[:idx])
	rest := item.S[idx+2:]
	if head == "" || !strings.Contains(head, ".") {
		return validation.VNull(), false
	}
	if strings.ContainsFunc(head, unicode.IsSpace) {
		return validation.VNull(), false
	}
	entry := validation.VObj(validation.KV{K: "file", V: validation.VStr(head)})
	if m := anchorLineRe.FindStringSubmatch(rest); m != nil {
		if line, err := strconv.Atoi(m[1]); err == nil && line >= 1 {
			entry = kvOf(entry, "line", validation.VInt(int64(line)))
		}
	}
	return entry, true
}

// kvOf appends one key/value to an object value.
func kvOf(v validation.Value, k string, val validation.Value) validation.Value {
	return validation.VObj(append(append([]validation.KV{}, v.O...),
		validation.KV{K: k, V: val})...)
}

// StripFilePrefix is strip_file_prefix: drop the <40hex>/<org>/<repo>/ prefix
// from a files entry when the org/repo is already known from the report URL.
// Pinned rules: strip the leading commit when hex-like; then a leading
// org/repo pair (org known) or repo (repo known); otherwise leave the path
// untouched.
func StripFilePrefix(path string, orgs, repos map[string]bool) string {
	text := strings.TrimSpace(path)
	segments := strings.Split(text, "/")
	index := 0
	if len(segments) > 0 && hexLikeRe.MatchString(segments[0]) {
		index = 1
	}
	rest := segments[index:]
	if len(rest) >= 3 && orgs[strings.ToLower(rest[0])] {
		index += 2
	} else if len(rest) >= 2 && repos[strings.ToLower(rest[0])] {
		index++
	}
	if index == 0 {
		return text
	}
	return strings.Join(segments[index:], "/")
}

// CleanCommit is clean_commit: the first schema-safe hex commit (7-64 chars)
// from a str|list|None, 0x-prefix stripped. None when nothing qualifies (empty,
// "n/a", "null", "Version 1", truncated hex with "...").
func CleanCommit(value validation.Value) *string {
	var candidates []validation.Value
	switch value.Kind {
	case validation.Arr:
		candidates = value.A
	default:
		candidates = []validation.Value{value}
	}
	for _, entry := range candidates {
		if entry.Kind != validation.Str {
			continue
		}
		text := strings.TrimSpace(entry.S)
		if strings.HasPrefix(strings.ToLower(text), "0x") && len(text) > 2 {
			text = text[2:]
		}
		if hexLikeRe.MatchString(text) {
			c := text
			return &c
		}
	}
	return nil
}

// firstStr is _first_str.
func firstStr(value validation.Value) *string {
	collect := func(v validation.Value) *string {
		if v.Kind != validation.Str {
			return nil
		}
		if t := strings.TrimSpace(v.S); t != "" {
			return &t
		}
		return nil
	}
	if value.Kind == validation.Arr {
		for _, item := range value.A {
			if s := collect(item); s != nil {
				return s
			}
		}
		return nil
	}
	return collect(value)
}

// urlOrgsRepos is _url_orgs_repos.
func urlOrgsRepos(info validation.Value) (map[string]bool, map[string]bool) {
	orgs, repos := map[string]bool{}, map[string]bool{}
	urls := at(info, "url")
	items := []validation.Value{urls}
	if urls.Kind == validation.Arr {
		items = urls.A
	}
	for _, item := range items {
		if item.Kind != validation.Str {
			continue
		}
		text := strings.TrimRight(strings.TrimSpace(item.S), "/")
		parts := strings.Split(text, "/")
		if len(parts) > 0 {
			repos[strings.ToLower(parts[len(parts)-1])] = true
		}
		if len(parts) >= 2 {
			orgs[strings.ToLower(parts[len(parts)-2])] = true
		}
	}
	return orgs, repos
}

// BuildCode is build_code: the common-shape code block. repo falls back to an
// explicit "unknown/<slug>" placeholder (ingest_record requires repo);
// snapshot_note records why a code pointer is weak.
func BuildCode(projectInfo validation.Value, findingFiles []validation.Value,
	slug string, withoutSource bool) validation.Value {
	info := projectInfo
	if info.Kind != validation.Obj {
		info = validation.VObj()
	}
	repo := "unknown/" + slug
	if s := firstStr(at(info, "url")); s != nil {
		repo = *s
	}
	code := validation.VObj(validation.KV{K: "repo", V: validation.VStr(repo)})
	commit := CleanCommit(at(info, "commit_id"))
	if commit != nil {
		code = kvOf(code, "commit", validation.VStr(*commit))
	}
	orgs, repos := urlOrgsRepos(info)
	var files []string
	for _, f := range findingFiles {
		if f.Kind != validation.Str {
			continue
		}
		if p := StripFilePrefix(f.S, orgs, repos); p != "" {
			files = append(files, p)
		}
	}
	if len(files) > 0 {
		items := make([]validation.Value, len(files))
		for i, f := range files {
			items[i] = validation.VStr(f)
		}
		code = kvOf(code, "files", validation.VArr(items...))
	}
	var notes []string
	if withoutSource {
		notes = append(notes, "no resolved source in FORGE-Curated "+
			"(findings-without-source); code pointers unresolved")
	}
	if strings.HasPrefix(repo, "unknown/") {
		notes = append(notes, "report publishes no repository URL")
	}
	if commit == nil {
		notes = append(notes, "commit as published in dataset; not a verified ref")
	}
	if len(notes) > 0 {
		code = kvOf(code, "snapshot_note", validation.VStr(strings.Join(notes, "; ")))
	}
	return code
}

// buildChains is _build_chains.
func buildChains(chain validation.Value) validation.Value {
	items := []validation.Value{chain}
	if chain.Kind == validation.Arr {
		items = chain.A
	}
	var chains []string
	seen := map[string]bool{}
	for _, item := range items {
		if item.Kind != validation.Str {
			continue
		}
		text := strings.TrimSpace(item.S)
		if absentTokens[strings.ToLower(text)] || seen[text] {
			continue
		}
		seen[text] = true
		chains = append(chains, text)
	}
	out := make([]validation.Value, len(chains))
	for i, c := range chains {
		out[i] = validation.VStr(c)
	}
	return validation.VArr(out...)
}

// requiredFindingKeys is the build_record presence check.
var requiredFindingKeys = []string{"id", "title", "description", "severity",
	"category", "location", "files"}

// BuildRecord is build_record: one common-shape record from a curated finding.
// Every FORGE row is a positive audit finding: negative stays False, prior is
// Medium+ only, pattern is the title (memory rows carry it), exploit is None
// (audit findings have no PoC), partition is dev.
func BuildRecord(report validation.Value, stem string, finding validation.Value,
	withoutSource bool) (validation.Value, error) {
	sevPtr, err := validateFinding(finding, stem)
	if err != nil {
		return validation.VNull(), err
	}
	recordID := stem + "-" + pyStr(at(finding, "id"))
	title := fitFindingTitle(recordID, pyStrOrEmpty(at(finding, "title")))
	description := fitFindingDescription(title,
		pyStrOrEmpty(at(finding, "description")))
	prior := sevPtr != nil && inList(*sevPtr, PriorSeverities)
	pattern := validation.VNull()
	if prior {
		p := title
		if runeLen(p) > 500 {
			p = runeSlice(p, 0, 500)
		}
		pattern = validation.VStr(p)
	}
	info := at(report, "project_info")
	outcome, err := MapOutcome(sevPtr)
	if err != nil {
		return validation.VNull(), err
	}
	mappedSeverity, err := MapSeverity(sevPtr)
	if err != nil {
		return validation.VNull(), err
	}
	sevValue := validation.VNull()
	if mappedSeverity != nil {
		sevValue = validation.VStr(*mappedSeverity)
	}
	labelValue := validation.VNull()
	if label := ExtractLabel(at(finding, "category")); label != nil {
		labelValue = validation.VStr(*label)
	}
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(recordID)},
		validation.KV{K: "dataset", V: validation.VStr(Dataset)},
		validation.KV{K: "url", V: validation.VNull()},
		validation.KV{K: "program", V: validation.VObj(
			validation.KV{K: "program", V: validation.VStr(stem)},
			validation.KV{K: "platform", V: validation.VNull()},
			validation.KV{K: "chains", V: buildChains(at(info, "chain"))})},
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "description", V: validation.VStr(description)},
		validation.KV{K: "bug_class_label", V: labelValue},
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "severity", V: sevValue},
		validation.KV{K: "negative", V: validation.VBool(false)},
		validation.KV{K: "prior", V: validation.VBool(prior)},
		validation.KV{K: "pattern", V: pattern},
		validation.KV{K: "root_cause", V: validation.VStr(
			ExtractRootCause(description))},
		validation.KV{K: "locations", V: validation.VArr(
			buildLocations(report, finding)...)},
		validation.KV{K: "code", V: BuildCode(info,
			valsOf(at(finding, "files")), stem, withoutSource)},
		validation.KV{K: "exploit", V: validation.VNull()},
		validation.KV{K: "partition", V: validation.VStr(Partition)},
	), nil
}

// validateFinding is build_record's presence + severity gate. It returns the
// raw severity pointer (nil for Python None) or the exact ValueError text.
func validateFinding(finding validation.Value, stem string) (*string, error) {
	for _, key := range requiredFindingKeys {
		if !hasKey(finding, key) {
			return nil, fmt.Errorf("forge-curated finding in %s is missing %s",
				validation.PyReprStr(stem), validation.PyReprStr(key))
		}
	}
	severity := at(finding, "severity")
	if severity.Kind == validation.Null {
		return nil, nil
	}
	if severity.Kind != validation.Str {
		return nil, unknownSeverity(stem, finding, severity)
	}
	if _, ok := severityMap[severity.S]; !ok {
		return nil, unknownSeverity(stem, finding, severity)
	}
	s := severity.S
	return &s, nil
}

func unknownSeverity(stem string, finding, severity validation.Value) error {
	return fmt.Errorf("forge-curated finding %s-%s: unknown severity %s",
		stem, validation.PyRepr(at(finding, "id")), validation.PyRepr(severity))
}

// fitFindingTitle is build_record's title rule: >=5 chars (padded with the
// record id), <=500 chars (ellipsis).
func fitFindingTitle(recordID, raw string) string {
	title := strings.TrimSpace(raw)
	if runeLen(title) < 5 {
		title = strings.Trim(strings.TrimSpace(title+" ("+recordID+")"), " ()")
		for runeLen(title) < 5 {
			title = title + " " + recordID
		}
	}
	if runeLen(title) > 500 {
		title = runeSlice(title, 0, 497) + "..."
	}
	return title
}

// fitFindingDescription is build_record's description rule: >=20 chars
// (title-prefixed), <=10000 chars.
func fitFindingDescription(title, raw string) string {
	description := strings.TrimSpace(raw)
	if runeLen(description) < 20 {
		description = strings.TrimSpace(title + "\n\n" + description)
	}
	if runeLen(description) > 10000 {
		description = runeSlice(description, 0, 10000)
	}
	return description
}

// buildLocations is build_record's locations loop: File::symbol anchors first
// (deduplicated on file+line), then prefix-stripped files entries.
func buildLocations(report, finding validation.Value) []validation.Value {
	type locKey struct {
		file    string
		line    int64
		hasLine bool
	}
	seen := map[locKey]bool{}
	var locations []validation.Value
	info := at(report, "project_info")
	orgs, repos := urlOrgsRepos(info)
	for _, item := range valsOf(at(finding, "location")) {
		entry, ok := ParseLocation(item)
		if !ok {
			continue
		}
		line := at(entry, "line")
		key := locKey{file: pyStrOrEmpty(at(entry, "file")),
			line: line.I, hasLine: line.Kind == validation.Int}
		if seen[key] {
			continue
		}
		seen[key] = true
		locations = append(locations, entry)
	}
	for _, raw := range valsOf(at(finding, "files")) {
		if raw.Kind != validation.Str {
			continue
		}
		path := StripFilePrefix(raw.S, orgs, repos)
		if path == "" || seen[locKey{file: path}] {
			continue
		}
		seen[locKey{file: path}] = true
		locations = append(locations, validation.VObj(
			validation.KV{K: "file", V: validation.VStr(path)}))
	}
	return locations
}

// LoadRecords is load_records: every curated report's findings as
// common-shape records (pure file reads; never writes to the clone).
// findings-without-source reports are included and flagged via snapshot_note.
// source overrides DATASET_DIR.
func LoadRecords(source *string) ([]validation.Value, error) {
	base := DatasetDir
	if source != nil {
		base = *source
	}
	var records []validation.Value
	for _, sub := range ReportSubdirs {
		withoutSource := sub == "findings-without-source"
		dir := filepath.Join(base, sub)
		names, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var paths []string
		for _, e := range names {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") ||
				!strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			paths = append(paths, e.Name())
		}
		sort.Strings(paths)
		for _, name := range paths {
			path := filepath.Join(dir, name)
			report, err := validation.ReadJson(path)
			if err != nil {
				return nil, err
			}
			findings := at(report, "findings")
			if report.Kind != validation.Obj || findings.Kind != validation.Arr {
				return nil, fmt.Errorf(
					"forge-curated report %s must hold a 'findings' list", path)
			}
			stem := strings.TrimSuffix(name, ".json")
			for _, finding := range findings.A {
				rec, err := BuildRecord(report, stem, finding, withoutSource)
				if err != nil {
					return nil, err
				}
				records = append(records, rec)
			}
		}
	}
	return records, nil
}

// IngestOptions are ingest's keyword arguments.
type IngestOptions struct {
	Maps *validation.Value
	Tier string
}

// Ingest is ingest: load the whole curated subset, ingest_record each, publish
// prior knowledge under one shared program key. maps pins the taxonomy lookup
// (default: common + forge maps); tier selects the publish target (the
// controller's real ingestion uses the default — never call this from a test).
func Ingest(opts IngestOptions) (validation.Value, error) {
	maps := opts.Maps
	if maps == nil {
		m, err := taxonomy.LoadMaps([]string{"forge"})
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
	programKey := ProgramKey
	summary, err := ingest.PublishIngested(results, Dataset, &programKey, tier)
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

func hasKey(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, p := range v.O {
		if p.K == key {
			return true
		}
	}
	return false
}

// valsOf is Python's iteration over a list ([] for None/non-list).
func valsOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0 || v.Big != ""
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

// pyStr is Python's str(v): raw text for strings, repr otherwise.
func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
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
