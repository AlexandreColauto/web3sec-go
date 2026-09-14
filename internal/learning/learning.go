package learning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// MEMORY_STATUSES is MEMORY_STATUSES (learning.py), in order.
var MEMORY_STATUSES = []string{"CONFIRMED", "DISPROVED", "DUPLICATE",
	"OUT_OF_SCOPE", "INTENDED_BEHAVIOR", "UNREACHABLE", "NON-ECONOMIC",
	"TEST-HARNESS-ONLY"}

// MemorySchemaVersion is MEMORY_SCHEMA_VERSION: the memory-row shape version.
const MemorySchemaVersion = 2

// REJECTION_CLASSES is REJECTION_CLASSES, in order.
var REJECTION_CLASSES = []string{"invalid-hypothesis", "not-exploitable",
	"below-threshold"}

// rejectionClassByStatus is _REJECTION_CLASS_BY_STATUS.
var rejectionClassByStatus = map[string]string{
	"DISPROVED":         "invalid-hypothesis",
	"UNREACHABLE":       "not-exploitable",
	"INTENDED_BEHAVIOR": "not-exploitable",
	"TEST-HARNESS-ONLY": "not-exploitable",
	"NON-ECONOMIC":      "below-threshold",
	"OUT_OF_SCOPE":      "below-threshold",
}

// MemoryKinds is the `kind` vocabulary queue_memory accepts, in the order
// the error text's tuple is not shown (Python uses a literal tuple).
var MemoryKinds = []string{"confirmed", "disproved", "detector", "benchmark",
	"reflection", "drift", "regression"}

// propositionTypes is the deciding-proposition `type` enum (schema order).
var propositionTypes = []string{"reachability", "authority", "control",
	"state", "invariant", "economic", "environment", "temporal", "cross_domain"}

// HINT_KINDS is HINT_KINDS.
var HINT_KINDS = []string{"priority", "exclusion", "detector", "note"}

// QueueOpts carries queue_memory's keyword arguments (pointers are Python's
// None).
type QueueOpts struct {
	Kind                 string
	Status               string
	Pattern              string
	FindingID            *string
	BugClass             *string
	CWE                  *string
	EvidenceSummary      string
	Negative             *validation.Value
	Detector             *validation.Value
	Regression           *validation.Value
	RejectionClass       *string
	DecidingPropositions []validation.Value
}

// findingCapabilityLabels is _finding_capability_labels: normalized
// `capabilities.<key>` labels of the finding a memory row is derived from —
// [] when there is no finding, or it carries none. Never raises on a
// missing finding: queue_memory has always accepted a finding_id without
// requiring the file to exist.
func findingCapabilityLabels(c *state.Campaign, findingID *string,
	key string) []string {
	if findingID == nil || *findingID == "" {
		return nil
	}
	if _, err := os.Stat(findings.FindingPath(c, *findingID)); err != nil {
		return nil
	}
	finding, err := findings.LoadFinding(c, *findingID)
	if err != nil {
		return nil
	}
	caps := objAt(finding, "capabilities")
	if caps.Kind != validation.Obj {
		return nil
	}
	return capabilities.NormalizeLabels(strList(objAt(caps, key)))
}

// QueueMemory is queue_memory: queue a memory candidate. promotion_status
// starts as 'pending' and NOTHING in this codebase can flip it to promoted —
// only ApproveMemory with an explicit human approver does.
func QueueMemory(c *state.Campaign, o QueueOpts) (validation.Value, error) {
	if !inList(o.Status, MEMORY_STATUSES) {
		return validation.VNull(), fmt.Errorf("invalid memory status %s",
			pyReprStr(o.Status))
	}
	if !inList(o.Kind, MemoryKinds) {
		return validation.VNull(), fmt.Errorf("invalid memory kind %s",
			pyReprStr(o.Kind))
	}
	var rejectionClass *string
	if o.RejectionClass == nil {
		if rc, ok := rejectionClassByStatus[o.Status]; ok {
			rejectionClass = &rc
		}
	} else {
		if !inList(*o.RejectionClass, REJECTION_CLASSES) {
			return validation.VNull(), fmt.Errorf("invalid rejection_class %s",
				pyReprStr(*o.RejectionClass))
		}
		rejectionClass = o.RejectionClass
	}
	if err := checkPropositions(o.DecidingPropositions); err != nil {
		return validation.VNull(), err
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	mem := validation.VObj(
		kv("memory_id", validation.VStr("MEM-"+idTail(8))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("finding_id", strOrNull(o.FindingID)),
		kv("snapshot_id", strOrNull(snap)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("kind", validation.VStr(o.Kind)),
		kv("status", validation.VStr(o.Status)),
		kv("pattern", validation.VStr(o.Pattern)),
		kv("bug_class", strOrNull(o.BugClass)),
		kv("cwe", strOrNull(o.CWE)),
		kv("evidence_summary", validation.VStr(o.EvidenceSummary)),
		kv("schema_version", validation.VInt(MemorySchemaVersion)),
		kv("rejection_class", strOrNull(rejectionClass)),
		kv("promotion_status", validation.VStr("pending")),
		kv("approved_by", validation.VNull()),
		kv("approved_at", validation.VNull()))
	if len(o.DecidingPropositions) > 0 {
		mem.O = append(mem.O, kv("deciding_propositions",
			validation.VArr(o.DecidingPropositions...)))
	}
	if o.Negative != nil && validation.PyTruthy(*o.Negative) {
		mem.O = append(mem.O, kv("negative_mode", *o.Negative))
	}
	if o.Detector != nil && validation.PyTruthy(*o.Detector) {
		mem.O = append(mem.O, kv("detector", *o.Detector))
	}
	if o.Regression != nil && validation.PyTruthy(*o.Regression) {
		mem.O = append(mem.O, kv("regression", *o.Regression))
	}
	// Capability labels (B3/D2): a row derived from a finding carries that
	// finding's explicit capability lists, normalized exactly as
	// shared_memory.derive_signature normalizes them.
	for _, key := range []string{"granted", "required"} {
		labels := findingCapabilityLabels(c, o.FindingID, key)
		if len(labels) > 0 {
			mem.O = append(mem.O, kv(key, strArr(labels)))
		}
	}
	if err := validation.Validate(mem, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	mid := objStr(mem, "memory_id")
	path := filepath.Join(c.MemoryDir, mid+".json")
	if err := validation.WriteJson(path, mem, ""); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("kind", validation.VStr(o.Kind)),
		kv("status", validation.VStr(o.Status)),
		kv("rejection_class", strOrNull(rejectionClass)),
		kv("deciding_propositions",
			validation.VInt(int64(len(o.DecidingPropositions)))))
	if _, err := c.Log("memory.queued", &mid, &data); err != nil {
		return validation.VNull(), err
	}
	return mem, nil
}

// checkPropositions is queue_memory's deciding_propositions validation.
func checkPropositions(props []validation.Value) error {
	if len(props) > 16 {
		return errors.New("deciding_propositions must be a list of <= 16")
	}
	for _, p := range props {
		if p.Kind != validation.Obj {
			return errors.New(
				"each deciding proposition needs a statement of 10-500 chars")
		}
		statement, ok := fieldAt(p, "statement")
		if !ok || statement.Kind != validation.Str ||
			len([]rune(statement.S)) < 10 || len([]rune(statement.S)) > 500 {
			return errors.New(
				"each deciding proposition needs a statement of 10-500 chars")
		}
		if t, ok := fieldAt(p, "type"); ok && t.Kind != validation.Null &&
			!(t.Kind == validation.Str && inList(t.S, propositionTypes)) {
			return fmt.Errorf("invalid proposition type %s", pyRepr(t))
		}
	}
	return nil
}

// memoryIDRe is the only shape a memory id may have (newId("MEM", n) emits
// MEM-<hex>). The id arrives from the command line and is joined into a path,
// so an id carrying a separator or ".." must not reach the filesystem; it gets
// the same not-found error a missing row gets, so the CLI's wording does not
// change for the garbage case.
var memoryIDRe = regexp.MustCompile(`^MEM-[0-9a-f]+$`)

// AssertApprovable is assert_approvable: the leakage-partition guard
// (constraint 4). Rows partitioned 'held-out'/'training' are evaluation data
// and can never be approved or promoted. Absent partition == 'dev'.
func AssertApprovable(memoryID string, mem validation.Value) error {
	partition := objStr(mem, "partition")
	if partition == "" {
		partition = "dev"
	}
	if partition != "dev" {
		return fmt.Errorf("%s has partition %s: 'held-out'/'training' rows "+
			"are evaluation data and can never be approved or promoted "+
			"(leakage-partition constraint 4)", memoryID, pyReprStr(partition))
	}
	return nil
}

// ApproveMemory is approve_memory: record human approval. It refuses to
// self-authorize: approver must be a non-empty identity string recorded in
// the file and the event log.
func ApproveMemory(c *state.Campaign, memoryID, approver string) (validation.Value, error) {
	if approver == "" {
		return validation.VNull(), errors.New(
			"memory promotion requires a recorded human approver")
	}
	path := filepath.Join(c.MemoryDir, memoryID+".json")
	// r7 (critic): a bare id as an error message names nothing — the
	// operator cannot tell a typo from a missing row from a shape bug.
	if !memoryIDRe.MatchString(memoryID) {
		return validation.VNull(), fmt.Errorf(
			"%s is not a memory id (expected MEM-<12 hex>)", memoryID)
	}
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Errorf(
			"memory %s not found in %s's queue — `webv2 memory %s` lists "+
				"what is there", memoryID, c.CampaignID, c.CampaignID)
	}
	mem, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := AssertApprovable(memoryID, mem); err != nil {
		return validation.VNull(), err
	}
	mem.O = validation.SetOrAppend(mem.O, "promotion_status",
		validation.VStr("human-approved"))
	mem.O = validation.SetOrAppend(mem.O, "approved_by", validation.VStr(approver))
	mem.O = validation.SetOrAppend(mem.O, "approved_at", validation.VStr(state.NowIso()))
	if err := validation.Validate(mem, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(path, mem, ""); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(kv("approver", validation.VStr(approver)))
	if _, err := c.Log("memory.approved", &memoryID, &data); err != nil {
		return validation.VNull(), err
	}
	return mem, nil
}

// RejectMemory is the missing other half of ApproveMemory (D5, 2026-09-10): a
// queued candidate could only ever be approved, so a wrong or unreachable row
// stayed in the inbox forever and a reviewer had no way to record "no". The
// REASON is required and goes into the event log (`memory.rejected`), not into
// the row: the memory schema has additionalProperties:false and no reason
// field, and the audit trail is the log. rejection_class carries the schema's
// three-way classification (invalid-hypothesis / not-exploitable /
// below-threshold) when the reviewer can give one; empty means null.
//
// Refuses to reject a row that is already human-approved or promoted — that is
// a revocation, not a rejection, and silently overwriting an approval would
// erase the record of who approved what.
func RejectMemory(c *state.Campaign, memoryID, reason, rejectionClass string) (validation.Value, error) {
	if strings.TrimSpace(reason) == "" {
		return validation.VNull(), errors.New(
			"memory rejection requires a written reason")
	}
	path := filepath.Join(c.MemoryDir, memoryID+".json")
	// r7 (critic): a bare id as an error message names nothing — the
	// operator cannot tell a typo from a missing row from a shape bug.
	if !memoryIDRe.MatchString(memoryID) {
		return validation.VNull(), fmt.Errorf(
			"%s is not a memory id (expected MEM-<12 hex>)", memoryID)
	}
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Errorf(
			"memory %s not found in %s's queue — `webv2 memory %s` lists "+
				"what is there", memoryID, c.CampaignID, c.CampaignID)
	}
	mem, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	status := objStr(mem, "promotion_status")
	if status == "human-approved" || status == "promoted" {
		return validation.VNull(), fmt.Errorf(
			"%s is already %s: revoke the approval instead of rejecting it",
			memoryID, status)
	}
	mem.O = validation.SetOrAppend(mem.O, "promotion_status", validation.VStr("rejected"))
	if rejectionClass != "" {
		mem.O = validation.SetOrAppend(mem.O, "rejection_class",
			validation.VStr(rejectionClass))
	}
	if err := validation.Validate(mem, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(path, mem, ""); err != nil {
		return validation.VNull(), err
	}
	rc := validation.VNull()
	if rejectionClass != "" {
		rc = validation.VStr(rejectionClass)
	}
	data := validation.VObj(
		kv("reason", validation.VStr(reason)),
		kv("rejection_class", rc))
	if _, err := c.Log("memory.rejected", &memoryID, &data); err != nil {
		return validation.VNull(), err
	}
	return mem, nil
}

// StripCampaignMemoryField is strip_campaign_memory_field: sanctioned,
// actor-attributed removal of a retired field from campaign-local memory
// rows (<root>/campaigns/*/memory/*.json). Returns {"campaigns":
// [{"campaign_id", "rows_stripped"}], "total_stripped": int}.
func StripCampaignMemoryField(root, field, actor, reason string) (validation.Value, error) {
	campaignsDir := filepath.Join(root, "campaigns")
	entries, err := os.ReadDir(campaignsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return validation.VObj(
				kv("campaigns", validation.VArr()),
				kv("total_stripped", validation.VInt(0))), nil
		}
		return validation.VNull(), err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := []validation.Value{}
	total := 0
	for _, name := range names {
		cdir := filepath.Join(campaignsDir, name)
		if fi, err := os.Stat(cdir); err != nil || !fi.IsDir() {
			continue
		}
		memdir := filepath.Join(cdir, "memory")
		if fi, err := os.Stat(memdir); err != nil || !fi.IsDir() {
			continue
		}
		paths := validation.ListPrefixed(memdir, "", ".json")
		if err != nil {
			return validation.VNull(), err
		}
		sort.Strings(paths)
		rows := make(map[string]validation.Value, len(paths))
		targets := []string{}
		for _, p := range paths {
			row, err := validation.ReadJson(p)
			if err != nil {
				return validation.VNull(), err
			}
			rows[p] = row
			if _, ok := fieldAt(row, field); ok {
				targets = append(targets, p)
			}
		}
		if len(targets) == 0 {
			continue
		}
		c, err := state.Open(root, name)
		if err != nil {
			return validation.VNull(), err
		}
		data := validation.VObj(
			kv("actor", validation.VStr(actor)),
			kv("field", validation.VStr(field)),
			kv("reason", validation.VStr(reason)),
			kv("rows_stripped", validation.VInt(int64(len(targets)))))
		ref := name
		// The rows are written BEFORE the event: the event claims the strip
		// happened, so it may only be logged once it did. (Logging first left
		// a hash-chained record of work that a failed write never performed.)
		for _, p := range targets {
			row := rows[p]
			row.O = removeKey(row.O, field)
			if err := validation.WriteJson(p, row, ""); err != nil {
				return validation.VNull(), err
			}
		}
		if _, err := c.Log("memory.field-stripped", &ref, &data); err != nil {
			return validation.VNull(), err
		}
		out = append(out, validation.VObj(
			kv("campaign_id", validation.VStr(name)),
			kv("rows_stripped", validation.VInt(int64(len(targets))))))
		total += len(targets)
	}
	return validation.VObj(
		kv("campaigns", validation.VArr(out...)),
		kv("total_stripped", validation.VInt(int64(total)))), nil
}

// PromotionCommands is promotion_commands: the approved write path for a
// human-approved candidate. The command is not executed here: promotion
// crosses the campaign boundary, which is an operator/harness act.
func PromotionCommands(c *state.Campaign, memoryID, actor string) ([]validation.Value, error) {
	if actor == "" {
		actor = "<human>"
	}
	mem, err := validation.ReadJson(filepath.Join(c.MemoryDir, memoryID+".json"))
	if err != nil {
		return nil, err
	}
	status := objStr(mem, "promotion_status")
	if status != "human-approved" {
		return nil, fmt.Errorf("%s is %s; human approval required before any "+
			"promotion", memoryID, pyReprStr(status))
	}
	return []validation.Value{validation.VObj(
		kv("substrate", validation.VStr("shared-memory-store")),
		kv("command", validation.VStr("webv2 publish "+c.CampaignID+
			" --actor "+actor)),
		kv("note", validation.VStr("promotes every approved memory row + "+
			"confirmed-finding signatures to the shared store (idempotent)")))}, nil
}

// ReflectionOpts carries reflection_entry's keyword arguments.
type ReflectionOpts struct {
	Round               int64
	FalseAssumptions    []string
	ToolFailures        []string
	WastedEffort        []string
	WhatWorked          []string
	ProcessImprovements []string
}

// ReflectionEntry is reflection_entry: append one trajectory-reflection
// entry to the learnings inbox (learnings.jsonl).
func ReflectionEntry(c *state.Campaign, o ReflectionOpts) (validation.Value, error) {
	entry := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("round", validation.VInt(o.Round)),
		kv("at", validation.VStr(state.NowIso())),
		kv("false_assumptions", strArr(o.FalseAssumptions)),
		kv("tool_failures", strArr(o.ToolFailures)),
		kv("wasted_effort", strArr(o.WastedEffort)),
		kv("what_worked", strArr(o.WhatWorked)),
		kv("process_improvements", strArr(o.ProcessImprovements)))
	path := filepath.Join(c.Dir, "learnings.jsonl")
	if err := validation.AppendJsonl(path,
		validation.DumpsOrdered(entry, false)); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(kv("round", validation.VInt(o.Round)))
	if _, err := c.Log("reflection.recorded", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// HintOpts carries planner_hint's keyword arguments.
type HintOpts struct {
	Kind      string
	Content   string
	SourceRef string
	Actor     string
}

// PlannerHint is planner_hint: a reflection-derived instruction for the
// PLANNER. Append-only, attributed, logged.
func PlannerHint(c *state.Campaign, o HintOpts) (validation.Value, error) {
	if !inList(o.Kind, HINT_KINDS) {
		return validation.VNull(), fmt.Errorf("invalid hint kind %s; kinds: %s",
			pyReprStr(o.Kind), pyReprTuple(HINT_KINDS))
	}
	if len([]rune(strings.TrimSpace(o.Content))) < 10 {
		return validation.VNull(), errors.New(
			"a planner hint needs substantive content (>=10 chars)")
	}
	if o.Actor == "" {
		o.Actor = "reflection"
	}
	row := validation.VObj(
		kv("hint_id", validation.VStr("HINT-"+idTail(8))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("kind", validation.VStr(o.Kind)),
		kv("content", validation.VStr(strings.TrimSpace(o.Content))),
		kv("source_ref", validation.VStr(o.SourceRef)),
		kv("actor", validation.VStr(o.Actor)),
		kv("at", validation.VStr(state.NowIso())))
	path := filepath.Join(c.Dir, "planner_hints.jsonl")
	if err := validation.AppendJsonl(path,
		validation.DumpsOrdered(row, false)); err != nil {
		return validation.VNull(), err
	}
	hid := objStr(row, "hint_id")
	data := validation.VObj(
		kv("kind", validation.VStr(o.Kind)),
		kv("actor", validation.VStr(o.Actor)))
	if _, err := c.Log("learning.planner_hint", &hid, &data); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// LoadPlannerHints is load_planner_hints: the JSONL rows, in file order,
// optionally filtered by kind.
func LoadPlannerHints(c *state.Campaign, kind *string) ([]validation.Value, error) {
	path := filepath.Join(c.Dir, "planner_hints.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []validation.Value{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		row, err := ReadJSONLine(line)
		if err != nil {
			return nil, err
		}
		if kind != nil && *kind != "" && objStr(row, "kind") != *kind {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

// ReadJSONLine is read_json_line: json.loads(line).
func ReadJSONLine(line string) (validation.Value, error) {
	return validation.ParseOrdered([]byte(line))
}

// PendingMemory is pending_memory: rows whose promotion_status is 'pending'.
func PendingMemory(c *state.Campaign) ([]validation.Value, error) {
	rows, err := AllMemory(c)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, m := range rows {
		if objStr(m, "promotion_status") == "pending" {
			out = append(out, m)
		}
	}
	return out, nil
}

// AllMemory is all_memory: every MEM-*.json row, filename-sorted.
func AllMemory(c *state.Campaign) ([]validation.Value, error) {
	paths := validation.ListPrefixed(c.MemoryDir, "MEM-", ".json")
	out := make([]validation.Value, 0, len(paths))
	for _, p := range paths {
		row, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// negativeStatuses is the status set negative_memory_lookup scans.
var negativeStatuses = []string{"DISPROVED", "INTENDED_BEHAVIOR",
	"NON-ECONOMIC", "TEST-HARNESS-ONLY", "UNREACHABLE"}

// NegativeMemoryLookup is negative_memory_lookup: local negative-mode
// retrieval — memory candidates whose pattern shares a keyword with the
// query.
func NegativeMemoryLookup(c *state.Campaign, patternText string) ([]validation.Value, error) {
	words := map[string]struct{}{}
	for _, w := range ReSplit(patternText) {
		// Runes, not bytes: sharedmem's keyword filter (the other half of this
		// retrieval) counts runes, so a non-ASCII keyword used to be eligible
		// in one path and not the other.
		if utf8.RuneCountInString(w) > 3 {
			words[w] = struct{}{}
		}
	}
	rows, err := AllMemory(c)
	if err != nil {
		return nil, err
	}
	hits := []validation.Value{}
	for _, m := range rows {
		if !inList(objStr(m, "status"), negativeStatuses) {
			continue
		}
		neg := objAt(m, "negative_mode")
		text := strings.ToLower(objStr(m, "pattern") + " " +
			objStr(neg, "why_safe"))
		for _, w := range ReSplit(text) {
			if _, ok := words[w]; ok {
				hits = append(hits, m)
				break
			}
		}
	}
	return hits, nil
}

// ReSplit is Python's re.split(r"\W+", s.lower()) over word runs (\w is
// Unicode-aware in Python: letters, numbers and underscore).
func ReSplit(s string) []string {
	out := []string{}
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// BenchmarkOpts carries benchmark_case's keyword arguments.
type BenchmarkOpts struct {
	Name          string
	Repo          string
	Expected      string
	SourceFinding *string
}

// BenchmarkCase is benchmark_case: register a benchmark case from a real
// result — the substrate for comparing prompt/model/pipeline changes.
func BenchmarkCase(c *state.Campaign, o BenchmarkOpts) (validation.Value, error) {
	c4 := validation.VObj(
		kv("case_id", validation.VStr("BENCH-"+idTail(6))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("name", validation.VStr(o.Name)),
		kv("repo", validation.VStr(o.Repo)),
		kv("expected", validation.VStr(o.Expected)),
		kv("source_finding", strOrNull(o.SourceFinding)),
		kv("created_at", validation.VStr(state.NowIso())))
	path := filepath.Join(c.Dir, "benchmarks.jsonl")
	if err := validation.AppendJsonl(path,
		validation.DumpsOrdered(c4, false)); err != nil {
		return validation.VNull(), err
	}
	cid := objStr(c4, "case_id")
	data := validation.VObj(kv("name", validation.VStr(o.Name)))
	if _, err := c.Log("benchmark.recorded", &cid, &data); err != nil {
		return validation.VNull(), err
	}
	return c4, nil
}

// ---- small shared helpers -------------------------------------------------

func inList(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func strOrNull(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.VArr(out...)
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

// removeKey is `del d[k]` (no-op when absent).
func removeKey(o []validation.KV, key string) []validation.KV {
	out := o[:0]
	for _, e := range o {
		if e.K != key {
			out = append(out, e)
		}
	}
	return out
}

// idTail is new_id('x', n).split('-')[1].
func idTail(n int) string {
	return strings.SplitN(state.NewID("x", n), "-", 2)[1]
}

// pyReprTuple is a Python tuple literal: ('a', 'b').
func pyReprTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, pyReprStr(it))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + joinComma(parts) + ")"
}

// StaleBugClass reports whether an approved row's bug_class no longer
// matches its source finding's root class (an amend --class after queueing
// moves the finding out from under the row). Returns the pair and true
// when the drift exists; absent finding id, missing row, or matching
// class all report false (r7: the promotion should not silently carry a
// stale taxonomy label — the CLI warns; the human decides).
func StaleBugClass(c *state.Campaign, mem validation.Value) (
	rowClass, findingClass string, stale bool) {
	fid := objStr(mem, "finding_id")
	rowClass = objStr(mem, "bug_class")
	if fid == "" || rowClass == "" {
		return "", "", false
	}
	// r8: follow supersession before judging. The superseded row keeps a
	// FROZEN class (supersede never rewrites root_cause); the live
	// successor carries the taxonomy the finding actually has now. The
	// chain is read from the event ledger — the append-only truth — not
	// from dedup_meta, and a visited set keeps a hand-forged cycle from
	// looping the check.
	seen := map[string]bool{fid: true}
	cur := fid
	for {
		f, err := findings.LoadFinding(c, cur)
		if err != nil {
			return "", "", false
		}
		findingClass = rootClass(f)
		next := supersededBy(c, cur)
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		cur = next
	}
	if findingClass == "" {
		return rowClass, "", false
	}
	if findingClass == "" || findingClass == rowClass {
		return rowClass, findingClass, false
	}
	return rowClass, findingClass, true
}

// rootClass is root_cause.class of a finding row.
func rootClass(f validation.Value) string {
	rc := objAt(f, "root_cause")
	if rc.Kind != validation.Obj {
		return ""
	}
	for _, kv := range rc.O {
		if kv.K == "class" && kv.V.Kind == validation.Str {
			return kv.V.S
		}
	}
	return ""
}

// supersededBy returns the LATEST successor recorded for fid via
// finding.superseded events (the ledger keeps the full chain history);
// "" when none.
func supersededBy(c *state.Campaign, fid string) string {
	events, err := c.Events()
	if err != nil {
		return ""
	}
	next := ""
	for _, ev := range events {
		if objStr(ev, "type") != "finding.superseded" {
			continue
		}
		d := objAt(ev, "data")
		if objStr(d, "old") == fid {
			next = objStr(d, "new")
		}
	}
	return next
}
