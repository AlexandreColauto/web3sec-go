package sft

// lint.go ports sft_dataset's curation lint (Task B, source doc §6,
// mechanized): the arc markers, the per-taxonomy requirements, reason
// completeness, TODO placeholders, pivot accounting, impact specificity, the
// name-anchoring guard and dedup. The lint NEVER raises — it returns rejection
// reasons (empty = pass); `warn:`-prefixed reasons are advisory.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"websec/internal/adapter"
	"websec/internal/validation"
)

// ArcMarkers is ARC_MARKERS: the reasoning arc the trace must walk.
var ArcMarkers = []string{"OBSERVATION", "INITIAL FRAMING", "PIVOT",
	"INVARIANT", "IMPACT"}

var (
	markerRe = regexp.MustCompile(
		`(?m)^\s*(OBSERVATION|INITIAL FRAMING|PIVOT|INVARIANT|IMPACT)\s*:`)
	assumptionStartRe = regexp.MustCompile(`(?m)^\s*A([0-9]{1,4})\b`)
	resolutionArrowRe = regexp.MustCompile(`->\s*(CONFIRMED|REFUTED|OPEN)\b`)
	codeRefRe         = regexp.MustCompile(`\(|function:|line \d+|\.sol`)
	quantifierRe      = regexp.MustCompile(
		`(?i)\d+(\.\d+)?\s*(%|wei|tokens?|shares?|eth|usdc|usd)\b|\b\d+\s*% of\b`)
	belowThresholdRe = regexp.MustCompile(
		`(?i)below (the )?(bounty )?threshold|does not clear`)
	pivotCountRe = regexp.MustCompile(`(?m)^\s*PIVOT\s*:`)
	nextBlockRe  = regexp.MustCompile(`(?m)^\s*A[0-9]{1,4}\b|^\s*(?:OBSERVATION|` +
		`INITIAL FRAMING|PIVOT|INVARIANT|IMPACT)\s*:`)
	wordRe = regexp.MustCompile(`[a-z0-9]+`)
)

var vagueImpactPhrases = []string{"could be at risk", "may allow",
	"potential loss", "funds could"}

var techStopwords = func() map[string]struct{} {
	out := map[string]struct{}{}
	for _, w := range strings.Fields(
		"the a an attacker adversary victim can is are of to in that this " +
			"with via before after when if so as by for on it its") {
		out[w] = struct{}{}
	}
	return out
}()

// ProposerPromptPath is the production proposer system prompt (the corpus
// trains on exactly what production sends).
const ProposerPromptPath = "prompts/47_proposer_system.md"

// proposerPromptText reads the embedded production prompt. Python reads the
// file from the repo; the Go binary carries the byte-identical embedded copy.
func proposerPromptText() (string, error) {
	return adapter.PromptText(ProposerPromptPath)
}

// arcSections is _arc_sections: marker-delimited sections of the assistant
// trace. Multiple PIVOT sections are joined with newlines; later markers close
// earlier sections.
func arcSections(content string) map[string]string {
	idx := markerRe.FindAllStringSubmatchIndex(content, -1)
	sections := map[string]string{}
	for i, m := range idx {
		name := content[m[2]:m[3]]
		stop := len(content)
		if i+1 < len(idx) {
			stop = idx[i+1][0]
		}
		body := strings.TrimSpace(content[m[1]:stop])
		if name == "PIVOT" {
			sections[name] = strings.TrimSpace(sections[name] + "\n" + body)
		} else {
			sections[name] = body
		}
	}
	return sections
}

// traceAssumptions is _trace_assumptions: assumption id -> FINAL resolution
// status in the trace (the last `-> STATUS` arrow inside the block wins).
func traceAssumptions(content string) map[string]string {
	out := map[string]string{}
	for _, m := range assumptionStartRe.FindAllStringSubmatchIndex(content, -1) {
		aid := "A" + content[m[2]:m[3]]
		rest := content[m[1]:]
		block := rest
		if nxt := nextBlockRe.FindStringIndex(rest); nxt != nil {
			block = rest[:nxt[0]]
		}
		for _, rm := range resolutionArrowRe.FindAllStringSubmatch(block, -1) {
			out[aid] = rm[1]
		}
	}
	return out
}

// ExampleSignature is example_signature: taxonomy + bug_class +
// assumption-status sequence + claim technique tokens.
func ExampleSignature(example validation.Value) string {
	st := objAt(example, "structured")
	assumptions := objAt(st, "assumptions")
	statuses := []string{}
	if assumptions.Kind == validation.Arr {
		for _, a := range assumptions.A {
			statuses = append(statuses, objStr(a, "status"))
		}
	}
	words := wordRe.FindAllString(strings.ToLower(objStr(st, "claim")), -1)
	tech := []string{}
	for _, w := range words {
		if _, stop := techStopwords[w]; !stop {
			tech = append(tech, w)
		}
		if len(tech) == 8 {
			break
		}
	}
	blob := strings.Join([]string{
		objStrDefault(example, "taxonomy", ""),
		objStrDefault(st, "bug_class", ""),
		strings.Join(statuses, ","),
		strings.Join(tech, " ")}, "|")
	sum := sha256.Sum256([]byte(blob))
	return hex.EncodeToString(sum[:])
}

// todoPlaceholders is _todo_placeholders: the unfilled skeleton fields.
// Case-insensitive: curators write TODO/todo/Todo interchangeably, and the
// backfill skeleton itself emits "TODO-..." placeholders.
func todoPlaceholders(st validation.Value) []string {
	hasTodo := func(v validation.Value) bool {
		return strings.Contains(strings.ToLower(pyStrValue(v)), "todo")
	}
	hits := []string{}
	assumptions := objAt(st, "assumptions")
	if assumptions.Kind == validation.Arr {
		for _, a := range assumptions.A {
			if hasTodo(objAt(a, "reason")) {
				hits = append(hits, "assumption "+pyStrValue(objAt(a, "id"))+
					".reason")
			}
		}
	}
	for _, field := range []string{"bug_class", "claim", "expected_impact",
		"next_test"} {
		if hasTodo(objAt(st, field)) {
			hits = append(hits, field)
		}
	}
	return hits
}

// pyStrValue is Python str() for a JSON value (None prints "None").
func pyStrValue(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return validation.CanonCompact(v)
}

// LintExample is lint_example: the curation rubric as mechanical checks.
// `existing` nil means "not supplied" (no dedup pass), matching Python's
// existing=None.
func LintExample(example validation.Value, existing []validation.Value,
	status string) []string {
	if err := validation.Validate(example, "sft_example", 1); err != nil {
		return []string{"schema: " + schemaMsg(err)}
	}
	reasons := []string{}
	msgs := objAt(example, "messages")
	content := ""
	if msgs.Kind == validation.Arr && len(msgs.A) == 3 && allObjects(msgs.A) {
		content = objStr(msgs.A[2], "content")
	}
	expected, err := proposerPromptText()
	if err != nil {
		return append(reasons, "system-prompt drift: cannot read the prompt "+
			"file: "+err.Error())
	}
	if msgs.Kind == validation.Arr && len(msgs.A) > 0 &&
		msgs.A[0].Kind == validation.Obj &&
		objStr(msgs.A[0], "content") != expected {
		reasons = append(reasons,
			"system-prompt drift: messages[0] is not byte-identical to "+
				"prompts/47_proposer_system.md — the corpus must train on "+
				"exactly what production sends")
	}
	sections := arcSections(content)
	trace := traceAssumptions(content)
	st := objAt(example, "structured")
	tax := objStr(example, "taxonomy")
	reasons = append(reasons, lintArcPresence(sections, trace)...)
	reasons = append(reasons, lintTaxonomy(tax, sections, st, trace, content)...)
	reasons = append(reasons, lintArcOrder(content, trace)...)
	reasons = append(reasons, lintReasonCompleteness(st)...)
	if todos := todoPlaceholders(st); len(todos) > 0 {
		reasons = append(reasons, "todo: unfilled TODO placeholder(s) in "+
			strings.Join(todos, ", "))
	}
	reasons = append(reasons, lintPivot(content, st)...)
	reasons = append(reasons, lintImpact(tax, sections, st)...)
	reasons = append(reasons, lintNameAnchoring(sections)...)
	reasons = append(reasons, lintDedup(example, existing, status)...)
	return reasons
}

// lintArcPresence is the arc requirement: the trace must walk the arc.
func lintArcPresence(sections map[string]string, trace map[string]string) []string {
	out := []string{}
	for _, marker := range []string{"OBSERVATION", "INITIAL FRAMING"} {
		if sections[marker] == "" {
			out = append(out, "arc: missing "+marker+" section — the trace "+
				"must walk the arc, not jump to a conclusion")
		}
	}
	if len(trace) == 0 {
		out = append(out, "arc: no assumption entry (A# with a -> STATUS "+
			"resolution) found in the trace")
	}
	return out
}

// lintTaxonomy is the per-taxonomy requirement block (source doc §6).
func lintTaxonomy(tax string, sections map[string]string, st validation.Value,
	trace map[string]string, content string) []string {
	out := []string{}
	invStatuses := []string{}
	if inv := objAt(st, "invariants"); inv.Kind == validation.Arr {
		for _, i := range inv.A {
			invStatuses = append(invStatuses, objStr(i, "status"))
		}
	}
	confirmed := func() {
		if sections["INVARIANT"] == "" {
			out = append(out, "arc: INVARIANT section required")
		}
		if sections["IMPACT"] == "" {
			out = append(out, "arc: IMPACT section required")
		}
		if !anyStatus(objAt(st, "assumptions"), "CONFIRMED") {
			out = append(out,
				"taxonomy: at least one CONFIRMED assumption required")
		}
		if !inList(invStatuses, "VIOLATED") {
			out = append(out,
				"taxonomy: an invariant with status VIOLATED required")
		}
		if trimSpace(objAt(st, "next_test")) == "" {
			out = append(out, "taxonomy: next_test must be non-empty")
		}
	}
	switch tax {
	case "confirmed-critical":
		confirmed()
	case "real-weakness-non-exploitable":
		if sections["INVARIANT"] == "" {
			out = append(out, "arc: INVARIANT section required")
		}
		if !anyValue(trace, "REFUTED") {
			out = append(out, "taxonomy: a REFUTED assumption that kills "+
				"exploitability is required")
		}
		if inList(invStatuses, "VIOLATED") || !inList(invStatuses, "HOLDS") {
			out = append(out, "taxonomy: the invariant must HOLD (status "+
				"HOLDS, no VIOLATED) for a non-exploitable weakness")
		}
	case "invalid-hypothesis":
		if !anyValue(trace, "REFUTED") {
			out = append(out, "taxonomy: a REFUTED assumption is required")
		} else {
			low := strings.ToLower(content)
			if !strings.Contains(low, "misread") &&
				!strings.Contains(low, "actually") {
				out = append(out, "taxonomy: the killing resolution must "+
					"name the misreading ('misread'/'actually')")
			}
		}
		if inList(invStatuses, "VIOLATED") {
			out = append(out, "taxonomy: an invalid hypothesis must not "+
				"claim a VIOLATED invariant")
		}
	case "exploitable-below-threshold":
		confirmed()
		impact := sections["IMPACT"]
		if impact == "" {
			impact = objStr(st, "expected_impact")
		}
		if !belowThresholdRe.MatchString(impact) {
			out = append(out, "taxonomy: the IMPACT must state why the "+
				"impact does not clear the bounty threshold")
		}
	}
	return out
}

func anyStatus(assumptions validation.Value, status string) bool {
	if assumptions.Kind != validation.Arr {
		return false
	}
	for _, a := range assumptions.A {
		if objStr(a, "status") == status {
			return true
		}
	}
	return false
}

func anyValue(m map[string]string, want string) bool {
	for _, v := range m {
		if v == want {
			return true
		}
	}
	return false
}

// lintArcOrder enforces canonical marker order and that assumption entries sit
// after INITIAL FRAMING (a reversed or shuffled trace is not a reasoning walk).
func lintArcOrder(content string, trace map[string]string) []string {
	rank := map[string]int{"OBSERVATION": 0, "INITIAL FRAMING": 1, "PIVOT": 2,
		"INVARIANT": 3, "IMPACT": 4}
	ordered := true
	maxRank := -1
	framingPos := -1
	for _, m := range markerRe.FindAllStringSubmatchIndex(content, -1) {
		r := rank[content[m[2]:m[3]]]
		if r < maxRank {
			ordered = false
			break
		}
		if r > maxRank {
			maxRank = r
		}
		if content[m[2]:m[3]] == "INITIAL FRAMING" && framingPos < 0 {
			framingPos = m[0]
		}
	}
	if ordered && len(trace) > 0 && framingPos >= 0 {
		first := -1
		for _, m := range assumptionStartRe.FindAllStringSubmatchIndex(content, -1) {
			if first < 0 || m[0] < first {
				first = m[0]
			}
		}
		ordered = first > framingPos
	}
	if ordered {
		return nil
	}
	return []string{"arc: markers out of order — the trace must walk " +
		"OBSERVATION → INITIAL FRAMING → PIVOT → INVARIANT → IMPACT in " +
		"sequence, with assumption entries after the framing"}
}

// lintReasonCompleteness requires a stated reason for CONFIRMED/REFUTED.
func lintReasonCompleteness(st validation.Value) []string {
	out := []string{}
	assumptions := objAt(st, "assumptions")
	if assumptions.Kind != validation.Arr {
		return out
	}
	for _, a := range assumptions.A {
		status := objStr(a, "status")
		if status != "CONFIRMED" && status != "REFUTED" {
			continue
		}
		if len(strings.TrimSpace(objStr(a, "reason"))) < 20 {
			out = append(out, "reason: assumption "+pyStrValue(objAt(a, "id"))+
				" is "+pyStrValue(objAt(a, "status"))+" without a stated "+
				"reason (>= 20 chars required)")
		}
	}
	return out
}

// lintPivot is the pivot accounting check.
func lintPivot(content string, st validation.Value) []string {
	pivots := len(pivotCountRe.FindAllString(content, -1))
	declared := intOf(objAt(st, "pivot_count"))
	if pivots == declared {
		return nil
	}
	return []string{"pivot: the trace shows " + itoa(pivots) +
		" PIVOT marker(s) but structured.pivot_count is " + itoa(declared)}
}

// lintImpact is the impact-specificity check for the two exploitable
// taxonomies: vague wording needs a concrete quantifier.
func lintImpact(tax string, sections map[string]string,
	st validation.Value) []string {
	if tax != "confirmed-critical" && tax != "exploitable-below-threshold" {
		return nil
	}
	impact := sections["IMPACT"]
	if impact == "" {
		impact = objStr(st, "expected_impact")
	}
	low := strings.ToLower(impact)
	vague := []string{}
	for _, p := range vagueImpactPhrases {
		if strings.Contains(low, p) {
			vague = append(vague, p)
		}
	}
	if len(vague) == 0 || quantifierRe.MatchString(impact) {
		return nil
	}
	return []string{"impact: vague wording (" + strings.Join(vague, ", ") +
		") without a concrete quantifier — state the asset, actor and " +
		"magnitude"}
}

// lintNameAnchoring requires the OBSERVATION to cite code, not names.
func lintNameAnchoring(sections map[string]string) []string {
	obs := sections["OBSERVATION"]
	if obs == "" || codeRefRe.MatchString(obs) {
		return nil
	}
	return []string{"name-anchoring: OBSERVATION cites no code reference (no " +
		"call signature, function:/line ref, or .sol path) — the bug class " +
		"must come from behavior, not names"}
}

// lintDedup is the signature-collision check against curated examples.
func lintDedup(example validation.Value, existing []validation.Value,
	status string) []string {
	if existing == nil {
		return nil
	}
	sig := ExampleSignature(example)
	for _, e := range existing {
		if objStr(e, "status") != "curated" || ExampleSignature(e) != sig {
			continue
		}
		prefix := "warn:dedup:"
		if status == "curated" {
			prefix = "dedup:"
		}
		return []string{prefix + " signature collision with curated " +
			pyStrValue(objAt(e, "id")) + " — near-duplicates teach surface " +
			"memorization, not reasoning"}
	}
	return nil
}

func allObjects(items []validation.Value) bool {
	for _, v := range items {
		if v.Kind != validation.Obj {
			return false
		}
	}
	return true
}

// intOf is Python int(value or 0).
func intOf(v validation.Value) int {
	switch v.Kind {
	case validation.Int:
		return int(v.I)
	case validation.Flt:
		return int(v.F)
	case validation.Bool:
		if v.B {
			return 1
		}
	}
	return 0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}
