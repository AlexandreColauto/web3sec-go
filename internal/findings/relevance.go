// relevance.go: recall relevance (B3/D2) — memory_check_relevance, the
// honest zero-overlap reasons, and the read surfaces around them
// (webv2.findings: ecea2b9, review fixes 5df013a and 7e341ee).
//
// The gate is satisfied by the ACT of a recorded recall, and it stays that
// way — this file adds the SIGNAL the act used to lack. A check that cites
// rows sharing no STRUCTURAL tag with the finding is stamped
// recalled_irrelevant and raises one corpus.gap event, not a failure. The
// event states WHAT was true, not the loudest possible claim: a cite sharing
// nothing at all leaves the corpus silent on the lineage, while a cite whose
// only shared tag is the catch-all label names a class the corpus has rows
// in (see IrrelevantReason).
//
// Prose is never part of the overlap: identical pattern/evidence_summary
// text scores zero ("20 random DeFi rows for a rollup question").
//
// The bases are fields that exist on BOTH sides. bug_class and cwe are
// declared memory fields. capability is honored whenever a row carries
// granted/required/terminal (see MemoryRowRelevanceTags) — granted and
// required are schema-declared since the B3 review fix, so rows derived from
// a finding carry them.
//
// PORT-NOTE (P3, unported): learning.queue_memory's stamping of
// granted/required on a row derived from a finding, and briefing.py's
// corpus_recall line, live in the shared-memory/briefing modules this port
// does not cover yet. CorpusRecallGaps below is the pure read the brief
// calls.
package findings

import (
	"slices"
	"sort"

	"websec/internal/capabilities"
	"websec/internal/state"
	"websec/internal/validation"
)

// RelevanceBases is RELEVANCE_BASES: the structural bases an overlap may
// fire on, in the order the verdict records them.
var RelevanceBases = []string{"bug_class", "capability", "cwe"}

// CATCH_ALL_BUG_CLASS is CATCH_ALL_BUG_CLASS: the taxonomy catch-all.
// planner rewrites any class outside taxonomy.known_classes() to it, and
// corpus_surface maps aliases (liquidation-logic, ...) onto it, so the label
// says nothing about the lineage.
//
// It is the ONLY non-discriminative class (fix round 2, part (a)). Round 1
// also discounted every class appearing in >= 2 dedup economic-compat
// groups (oracle-manipulation, economic-invariant, signature-replay), which
// was too wide: the overlap test fires bug_class on EXACT equality, so a
// fired match carries the SAME class string on both sides, and the
// economic-compat relation — which says which DIFFERENT classes dedup may
// treat as compatible — cannot make that match non-discriminative. Those
// same-class cites count again.
//
// Why the catch-all still does not count alone: cmd_recall ranks the cited
// rows class-first, so for a logic-error finding every cited row shares that
// catch-all label — counting it alone made the verdict self-fulfilling and
// corpus.gap could never fire for the plan's motivating case.
const CATCH_ALL_BUG_CLASS = "logic-error"

// CoarseClassRule is COARSE_CLASS_RULE: the predicate named on a verdict
// that discounted a bug_class match.
const CoarseClassRule = "bug_class alone counts as overlap unless it is " +
	"the taxonomy catch-all (" + CATCH_ALL_BUG_CLASS + "); a catch-all " +
	"match needs a second basis (capability/cwe)"

// The honest shapes of a zero-overlap verdict. They are NOT the same claim:
// a cite that shares nothing with the finding leaves the corpus silent on
// the lineage, but a cite whose only shared tag is the catch-all label names
// a class the corpus demonstrably HAS rows in — the label is simply not
// overlap. A check that cited no rows says that too.
const (
	GAP_NO_SHARED_TAG         = "no-shared-structural-tag"
	GAP_SHARED_CATCH_ALL_ONLY = "shared-catch-all-class-only"
	GAP_NO_ROWS_CITED         = "no-rows-cited"
)

// NondiscriminativeClasses is nondiscriminative_classes: the classes that
// need a second basis to count as overlap — the taxonomy catch-all ALONE
// (fix round 2, part (a)). See CATCH_ALL_BUG_CLASS.
func NondiscriminativeClasses() map[string]struct{} {
	return map[string]struct{}{CATCH_ALL_BUG_CLASS: {}}
}

// normTag is _norm_tag: str(value or "").strip().lower(), empty for absent.
func normTag(v validation.Value) string {
	if !validation.PyTruthy(v) {
		return ""
	}
	return pyStripLower(pyStr(v))
}

// normCapValues is _norm_cap_values: normalized capability labels from an
// explicit list field. A bare string is treated as one label, never
// iterated character by character (a malformed row must not manufacture
// spurious overlap).
func normCapValues(v validation.Value) map[string]struct{} {
	var items []string
	switch v.Kind {
	case validation.Str:
		items = []string{v.S}
	case validation.Arr:
		for _, e := range v.A {
			items = append(items, pyStr(e))
		}
	default:
		return map[string]struct{}{}
	}
	out := map[string]struct{}{}
	for _, label := range capabilities.NormalizeLabels(items) {
		out[label] = struct{}{}
	}
	return out
}

// FindingRelevanceTags is finding_relevance_tags: the finding's own
// structural tags, by basis. Explicit capability lists ONLY:
// capabilities.required's prose-precondition fallback
// (capabilities.Required()) is never promoted into the overlap, because
// prose must not count.
func FindingRelevanceTags(finding validation.Value) map[string][]string {
	tags := map[string][]string{}
	root := asDict(validation.ObjAt(finding, "root_cause"))
	if cls := normTag(validation.ObjAt(root, "class")); cls != "" {
		tags["bug_class"] = []string{cls}
	}
	cwe := normTag(validation.ObjAt(root, "cwe"))
	if cwe == "" {
		cwe = normTag(validation.ObjAt(finding, "cwe"))
	}
	if cwe != "" {
		tags["cwe"] = []string{cwe}
	}
	caps := asDict(validation.ObjAt(finding, "capabilities"))
	labels := normCapValues(validation.ObjAt(caps, "granted"))
	for l := range normCapValues(validation.ObjAt(caps, "required")) {
		labels[l] = struct{}{}
	}
	if len(labels) > 0 {
		tags["capability"] = sortedSetKeys(labels)
	}
	return tags
}

// MemoryRowRelevanceTags is memory_row_relevance_tags: the cited row's
// structural tags, by basis. bug_class/cwe and (for rows derived from a
// finding) granted/required are declared memory fields; terminal is read
// when present (a row terminal counts as a capability label). No taxonomy
// is invented for component kind/scope: no structured field exists on both
// sides, so no basis is fabricated.
func MemoryRowRelevanceTags(row validation.Value) map[string][]string {
	tags := map[string][]string{}
	if cls := normTag(validation.ObjAt(row, "bug_class")); cls != "" {
		tags["bug_class"] = []string{cls}
	}
	if cwe := normTag(validation.ObjAt(row, "cwe")); cwe != "" {
		tags["cwe"] = []string{cwe}
	}
	labels := normCapValues(validation.ObjAt(row, "granted"))
	for l := range normCapValues(validation.ObjAt(row, "required")) {
		labels[l] = struct{}{}
	}
	if term := validation.ObjAt(row, "terminal"); validation.PyTruthy(term) {
		for l := range normCapValues(validation.VArr(term)) {
			labels[l] = struct{}{}
		}
	}
	if len(labels) > 0 {
		tags["capability"] = sortedSetKeys(labels)
	}
	return tags
}

// MemoryCheckRelevance is memory_check_relevance: deterministic overlap
// verdict for one check — the cited rows sharing at least one structural tag
// with the finding, and the tag bases that fired. Canonical (sorted) on both
// axes, so identical inputs produce identical entries.
//
// The coarse-class rule (see CoarseClassRule) is applied per row: a
// bug_class match on a non-discriminative class does not count by itself.
// When such a match is set aside the verdict records it — discounted names
// the basis=value that was rejected and rule names the predicate — so a
// reviewer can see why a cite did or did not count. A second basis
// (capability/cwe) still carries the row.
func MemoryCheckRelevance(finding validation.Value, memoryIDs []string,
	rowsByID map[string]validation.Value) validation.Value {
	fTags := FindingRelevanceTags(finding)
	coarse := NondiscriminativeClasses()
	overlapping := []string{}
	basis := map[string]struct{}{}
	discounted := map[string]struct{}{}
	for _, mid := range sortedSetKeys(stringSet(memoryIDs)) {
		row, ok := rowsByID[mid]
		if !ok || row.Kind != validation.Obj {
			continue
		}
		rTags := MemoryRowRelevanceTags(row)
		var fired []string
		for _, b := range RelevanceBases {
			ft, fok := fTags[b]
			rt, rok := rTags[b]
			if fok && rok && intersects(ft, rt) {
				fired = append(fired, b)
			}
		}
		if len(fired) == 0 {
			continue
		}
		if slices.Contains(fired, "bug_class") {
			matched := sortedIntersect(fTags["bug_class"], rTags["bug_class"])
			if len(matched) > 0 && allInSet(matched, coarse) {
				// the class is not discriminative: it cannot carry the
				// overlap alone, so it is recorded as discounted and the
				// remaining bases (if any) decide.
				discounted["bug_class="+matched[0]] = struct{}{}
				fired = withoutStr(fired, "bug_class")
			}
		}
		if len(fired) == 0 {
			continue
		}
		overlapping = append(overlapping, mid)
		for _, b := range fired {
			basis[b] = struct{}{}
		}
	}
	verdict := validation.VObj(
		validation.KV{K: "overlapping", V: validation.StrArr(overlapping)},
		validation.KV{K: "basis", V: validation.StrArr(sortedSetKeys(basis))},
	)
	if len(discounted) > 0 {
		verdict.O = append(verdict.O,
			validation.KV{K: "discounted", V: validation.StrArr(sortedSetKeys(discounted))},
			validation.KV{K: "rule", V: validation.VStr(CoarseClassRule)})
	}
	return verdict
}

// LineageTags is lineage_tags: the finding's own tags as sorted
// "basis=value" strings — the lineage a corpus.gap event declares the
// corpus silent on.
func LineageTags(finding validation.Value) []string {
	tags := FindingRelevanceTags(finding)
	out := []string{}
	for basis, values := range tags {
		for _, value := range values {
			out = append(out, basis+"="+value)
		}
	}
	sort.Strings(out)
	return out
}

// IrrelevantReason is irrelevant_reason: (reason_code, reason) for one
// recalled_irrelevant verdict — the sentence the corpus.gap event carries
// and cmd_recall prints.
//
// A discounted match (relevance.discounted) means the cite DID share a class
// label, just not a discriminative one: the reason names that label and
// never says the corpus is silent on the lineage — the rows are right there,
// they simply agree on nothing but the catch-all. A check that cited no rows
// says that too, instead of borrowing the silence claim. Only a cite that
// genuinely shares no structural tag declares the corpus silent on the
// lineage.
func IrrelevantReason(relevance validation.Value,
	memoryIDs []string) (string, string) {
	discounted := validation.ObjAt(relevance, "discounted")
	if discounted.Kind == validation.Arr && len(discounted.A) > 0 {
		names := make([]string, 0, len(discounted.A))
		for _, d := range discounted.A {
			names = append(names, pyStr(d))
		}
		second := ""
		for _, b := range RelevanceBases {
			if b == "bug_class" {
				continue
			}
			if second != "" {
				second += "/"
			}
			second += b
		}
		return GAP_SHARED_CATCH_ALL_ONLY,
			"cited row(s) share only a non-discriminative class label (" +
				joinComma(names) + ") with this finding — the corpus holds " +
				"rows in that class, but the label alone is not lineage " +
				"overlap and needs a second basis (" + second + ")"
	}
	if len(memoryIDs) == 0 {
		return GAP_NO_ROWS_CITED,
			"the check cited no rows — nothing was consulted, so the " +
				"corpus has not been asked about this lineage"
	}
	return GAP_NO_SHARED_TAG,
		"cited row(s) share no structural tag (" + joinComma(RelevanceBases) +
			") with this finding — the corpus is silent on this lineage"
}

// CorpusRecallGaps is corpus_recall_gaps: checks stamped
// recalled_irrelevant, grouped by finding — what the brief reports. A pure
// read; the brief must mutate nothing.
//
// The count is split ADDITIVELY so the brief can tell the two facts apart:
// label_only_checks counts the irrelevant checks whose only shared tag was a
// non-discriminative class label (the corpus HAS rows in that class;
// discounted names the labels), no_rows_checks counts the checks that cited
// nothing, and silent_checks counts the rest — the cites that share no
// structural tag at all, where the silence claim is true.
func CorpusRecallGaps(campaign *state.Campaign) (validation.Value, error) {
	all, err := LoadAllFindings(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	var findingsList []string
	checksTotal, irrelevant, labelOnly, noRows := 0, 0, 0, 0
	labels := map[string]struct{}{}
	for _, f := range all {
		checks := validation.ObjAt(asDict(validation.ObjAt(f, "provenance")), "memory_checks")
		if checks.Kind != validation.Arr {
			continue
		}
		bad := 0
		for _, c := range checks.A {
			if c.Kind != validation.Obj {
				continue
			}
			checksTotal++
			v := validation.ObjAt(c, "recalled_irrelevant")
			if v.Kind != validation.Bool || !v.B {
				continue
			}
			bad++
			disc := validation.ObjAt(asDict(validation.ObjAt(c, "relevance")), "discounted")
			if disc.Kind == validation.Arr && len(disc.A) > 0 {
				labelOnly++
				for _, d := range disc.A {
					labels[pyStr(d)] = struct{}{}
				}
			} else if !validation.PyTruthy(validation.ObjAt(c, "memory_ids")) {
				noRows++
			}
		}
		if bad > 0 {
			irrelevant += bad
			findingsList = append(findingsList, validation.ObjStr(f, "finding_id"))
		}
	}
	sort.Strings(findingsList)
	if findingsList == nil {
		findingsList = []string{}
	}
	return validation.VObj(
		validation.KV{K: "checks", V: validation.VInt(int64(checksTotal))},
		validation.KV{K: "irrelevant_checks",
			V: validation.VInt(int64(irrelevant))},
		validation.KV{K: "label_only_checks",
			V: validation.VInt(int64(labelOnly))},
		validation.KV{K: "no_rows_checks", V: validation.VInt(int64(noRows))},
		validation.KV{K: "silent_checks",
			V: validation.VInt(int64(irrelevant - labelOnly - noRows))},
		validation.KV{K: "discounted", V: validation.StrArr(sortedSetKeys(labels))},
		validation.KV{K: "findings", V: validation.StrArr(findingsList)},
	), nil
}

// ---- small set/list helpers (Python set/sorted semantics) -----------------

func stringSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, s := range items {
		out[s] = struct{}{}
	}
	return out
}

func intersects(a, b []string) bool {
	bs := stringSet(b)
	for _, s := range a {
		if _, ok := bs[s]; ok {
			return true
		}
	}
	return false
}

func sortedIntersect(a, b []string) []string {
	bs := stringSet(b)
	out := []string{}
	for _, s := range a {
		if _, ok := bs[s]; ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func withoutStr(items []string, drop string) []string {
	out := []string{}
	for _, s := range items {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

func allInSet(items []string, set map[string]struct{}) bool {
	for _, s := range items {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}
