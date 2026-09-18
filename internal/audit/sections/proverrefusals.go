// proverrefusals.go: the L3 refusal histogram — ONE derived line, appended
// after invariant_verification's per-invariant harness lines, that tallies
// the campaign's stored MiniCertora refusals:
//
//	prover refusals (minicertora): 3 — honest-refusal:2, escalate-bound:1;
//	top reasons: rejected-feature×2, loop-bound-may-be-exceeded×1
//
// Source data is the stored state alone: every registry entry whose
// verification.harness object names kind minicertora AND rung inconclusive
// (L3's gap surface). Nothing here is state, an event or a flag — the line
// is a pure rendering of records the run path already wrote, so a campaign
// that stores no such record serializes byte-identically to before (the
// presence gate is the tally's own total: zero eligible records ⇒ no line).
//
// Two histograms per line, both sorted count-desc then key-asc:
//
//   - classes: harness.Disposition(summary)'s §L3 class. A summary that
//     disposes of nothing — the separator-free plumbing floors
//     ("exit output unmapped", "output is not JSONL", "duplicate verdict
//     lines for rule …", "no verdict line for rule …"), the
//     report-contradiction floor, and the rule-less abort envelopes
//     ("aborted: <reason>: <details>") the mapper writes when no verdict
//     line exists — buckets as "unmapped", as does a stored summary that is
//     not the expected "inconclusive (…)" shape at all. Unclassifiable
//     refusals are still refusals: they count, they just name no class.
//     (A killed/timed-out run is NOT one of them: "no clean completion"
//     disposes to escalate-runtime — the run never completed, but the
//     refusal still names its next action.)
//   - reasons: proof.reason when the sidecar stores a string (L-core; the
//     tool's verbatim code). A code outside the closed set buckets as
//     "unmapped" — disclosed rather than rendered as a code the §L3 table
//     does not know. When no string code is stored, only the summary's
//     class is recoverable, so the class IS the reason bucket (e.g. a
//     fallback row reads "escalate-flag×1").
//
// The class column therefore follows the STORED SUMMARY (the same input the
// per-invariant line's "| next: … (<class>)" suffix reads), while the reason
// column follows the stored CODE; a hand-edited record whose two halves
// disagree is the only shape where a reason's class is absent from the class
// list. At most refusalTopN reason rows render (count-desc, code-asc), while
// the class column is complete — the classes must sum to the printed total.
package sections

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/harness"
	"websec/internal/validation"
)

// refusalUnmapped is the bucket for a refusal the stored record cannot name:
// a summary that disposes of nothing, or a reason code outside §L3's closed
// set. It is the same word harness.Disposition uses for an unrecognised
// code, so a reader sees one label for "not in the table".
const refusalUnmapped = "unmapped"

// refusalTopN caps the printed reason rows (the class column is never
// capped: its counts sum to the total).
const refusalTopN = 3

// refusalTally accumulates the campaign's eligible refusals. It is built
// while the section walks the registry (single pass, no extra I/O).
type refusalTally struct {
	total   int
	classes map[string]int
	reasons map[string]int
}

// newRefusalTally is the empty tally.
func newRefusalTally() *refusalTally {
	return &refusalTally{
		classes: map[string]int{},
		reasons: map[string]int{},
	}
}

// add folds one invariant registry entry in. A non-object verification or
// harness field, another kind, or another rung contributes nothing —
// eligibility is exactly the spec's: kind minicertora + rung inconclusive.
// That is deliberately WEAKER than harnessRunLine's well-formedness gate
// (which also requires exec): a stored refusal counts even when the record is
// too malformed to render a per-invariant line, so a hand-edited record can
// never make a refusal vanish from the tally. The two histograms' totals
// therefore describe the STORED records, not the rendered lines.
func (t *refusalTally) add(e validation.Value) {
	h := validation.ObjAt(validation.ObjAt(e, "verification"), "harness")
	if h.Kind != validation.Obj {
		return
	}
	if validation.ObjStr(h, "kind") != string(harness.MiniCertora) ||
		validation.ObjStr(h, "rung") != harness.RungInconclusive {
		return
	}
	class, reason := refusalBuckets(h)
	t.total++
	t.classes[class]++
	t.reasons[reason]++
}

// refusalBuckets is one eligible record's (class, reason) pair, both
// non-empty by construction.
func refusalBuckets(h validation.Value) (string, string) {
	class, _, ok := harness.Disposition(validation.ObjStr(h, "summary"))
	if !ok {
		class = refusalUnmapped
	}
	code := validation.ObjStr(validation.ObjAt(h, "proof"), "reason")
	switch {
	case code == "":
		// No string code stored (absent sidecar, JSON null, or a
		// non-string value): the summary's class is all the record
		// can name.
		return class, class
	case harness.IsReasonCode(code):
		return class, code
	default:
		// A code outside the closed set: still a refusal, but not one
		// the §L3 table names.
		return class, refusalUnmapped
	}
}

// line renders the derived line and reports whether the tally holds any
// eligible record at all. ok=false is the presence gate: a campaign with no
// stored minicertora refusal emits no line (and, with no harness lines
// either, no harness_runs key).
func (t *refusalTally) line() (string, bool) {
	if t.total == 0 {
		return "", false
	}
	// The class column is never empty (total > 0 ⇒ at least one class),
	// and the reason column is non-empty for the same reason; the guard
	// keeps the line well-formed if that ever stopped holding.
	var b strings.Builder
	fmt.Fprintf(&b, "prover refusals (minicertora): %d — %s",
		t.total, classColumn(t.classes))
	if reasons := reasonColumn(t.reasons); reasons != "" {
		b.WriteString("; top reasons: " + reasons)
	}
	return b.String(), true
}

// classColumn is "<class>:<count>[, …]", complete and sorted count-desc
// then class-asc.
func classColumn(counts map[string]int) string {
	pairs := sortedCounts(counts)
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s:%d", p.key, p.n))
	}
	return strings.Join(parts, ", ")
}

// reasonColumn is "<code>×<n>[, …]", capped at refusalTopN rows and sorted
// count-desc then code-asc. (× is U+00D7, the multiplication sign the
// ARCHITECTURE §L6 tally example ("refused 22/30 rules") writes as the
// count separator.)
func reasonColumn(counts map[string]int) string {
	pairs := sortedCounts(counts)
	if len(pairs) > refusalTopN {
		pairs = pairs[:refusalTopN]
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s×%d", p.key, p.n))
	}
	return strings.Join(parts, ", ")
}

// countPair is one keyed count.
type countPair struct {
	key string
	n   int
}

// sortedCounts is the one ordering both columns use: descending count, then
// ascending key. The sort is total (keys are unique), so the rendering is
// deterministic without a stability crutch.
func sortedCounts(counts map[string]int) []countPair {
	out := make([]countPair, 0, len(counts))
	for k, n := range counts {
		out = append(out, countPair{key: k, n: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	return out
}
