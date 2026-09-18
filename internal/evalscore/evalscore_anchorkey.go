// Anchor canonicalization: the behavior-equal key behind the duplicate-anchor refusal.
package evalscore

import (
	"regexp"
	"sort"
	"strings"
	"websec/internal/validation"
)

// anchorKey is the canonical identity of a gold row's ANCHOR: everything
// the scorer's anchor() joins a finding against, EXACTLY as anchor()
// collapses it (r7-r8 law: the guard exists to refuse answer-key
// duplication, so it must fire on anchor-behavior equality — not on raw
// JSON that merely looks different):
//   - the ACCEPTED class SET, deduped and sorted (bug_class ∪
//     bug_class_accept; anchor() tests membership, order and repeats are
//     invisible to it),
//   - the location leg as (present?, usable basename set): a NON-EMPTY
//     locations array whose every basename is empty ({"file":"a/"}) makes
//     anchor() match NOTHING — that is NOT the same anchor as absent/[]
//     locations, which match EVERYTHING (r8 false-refusal),
//   - the gold outcome,
//   - the mechanism leg, deduped and TRIMMED the way
//     goldAcceptsMechanism trims ("phrase" == "phrase   ").
func anchorKey(row validation.Value) string {
	g := obj(row, "gold")
	// goldAcceptsClass membership is the union of bug_class and
	// bug_class_accept: one set, order and repeats invisible (r8).
	all := []string{field(g, "bug_class")}
	for _, a := range obj(g, "bug_class_accept").A {
		if a.Kind == validation.Str {
			all = append(all, a.S)
		}
	}
	classes := dedupeSorted(all)
	locs := obj(g, "locations").A
	locLeg := "*" // absent or []: class-only anchor, matches everything
	if len(locs) > 0 {
		bases := make([]string, 0, len(locs))
		for _, l := range locs {
			if b := base(field(l, "file")); b != "" {
				bases = append(bases, b)
			}
		}
		if len(bases) == 0 {
			locLeg = "!" // present-but-dead: matches NOTHING
		} else {
			locLeg = strings.Join(dedupeSorted(bases), ",")
		}
	}
	mechLeg := mechGateKey(g)
	return strings.Join([]string{
		strings.Join(classes, ","), locLeg,
		field(g, "outcome"), mechLeg,
	}, "\x00")
}

// dedupeSorted is the anchor-leg normalizer: unique, ascending.
func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// mechGateKey canonicalizes the mechanism gate the way goldAcceptsMechanism
// consumes it (r9): the gate's BEHAVIOR is fully described by the set of
// content-word fingerprints of its live phrases plus its root: class tests.
//   - absent/null  -> "*"  (always pass, the historical gate)
//   - [] / all entries inert (blank, non-string, or below the two-content-
//     word bar) -> "!" — every form that anchors NOTHING is one anchor,
//     because a phrase below the bar matches nothing exactly like an empty
//     array ("   " == [] == ["a"] behaviorally)
//   - live phrases -> sorted "P:"+wordset fingerprints, plus sorted
//     "R:"+class tokens for root: tests; two spellings folding to the same
//     content vocabulary ("a  b", "A_B", "b a"...) are ONE gate.
func mechGateKey(g validation.Value) string {
	v := obj(g, "match_mechanisms")
	if v.Kind == validation.Null {
		return "*"
	}
	if v.Kind != validation.Arr || len(v.A) == 0 {
		return "!" // malformed or empty: fail closed
	}
	var live []string
	for _, p := range v.A {
		if p.Kind != validation.Str {
			continue // inert
		}
		s := strings.TrimSpace(p.S)
		if s == "" {
			continue // inert
		}
		if strings.HasPrefix(s, "root:") {
			// r10: the honest bar for a root: test is the CLASS GRAMMAR
			// (finding schema ^[a-z0-9-]{3,64}$), not "non-empty". A
			// spaced or capitalized tail can never equal a valid class —
			// it matches nothing and must key INERT (dropping out, or
			// collapsing to "!"), never as a live R: leg. Otherwise one
			// junk "root: a b" entry is all it takes to evade the
			// duplicate-anchor refusal.
			r := strings.TrimSpace(strings.TrimPrefix(s, "root:"))
			if rootClassRe.MatchString(r) {
				live = append(live, "R:"+r)
			}
			continue
		}
		if k, ok := phraseFingerprint(s); ok {
			live = append(live, "P:"+k)
		}
		// Below-bar / stop-word-only phrases are INERT — they match
		// nothing, contributing exactly what an absent entry contributes.
	}
	if len(live) == 0 {
		return "!"
	}
	return strings.Join(dedupeSorted(live), "\u0000")
}

// phraseFingerprint is the content-word set phraseMatches anchors on:
// folded, deduped, stop-words dropped, ordered — with the same two-distinct
// bar. ok=false when the phrase cannot match anything.
func phraseFingerprint(phrase string) (string, bool) {
	seen := map[string]bool{}
	var content []string
	for _, w := range words(phrase) {
		if stopWords[w] || seen[w] {
			continue
		}
		seen[w] = true
		content = append(content, w)
	}
	if len(content) < 2 {
		return "", false
	}
	sort.Strings(content)
	return strings.Join(content, " "), true
}

// rootClassRe is the finding schema's class grammar; a root: gate tail that
// cannot name a real class cannot fire (r10).
var rootClassRe = regexp.MustCompile(`^[a-z0-9-]{3,64}$`)
