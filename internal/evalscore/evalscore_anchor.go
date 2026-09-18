// The anchor rule: does a live finding match a gold case — class leg, mechanism leg, location suffix leg — and its phrase machinery.
package evalscore

import (
	"strings"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// anchor reports whether a live finding matches a non-control gold case:
// same bug class — the gold row's bug_class OR any class in its
// bug_class_accept list — and (no gold locations, or the finding's
// affected[0] path suffix-matches some gold locations[i].file basename),
// and the gold's optional mechanism gate (goldAcceptsMechanism) passes.
//
// The accept list is the EVAL SPEC's own alternative classes for the same
// mechanism (an auditor who filed the bug as a logic error is not wrong
// when the dataset filed it as a DoS), NOT a weakening of the anchor: the
// path suffix rule below is unchanged and no other axis of the join moves.
func anchor(f, gold validation.Value) bool {
	if !goldAcceptsClass(gold, taxonomy.CanonicalClass(field(obj(f, "root_cause"), "class"))) {
		return false
	}
	if !goldAcceptsMechanism(gold, field(obj(f, "root_cause"), "mechanism"),
		field(obj(f, "root_cause"), "class")) {
		return false
	}
	locs := obj(gold, "locations")
	if len(locs.A) == 0 {
		return true
	}
	var path string
	if aff := obj(f, "affected"); len(aff.A) > 0 {
		path = field(aff.A[0], "path")
	}
	if path == "" {
		return false
	}
	for _, l := range locs.A {
		if b := base(field(l, "file")); b != "" && strings.HasSuffix(path, b) {
			return true
		}
	}
	return false
}

// goldAcceptsClass is the class leg of the anchor: the finding's class
// equals the gold bug_class, or it is named in the gold row's optional
// bug_class_accept list. An absent (or null) list means "the single class
// only" — exactly the equality test the join used before the list existed.
//
// Both sides pass through taxonomy.CanonicalClass first: a synonym of a
// canonical class is the same bug under a different label, and the join is
// an exact string compare, so a synonym can only ever bridge it explicitly.
// An unlisted label is returned unchanged and therefore still anchors
// nothing — fail-closed behavior is untouched.
func goldAcceptsClass(gold validation.Value, class string) bool {
	if class == "" {
		return false
	}
	if class == taxonomy.CanonicalClass(field(gold, "bug_class")) {
		return true
	}
	for _, v := range obj(gold, "bug_class_accept").A {
		if v.Kind == validation.Str && taxonomy.CanonicalClass(v.S) == class {
			return true
		}
	}
	return false
}

// goldAcceptsMechanism is the mechanism leg of the anchor, owned entirely by
// the gold row: when the row carries no match_mechanisms the leg is the
// historical always-pass (embedded dev cases and every pre-mechanism held-out
// pack are byte-identical in behavior). When the list exists it must be a
// non-empty array, and an empty or non-array list anchors nothing at all — a
// gold row that cannot state any mechanism gets no anchor, not a free one.
//
// Entries are judged PER ENTRY, and a malformed entry (a non-string, or a
// string that is empty after trimming) simply contributes no match: it is
// skipped, so it can never create an anchor and can never poison the
// well-formed entries around it. That matters because the list is a list of
// independent alternatives: "anchored" must mean "some entry matched", and a
// verdict that flips on where the junk sits (junk-first refusing what
// junk-last anchored) would be order-dependent nonsense. A list of nothing
// but junk already falls out of this rule as no anchor at all. The finding's
// root_cause.mechanism sentence (or its root_cause.class for a
// 'root:<class>' entry) must match at least one well-formed phrase, and a
// degenerate phrase anchors nothing (see phraseMatches).
//
// Phrase matching is mechanical, not semantic — semantic adjudication stays
// where it belongs, in the non-gold adjudication layer: a phrase with at
// least two distinct content words matches when EVERY one of those words
// (identifier-folded: underscores and hyphens dropped, lowercased,
// stop-words exempt) appears somewhere in the finding's mechanism sentence —
// an unordered containment test, robust to phrasing differences while still
// refusing a sentence that omits the mechanism's defining vocabulary. A
// phrase naming fewer than two content words matches NOTHING: single-word
// entries (and phrases whose only vocabulary is grammar) are refused by that
// rule rather than matched by token equality, because one shared word is a
// coin flip, not a mechanism. A 'root:<class>' entry is not a phrase at all:
// it obeys exact class equality (the class leg already enforces class
// equality, so root entries chiefly gate findings to class-level mechanism
// naming).
func goldAcceptsMechanism(gold validation.Value, mech, class string) bool {
	v := obj(gold, "match_mechanisms")
	if v.Kind == validation.Null {
		return true // absent: the historical always-pass
	}
	if v.Kind != validation.Arr || len(v.A) == 0 {
		return false // malformed (wrong type or empty array): fail closed
	}
	mw := words(mech)
	for _, p := range v.A {
		if p.Kind != validation.Str {
			continue // malformed entry: it contributes no match, nothing more
		}
		s := strings.TrimSpace(p.S)
		if s == "" {
			continue // blank entry: same — no match, no poisoning
		}
		if strings.HasPrefix(s, "root:") {
			if class != "" && class == strings.TrimSpace(strings.TrimPrefix(s, "root:")) {
				return true
			}
			continue
		}
		if phraseMatches(s, mw) {
			return true
		}
	}
	return false
}

// words lowercases a string into word runs. Underscores, hyphens and primes
// INSIDE a word are stripped (prevStateRoot -> prevstateroot) so code
// identifiers fold across the two spellings a sentence and a phrase may
// each use; everything non-alphanumeric separates.
func words(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '\'')
	}) {
		out = append(out, strings.ToLower(strings.NewReplacer("_", "", "-", "", "'", "").Replace(f)))
	}
	return out
}

// phraseMatches reports whether phrase's full content vocabulary is
// contained (case-folded, identifier-folded) in the finding's mechanism
// sentence words.
//
// A phrase must bring at least TWO DISTINCT non-stopword words to anchor at
// all: one content word is a coin flip ("commit" would anchor any sentence
// that happens to say "commit", whatever the mechanism), and repeating a
// single word ("commit commit") names one word of vocabulary, not two. A
// phrase that is empty after folding, or whose only vocabulary is stop-words,
// or that names a single content word, therefore matches nothing. Above that
// bar the test is plain containment: every content word of the phrase must
// appear somewhere in the sentence.
func phraseMatches(phrase string, mw []string) bool {
	pw := words(phrase)
	content := make([]string, 0, len(pw))
	seen := map[string]bool{}
	for _, w := range pw {
		if stopWords[w] || seen[w] {
			continue
		}
		seen[w] = true
		content = append(content, w)
	}
	if len(content) < 2 {
		return false // degenerate phrase: fewer than two content words
	}
	set := map[string]bool{}
	for _, w := range mw {
		set[w] = true
	}
	for _, w := range content {
		if !set[w] {
			return false
		}
	}
	return true
}

// stopWords are the grammar particles a mechanism phrase may carry but a
// finding sentence may phrase differently; they are exempt from containment.
//
// Negations are deliberately NOT in this set (I-3): "no", "not", "cannot"
// (and its folded "cant"), "without", "noone", "never" and the bare modal
// "can" carry the polarity of the claim, so exempting them let a phrase
// asserting an ABSENCE anchor a sentence asserting its PRESENCE — the exact
// inverse of the mechanism. "set" is likewise excluded despite reading like
// a particle: it is a domain noun here (a setter, a configuration set), and
// exempting it would let "set owner" anchor "owner" alone. "same" stays: it
// is genuine connective filler in these phrases.
var stopWords = map[string]bool{
	"a": true, "an": true, "and": true, "at": true, "but": true, "by": true,
	"for": true, "from": true, "if": true, "in": true, "into": true,
	"its": true, "of": true, "on": true, "or": true, "per": true,
	"same": true, "than": true, "that": true, "the": true, "their": true,
	"them": true, "then": true, "to": true, "via": true, "was": true,
	"were": true, "when": true, "with": true,
}
