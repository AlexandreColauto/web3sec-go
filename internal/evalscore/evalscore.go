// Package evalscore joins campaign live findings to gold anchors (G4).
//
// The join key is the campaign state doc's REQUIRED key "program", matched
// case-insensitively against each gold case's program.program. A gold case
// is HIT iff, among the campaign's live findings for its program, some
// finding has root_cause.class == gold.bug_class AND (gold has no locations
// OR finding affected[0].path suffix-matches a gold locations[i].file
// basename). outcome == "confirmed-not-exploitable" inverts: the case is
// HIT iff ZERO live findings exist for that program (clean control +
// decoy law). FP = live findings in a suite-matched program that anchored
// no gold case.
//
// A finding that anchors no gold case is not automatically WRONG: it may be a
// true bug the gold dataset does not contain, or it may rest on an assumption
// the campaign could not discharge. ScoreSuiteWith takes the campaign's
// non-gold adjudications (adjudicate.go) and splits the raw unanchored count
// accordingly; ScoreSuite is the no-adjudications case.
//
// ScoreSuiteWith is pure (no I/O): the only filesystem touch is Score, which
// reads the program key through (*state.Campaign).State, the live set through
// findings.LoadLiveFindings, and the adjudications through Load — plus
// LoadGoldPack/OpenGoldPack, which read an operator-supplied pack file and
// its sidecar. No scoring pass reads the disk beyond those.
package evalscore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"regexp"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// notExploitable is the gold outcome that inverts the hit rule.
const notExploitable = "confirmed-not-exploitable"

// heldOutPartition marks gold cases drawn from the held-out split.
const heldOutPartition = "held-out"

// Report is the scored join of one suite roll-up.
//
// FP keeps its exact original meaning — the RAW count of live findings in
// suite-matched programs that matched no gold anchor — so every existing
// caller and test reads the same number it always did. Unanchored is the same
// quantity named from the adjudication's point of view; the adjudication
// fields below are the split that raw count cannot express.
type Report struct {
	GoldTotal, Hits, Misses, FP int // FP: RAW unanchored live findings (unchanged meaning)
	RecallLine, PrecisionLine   string
	HeldOut                     bool

	// Anchored/Unanchored partition the live findings in precision scope.
	Anchored, Unanchored int
	// Additional/Gated/FalsePositives partition the UNANCHORED findings that
	// carry an adjudication row; Unadjudicated is the rest. StaleAdjudications
	// counts FINDINGS whose row applies to no scored finding (absent from the
	// live set, or already anchored) — reported, never silently dropped.
	Additional, Gated, FalsePositives, Unadjudicated, StaleAdjudications int
	// InvalidAdjudications counts the rows present in the state doc that
	// evalscore.Validate refuses (unknown verdict, gated without an
	// assumption, blank reason, ...). Such a row is NOT an adjudication: it
	// lands in no verdict bucket, and the finding it names is scored exactly
	// as if no row existed. Invisible would be worse than fail-closed in BOTH
	// directions — an unreadable row must not quietly behave like a good one
	// (it would move the precision number without satisfying the rules the
	// number depends on), and it must not be dropped without a trace either
	// (then the author never learns the row they wrote was refused).
	InvalidAdjudications int
	// AdjustedPrecisionLine is wilson.Format over
	// (Anchored, Anchored+FalsePositives+Unadjudicated): a finding judged
	// true-or-gated is removed from the penalty. With no adjudications the
	// denominator equals the raw one and the line equals PrecisionLine.
	AdjustedPrecisionLine string
	// ConfirmedLive/ConfirmedAnchored split the precision scope by status:
	// the eval spec's FP budget counts "all other CONFIRMED findings", while
	// the raw FP counts every live finding — an honest POSSIBLE hypothesis
	// must not be priced like a fabrication. Both numbers print; the raw
	// number stays the harsh one.
	ConfirmedLive, ConfirmedAnchored int
	ConfirmedPrecisionLine           string
}

// field returns an object's string field ("" when absent/non-string).
func field(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	return ""
}

// obj returns an object's sub-value (Null when absent/non-object).
func obj(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// base returns the basename of a slash-separated path.
func base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

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

// jsonKindName names a validation.Value's JSON type the way a reader of the
// pack file thinks of it, for the errors that have to say what was found
// where an array or an object was required.
func jsonKindName(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "null"
	case validation.Bool:
		return "a boolean"
	case validation.Int, validation.Flt:
		return "a number"
	case validation.Str:
		return "a string"
	case validation.Arr:
		return "an array"
	case validation.Obj:
		return "an object"
	}
	return "an unknown value"
}

// matchedCase is one suite case inside the matched program scope. It
// carries exactly what a scoring pass reads, so the scope rule lives in
// ONE place (matchCases) and every consumer — ScoreSuite, Bands — reuses
// it instead of restating it.
type matchedCase struct {
	id      string
	program string
	gold    validation.Value
	control bool
	heldOut bool
}

// matchCases resolves the program scope (lowercased membership, the join
// key), drops every out-of-scope row, and returns what is left sorted by
// case_id — the deterministic order every scoring pass starts from.
func matchCases(programs []string, cases []validation.Value) []matchedCase {
	scope := map[string]bool{}
	for _, p := range programs {
		scope[strings.ToLower(p)] = true
	}
	var matched []matchedCase
	for _, c := range cases {
		prog := strings.ToLower(field(obj(c, "program"), "program"))
		if !scope[prog] {
			continue
		}
		gold := obj(c, "gold")
		matched = append(matched, matchedCase{
			id:      field(c, "case_id"),
			program: prog,
			gold:    gold,
			control: field(gold, "outcome") == notExploitable,
			heldOut: field(c, "partition") == heldOutPartition,
		})
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].id < matched[j].id })
	return matched
}

// lowerLive keys the live-findings map by lowercased program (the same
// join key matchCases uses).
func lowerLive(liveByProgram map[string][]validation.Value) map[string][]validation.Value {
	live := map[string][]validation.Value{}
	for p, fs := range liveByProgram {
		k := strings.ToLower(p)
		live[k] = append(live[k], fs...)
	}
	return live
}

// goldByProgram groups the matched non-control golds per program so each
// live finding is anchor-checked once (a finding anchoring two golds
// still counts once toward precision).
func goldByProgram(matched []matchedCase) map[string][]validation.Value {
	byProg := map[string][]validation.Value{}
	for _, m := range matched {
		if !m.control {
			byProg[m.program] = append(byProg[m.program], m.gold)
		}
	}
	return byProg
}

// scopedPrograms is the precision scope: every program with ≥1 matched
// case, in case_id order, each once — including control-only programs (a
// finding under a control program anchored nothing by definition, so it
// is always FP).
func scopedPrograms(matched []matchedCase) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matched {
		if seen[m.program] {
			continue
		}
		seen[m.program] = true
		out = append(out, m.program)
	}
	return out
}

// anchorsAny reports whether any of the program's gold cases anchors the
// live finding.
func anchorsAny(f validation.Value, golds []validation.Value) bool {
	for _, g := range golds {
		if anchor(f, g) {
			return true
		}
	}
	return false
}

// ScoreSuite rolls the join up over a program scope: matched cases are the
// suite cases whose lowercased program.program is in programs; live
// findings are looked up by lowercased program. Findings under programs
// with no matched case are out of scope (never FP, never in the precision
// denominator).
//
// This is ScoreSuiteWith with no adjudications, kept as a one-line
// delegation so every existing caller and test is byte-for-byte unchanged.
func ScoreSuite(programs []string, liveByProgram map[string][]validation.Value, cases []validation.Value) Report {
	return ScoreSuiteWith(programs, liveByProgram, cases, nil)
}

// ScoreSuiteWith is ScoreSuite plus the non-gold adjudication accounting.
// Adjudications are matched to UNANCHORED findings only: a row whose finding
// anchored a gold case changes no bucket and is counted in
// StaleAdjudications; so is a row whose finding is not in the scored live
// set. A stale row is REPORTED rather than dropped or made fatal because it
// is a real claim about a finding that has moved (anchored since, or removed
// from the live set) — silently dropping it would hide an adjudication that
// no longer applies, and failing the score over one stale row would let a
// bookkeeping error veto an otherwise valid campaign score.
//
// The scorer re-runs Validate on every row: the state file is hand-editable,
// so the write-path gate in Record is not enough. A row that fails it is not
// an adjudication at all — it is counted in InvalidAdjudications, keeps out
// of every verdict bucket, and its finding is scored as unadjudicated.
func ScoreSuiteWith(programs []string, liveByProgram map[string][]validation.Value, cases []validation.Value, adjs []Adjudication) Report {
	sc := &scoreSuiteCtx{programs: programs, liveByProgram: liveByProgram,
		cases: cases, adjs: adjs}
	sc.scoreSuitePrep()
	sc.scoreSuiteHits()
	sc.scoreSuitePrecision()
	sc.scoreSuiteTally()
	return sc.r
}

// scoreSuiteCtx carries ScoreSuiteWith's shared scoring state across its
// extracted sections.
type scoreSuiteCtx struct {
	programs      []string
	liveByProgram map[string][]validation.Value
	cases         []validation.Value
	adjs          []Adjudication

	matched []matchedCase
	live    map[string][]validation.Value
	rows    []Adjudication
	byID    map[string]Adjudication

	r                 Report
	anchored          int
	liveTotal         int
	confirmedLive     int
	confirmedAnchored int
	applied           map[string]bool
}

// scoreSuitePrep resolves the program scope, the live set and the scoreable
// adjudication rows every later section reads.
func (sc *scoreSuiteCtx) scoreSuitePrep() {
	sc.matched = matchCases(sc.programs, sc.cases)
	sc.live = lowerLive(sc.liveByProgram)
	// One pass up front decides what counts as an adjudication: drop the
	// rows Validate refuses, then collapse duplicates by finding id. Rows
	// are deduped ONCE here, not per program, so every counter below counts
	// the same unit (findings, never raw rows).
	rows, invalid := scoreableRows(sc.adjs)
	sc.r.InvalidAdjudications = invalid
	sc.rows = rows
	sc.byID = make(map[string]Adjudication, len(rows))
	for _, a := range rows {
		sc.byID[a.Finding] = a
	}
	for _, m := range sc.matched {
		if m.heldOut {
			sc.r.HeldOut = true
		}
	}
}

// scoreSuiteHits counts the gold hits: a control case hits when its program
// has no live findings, a non-control case when some live finding anchors it.
func (sc *scoreSuiteCtx) scoreSuiteHits() {
	for _, m := range sc.matched {
		fs := sc.live[m.program]
		if m.control {
			if len(fs) == 0 {
				sc.r.Hits++
			}
			continue
		}
		for i := range fs {
			if anchor(fs[i], m.gold) {
				sc.r.Hits++
				break
			}
		}
	}
}

// scoreSuitePrecision walks the precision scope and buckets every unanchored
// live finding by its adjudication verdict.
func (sc *scoreSuiteCtx) scoreSuitePrecision() {
	// byProg groups the matched non-control golds per program so each
	// live finding is anchor-checked once.
	byProg := goldByProgram(sc.matched)
	// Precision scope: live findings in suite-matched programs — every
	// program with ≥1 matched case, including control-only ones.
	sc.applied = map[string]bool{}
	for _, p := range scopedPrograms(sc.matched) {
		fs := sc.live[p]
		sc.liveTotal += len(fs)
		for i := range fs {
			confirmed := field(fs[i], "status") == "CONFIRMED"
			if confirmed {
				sc.confirmedLive++
			}
			if anchorsAny(fs[i], byProg[p]) {
				sc.anchored++
				if confirmed {
					sc.confirmedAnchored++
				}
				continue
			}
			a, ok := sc.byID[field(fs[i], "finding_id")]
			if !ok {
				sc.r.Unadjudicated++
				continue
			}
			sc.applied[a.Finding] = true
			switch a.Verdict {
			case verdictAdditional:
				sc.r.Additional++
			case verdictGated:
				sc.r.Gated++
			case verdictFalsePositive:
				sc.r.FalsePositives++
			default:
				// Unreachable while scoreableRows gates on Validate, which
				// admits exactly the three verdicts above. Kept fail-closed:
				// should the vocabulary ever grow a name this switch does not
				// know, that row earns no reprieve (it is scored as
				// unadjudicated) instead of vanishing from the accounting.
				sc.r.Unadjudicated++
			}
		}
	}
}

// scoreSuiteTally derives the roll-up counters and the wilson report lines.
func (sc *scoreSuiteCtx) scoreSuiteTally() {
	sc.r.GoldTotal = len(sc.matched)
	sc.r.Misses = sc.r.GoldTotal - sc.r.Hits
	sc.r.FP = sc.liveTotal - sc.anchored
	sc.r.Anchored = sc.anchored
	sc.r.Unanchored = sc.liveTotal - sc.anchored
	// Every row that applied to no judged finding is stale — a row for an
	// anchored finding, or one for an id outside the scored live set. rows
	// holds one entry per finding id, so this counts FINDINGS: the same unit
	// every other counter in this Report counts (and never raw rows, which
	// duplicate rows would inflate).
	for _, a := range sc.rows {
		if !sc.applied[a.Finding] {
			sc.r.StaleAdjudications++
		}
	}
	sc.r.RecallLine = wilson.Format(sc.r.Hits, sc.r.GoldTotal, "recall")
	sc.r.PrecisionLine = wilson.Format(sc.anchored, sc.liveTotal, "precision")
	sc.r.AdjustedPrecisionLine = wilson.Format(sc.anchored,
		sc.anchored+sc.r.FalsePositives+sc.r.Unadjudicated, "precision")
	sc.r.ConfirmedLive = sc.confirmedLive
	sc.r.ConfirmedAnchored = sc.confirmedAnchored
	if sc.confirmedLive > 0 {
		sc.r.ConfirmedPrecisionLine = wilson.Format(sc.confirmedAnchored, sc.confirmedLive, "precision")
	}
}

// Score scores the single program named by the campaign state doc's
// REQUIRED key "program" (read via (*state.Campaign).State, the existing
// state accessor in internal/state/campaign.go:184) against the suite,
// with the live set from findings.LoadLiveFindings and the non-gold
// adjudications from Load. ok=false when no suite case matches the
// campaign's program (or the state/live reads fail — there is no error
// channel by design, matching the brief).
//
// A Load failure is NOT fatal: this package's posture is fail-open on
// advisory data, so an unreadable adjudication key degrades to "no rows"
// (the raw precision line and the adjusted one then coincide) rather than
// refusing a score the raw join could still produce.
func Score(c *state.Campaign, cases []validation.Value) (Report, bool) {
	st, err := c.State()
	if err != nil {
		return Report{}, false
	}
	program := field(st, "program")
	if program == "" {
		return Report{}, false
	}
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return Report{}, false
	}
	adjs, err := Load(c)
	if err != nil {
		adjs = nil
	}
	r := ScoreSuiteWith([]string{program}, map[string][]validation.Value{program: live}, cases, adjs)
	if r.GoldTotal == 0 {
		return r, false
	}
	return r, true
}

// GoldPack is an operator-supplied suite: an explicit file of
// evaluation_case rows, plus its sha256 sidecar when one sits next to it.
// It exists because a held-out answer key must never be embedded in the
// shipped binary (see the leakage partition rule): the operator loads the
// key at grading time, the tool verifies it, nothing persists.
//
// Digest is the sha256 of the RAW file bytes (never a re-serialisation:
// the sidecar describes the bytes on disk, and re-encoding the parsed JSON
// would hash something the operator never wrote). Verified is true only
// when a sidecar was found next to the pack and matched.
type GoldPack struct {
	Cases    []validation.Value
	Digest   string
	Verified bool
}

// LoadGoldPack reads and verifies an operator-supplied gold pack and
// returns its case rows. path == "" is the normal case — no pack, the
// embedded suite is the suite — and returns (nil, nil).
//
// Everything else is fail-loud, because this is grading, not scoring: a
// missing file, a file that is not a JSON array of objects, a row that
// fails evaluation_case validation (a mis-typed gold row must not quietly
// shrink the answer key — the error names the row's case_id), a duplicate
// case_id, and a mismatching sidecar all refuse. A pack with no sidecar is
// ACCEPTED and reported as unverified by the caller, which is a fact the
// operator must see in the provenance line.
func LoadGoldPack(path string) ([]validation.Value, error) {
	pack, err := OpenGoldPack(path)
	if err != nil {
		return nil, err
	}
	return pack.Cases, nil
}

// OpenGoldPack is LoadGoldPack plus the tamper-evidence facts the callers
// print (the digest, and whether a sidecar verified it). One read of the
// file: the hash the provenance line prints is the hash of the very bytes
// that were parsed.
func OpenGoldPack(path string) (GoldPack, error) {
	if path == "" {
		return GoldPack{}, nil
	}
	doc, digest, err := openGoldRead(path)
	if err != nil {
		return GoldPack{}, err
	}
	cases, err := openGoldCases(path, doc)
	if err != nil {
		return GoldPack{}, err
	}
	return openGoldVerifySidecar(path, digest, cases)
}

// openGoldRead reads the pack file, hashes the raw bytes and parses the
// document, refusing an unreadable file, invalid JSON and a non-array doc.
func openGoldRead(path string) (validation.Value, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.Value{}, "", fmt.Errorf("gold pack %s is not readable: %v",
			path, err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.Value{}, "", fmt.Errorf("gold pack %s is not valid JSON: %v",
			path, err)
	}
	if doc.Kind != validation.Arr {
		return validation.Value{}, "", fmt.Errorf(
			"gold pack %s must be a JSON array of evaluation_case objects, "+
				"found %s", path, jsonKindName(doc))
	}
	return doc, digest, nil
}

// openGoldCases validates the parsed pack's rows in order and returns the
// case rows, refusing duplicate case_ids and duplicate anchors.
func openGoldCases(path string, doc validation.Value) ([]validation.Value, error) {
	cases := make([]validation.Value, 0, len(doc.A))
	seen := map[string]bool{}
	anchors := map[string]string{}
	for i, row := range doc.A {
		if err := openGoldCheckRow(path, row, i); err != nil {
			return nil, err
		}
		cid := field(row, "case_id")
		if seen[cid] {
			return nil, fmt.Errorf(
				"gold pack %s: duplicate case_id %s — a case id names one "+
					"gold row", path, cid)
		}
		seen[cid] = true
		// r6 (critic issue 3): the same ANCHOR under two ids is answer-key
		// duplication — one real finding satisfies both, GoldTotal grows
		// without the suite learning anything new, and the Wilson
		// confidence widens off a phantom second sample. Refuse it the way
		// duplicate case_ids are refused; the anchor's canonical form is
		// bug_class + sorted location basenames + outcome + mechanisms.
		key := anchorKey(row)
		if prev, dup := anchors[key]; dup {
			return nil, fmt.Errorf(
				"gold pack %s: cases %s and %s have the same gold anchor "+
					"(bug_class, locations, outcome, mechanisms) — one "+
					"finding would satisfy both and inflate the answer key; "+
					"merge them", path, prev, cid)
		}
		anchors[key] = cid
		cases = append(cases, row)
	}
	return cases, nil
}

// openGoldCheckRow refuses one pack row that is not a well-formed
// evaluation_case: a non-object, a row failing evaluation_case validation,
// and a control row carrying match_mechanisms.
func openGoldCheckRow(path string, row validation.Value, i int) error {
	if row.Kind != validation.Obj {
		return fmt.Errorf(
			"gold pack %s row %d must be a JSON object, found %s",
			path, i, jsonKindName(row))
	}
	if err := validation.Validate(row, "evaluation_case", 1); err != nil {
		cid := field(row, "case_id")
		if cid == "" {
			cid = fmt.Sprintf("(row %d)", i)
		}
		return fmt.Errorf(
			"gold pack %s: case %s fails evaluation_case validation: %v",
			path, cid, err)
	}
	// R2-5 (critic): the mechanism leg runs only on NON-control anchors
	// (a control case is a program's ABSENCE check — nothing to anchor
	// a phrase against). A control row carrying match_mechanisms is
	// dead authoring: refused at load so an author believes the gate
	// bites when it cannot.
	if field(obj(row, "gold"), "outcome") == notExploitable &&
		obj(row, "gold").Kind == validation.Obj &&
		obj(obj(row, "gold"), "match_mechanisms").Kind != validation.Null {
		return fmt.Errorf(
			"gold pack %s: case %s is a control (outcome %s) and "+
				"carries match_mechanisms — the mechanism leg never runs "+
				"for control cases; drop the phrases or the outcome",
			path, field(row, "case_id"), notExploitable)
	}
	return nil
}

// openGoldVerifySidecar checks the pack's tamper-evidence sidecar, when one
// exists, and reports the pack with its digest (Verified only on a match).
func openGoldVerifySidecar(path, digest string, cases []validation.Value) (GoldPack, error) {
	sidecar, ok := goldPackSidecar(path)
	if !ok {
		return GoldPack{Cases: cases, Digest: digest}, nil
	}
	sraw, err := os.ReadFile(sidecar)
	if err != nil {
		return GoldPack{}, fmt.Errorf("gold pack sidecar %s is not readable: %v",
			sidecar, err)
	}
	// The sidecar is one hex line, or a `sha256sum`-style "<hex>  <name>"
	// line (the real pack's sidecar is the two-token form): the FIRST
	// whitespace-separated token is the digest either way.
	want := ""
	if f := strings.Fields(string(sraw)); len(f) > 0 {
		want = f[0]
	}
	if !strings.EqualFold(want, digest) {
		return GoldPack{}, fmt.Errorf(
			"gold pack %s does not match its sidecar %s: sidecar sha256 %s, "+
				"file sha256 %s", path, sidecar, want, digest)
	}
	return GoldPack{Cases: cases, Digest: digest, Verified: true}, nil
}

// goldPackSidecar finds the pack's tamper-evidence sidecar, or reports that
// there is none. The store convention (evalstore.SidecarName) is the stem
// with .json replaced by .sha256 — cases.json -> cases.sha256 — so the
// candidates are the same name beside the pack, the literal `<path>.sha256`,
// and the store's own <dir>/cases.sha256.
func goldPackSidecar(path string) (string, bool) {
	candidates := []string{path + ".sha256"}
	if ext := filepath.Ext(path); ext != "" {
		candidates = append(candidates, strings.TrimSuffix(path, ext)+".sha256")
	}
	candidates = append(candidates, filepath.Join(filepath.Dir(path), "cases.sha256"))
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, true
		}
	}
	return "", false
}

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
