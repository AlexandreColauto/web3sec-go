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
	"sort"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
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
