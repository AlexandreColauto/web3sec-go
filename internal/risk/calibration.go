package risk

// calibration.go — G3: acceptance priors over the adjudicated eval store.
//
// A prior answers "of the adjudicated cases in this class, what fraction
// were confirmed exploitable" — the base rate the triager multiplies by,
// never a verdict on a live finding. Adjudicated outcomes only:
// accepted := gold.outcome == "confirmed-exploitable" (a case's `paid`
// field, where one exists, is reserved for the immunefi loader's mapping —
// it never invents acceptance). Every OTHER adjudicated outcome
// (confirmed-not-exploitable, disproved, out-of-scope, duplicate,
// economic-no-go) counts AGAINST — they are triage outcomes, not
// absolution. Rows whose outcome is outside the ingest.Outcomes
// vocabulary (missing, null, "unknown") are EXCLUDED from every n: they
// were never adjudicated, so they carry no signal either way. The skip is
// internal — Prior stays pure; the backtest CLI (Task 12) prints the
// skipped count via AdjudicatedStats.
//
// Import home: internal/risk (this file). evalstore imports only state,
// taxonomy, and validation, and ingest's transitive deps (learning,
// sharedmem) touch neither risk nor evalstore, so risk -> {evalstore,
// ingest} closes no loop. The interval IS the wilson package's number:
// makePrior calls wilson.Interval, and the test pins CILo/CIHi to
// wilson.Interval(k, n) field-for-field.

import (
	"fmt"
	"math"

	"websec/internal/evalstore"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// AcceptedOutcome is the one adjudicated outcome that counts FOR
// acceptance (adjudicatedOutcomes[0], named for the comparison sites).
const AcceptedOutcome = "confirmed-exploitable"

// adjudicatedOutcomes is the adjudicated ground-truth vocabulary
// (evaluation_case gold.outcome). Authority: ingest.Outcomes —
// TestOutcomeVocabularySync pins this set equal to it, so a new outcome
// added to the loader fails a test here instead of silently changing
// every prior's n. Imported by value, not by package: risk -> ingest
// closes a test import cycle (ingest -> sharedmem -> chainengine, whose
// test binaries import risk via bounty), and the brief's leaf-package
// fallback would NOT have helped — the cycle rides the ingest EDGE, not
// the file's address — so the prior keeps the copy and the sync test.
var adjudicatedOutcomes = []string{
	"confirmed-exploitable",
	"confirmed-not-exploitable",
	"disproved",
	"out-of-scope",
	"duplicate",
	"economic-no-go",
}

// DefaultMinN is the thickness a class needs to carry its own number.
// Below it the class falls back to the global prior — and Render says so.
const DefaultMinN = 10

// Prior is one class's acceptance prior. N is the adjudicated rows for
// this class; Fallback reports the class was too thin (n < minN) so the
// rate and interval are the global prior's, carried under the class name.
// GlobalN is the global adjudicated n for context in both cases.
type Prior struct {
	Class            string
	Rate, CILo, CIHi float64
	N                int
	Fallback         bool
	GlobalN          int
}

// Render prints the prior the way the framework prints every "X of Y"
// claim: rate to two decimals, n, and the 95% Wilson interval as
// one-decimal percents — with the fallback saying so, e.g.
// "oracle-manipulation: 0.50 (n=12, 95% CI 26.7–72.5%)" or
// "reentrancy: 0.42 (n=3, 95% CI 20.1–67.3%) (fallback: global, n=3)".
func (p Prior) Render() string {
	s := fmt.Sprintf("%s: %.2f (n=%d, 95%% CI %.1f–%.1f%%)",
		p.Class, p.Rate, p.N,
		math.Round(p.CILo*1000)/10, math.Round(p.CIHi*1000)/10)
	if p.Fallback {
		s += fmt.Sprintf(" (fallback: global, n=%d)", p.N)
	}
	return s
}

// AcceptancePriors groups the stored eval cases by gold.bug_class and
// returns each class's prior plus the global prior over ALL classes. The
// global prior is always exact (Fallback false). A class with n < minN
// carries the global rate and interval under its own name with
// Fallback true. A class with zero adjudicated rows never appears in the
// map — there is nothing to carry, not even a fallback.
//
// Determinism: one pass over LoadCases() in stored order; the per-class
// buckets ride a map, so output ORDER is irrelevant (map return); no
// clock, no I/O beyond LoadCases.
func AcceptancePriors(minN int) (map[string]Prior, Prior, error) {
	if minN <= 0 {
		minN = DefaultMinN
	}
	cases, err := evalstore.LoadCases()
	if err != nil {
		return nil, Prior{}, err
	}
	counts, globalK, globalN, _ := adjudicated(cases)
	global := makePrior("global", globalK, globalN, false, globalN)
	out := make(map[string]Prior, len(counts))
	for class, c := range counts {
		if c.n >= minN {
			out[class] = makePrior(class, c.k, c.n, false, globalN)
			continue
		}
		fb := global
		fb.Class = class
		fb.N = c.n
		fb.Fallback = true
		out[class] = fb
	}
	return out, global, nil
}

// AdjudicatedStats reports the store's adjudicated n and the rows skipped
// as unadjudicated (outcome outside the ingest.Outcomes vocabulary). The
// backtest CLI prints both; AcceptancePriors keeps Prior pure.
func AdjudicatedStats() (n, skipped int, err error) {
	cases, err := evalstore.LoadCases()
	if err != nil {
		return 0, 0, err
	}
	_, globalKIgnored, globalN, sk := adjudicated(cases)
	_ = globalKIgnored
	return globalN, sk, nil
}

// classCount is one bucket's accepted/adjudicated tallies.
type classCount struct {
	k, n int
}

// adjudicated is the single counting pass: accepted := outcome ==
// AcceptedOutcome, n := accepted + every other adjudicated outcome, one
// bucket per gold.bug_class plus the global tallies. Returns the buckets,
// global k, global n, and the skipped (unadjudicated) count.
func adjudicated(cases []validation.Value) (map[string]classCount, int, int, int) {
	vocab := make(map[string]bool, len(adjudicatedOutcomes))
	for _, o := range adjudicatedOutcomes {
		vocab[o] = true
	}
	counts := map[string]classCount{}
	globalK, globalN, skipped := 0, 0, 0
	for _, c := range cases {
		gold := objAt(c, "gold")
		outcome := orStr(objAt(gold, "outcome"))
		if !vocab[outcome] {
			skipped++
			continue
		}
		class := orStr(objAt(gold, "bug_class"))
		cc := counts[class]
		if outcome == AcceptedOutcome {
			cc.k++
			globalK++
		}
		cc.n++
		globalN++
		counts[class] = cc
	}
	return counts, globalK, globalN, skipped
}

// makePrior builds a Prior from k accepted in n adjudicated. The interval
// is wilson.Interval's — no local math, so the number printed is always
// the number the framework's one interval package computes.
func makePrior(class string, k, n int, fallback bool, globalN int) Prior {
	var rate, lo, hi float64
	if n > 0 {
		rate = float64(k) / float64(n)
		lo, hi = wilson.Interval(k, n)
	}
	return Prior{Class: class, Rate: rate, CILo: lo, CIHi: hi,
		N: n, Fallback: fallback, GlobalN: globalN}
}
