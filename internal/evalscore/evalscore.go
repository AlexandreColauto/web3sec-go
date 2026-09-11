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
// ScoreSuite is pure (no I/O): the only filesystem touch is Score, which
// reads the program key through (*state.Campaign).State and the live set
// through findings.LoadLiveFindings — no direct os/filepath access lives
// in this package.
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
type Report struct {
	GoldTotal, Hits, Misses, FP int // FP: live findings in suite-matched programs that match no gold anchor
	RecallLine, PrecisionLine   string
	HeldOut                     bool
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
// same bug class, and (no gold locations, or the finding's affected[0]
// path suffix-matches some gold locations[i].file basename).
func anchor(f, gold validation.Value) bool {
	if field(obj(f, "root_cause"), "class") != field(gold, "bug_class") {
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

// ScoreSuite rolls the join up over a program scope: matched cases are the
// suite cases whose lowercased program.program is in programs; live
// findings are looked up by lowercased program. Findings under programs
// with no matched case are out of scope (never FP, never in the precision
// denominator).
func ScoreSuite(programs []string, liveByProgram map[string][]validation.Value, cases []validation.Value) Report {
	scope := map[string]bool{}
	for _, p := range programs {
		scope[strings.ToLower(p)] = true
	}
	live := map[string][]validation.Value{}
	for p, fs := range liveByProgram {
		k := strings.ToLower(p)
		live[k] = append(live[k], fs...)
	}
	type scored struct {
		id      string
		program string
		gold    validation.Value
		control bool
	}
	var matched []scored
	var r Report
	for _, c := range cases {
		prog := strings.ToLower(field(obj(c, "program"), "program"))
		if !scope[prog] {
			continue
		}
		gold := obj(c, "gold")
		matched = append(matched, scored{
			id:      field(c, "case_id"),
			program: prog,
			gold:    gold,
			control: field(gold, "outcome") == notExploitable,
		})
		if field(c, "partition") == heldOutPartition {
			r.HeldOut = true
		}
	}
	// Deterministic iteration: sort ids before any scoring pass.
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].id < matched[j].id })

	// byProg groups the matched non-control golds per program so each
	// live finding is anchor-checked once (a finding anchoring two golds
	// still counts once toward precision).
	byProg := map[string][]validation.Value{}
	for _, m := range matched {
		if !m.control {
			byProg[m.program] = append(byProg[m.program], m.gold)
		}
	}
	anchored, liveTotal := 0, 0
	for _, m := range matched {
		fs := live[m.program]
		if m.control {
			if len(fs) == 0 {
				r.Hits++
			}
			continue
		}
		for i := range fs {
			if anchor(fs[i], m.gold) {
				r.Hits++
				break
			}
		}
	}
	// Precision scope: live findings in suite-matched programs — every
	// program with ≥1 matched case, including control-only ones (a
	// finding under a control program anchored nothing by definition,
	// so it is always FP).
	seen := map[string]bool{}
	for _, m := range matched {
		if seen[m.program] {
			continue
		}
		seen[m.program] = true
		fs := live[m.program]
		liveTotal += len(fs)
		for i := range fs {
			for _, g := range byProg[m.program] {
				if anchor(fs[i], g) {
					anchored++
					break
				}
			}
		}
	}
	r.GoldTotal = len(matched)
	r.Misses = r.GoldTotal - r.Hits
	r.FP = liveTotal - anchored
	r.RecallLine = wilson.Format(r.Hits, r.GoldTotal, "recall")
	r.PrecisionLine = wilson.Format(anchored, liveTotal, "precision")
	return r
}

// Score scores the single program named by the campaign state doc's
// REQUIRED key "program" (read via (*state.Campaign).State, the existing
// state accessor in internal/state/campaign.go:184) against the suite,
// with the live set from findings.LoadLiveFindings. ok=false when no
// suite case matches the campaign's program (or the state/live reads
// fail — there is no error channel by design, matching the brief).
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
	r := ScoreSuite([]string{program}, map[string][]validation.Value{program: live}, cases)
	if r.GoldTotal == 0 {
		return r, false
	}
	return r, true
}
