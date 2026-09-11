package evalstore

// temporal.go — I1b (Wave I, Task 2): temporal + near-dup discipline at
// SCORING time.
//
// Two ways a held-out row can quietly corrupt a scorecard:
//
//   - TEMPORAL: it is older than the dev rows it is scored against. A row
//     dated before the data it is measured against is not a held-out row,
//     it is a leak in the other direction.
//   - NEAR-DUP: it restates a dev/training row — the same bug shape counted
//     twice, once on each side of the split, which inflates whatever the
//     shared shape scores.
//
// Both are REFUSALS, not repairs. No stored row is mutated, rewritten or
// deleted — PartitionHealth only reports which rows must not rank and why.
// The backtest drops them from the held-out leg and prints the counts; the
// audit section renders the problem list; the stored bytes are untouched.
// A run whose entire held-out set is excluded falls out through backtest's
// existing EmptyMessage exit-2 path, which is the honest answer: nothing
// rankable means nothing certified.
//
// Ordering rule (locked):
//
//   - compare `deployed_at` when BOTH rows carry a parseable YYYY-MM-DD;
//   - otherwise fall back to `created_at` (the schema requires it, so the
//     fallback is always available). `created_at` is compared as the raw
//     string; the framework stamps it with state.NowIso, so every stored
//     value shares one zone and one shape and orders lexicographically.
//   - a deployed_at that is present but unparseable makes the row
//     UNORDERABLE: fail-closed on the row (it does not rank, in either
//     partition — an unorderable dev row also leaves the dev pool it would
//     otherwise anchor), fail-open on the run (the other rows still score).
//
// Near-dup rule (locked): see dupKey and nearDupThreshold. Same-partition
// pairs are NOT scanned — dev-dev duplication is the loader's problem, not
// the scorecard's, and this file deliberately does not police it.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"websec/internal/textsim"
	"websec/internal/validation"
)

// nearDupThreshold is the Jaccard cut for "the same bug twice". Locked
// constant: it is the rule, not a tunable.
const nearDupThreshold = 0.8

// ymdRe is the date shape the temporal rule can order. The regex pins the
// SHAPE (4-2-2 digits) and time.Parse pins a real calendar date, so
// 2026-02-30 is unparseable rather than silently ordering as a February
// timestamp that does not exist.
var ymdRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// ExclusionReason is why a row was excluded from the scorecard leg.
type ExclusionReason string

const (
	// ReasonUnparseable: deployed_at was present but not a YYYY-MM-DD
	// date. Problem line: "unparseable-deployed_at <case_id>".
	ReasonUnparseable ExclusionReason = "unparseable-deployed_at"
	// ReasonTemporal: strictly older than a dev row. Counted, not
	// enumerated — it is a property of the split, not a defect to fix,
	// so it carries no problem line.
	ReasonTemporal ExclusionReason = "temporal"
	// ReasonNearDup: restates a dev/training row. Problem line:
	// "near-dup <held> ~ <other> <score>".
	ReasonNearDup ExclusionReason = "near-dup"
)

// Exclusion is one refused row: the row, the reason, and — for a near-dup —
// the best-matching reference row and its Jaccard score.
//
// Problem is the rendered problem line ("" for a temporal exclusion, which
// is a property of the split rather than a defect and is counted, not
// listed). It rides the exclusion so a consumer that needs per-row lines
// (the backtest) does not have to re-spell the formats.
type Exclusion struct {
	Case    validation.Value
	Reason  ExclusionReason
	Other   string  // near-dup counterpart case_id ("" otherwise)
	Score   float64 // near-dup Jaccard (0 otherwise)
	Problem string  // rendered problem line ("" for temporal)
}

// Health is the partition-health report: the excluded rows (canonical
// order: by case_id, so two input orders agree) and the problem lines
// (sorted). A row is excluded for exactly ONE reason, in the locked
// precedence unparseable > temporal > near-dup, so the reasons partition
// the excluded set and can never double-count a row.
type Health struct {
	Excluded []Exclusion
	Problems []string
}

// PartitionHealth is the locked entry point: the excluded rows (in
// canonical order) and the problem lines. The caller decides what to do
// with them — nothing here touches the store.
func PartitionHealth(cases []validation.Value) (excluded []validation.Value, problems []string) {
	h := PartitionHealthFull(cases)
	excluded = make([]validation.Value, 0, len(h.Excluded))
	for _, e := range h.Excluded {
		excluded = append(excluded, e.Case)
	}
	return excluded, h.Problems
}

// PartitionHealthFull is PartitionHealth plus the per-reason detail the
// scorecard line needs: "held-out excluded: <N> temporal, <M> near-dup"
// counts ROWS by reason, and parsing that back out of a formatted problem
// string would be a second, drifting source of truth. The locked
// PartitionHealth signature is the wrapper above.
func PartitionHealthFull(cases []validation.Value) Health {
	rows := make([]*healthRow, 0, len(cases))
	for _, c := range cases {
		r := &healthRow{c: c, id: objStr(c, "case_id"),
			created: objStr(c, "created_at"), key: dupKey(c)}
		// The partition vocabulary mirrors backtest.Run exactly (the
		// consumer): held-out ranks, dev sources priors, training is
		// neither. Training rows are still near-dup REFERENCES — the
		// locked rule says dev/training — but they never anchor the
		// temporal max, which the locked rule scopes to dev.
		switch objStr(c, "partition") {
		case "held-out":
			r.held = true
		case "dev", "":
			r.dev, r.ref = true, true
		case "training":
			r.ref = true
		}
		if dep := objAt(c, "deployed_at"); dep.Kind != validation.Null {
			date, ok := parseYMD(dep.S)
			if dep.Kind != validation.Str || !ok {
				r.excluded = true
				r.reason = ReasonUnparseable
			} else {
				r.deployed, r.hasDep = date, true
			}
		}
		rows = append(rows, r)
	}

	problems := []string{}

	// Temporal pass: a held-out row is excluded iff it is STRICTLY older
	// than some dev row — identical dates rank, so the same-day backfill
	// the shipped suite carries is not a mass exclusion.
	for _, h := range rows {
		if !h.held || h.excluded {
			continue
		}
		for _, d := range rows {
			if !d.dev || d.excluded {
				continue
			}
			if strictlyOlder(h, d) {
				h.excluded, h.reason = true, ReasonTemporal
				break
			}
		}
	}

	// Near-dup pass: only rows still standing are scanned, for the same
	// reason a row gets one reason — reporting an already-excluded row as
	// a duplicate of the very rows it was dropped against would read like
	// a second, independent defect.
	for _, h := range rows {
		if !h.held || h.excluded {
			continue
		}
		best, bestRow := 0.0, (*healthRow)(nil)
		for _, ref := range rows {
			if !ref.ref || ref.excluded {
				continue
			}
			// ties keep the first reference in store order: the
			// report must not depend on map iteration or on
			// which of two equally close rows happened to win.
			if j := textsim.Jaccard(h.key, ref.key); j > best {
				best, bestRow = j, ref
			}
		}
		if bestRow != nil && best >= nearDupThreshold {
			h.excluded, h.reason = true, ReasonNearDup
			h.other, h.score = bestRow.id, best
		}
	}

	excluded := make([]Exclusion, 0, len(rows))
	for _, r := range rows {
		if !r.excluded {
			continue
		}
		e := Exclusion{Case: r.c, Reason: r.reason,
			Other: r.other, Score: r.score}
		switch r.reason {
		case ReasonUnparseable:
			e.Problem = fmt.Sprintf("%s %s", ReasonUnparseable, r.id)
		case ReasonNearDup:
			e.Problem = fmt.Sprintf("%s %s ~ %s %s", ReasonNearDup, r.id,
				r.other,
				validation.PythonFloat(validation.PythonRound(r.score, 4)))
		}
		if e.Problem != "" {
			problems = append(problems, e.Problem)
		}
		excluded = append(excluded, e)
	}
	// Canonical report: the excluded set sorted by case_id, the problems
	// sorted as strings. Same rows in any input order => same bytes.
	sort.SliceStable(excluded, func(i, j int) bool {
		return objStr(excluded[i].Case, "case_id") <
			objStr(excluded[j].Case, "case_id")
	})
	sort.Strings(problems)
	return Health{Excluded: excluded, Problems: problems}
}

// healthRow is one case's partition-health state while the passes run.
type healthRow struct {
	c        validation.Value
	id       string
	held     bool // the scored leg
	dev      bool // the pool the temporal rule compares against
	ref      bool // the pool the near-dup scan compares against
	deployed string
	hasDep   bool
	created  string
	key      string // dupKey(c) — computed once, compared many times
	reason   ExclusionReason
	other    string
	score    float64
	excluded bool
}

// strictlyOlder is the locked comparison: deployed_at governs when BOTH
// rows carry a parseable date, otherwise created_at (raw string compare —
// one framework-written stamp shape, so lexicographic IS chronological).
func strictlyOlder(a, b *healthRow) bool {
	if a.hasDep && b.hasDep {
		return a.deployed < b.deployed
	}
	return a.created < b.created
}

// parseYMD accepts exactly YYYY-MM-DD with a real calendar date.
func parseYMD(s string) (string, bool) {
	if s == "" || !ymdRe.MatchString(s) {
		return "", false
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return "", false
	}
	return s, true
}

// dupKey is the near-dup comparison key (locked): lowercase tokens of
// gold.bug_class + gold.root_cause + basenames(gold.locations[].file) +
// code.repo, space-joined, compared with the shared bigram-Jaccard rule
// (internal/textsim, the same function archetypes.Jaccard delegates to —
// never a second implementation).
//
// The basename is deliberate: the same contract reached through two
// checkout layouts (src/Vault.sol vs contracts/Vault.sol) is the same
// anchor. A row the validated store cannot produce — only a raw/bypass row
// with no root_cause and no locations — collapses to its bare class label,
// which is a degenerate key rather than a duplicate shape; the store's own
// schema (gold.root_cause required, minLength 10) keeps that shape out of
// every stored suite.
func dupKey(c validation.Value) string {
	gold := objAt(c, "gold")
	parts := []string{
		strings.ToLower(objStr(gold, "bug_class")),
		strings.ToLower(objStr(gold, "root_cause")),
	}
	for _, loc := range objAt(gold, "locations").A {
		if loc.Kind != validation.Obj {
			continue
		}
		if f := objStr(loc, "file"); f != "" {
			parts = append(parts, strings.ToLower(filepath.Base(f)))
		}
	}
	parts = append(parts, strings.ToLower(objStr(objAt(c, "code"), "repo")))
	return strings.Join(parts, " ")
}
