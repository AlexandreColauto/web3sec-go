// classes.go — J-perclass: per-class recall/precision over the ScoreSuite
// scope (methodology checkpoint 3 / hard-kill #4 self-application: our own
// `## eval` must report per-class cells, not just the aggregate).
//
// Nothing here is a second definition of anything: the scope comes from
// matchCases/scopedPrograms, the hit rule from the same per-case loop
// ScoreSuite runs, and the anchor rule from anchor/anchorsAny — all in
// evalscore.go, shared. This file only BUCKETS the same join by class.
//
// Attribution: a live finding is attributed to strings.ToLower of its
// root_cause.class; an empty or missing class becomes `unmapped` and is
// COUNTED, never dropped. The bucket is deliberately zero-case tolerant —
// the unmapped bucket has no gold case by construction, and a wrong-class
// FP (class present, no gold case of it) belongs in the class column where
// the FP actually happened.
//
// Row set (this is the reading of "classes with zero cases never appear"
// that is consistent with the unmapped rule): a row exists iff its class
// has ≥1 matched gold case OR ≥1 attributed live finding. Rows are never
// EMPTY; the taxonomy is never enumerated.
//
// The anchor rule compares class bytes as stored (anchor()), exactly as
// ScoreSuite does, while attribution lowercases. A finding whose class is
// stored with different case therefore lands in the class cell AND stays
// unanchored — the same finding ScoreSuite counts toward its FP counter.
// One verdict, two views.
package evalscore

import (
	"sort"
	"strings"

	"websec/internal/validation"
	"websec/internal/wilson"
)

// unmappedClass is the bucket for live findings whose root_cause.class is
// empty or missing. It is a row like any other: rendered, counted, never
// dropped.
const unmappedClass = "unmapped"

// ClassRow is one bug_class cell over the ScoreSuite scope.
type ClassRow struct {
	Class          string // gold.bug_class, lowercased
	Cases, Hits    int    // matched gold cases of this class, hits among them
	Live, Anchored int    // live findings attributed to this class, anchored among them
	RecallLine     string // wilson.Format(Hits, Cases, "recall")
	PrecisionLine  string // wilson.Format(Anchored, Live, "precision")
}

// classOf attributes a live finding to its class cell: the lowercased
// root_cause.class, or unmappedClass when that key is empty or absent.
func classOf(f validation.Value) string {
	c := strings.ToLower(field(obj(f, "root_cause"), "class"))
	if c == "" {
		return unmappedClass
	}
	return c
}

// Classes buckets the ScoreSuite join by class.
//
// Scope: matchCases/scopedPrograms (one implementation, shared with
// ScoreSuite and Bands). Gold side: every matched case — controls
// included, because ScoreSuite's recall counts them — contributes its hit
// rule's verdict to its class cell, so sum(Cases) and sum(Hits) equal the
// aggregate GoldTotal and Hits. Live side: every live finding in the
// precision scope is attributed to exactly one class cell, so sum(Live) is
// the aggregate precision denominator and sum(Anchored) = sum(Live) − FP.
//
// Returns the rows sorted by Class. Empty input yields nil (no empty
// rows, no zero-valued keys downstream).
func Classes(programs []string, liveByProgram map[string][]validation.Value,
	cases []validation.Value) []ClassRow {
	matched := matchCases(programs, cases)
	live := lowerLive(liveByProgram)
	byProg := goldByProgram(matched)

	type cell struct{ cases, hits, live, anchored int }
	cells := map[string]*cell{}
	get := func(class string) *cell {
		c, ok := cells[class]
		if !ok {
			c = &cell{}
			cells[class] = c
		}
		return c
	}

	// Gold side: the SAME per-case loop ScoreSuite runs, writing its
	// verdict into the case's class cell instead of the aggregate.
	for _, m := range matched {
		c := get(strings.ToLower(field(m.gold, "bug_class")))
		c.cases++
		if m.control {
			if len(live[m.program]) == 0 {
				c.hits++
			}
			continue
		}
		for i := range live[m.program] {
			if anchor(live[m.program][i], m.gold) {
				c.hits++
				break
			}
		}
	}

	// Live side: the SAME precision scope, each finding attributed once.
	for _, p := range scopedPrograms(matched) {
		for _, f := range live[p] {
			c := get(classOf(f))
			c.live++
			if anchorsAny(f, byProg[p]) {
				c.anchored++
			}
		}
	}

	out := make([]ClassRow, 0, len(cells))
	for class, c := range cells {
		out = append(out, ClassRow{
			Class:         class,
			Cases:         c.cases,
			Hits:          c.hits,
			Live:          c.live,
			Anchored:      c.anchored,
			RecallLine:    wilson.Format(c.hits, c.cases, "recall"),
			PrecisionLine: wilson.Format(c.anchored, c.live, "precision"),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}
