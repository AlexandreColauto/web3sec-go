// bands.go — I3: acceptance score-band precision + the fabrication ledger.
//
// WHY NOT CALIBRATION / EXPECTED CALIBRATION ERROR (ECE) — the refusal is
// deliberate and permanent. The external feedback asked for "calibration"
// on the acceptance score. The acceptance score is NOT a probability: it
// is an additive evidence sum (severity band 0–3 + evidence level 0–3 +
// critic verdict −2.0/+1.5 − demotions + reversibility, clamped at 0;
// assets/schema/finding.schema.json documents the stored shape and
// internal/risk/acceptance.go computes it). ECE measures the gap between a
// forecast PROBABILITY and an observed frequency; running it over a
// non-probability score would emit a number with no referent and no
// possible honest interpretation. The question these scores CAN answer is
// the one this file answers: does a higher score band actually contain a
// higher fraction of gold-anchored findings? That is band precision
// against the suite anchors, rendered with the framework's only interval
// source (wilson.Format), over exactly the scope ScoreSuite already
// scores.
//
// This file is pure: no I/O, no clock, no randomness, and no import of
// internal/risk. The scorer is INJECTED (ScoreFn) by the caller — the
// audit section is the only package that imports internal/risk for it.
package evalscore

import (
	"fmt"
	"math"

	"websec/internal/validation"
	"websec/internal/wilson"
)

// ScoreFn assigns a finding its acceptance score. evalscore takes the
// scorer as a parameter so the package keeps its dependency shape: the
// acceptance score lives in internal/risk, and evalscore never imports it
// (the SECTION injects risk.AcceptanceScore).
//
// ok == false means "there is no usable score for this finding": it is
// counted as unscorable and appears in NO band. A nil ScoreFn is a
// programming error and panics.
type ScoreFn func(validation.Value) (float64, bool)

// bandEdges is the LOCKED bucket ladder over the acceptance score's real
// range (practical maximum ≈ 8.5 = critical 3.0 + E7 3.0 + confirmed 1.5 +
// irreversible 1.0; floor 0 after the clamp). It is a package-level var so
// every line the block prints can name its own edges and a reader can
// never misread a bucket. len(bandEdges) buckets: bucket i spans
// [bandEdges[i], bandEdges[i+1]) and the LAST one spans
// [bandEdges[len-1], +Inf).
var bandEdges = []float64{0, 1, 2, 4}

// BandRow is one non-empty acceptance bucket: its edges, how many of its
// live findings anchored a gold case, its size, and the canonical
// wilson.Format interval line for the pair.
type BandRow struct {
	Lo, Hi          float64 // Hi == +Inf on the last row
	Anchored, Total int
	Line            string // wilson.Format(Anchored, Total, "precision")
}

// BandEdges returns a copy of the bucket ladder's lower edges. The
// section needs every bucket — including the empty ones, which render no
// row but DO occupy a slot in the ledger's by-band distribution.
func BandEdges() []float64 {
	return append([]float64(nil), bandEdges...)
}

// bandHi is bucket i's exclusive upper edge (+Inf on the last bucket).
func bandHi(i int) float64 {
	if i+1 < len(bandEdges) {
		return bandEdges[i+1]
	}
	return math.Inf(1)
}

// Label renders one bucket the way the block prints it: "[0,1)", and the
// last bucket as "[4+)" because its upper edge is +Inf.
func (r BandRow) Label() string {
	if math.IsInf(r.Hi, 1) {
		return fmt.Sprintf("[%g+)", r.Lo)
	}
	return fmt.Sprintf("[%g,%g)", r.Lo, r.Hi)
}

// BandLabel renders bucket i (an index into BandEdges) with the same
// renderer BandRow.Label uses, so the ledger line and the band rows can
// never disagree about what a bucket is called. Out-of-range i yields "".
func BandLabel(i int) string {
	if i < 0 || i >= len(bandEdges) {
		return ""
	}
	return BandRow{Lo: bandEdges[i], Hi: bandHi(i)}.Label()
}

// bandIndex places a finite, non-negative score: bucket i is the first
// whose exclusive upper edge exceeds the score, and the last bucket
// absorbs everything at or above its lower edge.
func bandIndex(score float64) int {
	for i := 0; i+1 < len(bandEdges); i++ {
		if score < bandEdges[i+1] {
			return i
		}
	}
	return len(bandEdges) - 1
}

// isFabricated reports whether the finding was RETRACTED BY THE RECORD
// ITSELF.
//
// Fabricated = verification.critic_verdict == "disproved" OR status ==
// "DISPROVED" (DISPROVED is the terminal truth-demotion in
// internal/findings/levels.go).
//
// The other terminal states are NOT fabrications, and this is a
// deliberate, auditable line so it cannot drift silently:
//   - SUPERSEDED is a REPLACEMENT — the row was replaced by a newer one,
//     not invented;
//   - DUPLICATE is a dedup outcome — the same bug was recorded twice;
//   - OUT_OF_SCOPE is a scope call — the bug is real but out of bounds;
//   - INFORMATIONAL is a disclosure — a note, not a claim.
//
// A non-committal critic verdict ("pending"/"possible") refutes nothing
// and is not a fabrication either.
func isFabricated(f validation.Value) bool {
	if field(obj(f, "verification"), "critic_verdict") == "disproved" {
		return true
	}
	return field(f, "status") == "DISPROVED"
}

// Bands buckets the suite-scope live findings by acceptance score and
// reports, per non-empty bucket, how many of them anchored a gold case.
//
// Scope: the SAME scope ScoreSuite scores — live findings under any
// program with ≥1 matched case (matchCases/scopedPrograms, one
// implementation, shared with ScoreSuite). Anchor: the same anchor(f,
// gold) rule. Nothing here is a second definition of anything.
//
// Returns the rendered rows (ascending, empty buckets omitted), the
// unscorable count (findings the scorer declined, or a score that is not
// a position on the ladder: NaN, ±Inf, or negative), the fabricated count
// over the same scope, and the per-band fabrication distribution ALIGNED
// TO bandEdges POSITIONS — so it always has len(bandEdges) entries and a
// bucket that renders no row still owns its slot. A single provenance
// caveat: a fabricated finding that is also unscorable occupies no band
// position, so sum(fabByBand) can be less than fabricated; unscorable says
// how many findings were left out of the ladder.
func Bands(programs []string, liveByProgram map[string][]validation.Value,
	cases []validation.Value, score ScoreFn) (rows []BandRow, unscorable int,
	fabricated int, fabByBand []int) {
	matched := matchCases(programs, cases)
	live := lowerLive(liveByProgram)
	golds := goldByProgram(matched)

	totals := make([]int, len(bandEdges))
	anchored := make([]int, len(bandEdges))
	fabByBand = make([]int, len(bandEdges))

	for _, p := range scopedPrograms(matched) {
		for _, f := range live[p] {
			band := -1
			s, ok := score(f)
			switch {
			case !ok, math.IsNaN(s), math.IsInf(s, 0), s < bandEdges[0]:
				// No usable score. Never silently bucket 0: a declined
				// score, a non-finite one, or a negative one (the ladder
				// starts at 0 and the acceptance score is clamped there,
				// so a negative number is not a position on it) is
				// counted unscorable and shown in no band.
			default:
				band = bandIndex(s)
				totals[band]++
				if anchorsAny(f, golds[p]) {
					anchored[band]++
				}
			}
			if isFabricated(f) {
				fabricated++
				if band >= 0 {
					fabByBand[band]++
				}
			}
			if band < 0 {
				unscorable++
			}
		}
	}

	for i := range bandEdges {
		if totals[i] == 0 {
			continue
		}
		rows = append(rows, BandRow{
			Lo:       bandEdges[i],
			Hi:       bandHi(i),
			Anchored: anchored[i],
			Total:    totals[i],
			Line:     wilson.Format(anchored[i], totals[i], "precision"),
		})
	}
	return rows, unscorable, fabricated, fabByBand
}
