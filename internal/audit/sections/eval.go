// Section 15: eval — the G4 gold-suite join as an audit section.
//
// The section renders ONLY when the campaign's pinned program matches at
// least one assets/evalsuite case (evalscore.Score ok=true); otherwise it
// returns ErrSkip and AuditCampaign omits it from the report. Golden
// campaigns pin synthetic programs (toy-protocol etc.) that match
// nothing, so the section never appears there: check-golden.py's
// EXPECTED_SECTIONS stays 14 with zero fixture edits.
//
// The value carries both the structured counters and the pinned markdown
// lines (the ## eval block a human reads). The section is informational:
// ok is always true — it reports the join, it never gates the campaign.
//
// I1b (Wave I, Task 2): the section also reports the store's partition
// problems (evalstore.PartitionHealth): rows the scorecard refuses to rank
// because their deployed_at cannot be parsed or because they restate a
// dev/training row. The block is presence-gated — a clean store renders
// the same five lines as before, byte for byte — and ok stays true: a
// defect in the EVAL STORE is not a defect in this campaign, and the
// scoring-time posture is fail-open.
//
// I3 (Wave I, Task 7): the section appends the acceptance score-band
// precision block and the fabrication ledger (evalscore.Bands), both
// presence-gated. ECE is REFUSED: the acceptance score is an additive
// evidence sum, not a probability, so expected calibration error over it
// would be meaningless (see internal/evalscore/bands.go). ok stays true
// here too — the block is an advisory measurement, never a gate.
package sections

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"websec/assets"
	"websec/internal/evalscore"
	"websec/internal/evalstore"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// ErrSkip is the presence-gate signal: the campaign matched no suite
// case, so the section is absent by construction. AuditCampaign omits
// sections that return it (errors.Is); any other error fails the audit.
var ErrSkip = errors.New("sections: skip (presence gate closed)")

// evalCases is the suite loader. It is a var so a test can point the
// section at a synthetic pack: the shipped suite is partition-clean by
// construction (uniform parseable deployed_at dates, no held-out row
// duplicating a dev row), so the I1b problem render has no fixture to
// exercise over the real pack.
var evalCases = assets.LoadEvalCases

// riskScore is the injected evalscore.ScoreFn, and the only place this
// package reaches the acceptance score (evalscore never imports
// internal/risk — the dependency shape it had before I3 is unchanged).
//
// risk.AcceptanceScore's second result is DISQUALIFIED, and this adapter
// widens it to ok=true on purpose. A critic-disproved finding is
// disqualified, but its additive sum still exists — the −2.0 term has
// simply been erased by the score's 0 floor — and the band block's
// denominator is the SAME live set the existing precision line divides
// by. Dropping the disqualified rows would silently shrink one denominator
// and not the other, and would hide exactly the refuted rows the
// fabrication ledger exists to expose. Refutation is reported by the
// LEDGER, never by bucketing: a disproved finding clamps to 0.0 and lands
// in [0,1), which is where refuted evidence honestly sits on a "is this
// score backed by a gold anchor" ladder.
func riskScore(f validation.Value) (float64, bool) {
	s, _ := risk.AcceptanceScore(f)
	return s, true
}

// heldOutPartition is the suite partition counted as held-out in the
// suite line (mirrors evalscore's split; every other partition reads
// as dev — the pack only carries dev/held-out).
const heldOutPartition = "held-out"

// Eval is the G4 eval section: {matched, dev, held_out, hits, misses,
// fp, recall, precision, lines, problems, ok}.
func Eval(c *state.Campaign) (validation.Value, error) {
	cases, err := evalCases()
	if err != nil {
		return validation.Value{}, err
	}
	rep, ok := evalscore.Score(c, cases)
	if !ok {
		return validation.Value{}, ErrSkip
	}
	st, err := c.State()
	if err != nil {
		return validation.Value{}, ErrSkip
	}
	program := ""
	for _, kv := range st.O {
		if kv.K == "program" {
			program = kv.V.S
		}
	}
	dev, heldOut := 0, 0
	for _, cs := range cases {
		var prog string
		for _, kv := range cs.O {
			if kv.K == "program" {
				prog = objStr(kv.V, "program")
			}
		}
		if !strings.EqualFold(prog, program) {
			continue
		}
		var part string
		for _, kv := range cs.O {
			if kv.K == "partition" && kv.V.Kind == validation.Str {
				part = kv.V.S
			}
		}
		if part == heldOutPartition {
			heldOut++
		} else {
			dev++
		}
	}
	lines := []string{
		"## eval",
		fmt.Sprintf("- suite: %d gold cases matched (%d dev, %d held-out)",
			rep.GoldTotal, dev, heldOut),
		"- " + rep.RecallLine,
		"- " + rep.PrecisionLine,
		fmt.Sprintf("- false positives (unanchored live findings): %d", rep.FP),
	}
	// I1b: the scorecard's refusals, rendered only when there are any. The
	// rows are reported, never mutated — the problem list is the whole
	// remedy at this layer (the backtest prints the counts).
	_, problems := evalstore.PartitionHealth(cases)
	if len(problems) > 0 {
		lines = append(lines, fmt.Sprintf(
			"- partition problems (rows excluded from the scorecard, never mutated): %d",
			len(problems)))
		for _, p := range problems {
			lines = append(lines, "  - "+p)
		}
	}
	problemVals := make([]validation.Value, 0, len(problems))
	for _, p := range problems {
		problemVals = append(problemVals, validation.VStr(p))
	}

	// I3: acceptance score-band precision + the fabrication ledger. The
	// scope is the one evalscore already scores for this campaign (its
	// matched program); the live set is read again here because the
	// section — not evalscore — is what owns the risk import. A read
	// failure leaves the set empty, which closes both presence gates: the
	// block is an advisory addition and never fails the section.
	liveByProgram := map[string][]validation.Value{}
	if live, lerr := findings.LoadLiveFindings(c); lerr == nil {
		liveByProgram[program] = live
	}
	bandRows, unscorable, fabricated, fabByBand := evalscore.Bands(
		[]string{program}, liveByProgram, cases, riskScore)
	inScope := len(liveByProgram[program])
	if inScope > 0 {
		lines = append(lines, "- acceptance-band precision (gold-anchored / "+
			"live findings in suite-matched programs):")
		for _, r := range bandRows {
			// The header names the metric, so the row drops
			// wilson.Format's "precision: " noun and keeps the interval.
			lines = append(lines, "  - "+r.Label()+": "+
				strings.TrimPrefix(r.Line, "precision: "))
		}
	}
	if fabricated > 0 {
		parts := make([]string, 0, len(evalscore.BandEdges()))
		for i := range evalscore.BandEdges() {
			parts = append(parts, fmt.Sprintf("%s=%d",
				evalscore.BandLabel(i), fabByBand[i]))
		}
		lines = append(lines, fmt.Sprintf("- fabrication ledger: %d/%d live "+
			"findings retracted as disproved; by band %s",
			fabricated, inScope, strings.Join(parts, ", ")))
	}

	kvs := []validation.KV{
		KV("matched", validation.VInt(int64(rep.GoldTotal))),
		KV("dev", validation.VInt(int64(dev))),
		KV("held_out", validation.VInt(int64(heldOut))),
		KV("hits", validation.VInt(int64(rep.Hits))),
		KV("misses", validation.VInt(int64(rep.Misses))),
		KV("fp", validation.VInt(int64(rep.FP))),
		KV("recall", validation.VStr(rep.RecallLine)),
		KV("precision", validation.VStr(rep.PrecisionLine)),
		KV("lines", strArrOf(lines)),
		KV("problems", validation.VArr(problemVals...)),
	}
	// Presence gate: with no live finding in scope the band block is
	// absent AND none of the new value keys exist (no zero-valued keys —
	// the object is built by appending, not by emitting defaults).
	if inScope > 0 {
		bandVals := make([]validation.Value, 0, len(bandRows))
		for _, r := range bandRows {
			rowKVs := []validation.KV{KV("lo", validation.VFloat(r.Lo))}
			// The last row's upper edge is +Inf, which the ordered-JSON
			// writer cannot represent (encoding/json rejects the
			// Infinity token, so the report would not round-trip):
			// absence IS the open edge.
			if !math.IsInf(r.Hi, 1) {
				rowKVs = append(rowKVs, KV("hi", validation.VFloat(r.Hi)))
			}
			rowKVs = append(rowKVs,
				KV("anchored", validation.VInt(int64(r.Anchored))),
				KV("total", validation.VInt(int64(r.Total))),
				KV("line", validation.VStr(r.Line)))
			bandVals = append(bandVals, validation.VObj(rowKVs...))
		}
		kvs = append(kvs, KV("bands", validation.VArr(bandVals...)))
		if unscorable > 0 {
			kvs = append(kvs, KV("unscorable", validation.VInt(int64(unscorable))))
		}
		if fabricated > 0 {
			fabVals := make([]validation.Value, 0, len(fabByBand))
			for _, n := range fabByBand {
				fabVals = append(fabVals, validation.VInt(int64(n)))
			}
			kvs = append(kvs,
				KV("fabricated", validation.VInt(int64(fabricated))),
				KV("fabrication_bands", validation.VArr(fabVals...)))
		}
	}
	kvs = append(kvs, KV("ok", validation.VBool(true)))
	return validation.VObj(kvs...), nil
}
