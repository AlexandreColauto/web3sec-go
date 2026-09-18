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
//
// J-perclass (Wave J, Task 2): the section appends the per-class
// recall/precision cells (evalscore.Classes) — methodology checkpoint 3
// applied to our own output. Gated on the SAME presence rule as I3 (≥1
// live finding in scope AND ≥1 matched case); the header warns that
// per-class cells are small so the intervals are the reading, not the
// ratios. With no live finding in scope the block and the `classes` value
// key are absent: a zero-live campaign renders byte-for-byte what it
// rendered before this task.
//
// Non-gold adjudication (evalscore/adjudicate.go, written by `webv2
// adjudicate`): the section CLOSES with the split of the raw unanchored
// count into additional-true-positive / false-positive / assumption-gated,
// the adjusted precision line those rows produce, the unadjudicated
// remainder, and — when rows apply to no unanchored finding — a stale count.
// Gated on len(rows) > 0 alone (a row can outlive the finding it named), so
// a campaign with zero rows renders byte-for-byte what it rendered before
// this task: same `lines` array, same key set. ok stays true.
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
	// r44c: the live set is read ONCE, here, and a READ ERROR REFUSES.
	//
	// The section used to read it late (below) and fold any error into an
	// empty set, and — worse — evalscore.Score was called first: Score has
	// no error channel (its brief), so a findings read failure came back as
	// ok=false and the section returned ErrSkip, i.e. the section silently
	// VANISHED from the report for a store it never read. The two shapes are
	// now separated by reading the store here, before Score:
	//
	//   * absent findings/ is an empty campaign — that fold lives in
	//     findings.LoadAllFindings itself (ListPrefixedOptional), so a
	//     genuinely missing store still yields the empty set, both presence
	//     gates still close, and the section renders exactly the bytes it
	//     rendered before;
	//   * anything else (EACCES, ENOTDIR, EIO, an unreadable or unparseable
	//     FIND-*.json row) propagates: "no live findings in suite-matched
	//     programs" is a claim about a store, and a store that could not be
	//     read supports no such claim.
	//
	// With the store proven readable here, the only remaining meaning of
	// Score's ok=false (below) is the presence gate itself: the campaign's
	// pinned program matches no suite case. (Score re-reads the same store;
	// a store that breaks between the two reads is the one residual this
	// cannot distinguish, and closing it needs an error channel evalscore
	// does not have.)
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return validation.Value{}, fmt.Errorf(
			"the eval section cannot read the live findings store of %s: %v",
			c.CampaignID, err)
	}
	rep, ok := evalscore.Score(c, cases)
	if !ok {
		return validation.Value{}, ErrSkip
	}
	st, err := c.State()
	if err != nil {
		// Score read the state a moment ago; reaching here means the store
		// changed under us. A read error is a refusal, never a skip.
		return validation.Value{}, err
	}
	b := &evalBuilder{
		c:       c,
		cases:   cases,
		live:    live,
		rep:     rep,
		program: evalProgramOf(st),
	}
	dev, heldOut := b.evalCountPartitions()
	b.evalSuiteLines(dev, heldOut)
	b.evalPartitionProblems()
	b.evalBands()
	b.evalClassLines()
	b.evalAdjudicationLines()
	kvs := b.evalBaseKVs(dev, heldOut)
	kvs = b.evalI3KVs(kvs)
	kvs = b.evalAdjKVs(kvs)
	kvs = append(kvs, KV("ok", validation.VBool(true)))
	return validation.VObj(kvs...), nil
}

// evalBuilder carries the shared context of one Eval run so each of the
// section's blocks can be a short method with no parameter list: the
// campaign, the suite cases, the live findings read once at the top
// (r44c), the score report, the pinned program, and the state the blocks
// accumulate in order — the markdown lines and the optional value keys.
type evalBuilder struct {
	c             *state.Campaign
	cases         []validation.Value
	live          []validation.Value
	rep           evalscore.Report
	program       string
	lines         []string
	problems      []string
	liveByProgram map[string][]validation.Value
	bandRows      []evalscore.BandRow
	unscorable    int
	fabricated    int
	fabByBand     []int
	inScope       int
	classRows     []evalscore.ClassRow
	adjs          []evalscore.Adjudication
}

// evalProgramOf returns the campaign's pinned program from the state
// object, or "" when the state pins none.
func evalProgramOf(st validation.Value) string {
	program := ""
	for _, kv := range st.O {
		if kv.K == "program" {
			program = kv.V.S
		}
	}
	return program
}

// evalCountPartitions counts the matched suite cases into dev and
// held-out, matching the campaign's pinned program case-insensitively.
func (b *evalBuilder) evalCountPartitions() (dev, heldOut int) {
	for _, cs := range b.cases {
		var prog string
		for _, kv := range cs.O {
			if kv.K == "program" {
				prog = validation.ObjStr(kv.V, "program")
			}
		}
		if !strings.EqualFold(prog, b.program) {
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
	return dev, heldOut
}

// evalSuiteLines opens the section's markdown lines with the suite join
// summary and the score report's recall/precision lines.
func (b *evalBuilder) evalSuiteLines(dev, heldOut int) {
	b.lines = []string{
		"## eval",
		fmt.Sprintf("- suite: %d gold cases matched (%d dev, %d held-out)",
			b.rep.GoldTotal, dev, heldOut),
		"- " + b.rep.RecallLine,
		"- " + b.rep.PrecisionLine,
		fmt.Sprintf("- false positives (unanchored live findings): %d", b.rep.FP),
	}
}

// evalPartitionProblems appends the I1b partition-problem lines and keeps
// the raw problems for the `problems` value key.
func (b *evalBuilder) evalPartitionProblems() {
	// I1b: the scorecard's refusals, rendered only when there are any. The
	// rows are reported, never mutated — the problem list is the whole
	// remedy at this layer (the backtest prints the counts).
	_, b.problems = evalstore.PartitionHealth(b.cases)
	if len(b.problems) > 0 {
		b.lines = append(b.lines, fmt.Sprintf(
			"- partition problems (rows excluded from the scorecard, never mutated): %d",
			len(b.problems)))
		for _, p := range b.problems {
			b.lines = append(b.lines, "  - "+p)
		}
	}
}

// evalBands runs the I3 band computation and appends the acceptance-band
// precision lines and the fabrication ledger line.
func (b *evalBuilder) evalBands() {
	// I3: acceptance score-band precision + the fabrication ledger. The
	// scope is the one evalscore already scores for this campaign (its
	// matched program); the live set is the one read at the TOP of this
	// function (r44c: it was read AGAIN here and a failure left it empty,
	// which silently rendered "0 live findings in scope" for a store the
	// section could not read — a read error is a refusal, and it is refused
	// before Score). Both blocks below stay presence-gated on that set, so
	// a campaign with no live finding renders the same bytes as before.
	b.liveByProgram = map[string][]validation.Value{b.program: b.live}
	b.bandRows, b.unscorable, b.fabricated, b.fabByBand = evalscore.Bands(
		[]string{b.program}, b.liveByProgram, b.cases, riskScore)
	b.inScope = len(b.liveByProgram[b.program])
	if b.inScope > 0 {
		b.lines = append(b.lines, "- acceptance-band precision (gold-anchored / "+
			"live findings in suite-matched programs):")
		for _, r := range b.bandRows {
			// The header names the metric, so the row drops
			// wilson.Format's "precision: " noun and keeps the interval.
			b.lines = append(b.lines, "  - "+r.Label()+": "+
				strings.TrimPrefix(r.Line, "precision: "))
		}
	}
	if b.fabricated > 0 {
		parts := make([]string, 0, len(evalscore.BandEdges()))
		for i := range evalscore.BandEdges() {
			parts = append(parts, fmt.Sprintf("%s=%d",
				evalscore.BandLabel(i), b.fabByBand[i]))
		}
		b.lines = append(b.lines, fmt.Sprintf("- fabrication ledger: %d/%d live "+
			"findings retracted as disproved; by band %s",
			b.fabricated, b.inScope, strings.Join(parts, ", ")))
	}
}

// evalClassLines runs the J-perclass computation and appends the
// per-class recall/precision lines.
func (b *evalBuilder) evalClassLines() {
	// J-perclass: per-class recall/precision over the SAME scope and
	// anchor rule. Rendered after the fabrication ledger — but BEFORE the
	// adjudication block — and gated on ≥1 matched case (implied by Score
	// ok) AND ≥1 live finding in scope: a clean or live-less campaign keeps
	// its pre-J bytes.
	b.classRows = evalscore.Classes([]string{b.program}, b.liveByProgram, b.cases)
	if b.inScope > 0 && b.rep.GoldTotal > 0 {
		b.lines = append(b.lines, "- recall/precision by gold class (small cells — "+
			"read the intervals, not the ratios):")
		for _, r := range b.classRows {
			// The header names the metrics, so the rows drop
			// wilson.Format's "recall: "/"precision: " nouns and keep
			// the fractions and intervals.
			b.lines = append(b.lines, "  - "+r.Class+": recall "+
				strings.TrimPrefix(r.RecallLine, "recall: ")+
				", precision "+
				strings.TrimPrefix(r.PrecisionLine, "precision: "))
		}
	}
}

// evalAdjudicationLines loads the non-gold adjudications and appends the
// closing adjudication lines.
func (b *evalBuilder) evalAdjudicationLines() {
	// Non-gold adjudications (evalscore/adjudicate.go, written by
	// `webv2 adjudicate`): the rows that split the raw unanchored count
	// into "real but absent from the gold dataset", "wrong" and
	// "assumption-gated". Appended AFTER the J-perclass block and gated on
	// len(rows) > 0 ALONE — a row can outlive the finding it named, so this
	// gate is independent of the live-finding gate above. With no rows the
	// section renders exactly the bytes it rendered before this task; the
	// counters are the ones evalscore already scored (rep), never a second
	// accounting. ok stays true: a recorded verdict is a claim, and this
	// section reports it.
	adjs, aerr := evalscore.Load(b.c)
	if aerr != nil {
		// Fail-open on advisory data, exactly as evalscore.Score does: an
		// unreadable adjudication key degrades to "no rows".
		adjs = nil
	}
	b.adjs = adjs
	if len(adjs) > 0 {
		adjudicated := b.rep.Additional + b.rep.FalsePositives + b.rep.Gated
		b.lines = append(b.lines, fmt.Sprintf(
			"- non-gold adjudications: %d of %d unanchored findings "+
				"adjudicated (additional-true-positive %d, false-positive %d, "+
				"assumption-gated %d)", adjudicated, b.rep.Unanchored,
			b.rep.Additional, b.rep.FalsePositives, b.rep.Gated))
		b.lines = append(b.lines,
			"- adjusted precision (denominator excludes findings adjudicated "+
				"true or gated): "+b.rep.AdjustedPrecisionLine,
			fmt.Sprintf("- unadjudicated unanchored findings: %d",
				b.rep.Unadjudicated))
		if b.rep.StaleAdjudications > 0 {
			b.lines = append(b.lines, fmt.Sprintf("- stale adjudications (rows "+
				"that apply to no unanchored finding): %d",
				b.rep.StaleAdjudications))
		}
	}
}

// evalBaseKVs builds the section's always-present value keys: the score
// counters, the markdown lines, and the partition problems.
func (b *evalBuilder) evalBaseKVs(dev, heldOut int) []validation.KV {
	problemVals := make([]validation.Value, 0, len(b.problems))
	for _, p := range b.problems {
		problemVals = append(problemVals, validation.VStr(p))
	}
	return []validation.KV{
		KV("matched", validation.VInt(int64(b.rep.GoldTotal))),
		KV("dev", validation.VInt(int64(dev))),
		KV("held_out", validation.VInt(int64(heldOut))),
		KV("hits", validation.VInt(int64(b.rep.Hits))),
		KV("misses", validation.VInt(int64(b.rep.Misses))),
		KV("fp", validation.VInt(int64(b.rep.FP))),
		KV("recall", validation.VStr(b.rep.RecallLine)),
		KV("precision", validation.VStr(b.rep.PrecisionLine)),
		KV("lines", strArrOf(b.lines)),
		KV("problems", validation.VArr(problemVals...)),
	}
}

// evalI3KVs appends the I3/J value keys behind the live-finding presence
// gate: the band rows, the optional unscorable/fabrication counters, and
// the per-class cells.
func (b *evalBuilder) evalI3KVs(kvs []validation.KV) []validation.KV {
	// Presence gate: with no live finding in scope the band block is
	// absent AND none of the new value keys exist (no zero-valued keys —
	// the object is built by appending, not by emitting defaults).
	if b.inScope <= 0 {
		return kvs
	}
	kvs = b.evalBandKVs(kvs)
	kvs = b.evalClassKVs(kvs)
	return kvs
}

// evalBandKVs appends the bands array and the optional unscorable and
// fabrication counters.
func (b *evalBuilder) evalBandKVs(kvs []validation.KV) []validation.KV {
	bandVals := make([]validation.Value, 0, len(b.bandRows))
	for _, r := range b.bandRows {
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
	if b.unscorable > 0 {
		kvs = append(kvs, KV("unscorable", validation.VInt(int64(b.unscorable))))
	}
	if b.fabricated > 0 {
		fabVals := make([]validation.Value, 0, len(b.fabByBand))
		for _, n := range b.fabByBand {
			fabVals = append(fabVals, validation.VInt(int64(n)))
		}
		kvs = append(kvs,
			KV("fabricated", validation.VInt(int64(b.fabricated))),
			KV("fabrication_bands", validation.VArr(fabVals...)))
	}
	return kvs
}

// evalClassKVs appends the J-perclass cells, one object each, in class
// order.
func (b *evalBuilder) evalClassKVs(kvs []validation.KV) []validation.KV {
	// J-perclass: the same cells the block renders, one object each,
	// in class order. Absent — like every I3 key — when the gate is
	// closed: no zero-valued defaults.
	classVals := make([]validation.Value, 0, len(b.classRows))
	for _, r := range b.classRows {
		classVals = append(classVals, validation.VObj(
			KV("class", validation.VStr(r.Class)),
			KV("cases", validation.VInt(int64(r.Cases))),
			KV("hits", validation.VInt(int64(r.Hits))),
			KV("live", validation.VInt(int64(r.Live))),
			KV("anchored", validation.VInt(int64(r.Anchored))),
			KV("recall", validation.VStr(r.RecallLine)),
			KV("precision", validation.VStr(r.PrecisionLine))))
	}
	return append(kvs, KV("classes", validation.VArr(classVals...)))
}

// evalAdjKVs appends the adjudication value keys behind the rows
// presence gate.
func (b *evalBuilder) evalAdjKVs(kvs []validation.KV) []validation.KV {
	// Presence gate: the adjudication keys exist only when rows do — the
	// same append-don't-default rule as the I3/J keys above, so a campaign
	// with no adjudications carries the exact key set it carried before.
	// `assumption` and `exec` are themselves optional within a row (the
	// schema has no empty enum member), and `stale_adjudications` only
	// appears when the count is non-zero.
	if len(b.adjs) <= 0 {
		return kvs
	}
	adjVals := make([]validation.Value, 0, len(b.adjs))
	for _, a := range b.adjs {
		rowKVs := []validation.KV{
			KV("finding", validation.VStr(a.Finding)),
			KV("verdict", validation.VStr(a.Verdict)),
			KV("severity", validation.VStr(a.Severity)),
			KV("basis", validation.VStr(a.Basis)),
		}
		if a.Assumption != "" {
			rowKVs = append(rowKVs,
				KV("assumption", validation.VStr(a.Assumption)))
		}
		if a.Exec != "" {
			rowKVs = append(rowKVs, KV("exec", validation.VStr(a.Exec)))
		}
		rowKVs = append(rowKVs,
			KV("actor", validation.VStr(a.Actor)),
			KV("reason", validation.VStr(a.Reason)))
		adjVals = append(adjVals, validation.VObj(rowKVs...))
	}
	kvs = append(kvs,
		KV("adjudications", validation.VArr(adjVals...)),
		KV("adjusted_precision", validation.VStr(b.rep.AdjustedPrecisionLine)),
		KV("unadjudicated", validation.VInt(int64(b.rep.Unadjudicated))))
	if b.rep.StaleAdjudications > 0 {
		kvs = append(kvs, KV("stale_adjudications",
			validation.VInt(int64(b.rep.StaleAdjudications))))
	}
	return kvs
}
