// Package backtest implements the G3 `corpus-surface --backtest`
// scorecard: the ONLY place the framework may say a ranking "improved".
//
// Method: over the eval store's adjudicated rows ONLY, partition
// held-out for the scorecard and dev for the per-class table. Build ONE
// pseudo-finding per held-out case (class + severity band, no evidence,
// no critic — the backtest measures the RANKING SIGNALS THE STORE
// ACTUALLY CARRIES), rank it twice — (A) severity-only baseline,
// AcceptanceWithPriors with nil priors, and (B) AcceptanceWithPriors
// with the dev-only priors — and report top-K precision against the
// adjudicated outcomes with Wilson intervals.
//
// The priors come from the dev partition ONLY (leave-one-out for
// held-out cases; no self-confirmation): a held-out row can never vote
// for its own rank. Pseudo-findings carry class+band ONLY — this
// certifies the SIGNAL, not a full pipeline.
//
// Verdict rule (the two-experiments-same-data law from G3): improve
// only if B.lo > A.lo (Wilson lower bounds, strict); regress only if
// A.lo > B.lo; else "indistinguishable". Two rankings over the SAME
// held-out cases are the same experiment until their intervals stop
// overlapping, so the default verdict is indistinguishable and the
// backtest can never flatter a prior that merely reshuffles ties.
//
// Pure and deterministic: input is an explicit case slice (the caller
// passes evalstore.LoadCases()), ranking breaks every tie by case_id,
// and there is no clock and no I/O.
package backtest

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/risk"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// EmptyMessage is the fail-open refusal: with no adjudicated rows the
// backtest certifies nothing without ground truth, so it exits 2
// instead of printing a verdict over an empty scorecard.
const EmptyMessage = "eval store: no adjudicated rows — " +
	"the backtest certifies nothing without ground truth\n"

// HeaderLine is the output's first line: what the priors may see and
// what the pseudo-findings carry, stated on every run so a quoted
// verdict can never outlive its method.
const HeaderLine = "backtest: priors from dev partition only " +
	"(leave-one-out for held-out cases; no self-confirmation); " +
	"pseudo-findings carry class+band ONLY — this certifies the " +
	"SIGNAL, not a full pipeline."

// BandLine is the output's second line: the schema honesty label. The
// evaluation_case gold.severity enum carries NO critical slot
// (high|medium|low|informational|none|null), so a critical ground-truth
// value can only arrive outside the validated path (loaders fold
// critical->high before the store — see G3 and the immunefi loader — and
// AddCase itself rejects it at validation). The backtest refuses to
// invent a critical weight for such a row: it scores 0 from severity,
// exactly like a null-severity row, and says so here plus in the
// per-run band-coverage count below — never silently.
const BandLine = "bands: critical is unrepresentable in gold.severity " +
	"(schema) — critical-band rows score 0 here; " +
	"loaders must fold (see G3)"

// severityBands is the contributing band set: gold severities that carry
// weight through AcceptanceWithPriors (high 2.0 / medium 1.0 / low 0.5 —
// all nonzero, so membership here IS contribution). Everything else
// (critical — unrepresentable in the schema — plus informational, none,
// null) contributes nothing: Acceptance's own posture for an
// unrecognized band is 0, so the copy below is the mapping, not a
// reinterpretation.
var severityBands = map[string]bool{
	"high": true, "medium": true, "low": true,
}

// Run scores the held-out partition twice and renders the scorecard.
// top is the caller's --top AFTER validation (top >= 1; the CLI rejects
// --top 0 or negative as an argparse usage error before calling here).
// top larger than the held-out count clamps to the count with a note
// line. The returned code is 0, or 2 with EmptyMessage when no
// adjudicated held-out row exists to score.
//
// Verdict rule (the two-experiments-same-data law from G3): improve
// only if B.lo > A.lo (Wilson lower bounds, strict); regress only if
// A.lo > B.lo; else "indistinguishable".
func Run(cases []validation.Value, top int) (string, int) {
	adjudicated, skipped := 0, 0
	var dev, held []validation.Value
	for _, c := range cases {
		if !risk.IsAdjudicated(orStr(objAt(objAt(c, "gold"), "outcome"))) {
			skipped++
			continue
		}
		adjudicated++
		switch orStr(objAt(c, "partition")) {
		case "held-out":
			held = append(held, c)
		case "dev", "":
			dev = append(dev, c)
		}
	}
	if len(held) == 0 {
		return EmptyMessage, 2
	}
	devPriors, devGlobal := risk.AcceptancePriorsFrom(dev, risk.DefaultMinN)

	var b strings.Builder
	b.WriteString(HeaderLine + "\n")
	b.WriteString(BandLine + "\n")
	fmt.Fprintf(&b, "eval store: %d adjudicated, %d skipped\n",
		adjudicated, skipped)
	fmt.Fprintf(&b, "band coverage: %d/%d rows contributed\n",
		bandContrib(held), len(held))
	k := top
	if k > len(held) {
		fmt.Fprintf(&b, "note: --top %d clamped to %d held-out cases\n",
			top, len(held))
		k = len(held)
	}
	accepted := 0
	for _, c := range held {
		if orStr(objAt(objAt(c, "gold"), "outcome")) ==
			"confirmed-exploitable" {
			accepted++
		}
	}
	hitsA := rankHits(held, nil, risk.Prior{}, k)
	hitsB := rankHits(held, devPriors, devGlobal, k)
	loA, _ := wilson.Interval(hitsA, k)
	loB, _ := wilson.Interval(hitsB, k)
	// Verdict rule (the two-experiments-same-data law from G3):
	// improve only if B.lo > A.lo (Wilson lower bounds, strict);
	// regress only if A.lo > B.lo; else "indistinguishable".
	verdict := "indistinguishable"
	switch {
	case loB > loA:
		verdict = "improves"
	case loA > loB:
		verdict = "regresses"
	}
	fmt.Fprintf(&b, "method A (severity-only):\n%s\nselected accepted: %d\n"+
		"accepted available: %d\n",
		wilson.Format(hitsA, k, fmt.Sprintf("top-%d precision", k)),
		hitsA, accepted)
	fmt.Fprintf(&b, "method B (with dev priors):\n%s\nselected accepted: %d\n"+
		"accepted available: %d\n",
		wilson.Format(hitsB, k, fmt.Sprintf("top-%d precision", k)),
		hitsB, accepted)
	fmt.Fprintf(&b, "verdict: %s\n", verdict)
	return b.String(), 0
}

// bandContrib counts the held-out rows whose gold severity maps to a
// contributing band (severityBands membership == nonzero severity weight,
// per the table in the severityBands comment). Rows outside the set —
// critical, informational, none, null, absent — score 0 from severity;
// the count keeps that visible instead of silent.
func bandContrib(held []validation.Value) int {
	n := 0
	for _, c := range held {
		if severityBands[orStr(objAt(objAt(c, "gold"), "severity"))] {
			n++
		}
	}
	return n
}

// rankHits ranks one pseudo-finding per held-out case by score desc,
// case_id asc (a stable total order — case ids are unique per store)
// and returns the accepted rows inside the top K.
func rankHits(held []validation.Value, priors map[string]risk.Prior,
	global risk.Prior, k int) int {
	type scored struct {
		id       string
		score    float64
		accepted bool
	}
	rows := make([]scored, 0, len(held))
	for _, c := range held {
		gold := objAt(c, "gold")
		entry := risk.AcceptanceWithPriors(
			pseudoFinding(orStr(objAt(gold, "bug_class")),
				orStr(objAt(gold, "severity"))),
			priors, global)
		rows = append(rows, scored{
			id:    orStr(objAt(c, "case_id")),
			score: entry.Score,
			accepted: orStr(objAt(gold, "outcome")) ==
				"confirmed-exploitable",
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].id < rows[j].id
	})
	hits := 0
	for i := 0; i < k && i < len(rows); i++ {
		if rows[i].accepted {
			hits++
		}
	}
	return hits
}

// pseudoFinding builds the backtest's unit of ranking: class + band
// ONLY. No evidence level, no critic verdict, no corroboration —
// anything more would certify a pipeline the store never ran. A
// severity outside severityBands (critical included — the schema has no
// critical slot) yields a bandless finding: 0 from severity, stated in
// BandLine and the coverage count rather than papered over.
func pseudoFinding(class, severity string) validation.Value {
	riskObj := validation.VObj()
	if severityBands[severity] {
		riskObj = validation.VObj(validation.KV{K: "validated",
			V: validation.VObj(validation.KV{K: "band",
				V: validation.VStr(severity)})})
	}
	return validation.VObj(
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr(class)})},
		validation.KV{K: "risk", V: riskObj},
	)
}

// ---- local Value access (this leaf's own copy; risk's is private) ----

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func orStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return ""
}
