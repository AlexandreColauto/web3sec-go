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
package sections

import (
	"errors"
	"fmt"
	"strings"

	"websec/assets"
	"websec/internal/evalscore"
	"websec/internal/evalstore"
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
	return validation.VObj(
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
		KV("ok", validation.VBool(true)),
	), nil
}
