// regressionsuite_handoff.go is the P1 handoff's reader: the two honest forms
// the section accepts, and the LEDGER behind the named decision.
//
// The handoff carries a decision now (priceable false + ceiling + reason +
// recorded_by), and a decision is a claim about the log. risk.RecordUnpriceable
// writes the same shape on a finding's economic_impact, and section 14
// reconciles that one in BOTH directions (internal/audit/sections/
// unpriceable.go): a decision the log never recorded, whose leaves the log
// disagrees with, or which the log still holds after it was erased from the
// record, is a hand edit. This is the same discipline on the control target's
// handoff, which had no ledger reconciliation at all.
//
// The projection is also checked against the SCHEMA here, the way section 4
// checks every finding file and section 5 every exec record. The target
// records had no such reader, so a hand-edited handoff — a missing reason, a
// blank ceiling, a figure the decision's own `false` subschema refuses — was
// invisible to the audit even though the shipped validator refused it.
package sections

import (
	"errors"
	"fmt"
	"strconv"

	"websec/internal/state"
	"websec/internal/validation"
)

// handoffEvent is the one ledger event RecordHandoff writes for a target's
// handoff (internal/regression/control.go), keyed by the target id in "ref".
const handoffEvent = "regression.control.handoff"

// handoffLedger indexes the log's handoff events by target id, keeping the
// LAST event for each target — the same "last word wins" rule section 14
// applies to a finding's impact decisions.
func handoffLedger(c *state.Campaign) (map[string]validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	out := map[string]validation.Value{}
	for _, e := range events {
		if validation.ObjStr(e, "type") != handoffEvent {
			continue
		}
		if tid := validation.ObjStr(e, "ref"); tid != "" {
			out[tid] = e
		}
	}
	return out, nil
}

// targetSchemaProblems reports a target record the schema refuses. It is a
// problem in its own right, exactly as section 4's findings check is: the
// write path validates before it writes, so a record the schema refuses can
// only have arrived by hand.
func targetSchemaProblems(t validation.Value) ([]validation.Value, error) {
	if err := validation.Validate(t, "regression_target", 1); err != nil {
		var se *validation.SchemaError
		if errors.As(err, &se) {
			return []validation.Value{validation.VStr(fmt.Sprintf(
				"target %s: %s", validation.ObjStr(t, "target_id"), se.Msg))}, nil
		}
		return nil, err
	}
	return nil, nil
}

// handoffSatisfiesP1 is the P1 handoff check, stated as the two honest forms
// it accepts: a positive extractable_usd, or the unpriceable decision — an
// explicit priceable false carrying the ceiling basis it was made against, a
// written reason, and NOT the figure the decision exists to refuse.
//
// The schema says the same thing, and re-reading it here is not redundant:
// this section's job is the hand-edited record, and the two checks fail
// independently — the schema refuses the BYTES, this refuses to call a
// contradictory record a handoff.
func handoffSatisfiesP1(t validation.Value) bool {
	ho := validation.ObjAt(t, "handoff")
	if ho.Kind != validation.Obj {
		return false
	}
	if p := validation.ObjAt(ho, "priceable"); p.Kind == validation.Bool && !p.B {
		return decisionLeaves(ho)
	}
	usd := validation.ObjAt(ho, "extractable_usd")
	return isNumKind(usd) && ratOf(usd).Sign() > 0
}

// decisionLeaves reports whether an unpriceable handoff carries the decision
// rather than a bare flag: a non-blank ceiling and reason, and no figure
// alongside — "a bare flag is not a decision" (internal/findings/levels.go).
// The attribution is the schema's and the ledger's business (see
// handoffLedgerProblems), not this form check's.
func decisionLeaves(ho validation.Value) bool {
	if validation.HasKey(ho, "extractable_usd") {
		return false
	}
	for _, k := range []string{"ceiling", "reason"} {
		if validation.PyStrip(validation.ObjStr(ho, k)) == "" {
			return false
		}
	}
	return true
}

// handoffUSDText renders the handoff's extractable figure as text, empty when
// there is no handoff, when the handoff records the unpriceable decision, or
// when the value is not a number — the same "absence is not a zero" rule the
// rest of this section follows. An unpriceable handoff is not a missing figure
// to be filled in later; it is the recorded answer that no figure is
// defensible, and it SUPERSEDES any figure a hand edit left beside it
// (risk.RecordUnpriceable pops the figure for the same reason), so printing
// one here would invent the measurement the record refuses.
//
// The figure is read Int/Flt-aware: an integer 900000 is a schema-VALID
// figure, and reading .F alone turned it into a fabricated 0 — which the
// section then reported as "carries no P1 handoff".
func handoffUSDText(t validation.Value) string {
	ho := validation.ObjAt(t, "handoff")
	if p := validation.ObjAt(ho, "priceable"); p.Kind == validation.Bool && !p.B {
		return ""
	}
	usd := validation.ObjAt(ho, "extractable_usd")
	if !isNumKind(usd) {
		return ""
	}
	return numText(usd)
}

// numText renders a JSON number as text: an Int keeps its exact decimal text,
// a Flt its shortest round-trip form (the shape this cell has always printed).
func numText(v validation.Value) string {
	if v.Kind == validation.Int {
		return validation.IntText(v)
	}
	return strconv.FormatFloat(v.F, 'f', -1, 64)
}

// handoffDriftPairs is the decision's reconciled leaves: the record's key, the
// event's key (RecordUnpriceable's own name for the actor), and the word the
// problem uses for it.
var handoffDriftPairs = []struct{ proj, logged, what string }{
	{"ceiling", "ceiling", "ceiling"},
	{"reason", "reason", "reason"},
	{"recorded_by", "actor", "actor"},
}

// handoffLedgerProblems cross-checks one target's handoff against the log's
// last handoff event for it, in BOTH directions, the way section 14 checks a
// finding's economic_impact:
//
//   - the record carries a decision the log contradicts (no event at all, a
//     priced last event, or a ceiling/reason/actor the log disagrees with);
//   - the record no longer carries a decision the log's last word still holds,
//     because the decision was erased by hand-edit.
//
// The event is matched on the target id, not on the finding: the handoff IS
// the target's, and a hand edit that repoints the finding is a different
// problem (the schema's finding_id pattern, and the CONFIRMED gate on write).
func handoffLedgerProblems(t validation.Value, ledger map[string]validation.Value) []validation.Value {
	tid := validation.ObjStr(t, "target_id")
	last, logged := ledger[tid]
	if !decisionFromProjection(t) {
		return erasedDecisionProblem(tid, last, logged)
	}
	return decisionDriftProblems(t, tid, last, logged)
}

// decisionFromProjection reports whether the record's handoff carries the
// unpriceable decision. priceable ABSENT means priceable, so only an explicit
// false counts — internal/findings.UnpriceableDecision's own rule.
func decisionFromProjection(t validation.Value) bool {
	p := validation.ObjAt(validation.ObjAt(t, "handoff"), "priceable")
	return p.Kind == validation.Bool && !p.B
}

// isDecisionEvent reports whether a logged handoff event recorded the
// unpriceable decision rather than a figure.
func isDecisionEvent(e validation.Value) bool {
	p := validation.ObjAt(validation.ObjAt(e, "data"), "priceable")
	return p.Kind == validation.Bool && !p.B
}

// erasedDecisionProblem is the mirror direction: the log's last word for this
// target is a recorded unpriceable, and the record does not carry it. A target
// with no record at all is not this check's business (there is nothing to
// reconcile), the same call section 14 makes for a missing finding file.
func erasedDecisionProblem(tid string, last validation.Value, logged bool) []validation.Value {
	if !logged || !isDecisionEvent(last) {
		return nil
	}
	return []validation.Value{validation.VStr(fmt.Sprintf(
		"target %s: the log's last handoff is a recorded unpriceable, but the "+
			"record does not carry it (priceable false absent?) — the decision "+
			"was erased by hand-edit", tid))}
}

// decisionDriftProblems is the record-carries-a-decision direction: the log
// must hold the same decision, leaf for leaf, and the same attribution.
func decisionDriftProblems(t validation.Value, tid string, last validation.Value,
	logged bool) []validation.Value {
	if !logged {
		return []validation.Value{validation.VStr(fmt.Sprintf(
			"target %s records an unpriceable P1 handoff with no %s event — "+
				"the decision was hand-edited", tid, handoffEvent))}
	}
	if !isDecisionEvent(last) {
		return []validation.Value{validation.VStr(fmt.Sprintf(
			"target %s records an unpriceable P1 handoff but the log's latest "+
				"handoff is a priced one — projection drifted from the log", tid))}
	}
	ho, data := validation.ObjAt(t, "handoff"), validation.ObjAt(last, "data")
	var problems []validation.Value
	for _, f := range handoffDriftPairs {
		got, want := validation.ObjAt(ho, f.proj), validation.ObjAt(data, f.logged)
		if !pyEqual(got, want) {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"target %s records %s %s but the log's last %s event cites %s — "+
					"projection drifted from the log", tid, f.what,
				validation.PyRepr(got), handoffEvent, validation.PyRepr(want))))
		}
	}
	return problems
}
