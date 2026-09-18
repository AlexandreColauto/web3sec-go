package planner

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// AnsweredRow is one row of a batch closure: the priority to move, the
// status to move it to (an id+status tuple), and that row's option tail
// (reason/ref/anchor/actor/override). The CLI passes one shared status for
// every row — a mixed-status batch is not supported — and one shared reason
// that rides the rows carrying none of their own.
type AnsweredRow struct {
	PriorityID string
	Outcome    string
	Opts       AnsweredOpts
}

// MarkAnsweredBatch closes (or re-opens) several plan priorities behind the
// SAME gates as MarkAnswered, all-or-nothing: every row's gates run through
// the shared runAnsweredGates runner on a pre-flight pass that performs zero
// mutations, the first failure naming its row ("answered: row 2 (Q-005): <gate message>"); the mutations
// (plan writes + one plan.priority_status event per row, in the exact
// single-mark shape) apply only when zero rows fail.
//
// The shared reason rides every row that carries none of its own; a row's
// own reason wins. Whether a closing status REQUIRES a reason is enforced
// by the CLI, exactly as for the single-priority call.
func MarkAnsweredBatch(campaign *state.Campaign, plan validation.Value,
	rows []AnsweredRow, reason string) (validation.Value, error) {
	if len(rows) == 0 {
		return validation.VNull(),
			errValue("answered: batch needs at least one priority")
	}
	eff := make([]AnsweredRow, len(rows))
	for i, r := range rows {
		eff[i] = r
		if eff[i].Opts.Reason == nil && reason != "" {
			rs := reason
			eff[i].Opts.Reason = &rs
		}
	}
	for i, r := range eff {
		if err := preflightAnswered(campaign, plan, r); err != nil {
			return validation.VNull(), batchRowErr(i, r.PriorityID, err)
		}
	}
	out := plan
	for i, r := range eff {
		var err error
		out, err = MarkAnswered(campaign, out, r.PriorityID, r.Outcome,
			r.Opts)
		if err != nil {
			return validation.VNull(), batchRowErr(i, r.PriorityID, err)
		}
	}
	return out, nil
}

// preflightAnswered runs one row's gates with zero mutations by delegating
// to the shared runner (dry dismissal gate: an override is validated but not
// recorded). There is no gate logic here by design — see runAnsweredGates.
func preflightAnswered(campaign *state.Campaign, plan validation.Value,
	r AnsweredRow) error {
	_, err := runAnsweredGates(campaign, plan, r.PriorityID, r.Outcome,
		r.Opts, true)
	return err
}

// findPriority is MarkAnswered's priority lookup: the index of the priority
// with the given id, or the same "no priority" error the single call
// reports.
func findPriority(plan validation.Value,
	priorityID string) (int, error) {
	idx := priorityIndex(plan, priorityID)
	if idx < 0 {
		return -1, errKey("no priority " +
			validation.PyReprStr(priorityID) + " in the campaign plan")
	}
	return idx, nil
}

// priorityIndex is the linear scan for a priority id (-1 when absent).
func priorityIndex(plan validation.Value, priorityID string) int {
	for i, p := range listOf(plan, "priorities") {
		if validation.ObjStr(p, "id") == priorityID {
			return i
		}
	}
	return -1
}

// batchRowErr names the first bad row: 1-based position plus priority id.
func batchRowErr(i int, pid string, err error) error {
	return fmt.Errorf("answered: row %d (%s): %s", i+1, pid, err)
}
