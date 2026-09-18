package cli

// cmd_answered_batch: the Q-* batch route — one status for every row,
// --reason-all required, gates before mutations (moved verbatim from
// cmd_answered.go).
import (
	"fmt"
	"path/filepath"
	"strings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// answeredBatch is the Q-* batch route: one status applies to every row (a
// mixed-status batch is not supported), --reason-all rides every row, and
// every row's gates run before any mutation lands — the first failure names
// its row and nothing is written. Lenses close one at a time, never here.
func answeredBatch(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	// Round-3 chief item 2: the batch is a Q-* route — --reconcile has no
	// row to reconcile here and would be silently ignored.
	if a.reconcile != nil {
		return t14ExitErr(2, "answered: --reconcile reconciles the "+
			"divergence rows of an L-04 primitive-symmetry lens closure — "+
			"%s is a Q-* priority, so there is nothing to reconcile: drop "+
			"--reconcile\n", validation.PyReprStr(a.priorities[0]))
	}
	for _, pid := range a.priorities {
		if strings.HasPrefix(pid, "L-") {
			return t14ExitErr(2, "answered: batch close supports Q-* "+
				"priorities only — close lenses one at a time (got %s)\n",
				pid)
		}
	}
	var reason *string
	switch {
	case a.reasonAll != nil:
		reason = a.reasonAll
	case a.reason != nil:
		if len(a.priorities) > 1 {
			return t14ExitErr(2, "answered: closing %d priorities "+
				"needs --reason-all (why) — --reason names a single "+
				"closure, --reason-all rides every row.\n",
				len(a.priorities))
		}
		reason = a.reason
	}
	if closing && (reason == nil || strings.TrimSpace(*reason) == "") {
		return t14ExitErr(2, "answered: %s requires --reason-all (why). "+
			"Pass --ref too when the answer rests on evidence "+
			"(finding/exec/artifact/file#L).\n", validation.PyReprStr(a.status))
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	reasonStr := ""
	if reason != nil {
		reasonStr = *reason
	}
	rows := make([]planner.AnsweredRow, len(a.priorities))
	logged := make([]bool, len(a.priorities))
	notices := make([]string, len(a.priorities))
	for i, pid := range a.priorities {
		rows[i] = planner.AnsweredRow{PriorityID: pid, Outcome: a.status,
			Opts: planner.AnsweredOpts{Ref: a.ref, Actor: actor,
				Anchor: a.anchor, PassesValue: a.passes, Interim: a.interim,
				Finding:           a.finding,
				OverrideDismissal: a.overrideDismissal,
				OverrideReason:    a.overrideReason,
				OverrideLogged:    &logged[i], SkipNotice: &notices[i]}}
	}
	updated, err := planner.MarkAnsweredBatch(c, plan, rows, reasonStr)
	if err != nil {
		// The batch error already names the row
		// ("answered: row 2 (Q-005): ..."), so it prints as-is.
		return t14ExitErr(2, "%s\n", err)
	}
	for i, pid := range a.priorities {
		if notices[i] != "" {
			// FIX-3: a gate that stood down says so — on stderr, so the
			// closure's success line never quietly absorbs it.
			fmt.Fprintln(r.Err, notices[i])
		}
		if logged[i] {
			fmt.Fprintf(r.Out, "  dismissal overridden: %s logged as "+
				"probe.dismissal_overridden (actor %s)\n", pid, actor)
		}
		p, _ := t14FindByID(t14List(updated, "priorities"), pid)
		ref := ""
		if cr := validation.ObjAt(p, "closed_ref"); t14Truthy(cr) {
			ref = " (ref: " + scalarStr(cr) + ")"
		}
		if anchor := validation.ObjAt(validation.ObjAt(p, "probe"), "anchor"); t14Truthy(anchor) {
			ref += " [anchor " + validation.ObjStr(anchor, "field") + "]"
		}
		fmt.Fprintf(r.Out, "%s: status -> %s%s\n", pid, a.status, ref)
	}
	return nil
}
