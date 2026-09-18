package cli

// cmd_answered_batch: the Q-* batch route — one status for every row,
// --reason-all required, gates before mutations (moved verbatim from
// cmd_answered.go), plus the B10(b) probe-row batch that names SURFACE ROWS
// instead of priorities.
import (
	"fmt"
	"path/filepath"
	"strings"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// answeredRows is the B10(b) probe-row batch route:
//
//	answered <C> --rows ROWID,ROWID <status> --reason-all R --anchor A
//
// The operator drains the worklist `probes <C> pending` printed by naming the
// rows, not the Q-* ids the emit minted: the row id is what the surface, the
// audit and the pending view all speak, and the row→priority join is the
// same one the pending view used (probes.RowDispositions, the seam that
// decides what "dispositioned" means). Everything after the resolution is the
// Q-* batch discipline verbatim — one status for every row, --reason-all
// riding each row, every row's gates run before any mutation lands — so a
// probe-row batch cannot grow a private closure path.
//
// The one rule the Q-* route does not have is the bootstrap's anti-dismissal
// rule for the BULK route: --reason-all is legal only when EVERY named row is
// tier>0 AND assertion_gap<3. A tier-0 or gap>=3 row is discharged
// one-per-call, with its own --anchor and a reason that cites its own code —
// which is exactly the route `probes <C> pending` prints per row. The check
// runs before any gate or write, so a refused batch leaves the plan and the
// ledger untouched.
func answeredRows(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	surface, err := probes.CampaignSurface(c)
	if err != nil {
		return err
	}
	if surface == nil {
		return t14ExitErr(2, "answered: no probe surface for %s — run "+
			"`webv2 probes %s run --emit` first\n", c.CampaignID, c.CampaignID)
	}
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	disp := probes.RowDispositions(&plan, *surface)
	prios := make([]string, 0, len(a.rows))
	for i, rid := range a.rows {
		if _, ok := answeredSurfaceRow(*surface, rid); !ok {
			return t14ExitErr(2, "answered: row %d (%s): not in the "+
				"current surface — run `webv2 probes %s run --emit`\n",
				i+1, rid, c.CampaignID)
		}
		pid := validation.ObjStr(validation.ObjAt(disp, rid), "priority_id")
		if pid == "" {
			return t14ExitErr(2, "answered: row %d (%s): the plan does "+
				"not carry this row — run `webv2 probes %s run --emit`\n",
				i+1, rid, c.CampaignID)
		}
		prios = append(prios, pid)
	}
	if a.reasonAll != nil {
		if err := answeredRowsAntiDismissal(c, *surface, a, prios); err != nil {
			return err
		}
	}
	// From here the route IS the Q-* batch: hand the resolved priorities to
	// the same body, with --rows cleared so nothing re-enters this path.
	sub := *a
	sub.priorities = prios
	sub.priority = prios[0]
	sub.rows = nil
	sub.rowsRaw = nil
	return answeredBatch(c, &sub, closing, r)
}

// answeredSurfaceRow is the surface row a row id names, or false when the
// current surface no longer carries it (a re-run of `probes run` that dropped
// the row is a refusal, never a silent no-op).
func answeredSurfaceRow(surface validation.Value,
	rid string) (validation.Value, bool) {
	for _, row := range t14List(surface, "rows").A {
		if validation.ObjStr(row, "row_id") == rid {
			return row, true
		}
	}
	return validation.VNull(), false
}

// answeredRowsAntiDismissal is the bulk route's anti-dismissal rule: every
// named row must be tier>0 AND assertion_gap<3, or the whole batch is refused
// with one line per offending row (the row, its resolved priority, its tier
// and its gap) and nothing is written. The one-per-call heal is named, because
// the operator who read `probes pending` already has it.
func answeredRowsAntiDismissal(c *state.Campaign, surface validation.Value,
	a *answeredArgs, prios []string) error {
	type offender struct {
		rid, pid string
		tier     int64
		gap      int64
	}
	bad := []offender{}
	for i, rid := range a.rows {
		row, _ := answeredSurfaceRow(surface, rid)
		tier, gap := objInt(row, "tier"), objInt(row, "assertion_gap")
		if tier > 0 && gap < 3 {
			continue
		}
		bad = append(bad, offender{rid: rid, pid: prios[i], tier: tier,
			gap: gap})
	}
	if len(bad) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "answered: --reason-all is refused for %d of %d rows "+
		"— the bulk route is legal only when EVERY named row is tier>0 and "+
		"assertion_gap<3 (a tier-0 or gap>=3 row is discharged one-per-call, "+
		"with a reason that cites its own code):\n", len(bad), len(a.rows))
	for _, o := range bad {
		fmt.Fprintf(&b, "  %s (%s): tier %d, gap %d\n", o.rid, o.pid, o.tier,
			o.gap)
	}
	fmt.Fprintf(&b, "`webv2 probes %s pending` prints the exact per-row "+
		"command.\n", c.CampaignID)
	return t14ExitErr(2, "%s", b.String())
}

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
