package cli

// cmd_answered_priority: the Q-* single-priority route and the probe
// anchor/surface checks it enforces (moved verbatim from
// cmd_answered.go).
import (
	"fmt"
	"path/filepath"
	"strings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// answeredPriority is the Q-* route.
func answeredPriority(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	// Round-3 chief item 2: --reconcile is consumed only by the L-04
	// primitive-symmetry lens closure — on a Q-* priority it would exit 0
	// silently ignoring the spec. Refused, naming the route that does
	// consume it.
	if a.reconcile != nil {
		return t14ExitErr(2, "answered: --reconcile reconciles the "+
			"divergence rows of an L-04 primitive-symmetry lens closure — "+
			"%s is a Q-* priority, so there is nothing to reconcile: drop "+
			"--reconcile\n", validation.PyReprStr(a.priority))
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	plan, err := validation.ReadJson(planPath)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	target, ok := t14FindByID(t14List(plan, "priorities"), a.priority)
	if !ok {
		return t14ExitErr(2, "answered failed: no priority %s in the "+
			"campaign plan\n", validation.PyReprStr(a.priority))
	}
	probe := validation.ObjAt(target, "probe")
	if probe.Kind == validation.Obj &&
		t14InList(a.status, planner.ProbeRowDispositioned) {
		if err := checkProbeAnchor(c, a, target, probe); err != nil {
			return err
		}
	}
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	overrideLogged := false
	skipNotice := ""
	updated, err := planner.MarkAnswered(c, plan, a.priority, a.status,
		planner.AnsweredOpts{Reason: a.reason, Ref: a.ref, Actor: actor,
			Anchor: a.anchor, PassesValue: a.passes, Interim: a.interim,
			Finding:           a.finding,
			OverrideDismissal: a.overrideDismissal,
			OverrideReason:    a.overrideReason, OverrideLogged: &overrideLogged,
			SkipNotice: &skipNotice})
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	if skipNotice != "" {
		// FIX-3: a gate that stood down says so — on stderr, so the
		// closure's success line never quietly absorbs it.
		fmt.Fprintln(r.Err, skipNotice)
	}
	if overrideLogged {
		// The override is a decision, not a formality: say so where the
		// operator can see it, and name the record it left behind.
		fmt.Fprintf(r.Out, "  dismissal overridden: %s logged as "+
			"probe.dismissal_overridden (actor %s)\n", a.priority, actor)
	}
	p, _ := t14FindByID(t14List(updated, "priorities"), a.priority)
	ref := ""
	if cr := validation.ObjAt(p, "closed_ref"); t14Truthy(cr) {
		ref = " (ref: " + scalarStr(cr) + ")"
	}
	if anchor := validation.ObjAt(validation.ObjAt(p, "probe"), "anchor"); t14Truthy(anchor) {
		ref += " [anchor " + validation.ObjStr(anchor, "field") + "]"
	}
	fmt.Fprintf(r.Out, "%s: status -> %s%s\n", a.priority, a.status, ref)
	if closing && validation.ObjAt(p, "probe").Kind == validation.Obj {
		lensName := ""
		if spec, ok := planner.PB().Probes[validation.ObjStr(probe, "probe_id")]; ok {
			lensName = spec.Lens
		}
		var lensSet map[string]struct{}
		if lensName != "" {
			lensSet = map[string]struct{}{lensName: {}}
		}
		printProbeClosure(c, updated, lensSet, r.Out)
	}
	return nil
}

// checkProbeAnchor is the A4 operator-facing requirement: a probe closure
// without an anchor is not a disposition, it is a shrug.
func checkProbeAnchor(c *state.Campaign, a *answeredArgs, target,
	probe validation.Value) error {
	row, err := probeSurfaceRow(c, target)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	if row == nil {
		return t14ExitErr(2, "answered: probe row %s is not in the current "+
			"surface — re-run `webv2 probes %s run --emit`\n",
			validation.PyReprStr(validation.ObjStr(probe, "row_id")), c.CampaignID)
	}
	var allowed []string
	if spec, ok := planner.PB().Probes[validation.ObjStr(*row, "probe")]; ok &&
		spec.Anchors != nil {
		allowed = *spec.Anchors
	}
	if a.anchor == nil || *a.anchor == "" {
		return t14ExitErr(2, "answered: %s is probe row %s — a probe "+
			"disposition must name the field it claims is safe: "+
			"--anchor <field> (one of %s)\n", a.priority,
			validation.ObjStr(probe, "row_id"), strings.Join(allowed, ", "))
	}
	if !t14InList(*a.anchor, allowed) {
		return t14ExitErr(2, "answered: --anchor %s is not produced by "+
			"probe %s; allowed: %s\n", validation.PyReprStr(*a.anchor),
			validation.PyReprStr(validation.ObjStr(*row, "probe")),
			strings.Join(allowed, ", "))
	}
	return nil
}

// probeSurfaceRow is cli.py's _probe_surface_row: the surface row a probe
// priority points at, or nil when the campaign has no surface / the row is
// absent. The probes module is unported (P3), so CampaignSurface is the
// "feature absent" reader and this is nil in practice.
func probeSurfaceRow(c *state.Campaign,
	target validation.Value) (*validation.Value, error) {
	surface, err := planner.PB().CampaignSurface(c)
	if err != nil || surface == nil {
		return nil, err
	}
	rid := validation.ObjStr(validation.ObjAt(target, "probe"), "row_id")
	for _, row := range t14List(*surface, "rows").A {
		if validation.ObjStr(row, "row_id") == rid {
			row := row
			return &row, nil
		}
	}
	return nil, nil
}
