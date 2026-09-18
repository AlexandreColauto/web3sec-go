package cli

// cmd_answered_lens: the L-* lens route — family/symmetry
// attestations, the FIX-6 divergence reconciliation and the symmetry
// spec parser (moved verbatim from cmd_answered.go).
import (
	"fmt"
	"strings"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// answeredLens is the L-* route: the plan's lens entries, same verb, same
// reason enforcement, plus the family/symmetry attestations.
func answeredLens(c *state.Campaign, a *answeredArgs, closing bool,
	r *Runner) error {
	// Round-3 chief item 1: the probe-row flags are inert on a lens route —
	// a lens entry has no probe row to disposition, no guard to satisfy and
	// no interim window to price, so any of them here would be silently
	// dropped while the help text claims validation on every closure.
	// Refused before the recon gate, the way the reconcile shape refusals
	// are.
	for _, f := range []struct {
		flag, what, why string
		val             *string
	}{
		{"--finding", "records the interim window of a Q-* probe row on " +
			"a filed finding", "there is no probe row to price", a.finding},
		{"--interim", "prices a Q-* probe row's interim window with a " +
			"statement", "there is no probe row to price", a.interim},
		{"--passes", "records the passing value of a sentinel-guarded " +
			"Q-* probe row", "there is no guard to satisfy", a.passes},
		{"--anchor", "dispositions a Q-* probe row by naming the field " +
			"it claims is safe", "there is no probe row to disposition",
			a.anchor},
	} {
		if f.val != nil {
			return t14ExitErr(2, "answered: %s %s — %s is an L-* lens "+
				"route, so %s: drop %s\n", f.flag, f.what,
				validation.PyReprStr(a.priority), f.why, f.flag)
		}
	}
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	target, ok := t14FindByID(t14List(plan, "lenses"), a.priority)
	if !ok {
		return t14ExitErr(2, "answered: unknown lens %s\n", a.priority)
	}
	fams := splitFamilies(a.families)
	seeded := t14Strings(t14List(target, "families"))
	if closing {
		if err := checkLensFamilies(a, fams, seeded); err != nil {
			return err
		}
	}
	sym, err := lensSymmetry(a, target, seeded, closing)
	if err != nil {
		return err
	}
	// FIX-6: the divergence reconciliation rides the attestation. A malformed
	// spec is refused here — the gate inside mark_lens would otherwise
	// diagnose it per-row, and the shape error is the one the operator can
	// fix without reading the surface. The flag only means something to the
	// lens that owns the divergence rows: anything else is refused, not
	// silently recorded on an entry that reconciles nothing.
	var recs *[]validation.Value
	if a.reconcile != nil {
		if validation.ObjStr(target, "lens") != "primitive-symmetry" {
			return t14ExitErr(2, "answered: --reconcile reconciles the "+
				"divergence rows of a primitive-symmetry lens — %s is not "+
				"one, so there is nothing to reconcile: drop --reconcile\n",
				validation.PyReprStr(a.priority))
		}
		// Round-3 chief item 2: the reconciliation is part of the closing
		// attestation — markLensEntry consumes the spec only on a closing
		// status, so a non-closing one would ignore it (and drop the stored
		// reconciliation outright). Refused, naming the L-04 closing route.
		if !closing {
			return t14ExitErr(2, "answered: --reconcile is consumed only "+
				"by an L-04 primitive-symmetry lens closure — %s with "+
				"status %s is not a closure, so there is nothing to "+
				"reconcile: drop --reconcile\n",
				validation.PyReprStr(a.priority),
				validation.PyReprStr(a.status))
		}
		parsed, err := planner.ParseReconcile(a.reconcile)
		if err != nil {
			return t14ExitErr(2, "answered: %s\n", err)
		}
		recs = &parsed
	}
	actor := a.actor
	if actor == "" {
		actor = "cli"
	}
	updated, err := planner.MarkLens(c, plan, a.priority, a.status,
		planner.LensOpts{Reason: a.reason, Ref: a.ref, Actor: actor,
			FamiliesChecked: famPtr(fams, a.families), Symmetry: sym,
			Reconcile: recs})
	if err != nil {
		return t14ExitErr(2, "answered failed: %s\n", err)
	}
	printAnsweredLens(c, a, updated, closing, r)
	return nil
}

// splitFamilies is the Python list comprehension over --families.
func splitFamilies(families *string) []string {
	if families == nil {
		return nil
	}
	var out []string
	for _, f := range strings.Split(*families, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// checkLensFamilies enforces the attestation: every seeded family must be
// named, unless the lens is degenerate and the operator attests none apply.
func checkLensFamilies(a *answeredArgs, fams, seeded []string) error {
	checked := map[string]struct{}{}
	for _, f := range fams {
		checked[f] = struct{}{}
	}
	var missing []string
	for _, f := range seeded {
		if _, ok := checked[f]; !ok {
			missing = append(missing, f)
		}
	}
	degenerate := len(seeded) == 0 || (len(seeded) == 1 && seeded[0] == "protocol")
	_, noneApplicable := checked["none-applicable"]
	if len(missing) > 0 && !(degenerate && noneApplicable) {
		return t14ExitErr(2, "answered: %s has unattested families "+
			"(missing: %s). Pass --families %s (or attest none apply) "+
			"with --reason (why).\n", a.priority,
			strings.Join(missing, ", "), strings.Join(missing, ","))
	}
	return nil
}

// lensSymmetry parses and validates --symmetry for a primitive-symmetry lens.
func lensSymmetry(a *answeredArgs, target validation.Value, seeded []string,
	closing bool) (*[]validation.Value, error) {
	if validation.ObjStr(target, "lens") != "primitive-symmetry" || !closing ||
		len(seeded) == 0 || (len(seeded) == 1 && seeded[0] == "protocol") {
		return nil, nil
	}
	parsed := parseSymmetry(a.symmetry)
	have := map[string]int{}
	for _, s := range parsed {
		n := 0
		for _, p := range t14List(s, "primitives").A {
			if strings.TrimSpace(scalarStr(p)) != "" {
				n++
			}
		}
		have[validation.ObjStr(s, "family")] = n
	}
	var missing []string
	for _, f := range seeded {
		if have[f] == 0 {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		parts := make([]string, 0, len(missing))
		for _, f := range missing {
			parts = append(parts, f+"=burn")
		}
		return nil, t14ExitErr(2, "answered: %s has unattested symmetry "+
			"primitives (missing: %s). Pass --symmetry '%s' "+
			"(family=primitive[|primitive];...) with --reason (why).\n",
			a.priority, strings.Join(missing, ", "), strings.Join(parts, ";"))
	}
	return &parsed, nil
}

// printAnsweredLens reports the closure and, for a closing lens, the probe
// surface rows it dispositioned.
func printAnsweredLens(c *state.Campaign, a *answeredArgs,
	updated validation.Value, closing bool, r *Runner) {
	lens, _ := t14FindByID(t14List(updated, "lenses"), a.priority)
	ref := ""
	if cr := validation.ObjAt(lens, "closed_ref"); t14Truthy(cr) {
		ref = " (ref: " + scalarStr(cr) + ")"
	}
	fmt.Fprintf(r.Out, "%s: status -> %s%s\n", a.priority, a.status, ref)
	if closing {
		printProbeClosure(c, updated, map[string]struct{}{
			validation.ObjStr(lens, "lens"): {}}, r.Out)
	}
}

// parseSymmetry is _parse_symmetry: "family=primitive[|primitive];...".
func parseSymmetry(spec *string) []validation.Value {
	out := []validation.Value{}
	if spec == nil || *spec == "" {
		return out
	}
	for _, part := range strings.Split(*spec, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		fam, prims, _ := strings.Cut(part, "=")
		var list []validation.Value
		for _, p := range strings.Split(prims, "|") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, validation.VStr(p))
			}
		}
		out = append(out, validation.VObj(
			validation.KV{K: "family", V: validation.VStr(strings.TrimSpace(fam))},
			validation.KV{K: "primitives", V: validation.VArr(list...)},
		))
	}
	return out
}

// famPtr renders cli.py's `families_checked=fams`: None when --families was
// absent, the (possibly empty) list otherwise.
func famPtr(fams []string, given *string) *[]string {
	if given == nil {
		return nil
	}
	return &fams
}
