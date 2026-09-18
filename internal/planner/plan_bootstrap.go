// plan_bootstrap.go: the bootstrap question minters (privileged roles,
// uncovered invariants, risky tokens, roles, open questions) and the
// plan's coverage-target helpers.
package planner

import (
	"sort"
	"strings"
	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

// bootstrapPrivileged adds the drain / upgrade / trust-boundary / economic
// bootstrap questions (the pre-3.1 body, in order).
func bootstrapPrivileged(b *planBuilder, campaign *state.Campaign,
	model validation.Value) {
	drains := protocolgraph.WhoCan(model, "can_drain")
	if len(drains) > 0 {
		ids := make([]string, 0, len(drains))
		for _, a := range drains {
			ids = append(ids, validation.ObjStr(a, "id"))
		}
		b.add(validation.VNull(), "Can the drain-capable roles ("+
			strings.Join(ids, ", ")+
			") be reached or captured by an unprivileged attacker?",
			0.9, ids, []string{"attacker", "code"}, addOpts{budget: "cheap"})
	}
	var upgrades []validation.Value
	for _, a := range listOf(model, "actors") {
		if pyTruthyBigNonEmpty(validation.ObjAt(a, "can_upgrade")) {
			upgrades = append(upgrades, a)
		}
	}
	if len(upgrades) > 0 {
		ids := make([]string, 0, len(upgrades))
		for _, a := range upgrades {
			ids = append(ids, validation.ObjStr(a, "id"))
		}
		b.add(validation.VNull(), "Can upgrade authorization be captured, "+
			"front-run, or exercised on an already-initialized contract?", 0.85,
			ids, []string{"code", "attacker"}, addOpts{budget: "cheap"})
	}
	for _, g := range protocolgraph.TrustBoundaryGaps(model) {
		b.add(g, "Is the unvalidated trust boundary "+validation.ObjStr(g, "from")+" -> "+
			validation.ObjStr(g, "to")+" ("+validation.ObjStr(g, "crossing")+") exploitable?", 0.8,
			[]string{validation.ObjStr(g, "to")}, []string{"integration", "code"},
			addOpts{})
	}
	components := []string{}
	if len(protocolgraph.AccountingVars(model)) > 0 {
		components = []string{"accounting"}
	}
	for _, t := range EcoTransforms(campaign, model) {
		name := validation.ObjStr(t, "name")
		budget := "standard"
		if strings.Contains(name, "oracle") {
			budget = "expensive"
		}
		b.add(t, "Economic transform "+name+": "+validation.ObjStr(t, "question"), 0.75,
			components, []string{"economic"}, addOpts{budget: budget})
	}
}

// bootstrapUncovered adds one question per uncovered critical invariant.
func bootstrapUncovered(b *planBuilder, uncovered []validation.Value) {
	for _, u := range uncovered {
		components := []string{}
		for _, a := range listOf(u, "applies_to") {
			components = append(components, validation.PyStr(a))
		}
		b.add(u, "Test the uncovered critical invariant: "+
			validation.ObjStr(u, "statement"), 0.7, components,
			[]string{"code", "state-machine"}, addOpts{
				invariantIDs: []string{validation.ObjStr(u, "invariant_id")}})
	}
}

// bootstrapRisky adds the nonstandard-token question.
func bootstrapRisky(b *planBuilder, risky []validation.Value) {
	assets := make([]string, 0, len(risky))
	for _, r := range risky {
		assets = append(assets, validation.ObjStr(r, "asset"))
	}
	b.add(validation.VNull(), "Do nonstandard token behaviors ("+
		strings.Join(assets, ", ")+") break accounting assumptions?", 0.65,
		assets, []string{"integration", "economic"}, addOpts{})
}

// bootstrapRoles is the 3.1 D5 extension: one D-attacker question per role on
// the privilege surface — not only the drain-capable ones. The constraints are
// RECORDED values from the model's own privilege table (timelocked /
// multisig_threshold), never inferred, and they ride inside the question text
// so no new schema shape is needed. Appended after every pre-3.1 question:
// existing texts, order and Q-numbers stay byte-identical.
func bootstrapRoles(b *planBuilder, model validation.Value) {
	surface := RolePrivilegeSurface(model)
	for _, role := range sortedMapKeys(surface) {
		entries := surface[role]
		caps := make([]string, 0, len(entries))
		for _, e := range entries {
			caps = append(caps, validation.ObjStr(e, "capability"))
		}
		sort.Strings(caps)
		tl := "no"
		for _, e := range entries {
			if v := validation.ObjAt(e, "timelocked"); v.Kind == validation.Bool && v.B {
				tl = "yes"
				break
			}
		}
		th := "n/a"
		var thresholds []float64
		for _, e := range entries {
			v := validation.ObjAt(e, "multisig_threshold")
			if v.Kind == validation.Int || v.Kind == validation.Flt {
				thresholds = append(thresholds, floatOrInt(v))
			}
		}
		if len(thresholds) > 0 {
			th = maxThresholdText(entries)
		}
		b.add(validation.VNull(), "Within its stated constraints (timelocked="+
			tl+", threshold="+th+"), what can role `"+role+"` do via `"+
			strings.Join(caps, "; ")+"` that violates user expectations?", 0.8,
			[]string{role}, []string{"attacker"}, addOpts{budget: "cheap"})
	}
}

// bootstrapOpenQuestions compiles the protocol model's OWN open questions
// into plan priorities (Task 10). The model already records what it could not
// decide; before this, those questions were rendered by `coverage` as gaps
// and then never worked — the queue did not carry them, so nothing in the
// campaign ever answered them.
//
// Only questions that NAME something are compiled: a `blocks` or `applies_to`
// contract reference is what makes the question actionable (it names the
// surface the answer changes). A question with no reference, and one already
// marked `resolved`, produce nothing — an empty or reference-free
// open_questions list leaves the queue byte-identical.
//
// The minted question text is `resolve open question <id>: <text>` so the row
// the operator must answer names itself: the id in the text is the id of the
// very priority that carries it, which is what `webv2 answered <campaign>
// <id> answered …` takes.
func bootstrapOpenQuestions(b *planBuilder, model validation.Value) {
	for _, q := range listOf(model, "open_questions") {
		if pyTruthyBigNonEmpty(validation.ObjAt(q, "resolved")) {
			continue
		}
		text := validation.ObjStr(q, "question")
		if text == "" {
			continue
		}
		refs := openQuestionRefs(q)
		if len(refs) == 0 {
			continue
		}
		id := qid(b.qi + 1)
		// risk 0.9 / cheap: an unresolved question about a named surface is
		// answerable by a look at the code or the deployment — it belongs in
		// the `now` slot, ahead of generic index work.
		b.add(q, "resolve open question "+id+": "+text, 0.9, refs,
			[]string{"drift", "code"}, addOpts{budget: "cheap"})
	}
}

// openQuestionRefs is the contract references an open question names: the
// `blocks` list the schema defines plus the `applies_to` spelling other
// producers use. Declaration order is kept (deterministic output), duplicates
// and empty strings are dropped.
func openQuestionRefs(q validation.Value) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, key := range []string{"blocks", "applies_to"} {
		for _, ref := range listOf(q, key) {
			s := validation.PyStr(ref)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// floatOrInt is a numeric Value as float64 (only used for presence checks).
func floatOrInt(v validation.Value) float64 {
	if v.Kind == validation.Flt {
		return v.F
	}
	return float64(v.I)
}

// maxThresholdText is str(max(thresholds)) over the numeric multisig
// thresholds, preserving int-vs-float rendering.
func maxThresholdText(entries []validation.Value) string {
	best := validation.VNull()
	bestVal := 0.0
	first := true
	for _, e := range entries {
		v := validation.ObjAt(e, "multisig_threshold")
		if v.Kind != validation.Int && v.Kind != validation.Flt {
			continue
		}
		f := floatOrInt(v)
		if first || f > bestVal {
			best, bestVal, first = v, f, false
		}
	}
	return validation.PyStr(best)
}

// coverageTargets is the plan's coverage_targets block.
func coverageTargets(model validation.Value) validation.Value {
	components := []string{}
	for _, c := range listOf(model, "contracts") {
		if pyTruthyBigNonEmpty(validation.ObjAt(c, "in_scope")) {
			components = append(components, validation.ObjStr(c, "name"))
		}
	}
	return validation.VObj(
		kv("min_invariants", validation.VInt(1)),
		kv("min_trajectories_per_critical_component", validation.VInt(2)),
		kv("components_must_cover", validation.StrArr(components)),
	)
}

// snapshotIDOrUnpinned is `active_snapshot_id_or_none() or "unpinned"`.
func snapshotIDOrUnpinned(campaign *state.Campaign) string {
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil || *sid == "" {
		return "unpinned"
	}
	return *sid
}
