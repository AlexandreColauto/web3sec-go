package planner

import (
	"path/filepath"
	"strings"

	"websec/internal/invariants"
	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// TrajectoryContracts is TRAJECTORY_CONTRACTS (insertion order is the plan's
// trajectory_matrix order).
var TrajectoryContracts = []validation.KV{
	kv("A-code", validation.VStr("implementation-centric: find bugs in the "+
		"code as written")),
	kv("B-economic", validation.VStr("economic attacker: assume the protocol "+
		"is economically exploitable and find the imbalance")),
	kv("C-state-machine", validation.VStr("state-machine attacker: find "+
		"dangerous call/state sequences and illegal transitions")),
	kv("D-attacker", validation.VStr("privileged actor: assume the attacker "+
		"holds each realistic role and abuse it")),
	kv("E-historical", validation.VStr("historical analog: find variants of "+
		"known exploits, patches and disclosures")),
	kv("F-integration", validation.VStr("adversarial integrator: assume every "+
		"external contract/token behaves unexpectedly")),
	kv("G-drift", validation.VStr("spec drift: spec vs implementation vs "+
		"deployment vs config divergence")),
	kv("H-lifecycle", validation.VStr("consensus/lifecycle game: model the "+
		"full commit→challenge→finalize (or propose→vote→execute) game and "+
		"the adversary WINNING it — a valid transition proven from an "+
		"invalid claimed root, a challenge that never fires, a finalization "+
		"that can be blocked")),
}

// TrajectoryToEnum is TRAJECTORY_TO_ENUM.
var TrajectoryToEnum = map[string]string{
	"A-code": "code", "B-economic": "economic", "C-state-machine": "state-machine",
	"D-attacker": "attacker", "E-historical": "historical",
	"F-integration": "integration", "G-drift": "drift",
	"H-lifecycle": "lifecycle",
}

// LoadPlan is load_plan: read + validate + keep the artifact registration
// current + log the load.
func LoadPlan(campaign *state.Campaign,
	path string) (validation.Value, error) {
	plan, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		return validation.VNull(), err
	}
	n := len(listOf(plan, "priorities"))
	note := "campaign plan, " + itoa(n) + " priorities"
	if _, err := campaign.RegisterOrRefresh("plan", path, note, nil,
		"plan re-loaded (content may have changed)"); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(kv("priorities", validation.VInt(int64(n))))
	if _, err := campaign.Log("plan.loaded", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// ValidatePlan is validate_plan: the plan's write-time checks WITHOUT touching
// disk — seed the canonical lens entries, reject non-canonical bug classes,
// validate against the schema. Split out of SavePlan so a rebuild can prove
// the incoming plan is writable BEFORE it archives the outgoing one (a failed
// rebuild must not retire a live contract).
func ValidatePlan(campaign *state.Campaign,
	plan validation.Value) (validation.Value, error) {
	_, plan = SeedLenses(plan, ModelOrEmpty(campaign))
	bad := nonCanonicalClasses(plan)
	if len(bad) > 0 {
		return validation.VNull(), errValue("priorities " + strings.Join(bad, ", ") +
			" declare non-canonical bug_class; the canonical class list is " +
			"what `webv2 floors <campaign>` prints (one row per class, with " +
			"its CONFIRMED floor) — use a listed class or drop the " +
			"bug_class key")
	}
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// SavePlan is save_plan: write the plan and keep its artifact registration
// current. The plan is a LIVING document (mark_answered rewrites it in
// place); the registry follows the content via a logged refresh instead of
// accumulating ghost rows.
//
// This is the LIVING-document writer, deliberately without a "does a plan
// already exist?" guard: `mark_answered`, `--emit`, lens closures and every
// other sanctioned in-place rewrite go through here. The no-clobber guard for
// REGENERATION lives in `Orchestrator.plan` (B1) — put it here and the living
// document freezes. An empty path is Python's `path=None`.
func SavePlan(campaign *state.Campaign, plan validation.Value,
	path ...string) (string, error) {
	plan, err := ValidatePlan(campaign, plan)
	if err != nil {
		return "", err
	}
	target := filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	if len(path) > 0 && path[0] != "" {
		target = path[0]
	}
	if err := validation.WriteJson(target, plan, ""); err != nil {
		return "", err
	}
	n := len(listOf(plan, "priorities"))
	note := "campaign plan, " + itoa(n) + " priorities"
	reason := "plan saved (" + itoa(n) + " priorities)"
	if _, err := campaign.RegisterOrRefresh("plan", target, note, nil,
		reason); err != nil {
		return "", err
	}
	return target, nil
}

// nonCanonicalClasses is the bug_class hard-validation list.
func nonCanonicalClasses(plan validation.Value) []string {
	known := taxonomy.KnownClasses()
	bad := []string{}
	for _, p := range listOf(plan, "priorities") {
		bc := objAt(p, "bug_class")
		if !pyTruthy(bc) {
			continue
		}
		canonical := false
		if bc.Kind == validation.Str {
			_, canonical = known[bc.S]
		}
		if !canonical {
			bad = append(bad, objStr(p, "id")+" (bug_class "+
				validation.PyRepr(bc)+")")
		}
	}
	return bad
}

// planBuilder is the `add` closure of default_plan_from_model: one Q-%03d
// priority per call, keys in the Python dict's order.
type planBuilder struct {
	priorities []validation.Value
	qi         int
}

// addOpts is the optional tail of add (Python: invariant_ids=None,
// stages=None, budget="standard").
type addOpts struct {
	invariantIDs []string
	stages       []string
	budget       string
}

func (b *planBuilder) add(question string, risk float64, components,
	trajectories []string, opts addOpts) {
	b.qi++
	budget := opts.budget
	if budget == "" {
		budget = "standard"
	}
	inv := opts.invariantIDs
	if inv == nil {
		inv = []string{}
	}
	stages := opts.stages
	if stages == nil {
		stages = []string{}
	}
	b.priorities = append(b.priorities, validation.VObj(
		kv("id", validation.VStr(qid(b.qi))),
		kv("question", validation.VStr(question)),
		kv("risk", validation.VFloat(risk)),
		kv("components", strArr(components)),
		kv("invariant_ids", strArr(inv)),
		kv("required_context", strArr([]string{"structural_index",
			"protocol_model"})),
		kv("trajectories", strArr(trajectories)),
		kv("recommended_stages", strArr(stages)),
		kv("budget_class", validation.VStr(budget)),
		kv("status", validation.VStr("open")),
	))
}

// qid is f"Q-{n:03d}".
func qid(n int) string {
	s := itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return "Q-" + s
}

// DefaultPlanFromModel is default_plan_from_model: bootstrap a plan
// deterministically from the protocol model + risk heuristics. The LLM
// planner then refines priorities/questions — this exists so the pipeline
// runs even before the planner stage is executed.
func DefaultPlanFromModel(campaign *state.Campaign,
	model validation.Value) (validation.Value, error) {
	b := &planBuilder{}
	bootstrapPrivileged(b, campaign, model)
	uncovered, err := invariants.UncoveredCritical(campaign, model)
	if err != nil {
		return validation.VNull(), err
	}
	bootstrapUncovered(b, uncovered)
	b.add("Which known exploit patterns apply to this protocol's design "+
		"(history mining)?", 0.6, []string{}, []string{"historical"},
		addOpts{budget: "cheap"})
	risky := protocolgraph.ExternalAssets(model)
	if len(risky) > 0 {
		bootstrapRisky(b, risky)
	}
	bootstrapRoles(b, model)
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(campaign.CampaignID)),
		kv("created_at", validation.VStr(nowIso())),
		kv("snapshot_id", validation.VStr(snapshotIDOrUnpinned(campaign))),
		kv("strategy_note", validation.VStr("bootstrapped deterministically "+
			"from protocol model; refine via the planner stage")),
		kv("priorities", validation.VArr(b.priorities...)),
		kv("trajectory_matrix", validation.VObj(TrajectoryContracts...)),
		kv("coverage_targets", coverageTargets(model)),
	)
	_, plan = SeedLenses(plan, model)
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// bootstrapPrivileged adds the drain / upgrade / trust-boundary / economic
// bootstrap questions (the pre-3.1 body, in order).
func bootstrapPrivileged(b *planBuilder, campaign *state.Campaign,
	model validation.Value) {
	drains := protocolgraph.WhoCan(model, "can_drain")
	if len(drains) > 0 {
		ids := make([]string, 0, len(drains))
		for _, a := range drains {
			ids = append(ids, objStr(a, "id"))
		}
		b.add("Can the drain-capable roles ("+strings.Join(ids, ", ")+
			") be reached or captured by an unprivileged attacker?",
			0.9, ids, []string{"attacker", "code"}, addOpts{budget: "cheap"})
	}
	var upgrades []validation.Value
	for _, a := range listOf(model, "actors") {
		if pyTruthy(objAt(a, "can_upgrade")) {
			upgrades = append(upgrades, a)
		}
	}
	if len(upgrades) > 0 {
		ids := make([]string, 0, len(upgrades))
		for _, a := range upgrades {
			ids = append(ids, objStr(a, "id"))
		}
		b.add("Can upgrade authorization be captured, front-run, or "+
			"exercised on an already-initialized contract?", 0.85, ids,
			[]string{"code", "attacker"}, addOpts{budget: "cheap"})
	}
	for _, g := range protocolgraph.TrustBoundaryGaps(model) {
		b.add("Is the unvalidated trust boundary "+objStr(g, "from")+" -> "+
			objStr(g, "to")+" ("+objStr(g, "crossing")+") exploitable?", 0.8,
			[]string{objStr(g, "to")}, []string{"integration", "code"},
			addOpts{})
	}
	components := []string{}
	if len(protocolgraph.AccountingVars(model)) > 0 {
		components = []string{"accounting"}
	}
	for _, t := range EcoTransforms(campaign, model) {
		name := objStr(t, "name")
		budget := "standard"
		if strings.Contains(name, "oracle") {
			budget = "expensive"
		}
		b.add("Economic transform "+name+": "+objStr(t, "question"), 0.75,
			components, []string{"economic"}, addOpts{budget: budget})
	}
}

// bootstrapUncovered adds one question per uncovered critical invariant.
func bootstrapUncovered(b *planBuilder, uncovered []validation.Value) {
	for _, u := range uncovered {
		components := []string{}
		for _, a := range listOf(u, "applies_to") {
			components = append(components, pyStr(a))
		}
		b.add("Test the uncovered critical invariant: "+
			objStr(u, "statement"), 0.7, components,
			[]string{"code", "state-machine"}, addOpts{
				invariantIDs: []string{objStr(u, "invariant_id")}})
	}
}

// bootstrapRisky adds the nonstandard-token question.
func bootstrapRisky(b *planBuilder, risky []validation.Value) {
	assets := make([]string, 0, len(risky))
	for _, r := range risky {
		assets = append(assets, objStr(r, "asset"))
	}
	b.add("Do nonstandard token behaviors ("+strings.Join(assets, ", ")+
		") break accounting assumptions?", 0.65, assets,
		[]string{"integration", "economic"}, addOpts{})
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
			caps = append(caps, objStr(e, "capability"))
		}
		sortStrings(caps)
		tl := "no"
		for _, e := range entries {
			if v := objAt(e, "timelocked"); v.Kind == validation.Bool && v.B {
				tl = "yes"
				break
			}
		}
		th := "n/a"
		var thresholds []float64
		for _, e := range entries {
			v := objAt(e, "multisig_threshold")
			if v.Kind == validation.Int || v.Kind == validation.Flt {
				thresholds = append(thresholds, floatOrInt(v))
			}
		}
		if len(thresholds) > 0 {
			th = maxThresholdText(entries)
		}
		b.add("Within its stated constraints (timelocked="+tl+", threshold="+
			th+"), what can role `"+role+"` do via `"+strings.Join(caps,
			"; ")+"` that violates user expectations?", 0.8, []string{role},
			[]string{"attacker"}, addOpts{budget: "cheap"})
	}
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
		v := objAt(e, "multisig_threshold")
		if v.Kind != validation.Int && v.Kind != validation.Flt {
			continue
		}
		f := floatOrInt(v)
		if first || f > bestVal {
			best, bestVal, first = v, f, false
		}
	}
	return pyStr(best)
}

// coverageTargets is the plan's coverage_targets block.
func coverageTargets(model validation.Value) validation.Value {
	components := []string{}
	for _, c := range listOf(model, "contracts") {
		if pyTruthy(objAt(c, "in_scope")) {
			components = append(components, objStr(c, "name"))
		}
	}
	return validation.VObj(
		kv("min_invariants", validation.VInt(1)),
		kv("min_trajectories_per_critical_component", validation.VInt(2)),
		kv("components_must_cover", strArr(components)),
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
