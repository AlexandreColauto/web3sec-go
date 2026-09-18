package planner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/findings"
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
			"what `webv2 floors " + campaign.CampaignID + "` prints (one row per class, with " +
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
//
// The write->register window is the r40e UNWIND-ON-REFUSAL site for every
// planner verb that ends in SavePlan (mark_answered, sibling_rescan,
// mark_lens, probes emit, the rebuild corridor): the plan file is written,
// and then the artifact registration APPENDS its ledger event
// (artifact.registered / artifact.refreshed — the refresh pins the new
// bytes' sha256 in the event). A refused append (torn ledger, mirror lag or
// hole, held lock, unreadable ledger) used to leave the new plan file on
// disk while the registration's own unwind reverted the registry row to the
// OLD sha — audit section 2 then burns "content hash mismatch (stored
// <old>..., actual <new>...)" on a plan whose decision the ledger never
// recorded, and the retry after the heal rewrites it twice. So the file's
// bytes are snapshotted before the write, and ANY refusal in the window
// restores those exact bytes (or removes a file that did not exist yet) —
// the same snapshot -> write -> append -> restore dance as
// state.AppendJsonlThenLog, applied to a whole-file artifact, under the
// campaign process lock the inner append re-enters by depth.
func SavePlan(campaign *state.Campaign, plan validation.Value,
	path ...string) (string, error) {
	plan, err := ValidatePlan(campaign, plan)
	if err != nil {
		return "", err
	}
	target := planPath(campaign)
	if len(path) > 0 && path[0] != "" {
		target = path[0]
	}
	n := len(listOf(plan, "priorities"))
	note := "campaign plan, " + itoa(n) + " priorities"
	reason := "plan saved (" + itoa(n) + " priorities)"
	if err := planWindow(campaign, target,
		func() error { return validation.WriteJson(target, plan, "") },
		func() error {
			_, lerr := campaign.RegisterOrRefresh("plan", target, note,
				nil, reason)
			return lerr
		}); err != nil {
		return "", err
	}
	return target, nil
}

// planPath is the campaign plan artifact: artifacts/campaign_plan.json.
func planPath(campaign *state.Campaign) string {
	return filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
}

// planWindow is the planner's ONE unwind-on-refusal door: snapshot the plan
// file's bytes, hold the campaign process lock across the whole
// snapshot -> write -> append -> restore window (the inner Log/register
// re-enters the lock by depth), run the write, run the ledger append, and
// on ANY refusal restore the exact pre-write bytes — or remove a file that
// did not exist yet, never creating an empty one. A FAILED restore means
// the plan bytes are still AHEAD of the refused event — the exact
// half-land this helper exists to prevent; name both failures so no caller
// can report a clean unwind that never happened.
//
// Two callers share it: SavePlan runs the write + the artifact-registration
// append; planThenLog wraps the whole SavePlan + semantic-event pair (the
// semantic append itself — plan.priority_status / plan.sibling_priority /
// plan.lens_status — is the same law at one level up: a status flip the
// ledger never recorded is a decision the gates read as truth, so its
// refusal must also put the plan bytes back).
func planWindow(campaign *state.Campaign, target string,
	write func() error, log func() error) error {
	if err := campaign.LockProcess(); err != nil {
		return err
	}
	defer campaign.UnlockProcess()
	prevRaw, perr := os.ReadFile(target)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	restore := func() error {
		if had {
			return os.WriteFile(target, prevRaw, 0o644)
		}
		if rerr := os.Remove(target); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	fail := func(err error) error {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s holds "+
				"post-write bytes with no event; repair by hand before "+
				"continuing)", err, rerr, filepath.Base(target))
		}
		return err
	}
	if err := write(); err != nil {
		// A failed or short write can still have put bytes on disk
		// (a non-atomic writer, a failing fsync): the plan file would be
		// there with the error returned — the same half-land as a refused
		// append.
		return fail(err)
	}
	if err := log(); err != nil {
		return fail(err)
	}
	return nil
}

// planThenLog is the r40e door for the named SavePlan->Log pairings
// (mark_answered, sibling_rescan, mark_lens): snapshot the plan file, save
// the plan (SavePlan's own window restores on ITS refusal), append the
// semantic event, and on ITS refusal restore the pre-write bytes exactly.
// The restore is the loud shape on purpose: when the semantic append is the
// refused one, the artifact registration ahead of it has already refreshed
// the registry row to the post-write bytes (its event pins them), so a
// restored file and an advanced row disagree — audit section 2 names the
// mismatch, with `webv2 artifact-reconcile` as the sanctioned repair — while
// the alternative (leaving the flipped status in place) is the silent
// half-land no audit direction sees.
func planThenLog(campaign *state.Campaign, plan validation.Value,
	log func() error) error {
	target := planPath(campaign)
	return planWindow(campaign, target,
		func() error {
			_, werr := SavePlan(campaign, plan)
			return werr
		}, log)
}

// isCanonicalClass reports whether cls is in the canonical bug-class vocabulary
// SavePlan hard-validates against (taxonomy.KnownClasses — the same set the
// findings transitions seam wires). One classifier for the validator, the plan
// builder and the divergence gate's findings reader, so a class one of them
// accepts can never be one the others reject.
func isCanonicalClass(cls string) bool {
	_, ok := taxonomy.KnownClasses()[cls]
	return ok
}

// nonCanonicalClasses is the bug_class hard-validation list.
func nonCanonicalClasses(plan validation.Value) []string {
	bad := []string{}
	for _, p := range listOf(plan, "priorities") {
		bc := validation.ObjAt(p, "bug_class")
		if !pyTruthyBigNonEmpty(bc) {
			continue
		}
		if bc.Kind != validation.Str || !isCanonicalClass(bc.S) {
			bad = append(bad, validation.ObjStr(p, "id")+" (bug_class "+
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

// add builds one priority: one Q-%03d row per call, keys in the Python dict's
// order. src is the source row the question was derived from (validation.VNull
// for the static/aggregate questions); when it names a CANONICAL bug_class the
// row is stamped onto the priority, so the diversity clause counts a class the
// model actually asserted. A non-canonical source class is dropped rather than
// copied — SavePlan would reject the plan the builder just produced.
func (b *planBuilder) add(src validation.Value, question string, risk float64,
	components, trajectories []string, opts addOpts) {
	b.qi++
	b.addWithID(qid(b.qi), src, question, risk, components, trajectories, opts)
}

// addWithID is add with an explicit id: the adversarial-lifecycle rows carry
// positional LC-%03d ids (their stable handle is the machine NAME), every
// other row keeps the Q-%03d stream.
func (b *planBuilder) addWithID(id string, src validation.Value, question string,
	risk float64, components, trajectories []string, opts addOpts) {
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
	prio := validation.VObj(
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr(question)),
		kv("risk", validation.VFloat(risk)),
		kv("components", validation.StrArr(components)),
		kv("invariant_ids", validation.StrArr(inv)),
		kv("required_context", validation.StrArr([]string{"structural_index",
			"protocol_model"})),
		kv("trajectories", validation.StrArr(trajectories)),
		kv("recommended_stages", validation.StrArr(stages)),
		kv("budget_class", validation.VStr(budget)),
		kv("status", validation.VStr("open")),
	)
	if bc := validation.ObjAt(src, "bug_class"); bc.Kind == validation.Str &&
		isCanonicalClass(bc.S) {
		prio.O = validation.SetOrAppend(prio.O, "bug_class", bc)
	}
	b.priorities = append(b.priorities, prio)
}

// qid is f"Q-{n:03d}".
func qid(n int) string {
	return "Q-" + pad3(n)
}

// pad3 is f"{n:03d}".
func pad3(n int) string {
	s := itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
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
	b.add(validation.VNull(), "Which known exploit patterns apply to this "+
		"protocol's design (history mining)?", 0.6, []string{},
		[]string{"historical"}, addOpts{budget: "cheap"})
	risky := protocolgraph.ExternalAssets(model)
	if len(risky) > 0 {
		bootstrapRisky(b, risky)
	}
	bootstrapRoles(b, model)
	// Task 10: the model's OWN open questions compile into the queue. Last,
	// so every pre-existing question keeps its Q-number byte-for-byte.
	bootstrapOpenQuestions(b, model)
	// Task 2 (defect 4): the model's own adversarial lifecycle machines mint
	// into the same queue, through the same scoring path. Last again, so every
	// pre-existing question keeps its Q-number byte-for-byte.
	if err := bootstrapLifecycleSurfaces(b, campaign, model); err != nil {
		return validation.VNull(), err
	}
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(campaign.CampaignID)),
		kv("created_at", validation.VStr(state.NowIso())),
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

// ---- Task 2: adversarial-lifecycle surfaces mint into the queue ------------

// lifecycleVocabulary is the adversarial-lifecycle verb vocabulary: the verbs
// a commit→challenge→finalize (or propose→vote→execute) game is spelled with.
// Asset-flow verbs (deposit/transfer/relay/swap/mint/burn) are deliberately
// absent — they are happy-path surface, not the game an adversary wins.
var lifecycleVocabulary = []string{"commit", "challenge", "finalize", "settle",
	"claim", "withdraw", "dispute", "prove", "refund", "liquidate", "redeem"}

// lifecycleSurface is one qualifying state machine: its name (the STABLE
// handle — see the id scheme below) and its verb chain, in vocabulary order.
type lifecycleSurface struct {
	name  string
	chain string
}

// adversarialLifecycleSurfaces is the model's own state machines that carry an
// adversarial game, sorted by machine name. The CARDINALITY RULE is binding: a
// machine qualifies only when >= 2 DISTINCT vocabulary tokens occur across its
// name and its transition action names combined. A lone `withdraw` (every
// vault), lone `claim` (airdrops), lone `redeem` (receipt tokens) or lone
// `settle` (oracle fulfillment) is benign happy-path surface, and minting rows
// for those would recreate the very noise this task exists to remove.
//
// Only transition OBJECTS count, through their schema `trigger` (the action
// name): a machine whose transitions are not schema-shaped is degenerate and
// contributes nothing.
func adversarialLifecycleSurfaces(model validation.Value) []lifecycleSurface {
	out := []lifecycleSurface{}
	for _, sm := range listOf(model, "state_machines") {
		name := validation.ObjStr(sm, "name")
		if name == "" {
			continue
		}
		toks := lifecycleMachineTokens(sm)
		if len(toks) < 2 {
			continue
		}
		out = append(out, lifecycleSurface{name: name,
			chain: strings.Join(toks, " → ")})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].name < out[j].name
	})
	return out
}

// AdversarialLifecycleMachines is the exported handle for the selection above:
// the sorted names of the model's adversarial lifecycle machines (Task 2).
// Downstream consumers match on the NAME, never on a minted row id — the
// LC-%03d ids are positional, so a later model that adds an alphabetically
// earlier machine shifts every id after it.
func AdversarialLifecycleMachines(model validation.Value) []string {
	out := []string{}
	for _, s := range adversarialLifecycleSurfaces(model) {
		out = append(out, s.name)
	}
	return out
}

// lifecycleMachineTokens is the distinct vocabulary tokens the machine's NAME
// and its transition action names carry, left-boundary and case-insensitive,
// in vocabulary order (deterministic, independent of transition order).
func lifecycleMachineTokens(sm validation.Value) []string {
	hit := map[string]bool{}
	scan := func(text string) {
		for _, tok := range lifecycleVocabulary {
			if tokenOccursLeftBound(text, tok) {
				hit[tok] = true
			}
		}
	}
	scan(validation.ObjStr(sm, "name"))
	for _, tr := range listOf(sm, "transitions") {
		if tr.Kind != validation.Obj {
			continue
		}
		scan(validation.ObjStr(tr, "trigger"))
	}
	out := []string{}
	for _, tok := range lifecycleVocabulary {
		if hit[tok] {
			out = append(out, tok)
		}
	}
	return out
}

// tokenOccursLeftBound reports whether text contains token starting at a left
// boundary: the match begins the string, or the character before it is outside
// [0-9a-z_]. Matching is case-insensitive and there is deliberately NO trailing
// boundary — `commitBatch` and `challengeState` are action names, so a trailing
// \b would reject exactly the machines this task must rank.
//
// This is the same spec as invariants' tokenOccursLeftBound (Task 1), spelled
// out here on purpose: the invariants helper is unexported, the two packages'
// pinned tables are independent, and neither should have to move for the
// other. Keep the two in sync.
func tokenOccursLeftBound(text, token string) bool {
	if token == "" {
		return false
	}
	body := strings.ToLower(text)
	tok := strings.ToLower(token)
	for from := 0; from < len(body); {
		i := strings.Index(body[from:], tok)
		if i < 0 {
			return false
		}
		at := from + i
		if at == 0 || !isLowerWordByte(body[at-1]) {
			return true
		}
		from = at + 1
	}
	return false
}

// isLowerWordByte is the left-boundary alphabet on the lowered text: [0-9a-z_].
func isLowerWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
}

// bootstrapLifecycleSurfaces mints one `now`-slotted row per adversarial
// lifecycle machine, LAST in the plan build so no pre-existing question's
// Q-number moves. The rows carry the machine name as their named component, so
// the EXISTING planner scoring (untouched * 1.0 + severity * 2.0 + openQ *
// 1.5, slot class primary) ranks them — no new scoring path.
//
// Skips are deliberate and run against the ENTIRE work queue minted so far
// (every earlier minter's rows, not just one family's output), the campaign's
// live findings, and the coverage ledger's own swept test — the same predicate
// the queue scoring calls "untouched". A machine whose surface is already
// covered would make the row's "no covering finding" claim false.
func bootstrapLifecycleSurfaces(b *planBuilder, campaign *state.Campaign,
	model validation.Value) error {
	surfaces := adversarialLifecycleSurfaces(model)
	if len(surfaces) == 0 {
		return nil
	}
	signals, err := buildQueueSignals(campaign, model)
	if err != nil {
		return err
	}
	live, err := findings.LoadLiveFindings(campaign)
	if err != nil {
		return err
	}
	for i, s := range surfaces {
		if lifecycleSurfaceCovered(s.name, b.priorities, signals, live) {
			continue
		}
		// risk 0.9 / cheap: the adversarial game is answerable by a look at
		// the code, and it is the highest-risk unmodeled surface — it belongs
		// in the `now` slot (DecisionRule(0.9, "cheap")), ahead of generic
		// index work. Positional id over the SORTED machines: a skipped
		// machine keeps its position, and the machine NAME stays the handle.
		b.addWithID(lifecycleID(i+1), validation.VNull(),
			"review adversarial lifecycle "+s.name+" ("+s.chain+
				") — no covering finding", 0.9, []string{s.name},
			[]string{"lifecycle"}, addOpts{budget: "cheap"})
	}
	return nil
}

// lifecycleSurfaceCovered is the skip predicate: a queue row already names the
// machine as one of its components, a live finding already implicates it, or
// the coverage ledger already marks its surface swept. The component test is
// exact (not a text search): the queue's own scoring reads `components` as the
// row's surface identity, and a substring match would let a machine named
// `rollup` suppress `rollup_finalization`.
func lifecycleSurfaceCovered(name string, queue []validation.Value,
	signals *queueSignals, live []validation.Value) bool {
	for _, row := range queue {
		for _, c := range listOf(row, "components") {
			if validation.PyStr(c) == name {
				return true
			}
		}
	}
	for _, f := range live {
		for _, a := range listOf(f, "affected") {
			if validation.ObjStr(a, "contract") == name || validation.ObjStr(a, "path") == name {
				return true
			}
		}
	}
	path, ok := signals.inScope[name]
	return ok && signals.touched[path]
}

// lifecycleID is f"LC-{n:03d}" — the display-only positional id of a minted
// lifecycle row. Never a handle: match on the machine name.
func lifecycleID(n int) string {
	return "LC-" + pad3(n)
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
