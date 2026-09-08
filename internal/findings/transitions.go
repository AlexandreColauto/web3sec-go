// transitions.go: transition / _anchor_rescan / set_critic_verdict /
// set_shield_adjudication / mark_precondition / fold_into_lineage /
// mark_duplicate / flag_possible_duplicate (webv2.findings).
//
// transition is the ONLY way a finding's status changes: it enforces the
// transition table, the evidence floor, and the CONFIRMED gate bundle.
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// IllegalTransition is IllegalTransition: raised when a status move violates
// the state machine or its gates.
type IllegalTransition struct{ Msg string }

func (e *IllegalTransition) Error() string { return e.Msg }

// ---- planner / taxonomy seams (their tasks own the real modules). The
// ---- defaults keep the finding-side logic honest without them: no model
// ---- means no family tokens, and the adjacent-property guard stays armed
// ---- with the Python message.

// plannerModelOrEmptyFunc is planner._model_or_empty: the protocol model, or
// an empty object when it is absent/unreadable.
var plannerModelOrEmptyFunc = func(*state.Campaign) validation.Value {
	return validation.VObj()
}

// SetPlannerModelOrEmpty wires planner._model_or_empty.
func SetPlannerModelOrEmpty(f func(*state.Campaign) validation.Value) {
	if f == nil {
		panic("findings: nil planner model loader")
	}
	plannerModelOrEmptyFunc = f
}

// plannerFamiliesForFindingFunc is planner.families_for_finding.
var plannerFamiliesForFindingFunc = func(model, finding validation.Value) map[string]struct{} {
	return map[string]struct{}{}
}

// SetPlannerFamiliesForFinding wires planner.families_for_finding.
func SetPlannerFamiliesForFinding(f func(validation.Value, validation.Value) map[string]struct{}) {
	if f == nil {
		panic("findings: nil planner families resolver")
	}
	plannerFamiliesForFindingFunc = f
}

// adjacentRequiredMsg is planner.ADJACENT_REQUIRED_MSG.
var adjacentRequiredMsg = "DISPROVED on a lifecycle finding must name the " +
	"adjacent unchecked property (--adjacent '...') or attest it clear " +
	"(--adjacent-clear --reason R)"

// SetAdjacentRequiredMsg wires planner.ADJACENT_REQUIRED_MSG.
func SetAdjacentRequiredMsg(msg string) {
	if msg == "" {
		panic("findings: empty adjacent-required message")
	}
	adjacentRequiredMsg = msg
}

// plannerLoadPlanReadonlyFunc is planner.load_plan_readonly.
var plannerLoadPlanReadonlyFunc = func(*state.Campaign) (validation.Value, error) {
	return validation.VNull(), fmt.Errorf("no campaign plan")
}

// SetPlannerLoadPlanReadonly wires planner.load_plan_readonly.
func SetPlannerLoadPlanReadonly(f func(*state.Campaign) (validation.Value, error)) {
	if f == nil {
		panic("findings: nil plan loader")
	}
	plannerLoadPlanReadonlyFunc = f
}

// plannerSavePlanFunc is planner.save_plan.
var plannerSavePlanFunc = func(*state.Campaign, validation.Value) error { return nil }

// SetPlannerSavePlan wires planner.save_plan.
func SetPlannerSavePlan(f func(*state.Campaign, validation.Value) error) {
	if f == nil {
		panic("findings: nil plan saver")
	}
	plannerSavePlanFunc = f
}

// plannerSiblingRescanFunc is planner.sibling_rescan.
var plannerSiblingRescanFunc = func(*state.Campaign, validation.Value,
	string, bool, string, string) error {
	return nil
}

// SetPlannerSiblingRescan wires planner.sibling_rescan.
func SetPlannerSiblingRescan(f func(*state.Campaign, validation.Value, string,
	bool, string, string) error) {
	if f == nil {
		panic("findings: nil sibling rescan")
	}
	plannerSiblingRescanFunc = f
}

// taxonomyKnownClassesFunc is taxonomy.known_classes: the canonical class
// vocabulary save_plan hard-validates against.
var taxonomyKnownClassesFunc = func() map[string]struct{} {
	return map[string]struct{}{}
}

// SetTaxonomyKnownClasses wires taxonomy.known_classes.
func SetTaxonomyKnownClasses(f func() map[string]struct{}) {
	if f == nil {
		panic("findings: nil taxonomy class set")
	}
	taxonomyKnownClassesFunc = f
}

// transitionOpts is the optional tail of transition (Python's
// actor="orchestrator", adjacent=None, adjacent_clear=False).
type transitionOpts struct {
	actor         string
	adjacent      string
	adjacentClear bool
}

// Transition is transition: the ONLY way a finding's status changes. It
// enforces the transition table, the evidence floor, and the CONFIRMED gate
// bundle. An empty actor is Python's default "orchestrator"; an empty
// adjacent is Python's None.
func Transition(campaign *state.Campaign, findingID, toStatus, reason,
	actor, adjacent string, adjacentClear bool) (validation.Value, error) {
	return transition(campaign, findingID, toStatus, reason, transitionOpts{
		actor: actor, adjacent: adjacent, adjacentClear: adjacentClear})
}

func transition(campaign *state.Campaign, findingID, toStatus, reason string,
	opts transitionOpts) (validation.Value, error) {
	actor := opts.actor
	if actor == "" {
		actor = "orchestrator"
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	fromStatus := objStr(finding, "status")
	if toStatus == fromStatus {
		return finding, nil
	}
	if !TransitionAllowed(fromStatus, toStatus) {
		legal := sortedSetKeys(ALLOWED_TRANSITIONS[fromStatus])
		return validation.VNull(), &IllegalTransition{Msg: fmt.Sprintf(
			"%s -> %s is not a legal transition (legal: %s)", fromStatus,
			toStatus, listRepr(legal))}
	}
	if toStatus == "CONFIRMED" {
		clauses, err := ConfirmationGateClauses(campaign, finding)
		if err != nil {
			return validation.VNull(), err
		}
		failures := []string{}
		for _, cl := range clauses {
			if !cl.OK {
				failures = append(failures, cl.CheckID+": "+cl.Message)
			}
		}
		if len(failures) > 0 {
			// A refusal is RECORDED (round-7 D4): the next `gate --dry-run`
			// can say which clause you just fixed. One additive event, the
			// failing ids only — the event log is the state, there is no
			// gate-attempt file.
			ids := FailingCheckIDs(clauses)
			items := make([]validation.Value, 0, len(ids))
			for _, id := range ids {
				items = append(items, validation.VStr(id))
			}
			data := validation.VObj(
				validation.KV{K: "finding", V: validation.VStr(findingID)},
				validation.KV{K: "check_ids", V: validation.VArr(items...)})
			if _, err := campaign.Log("finding.gate_attempt", &findingID,
				&data); err != nil {
				return validation.VNull(), err
			}
			return validation.VNull(), &IllegalTransition{Msg: "CONFIRMED gate " +
				"failed for " + findingID + ": " + strings.Join(failures, "; ")}
		}
	}
	if toStatus == "DISPROVED" {
		toks := plannerFamiliesForFindingFunc(plannerModelOrEmptyFunc(campaign),
			finding)
		if len(toks) > 0 && strings.TrimSpace(opts.adjacent) == "" &&
			!opts.adjacentClear {
			return validation.VNull(), fmt.Errorf("%s", adjacentRequiredMsg)
		}
	}
	if err := applyStatus(campaign, &finding, fromStatus, toStatus, reason,
		actor); err != nil {
		return validation.VNull(), err
	}
	if toStatus == "CONFIRMED" {
		if err := anchorRescan(campaign, finding); err != nil {
			return validation.VNull(), err
		}
	}
	if toStatus == "DISPROVED" {
		err := plannerSiblingRescanFunc(campaign, finding, opts.adjacent,
			opts.adjacentClear, reason, actor)
		if err != nil {
			data := validation.VObj(validation.KV{K: "error",
				V: validation.VStr(err.Error())})
			if _, lerr := campaign.Log("plan.sibling_error", &findingID,
				&data); lerr != nil {
				return validation.VNull(), lerr
			}
		}
	}
	return finding, nil
}

// applyStatus writes the status, appends the history row, saves, and logs —
// the durable half of transition.
func applyStatus(campaign *state.Campaign, finding *validation.Value,
	fromStatus, toStatus, reason, actor string) error {
	finding.O = setOrAppend(finding.O, "status", validation.VStr(toStatus))
	hist := objAt(*finding, "history")
	if hist.Kind != validation.Arr {
		hist = validation.VArr()
	}
	hist.A = append(hist.A, validation.VObj(
		validation.KV{K: "at", V: validation.VStr(nowIso())},
		validation.KV{K: "from", V: validation.VStr(fromStatus)},
		validation.KV{K: "to", V: validation.VStr(toStatus)},
		validation.KV{K: "reason", V: validation.VStr(reason)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	))
	finding.O = setOrAppend(finding.O, "history", hist)
	if err := SaveFinding(campaign, finding); err != nil {
		return err
	}
	data := validation.VObj(
		validation.KV{K: "from", V: validation.VStr(fromStatus)},
		validation.KV{K: "to", V: validation.VStr(toStatus)},
		validation.KV{K: "reason", V: validation.VStr(reason)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)
	fid := objStr(*finding, "finding_id")
	_, err := campaign.Log("finding.status", &fid, &data)
	return err
}

// anchorRescan is _anchor_rescan: a CONFIRMED high/critical finding is an
// ANCHOR — add one re-scan priority (idempotent per finding) so the discovery
// queue carries it.
func anchorRescan(campaign *state.Campaign, finding validation.Value) error {
	sev := objStr(finding, "reported_severity")
	if sev != "high" && sev != "critical" {
		return nil
	}
	planPath := filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
	if _, err := os.Stat(planPath); err != nil {
		return nil // the discovery proof already reports the missing plan
	}
	if err := reopenExhaustedLenses(campaign, finding); err != nil {
		fid := objStr(finding, "finding_id")
		data := validation.VObj(validation.KV{K: "error",
			V: validation.VStr(err.Error())})
		if _, lerr := campaign.Log("plan.lens_reopen_failed", &fid,
			&data); lerr != nil {
			return nil
		}
	}
	plan, err := plannerLoadPlanReadonlyFunc(campaign)
	if err != nil {
		return err
	}
	fid := objStr(finding, "finding_id")
	if hasAnchorPriority(plan, fid) {
		return nil
	}
	priority, err := anchorPriority(finding, plan)
	if err != nil {
		return err
	}
	priorities := objAt(plan, "priorities")
	if priorities.Kind != validation.Arr {
		return fmt.Errorf("%s", validation.PyReprStr("priorities"))
	}
	priorities.A = append(priorities.A, priority)
	plan.O = setOrAppend(plan.O, "priorities", priorities)
	if err := plannerSavePlanFunc(campaign, plan); err != nil {
		return err
	}
	data := validation.VObj(
		validation.KV{K: "priority_id", V: objAt(priority, "id")},
		validation.KV{K: "severity", V: objAt(finding, "reported_severity")},
	)
	_, err = campaign.Log("plan.anchor_priority", &fid, &data)
	return err
}

// reopenExhaustedLenses is the exhaustive-divergence pass: a CONFIRMED
// finding in a family a lens claimed to have exhausted proves the closure
// premature — re-open that lens.
func reopenExhaustedLenses(campaign *state.Campaign, finding validation.Value) error {
	toks := plannerFamiliesForFindingFunc(plannerModelOrEmptyFunc(campaign),
		finding)
	if len(toks) == 0 {
		return nil
	}
	plan, err := plannerLoadPlanReadonlyFunc(campaign)
	if err != nil {
		return err
	}
	lenses := objAt(plan, "lenses")
	if lenses.Kind != validation.Arr {
		return nil
	}
	changed := false
	for i, l := range lenses.A {
		if l.Kind != validation.Obj {
			continue
		}
		st := objStr(l, "status")
		if st != "answered" && st != "not-applicable" {
			continue
		}
		hit := intersectSorted(objAt(l, "families"), toks)
		if len(hit) == 0 {
			continue
		}
		l = reopenLens(campaign, finding, l, hit)
		lenses.A[i] = l
		changed = true
	}
	if !changed {
		return nil
	}
	plan.O = setOrAppend(plan.O, "lenses", lenses)
	return plannerSavePlanFunc(campaign, plan)
}

// reopenLens applies one lens re-open and logs it.
func reopenLens(campaign *state.Campaign, finding, lens validation.Value,
	hit []string) validation.Value {
	fid := objStr(finding, "finding_id")
	lens.O = setOrAppend(lens.O, "status", validation.VStr("open"))
	lens.O = setOrAppend(lens.O, "reopen_reason", validation.VStr(
		fmt.Sprintf("CONFIRMED %s in family %s after %s was closed — re-scan "+
			"the family", fid, strings.Join(hit, ", "), objStr(lens, "lens"))))
	lens.O = setOrAppend(lens.O, "reopened_at", validation.VStr(nowIso()))
	for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
		"closed_by", "families_checked", "symmetry"} {
		lens.O = dropKey(lens.O, k)
	}
	data := validation.VObj(
		validation.KV{K: "lens_id", V: objAt(lens, "id")},
		validation.KV{K: "families", V: strArr(hit)},
	)
	_, _ = campaign.Log("plan.lens_reopened", &fid, &data)
	return lens
}

// hasAnchorPriority is any(q.get("anchor_of") == finding_id ...).
func hasAnchorPriority(plan validation.Value, findingID string) bool {
	for _, q := range objAt(plan, "priorities").A {
		if objAt(q, "anchor_of").Kind == validation.Str &&
			objStr(q, "anchor_of") == findingID {
			return true
		}
	}
	return false
}

// anchorPriority builds the ANCHOR priority row for a CONFIRMED finding.
func anchorPriority(finding, plan validation.Value) (validation.Value, error) {
	surfaces := sortedContracts(finding)
	if len(surfaces) == 0 {
		surfaces = []string{"the affected surface"}
	}
	n, err := nextPriorityNumber(plan)
	if err != nil {
		return validation.VNull(), err
	}
	fid := objStr(finding, "finding_id")
	cls := objStr(asDict(objAt(finding, "root_cause")), "class")
	clsText := cls
	if clsText == "" {
		clsText = "unclassified"
	}
	question := fmt.Sprintf("ANCHOR: %s (%s, %s) is CONFIRMED at %s — re-scan "+
		"the SAME lifecycle for a non-obvious coordination bug before "+
		"converging (the loud bug usually hides the subtle one)", fid,
		pyStr(objAt(finding, "reported_severity")), clsText,
		strings.Join(surfaces, ", "))
	priority := validation.VObj(
		validation.KV{K: "id", V: validation.VStr(fmt.Sprintf("Q-%03d", n))},
		validation.KV{K: "question", V: validation.VStr(question)},
		validation.KV{K: "risk", V: validation.VFloat(0.8)},
		validation.KV{K: "components", V: strArr(surfaces)},
		validation.KV{K: "trajectories", V: validation.VArr(validation.VStr("code"))},
		validation.KV{K: "status", V: validation.VStr("open")},
		validation.KV{K: "anchor_of", V: validation.VStr(fid)},
	)
	// root_cause.class is schema-free-form (advisory taxonomy mapping) but
	// save_plan hard-validates bug_class against the canonical vocabulary:
	// copying a non-canonical class would raise AFTER the CONFIRMED status
	// is already durable.
	if cls != "" && inSet(taxonomyKnownClassesFunc(), cls) {
		priority.O = setOrAppend(priority.O, "bug_class",
			validation.VStr(cls))
	}
	return priority, nil
}

// sortedContracts is sorted({a["contract"] for a in affected if a.contract}).
func sortedContracts(finding validation.Value) []string {
	seen := map[string]struct{}{}
	for _, a := range objAt(finding, "affected").A {
		if a.Kind != validation.Obj {
			continue
		}
		if c := objStr(a, "contract"); c != "" {
			seen[c] = struct{}{}
		}
	}
	return sortedSetKeys(seen)
}

// nextPriorityNumber is max([int(q["id"][2:]) for Q- ids] or [0]) + 1.
func nextPriorityNumber(plan validation.Value) (int, error) {
	var nums []int
	for _, q := range objAt(plan, "priorities").A {
		id := objStr(q, "id")
		if !strings.HasPrefix(id, "Q-") {
			continue
		}
		n, ok := pyIntText(id[2:])
		if !ok {
			return 0, fmt.Errorf("invalid literal for int() with base 10: %s",
				validation.PyReprStr(id[2:]))
		}
		nums = append(nums, n)
	}
	best := 0 // max([...] or [0])
	if len(nums) > 0 {
		best = nums[0]
		for _, n := range nums[1:] {
			if n > best {
				best = n
			}
		}
	}
	return best + 1, nil
}

// pyIntText is Python int() on a base-10 literal: surrounding whitespace, an
// optional sign, and single underscores between digits are accepted.
func pyIntText(s string) (int, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	neg := false
	if t[0] == '+' || t[0] == '-' {
		neg = t[0] == '-'
		t = t[1:]
	}
	if t == "" {
		return 0, false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c == '_' {
			if i == 0 || i == len(t)-1 || !isDigit(t[i-1]) || !isDigit(t[i+1]) {
				return 0, false
			}
			continue
		}
		if !isDigit(c) {
			return 0, false
		}
	}
	n, err := strconv.Atoi(strings.ReplaceAll(t, "_", ""))
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// intersectSorted is sorted(set(families) & toks).
func intersectSorted(families validation.Value, toks map[string]struct{}) []string {
	seen := map[string]struct{}{}
	for _, f := range families.A {
		if f.Kind != validation.Str {
			continue
		}
		if _, ok := toks[f.S]; ok {
			seen[f.S] = struct{}{}
		}
	}
	return sortedSetKeys(seen)
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// dropKey is dict.pop(k, None): the object without that key.
func dropKey(o []validation.KV, key string) []validation.KV {
	out := make([]validation.KV, 0, len(o))
	for _, kv := range o {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	return out
}

// SetCriticVerdict is set_critic_verdict: record the hostile-critic verdict
// and its reasoning.
func SetCriticVerdict(campaign *state.Campaign, findingID, verdict,
	reasoning string) (validation.Value, error) {
	switch verdict {
	case "pending", "confirmed", "possible", "disproved", "duplicate",
		"out_of_scope", "informational":
	default:
		return validation.VNull(), fmt.Errorf("invalid critic verdict %s",
			validation.PyReprStr(verdict))
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ver := asDict(objAt(finding, "verification"))
	ver.O = setOrAppend(ver.O, "critic_verdict", validation.VStr(verdict))
	finding.O = setOrAppend(finding.O, "verification", ver)
	meta := asDict(objAt(finding, "dedup_meta"))
	meta.O = setOrAppend(meta.O, "critic_reasoning", validation.VStr(reasoning))
	finding.O = setOrAppend(finding.O, "dedup_meta", meta)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(validation.KV{K: "verdict", V: validation.VStr(verdict)})
	if _, err := campaign.Log("finding.critic", &findingID, &data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// SetShieldAdjudication is set_shield_adjudication: record the
// plausibility-shield adjudication — the protocol's docs call the mechanism
// INTENTIONAL, and this finding says the economic effect is (or is not)
// extraction DESPITE that intent.
func SetShieldAdjudication(campaign *state.Campaign, findingID string,
	extracts bool, reasoning, actor string) (validation.Value, error) {
	if actor == "" {
		actor = "orchestrator"
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ver := asDict(objAt(finding, "verification"))
	if len([]rune(reasoning)) < 15 {
		return validation.VNull(), fmt.Errorf("shield adjudication reasoning " +
			"must be substantive (>= 15 chars) — 'it extracts' is not an " +
			"adjudication")
	}
	ver.O = setOrAppend(ver.O, "shield_adjudication", validation.VObj(
		validation.KV{K: "extraction_despite_intent", V: validation.VBool(extracts)},
		validation.KV{K: "reasoning", V: validation.VStr(reasoning)},
		validation.KV{K: "at", V: validation.VStr(nowIso())},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	))
	finding.O = setOrAppend(finding.O, "verification", ver)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "extracts", V: validation.VBool(extracts)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)
	if _, err := campaign.Log("finding.shield_adjudication", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// MarkPrecondition is mark_precondition: audit a precondition against the
// PoC — does the CODE enforce it? enforced_by_poc becomes "true"/"false" for
// the first precondition whose description matches (exact, else
// case-insensitive substring).
func MarkPrecondition(campaign *state.Campaign, findingID, description string,
	enforced bool) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	value := "false"
	if enforced {
		value = "true"
	}
	pre := objAt(finding, "preconditions")
	for i, p := range pre.A {
		if p.Kind != validation.Obj {
			continue
		}
		if objStr(p, "description") == description {
			return auditPrecondition(campaign, &finding, i, p, description, value)
		}
	}
	low := strings.ToLower(description)
	for i, p := range pre.A {
		if p.Kind != validation.Obj {
			continue
		}
		desc := strings.ToLower(objStr(p, "description"))
		if strings.Contains(desc, low) || strings.Contains(low, desc) {
			return auditPrecondition(campaign, &finding, i, p,
				objStr(p, "description"), value)
		}
	}
	return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(
		fmt.Sprintf("%s: no precondition matching %s", findingID,
			validation.PyReprStr(description))))
}

func auditPrecondition(campaign *state.Campaign, finding *validation.Value,
	i int, p validation.Value, loggedDesc, value string) (validation.Value, error) {
	p.O = setOrAppend(p.O, "enforced_by_poc", validation.VStr(value))
	pre := objAt(*finding, "preconditions")
	pre.A[i] = p
	finding.O = setOrAppend(finding.O, "preconditions", pre)
	if err := SaveFinding(campaign, finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "description", V: validation.VStr(loggedDesc)},
		validation.KV{K: "enforced", V: validation.VStr(value)},
	)
	fid := objStr(*finding, "finding_id")
	if _, err := campaign.Log("finding.precondition_audited", &fid,
		&data); err != nil {
		return validation.VNull(), err
	}
	return *finding, nil
}

// FoldIntoLineage is fold_into_lineage: pin the finding's lineage id.
func FoldIntoLineage(campaign *state.Campaign, findingID,
	lineageID string) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	dedup := asDict(objAt(finding, "dedup"))
	dedup.O = setOrAppend(dedup.O, "lineage_id", validation.VStr(lineageID))
	finding.O = setOrAppend(finding.O, "dedup", dedup)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// MarkDuplicate is mark_duplicate: transition to DUPLICATE and record which
// finding it duplicates.
func MarkDuplicate(campaign *state.Campaign, findingID,
	ofFindingID string) (validation.Value, error) {
	finding, err := transition(campaign, findingID, "DUPLICATE",
		"technical/root-cause duplicate of "+ofFindingID,
		transitionOpts{actor: "dedup"})
	if err != nil {
		return validation.VNull(), err
	}
	dedup := asDict(objAt(finding, "dedup"))
	dedup.O = setOrAppend(dedup.O, "duplicate_of",
		validation.VStr(ofFindingID))
	finding.O = setOrAppend(finding.O, "dedup", dedup)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// FlagPossibleDuplicate is flag_possible_duplicate: tier-3 (economic-effect)
// matches are flagged, never auto-merged.
func FlagPossibleDuplicate(campaign *state.Campaign, findingID,
	ofFindingID string) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	dedup := asDict(objAt(finding, "dedup"))
	lst := objAt(dedup, "possible_duplicate_of")
	if lst.Kind != validation.Arr {
		lst = validation.VArr()
	}
	if !containsStr(valueStrings(lst), ofFindingID) {
		lst.A = append(lst.A, validation.VStr(ofFindingID))
	}
	dedup.O = setOrAppend(dedup.O, "possible_duplicate_of", lst)
	finding.O = setOrAppend(finding.O, "dedup", dedup)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(validation.KV{K: "of", V: validation.VStr(ofFindingID)})
	if _, err := campaign.Log("finding.possible_duplicate", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// valueStrings is the string members of a list (Python's `in` on a list of
// ids compares by equality; non-strings never equal an id).
func valueStrings(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}
