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
// actor="orchestrator", adjacent=None, adjacent_clear=False) plus the
// targeted-move field (Task 7c): duplicateOf is the `--of` finding a
// DUPLICATE names.
type transitionOpts struct {
	actor         string
	adjacent      string
	adjacentClear bool
	duplicateOf   string
}

// DuplicateTargetRequiredMsg is the refusal for a move to DUPLICATE that does
// not name the duplicate of. A DUPLICATE that names nothing can never be
// re-checked, and it is the operator's only handle on what the merge claimed.
const DuplicateTargetRequiredMsg = "move to DUPLICATE must name the duplicate of (--of <finding-id>)"

// DuplicateTargetRequired is the refusal type for a targetless DUPLICATE
// move. cmd_move prints it in the handler class (`move failed: {e}`, exit 2),
// like the adjacent-property guard: the move cannot proceed until the
// operator supplies the missing name.
type DuplicateTargetRequired struct{}

func (*DuplicateTargetRequired) Error() string { return DuplicateTargetRequiredMsg }

// DuplicateTargetInvalid is the ValueError-class refusal for a move to
// DUPLICATE whose --of target is unusable: it names a finding that does not
// exist (a ghost pointer nothing can re-check), the finding itself (a merge
// that can never be unwound from inside), or re-targets an existing merge.
// cmd_move prints it in the handler class (`move failed: {e}`, exit 2), like
// DuplicateTargetRequired.
type DuplicateTargetInvalid struct{ Msg string }

func (e *DuplicateTargetInvalid) Error() string { return e.Msg }

// TransitionOpts is the optional tail of Transition plus the targeted-move
// fields:
//
//	actor         — "orchestrator" when empty (Python's default)
//	adjacent      — the adjacent unchecked property (DISPROVED on a lifecycle
//	                finding)
//	adjacentClear — attest that there is no adjacent property
//	duplicateOf   — the `--of` finding; REQUIRED when toStatus is DUPLICATE,
//	                and it must name a real finding other than the one being
//	                merged (a ghost or self target is refused)
type TransitionOpts struct {
	Actor         string
	Adjacent      string
	AdjacentClear bool
	DuplicateOf   string
}

// Transition is transition: the ONLY way a finding's status changes. It
// enforces the transition table, the evidence floor, and the CONFIRMED gate
// bundle. An empty actor is Python's default "orchestrator"; an empty
// adjacent is Python's None. A move to DUPLICATE through this entry point has
// no target and is therefore refused — use TransitionWith with DuplicateOf.
func Transition(campaign *state.Campaign, findingID, toStatus, reason,
	actor, adjacent string, adjacentClear bool) (validation.Value, error) {
	return transition(campaign, findingID, toStatus, reason, transitionOpts{
		actor: actor, adjacent: adjacent, adjacentClear: adjacentClear})
}

// TransitionWith is Transition carrying the targeted-move fields (the CLI's
// `--of`). Same table, same floors, same gate bundle.
func TransitionWith(campaign *state.Campaign, findingID, toStatus, reason string,
	opts TransitionOpts) (validation.Value, error) {
	return transition(campaign, findingID, toStatus, reason, transitionOpts{
		actor: opts.Actor, adjacent: opts.Adjacent,
		adjacentClear: opts.AdjacentClear, duplicateOf: opts.DuplicateOf})
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
	// A same-status move is a no-op — EXCEPT a targeted re-merge: a DUPLICATE
	// moved to DUPLICATE with a DIFFERENT --of must not exit 0 having
	// silently rewritten (or, worse, here: not rewritten) the recorded merge
	// pointer. The short-circuit therefore routes DUPLICATE through the
	// retarget guard below.
	if toStatus == fromStatus {
		if toStatus != "DUPLICATE" {
			return finding, nil
		}
		recorded := objStr(objAt(finding, "dedup"), "duplicate_of")
		if strings.TrimSpace(opts.duplicateOf) == "" {
			// A bare same-status move keeps the recorded target untouched:
			// the operator asked for exactly the state on disk.
			return finding, nil
		}
		if opts.duplicateOf == recorded {
			// DOCUMENTED DECISION: naming the target already recorded is an
			// accepted no-op (the pointer is what the operator asked for).
			return finding, nil
		}
		if recorded == "" {
			// A legacy row: DUPLICATE status with no recorded pointer (the
			// retired twin wrote such rows). The merge refusal must not read
			// "already merged into " with an empty hole — name what the row
			// actually is.
			return validation.VNull(), &DuplicateTargetInvalid{Msg: fmt.Sprintf(
				"%s is a DUPLICATE with no merge target on record (a legacy "+
					"row that predates --of); reopen it first (DUPLICATE -> "+
					"HYPOTHESIS) before merging into %s", findingID,
				opts.duplicateOf)}
		}
		return validation.VNull(), &DuplicateTargetInvalid{Msg: fmt.Sprintf(
			"%s is already merged into %s; reopen it first (DUPLICATE -> "+
				"HYPOTHESIS) before merging into %s", findingID, recorded,
			opts.duplicateOf)}
	}
	if !TransitionAllowed(fromStatus, toStatus) {
		legal := sortedSetKeys(ALLOWED_TRANSITIONS[fromStatus])
		return validation.VNull(), &IllegalTransition{Msg: fmt.Sprintf(
			"%s -> %s is not a legal transition (legal: %s)", fromStatus,
			toStatus, listRepr(legal))}
	}
	// A targeted move: DUPLICATE must name the duplicate of, or the record is
	// a dead end (nothing to re-check, nothing to reopen from) — and the name
	// must point at a REAL finding other than the one being merged, or the
	// pointer is the same dead end wearing an id.
	if toStatus == "DUPLICATE" {
		if strings.TrimSpace(opts.duplicateOf) == "" {
			return validation.VNull(), &DuplicateTargetRequired{}
		}
		if err := validateDuplicateTarget(campaign, finding,
			opts.duplicateOf); err != nil {
			return validation.VNull(), err
		}
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
	// A promotion that lifts the finding above the E0 baseline is a rise: it
	// pays the discovery slot once, before the move is durable (a refusal
	// leaves the finding exactly where it was). Terminal junk states carry no
	// floor row and sit at the baseline, so they never charge.
	if toIdx, fromIdx := statusBaselineIndex(toStatus),
		statusBaselineIndex(fromStatus); toIdx > fromIdx && toIdx > 0 {
		if err := ConsumeSlotOnce(campaign, &finding); err != nil {
			return validation.VNull(), err
		}
	}
	// ONE durable write per transition: the status change, the history row,
	// and the dedup merge pointer (set on the merge, cleared on the reopen)
	// all mutate the finding first, then a single SaveFinding lands them
	// together. The old two-save window (the status write saved, then
	// recordDuplicateOf saved again) could strand a durable targetless
	// DUPLICATE on a failure between writes — the exact dead end the
	// DuplicateTargetRequired guard makes unrepresentable.
	mutateStatus(&finding, fromStatus, toStatus, reason, actor)
	if toStatus == "DUPLICATE" {
		recordDuplicateOf(&finding, opts.duplicateOf)
	}
	// The operator's undo (Task 7c): reopening a DUPLICATE clears the recorded
	// merge target — a stale duplicate_of would keep the merge alive for every
	// reader of the dedup block, and the finding is a hypothesis again.
	// Evidence and history stay attached; only the merge pointer goes.
	if fromStatus == "DUPLICATE" && toStatus == "HYPOTHESIS" {
		clearDuplicateOf(&finding)
	}
	// r17 P1: a TERMINAL status without its event is a one-way door —
	// the transition table cannot reopen what the log never recorded,
	// so a refused Log must RESTORE the finding file (SaveThenLog, the
	// findings sibling of the state package's unwind law).
	if err := SaveThenLog(campaign, &finding, func() error {
		return logStatus(campaign, &finding, fromStatus, toStatus,
			reason, actor)
	}); err != nil {
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

// validateDuplicateTarget is the DUPLICATE-target guard: the --of name must
// point at a finding that EXISTS and is not the finding being merged. A ghost
// pointer or a self pointer is the targetless-DUPLICATE dead end wearing an
// id. It runs before anything is written.
func validateDuplicateTarget(campaign *state.Campaign, finding validation.Value,
	target string) error {
	fid := objStr(finding, "finding_id")
	if target == fid {
		return &DuplicateTargetInvalid{Msg: fmt.Sprintf(
			"a finding cannot be merged into itself (--of %s names the "+
				"moving finding)", validation.PyReprStr(target))}
	}
	if _, err := LoadFinding(campaign, target); err != nil {
		return &DuplicateTargetInvalid{Msg: fmt.Sprintf("duplicate of "+
			"target does not exist: %v", err)}
	}
	return nil
}

// mutateStatus writes the status and appends the history row — the in-memory
// half of transition. The caller saves ONCE for the whole move (the dedup
// pointer and its clearing are folded in before this save) and then logs
// finding.status.
func mutateStatus(finding *validation.Value, fromStatus, toStatus, reason,
	actor string) {
	finding.O = validation.SetOrAppend(finding.O, "status", validation.VStr(toStatus))
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
	finding.O = validation.SetOrAppend(finding.O, "history", hist)
}

// logStatus logs finding.status — the campaign-log half of the move, unchanged
// in shape; it only moved to after transition's single save.
func logStatus(campaign *state.Campaign, finding *validation.Value,
	fromStatus, toStatus, reason, actor string) error {
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
	plan.O = validation.SetOrAppend(plan.O, "priorities", priorities)
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
	plan.O = validation.SetOrAppend(plan.O, "lenses", lenses)
	return plannerSavePlanFunc(campaign, plan)
}

// reopenLens applies one lens re-open and logs it.
func reopenLens(campaign *state.Campaign, finding, lens validation.Value,
	hit []string) validation.Value {
	fid := objStr(finding, "finding_id")
	lens.O = validation.SetOrAppend(lens.O, "status", validation.VStr("open"))
	lens.O = validation.SetOrAppend(lens.O, "reopen_reason", validation.VStr(
		fmt.Sprintf("CONFIRMED %s in family %s after %s was closed — re-scan "+
			"the family", fid, strings.Join(hit, ", "), objStr(lens, "lens"))))
	lens.O = validation.SetOrAppend(lens.O, "reopened_at", validation.VStr(nowIso()))
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
		priority.O = validation.SetOrAppend(priority.O, "bug_class",
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
	// R3 (critic): a verdict is a claim about a finding that EXISTS —
	// adjudicate already refuses dead rows for exactly this reason, and
	// verdict must not be the exception that pollutes a SUPERSEDED or
	// DUPLICATE row's verification block with fresh opinions.
	if IsTerminal(objStr(finding, "status")) { // r5: one law, one predicate
		return validation.VNull(), fmt.Errorf(
			"cannot record a critic verdict on terminal finding %s (%s) — "+
				"a verdict is a claim about a finding that exists; the "+
				"successor row carries its own verdict",
			findingID, objStr(finding, "status"))
	}
	ver := asDict(objAt(finding, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "critic_verdict", validation.VStr(verdict))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	meta := asDict(objAt(finding, "dedup_meta"))
	meta.O = validation.SetOrAppend(meta.O, "critic_reasoning", validation.VStr(reasoning))
	finding.O = validation.SetOrAppend(finding.O, "dedup_meta", meta)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move) — file+event land together or not
		// at all.
		data := validation.VObj(validation.KV{K: "verdict", V: validation.VStr(verdict)})
		if _, lerr := campaign.Log("finding.critic", &findingID, &data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// TriagerOutlooks is the SINGLE source of the outlook enum (schema, CLI and
// the acceptance table must all agree with it; the sync assertions in
// risk/acceptance_test.go enforce it — a fourth consumer is forbidden to
// hardcode its own copy).
func TriagerOutlooks() []string { return []string{"likely", "uncertain", "unlikely"} }

// SetTriagerOutlook is the G6 companion of set_critic_verdict: record the
// critic's acceptance-likelihood call — WILL A TRIAGER ACCEPT AND PAY THIS —
// kept structurally separate from critic_verdict (truth) and
// bounty.accepted_risk (policy). Absent field = no call = no score effect.
func SetTriagerOutlook(campaign *state.Campaign, findingID, outcome,
	reason string) (validation.Value, error) {
	// Membership is checked against TriagerOutlooks() — the single source —
	// so a new enum member cannot be accepted by the schema/CLI and still be
	// rejected here (which would fail after SetCriticVerdict already wrote).
	outcomes := TriagerOutlooks()
	member := false
	for _, o := range outcomes {
		if o == outcome {
			member = true
			break
		}
	}
	if !member {
		return validation.VNull(), fmt.Errorf("invalid triager outlook %s "+
			"(choose: %s)", validation.PyReprStr(outcome),
			strings.Join(outcomes, ", "))
	}
	stripped := strings.TrimSpace(reason)
	if len([]rune(stripped)) < 15 {
		return validation.VNull(), fmt.Errorf("triager outlook reasoning must " +
			"be substantive (>= 15 chars) — 'probably fine' is not a call")
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ver := asDict(objAt(finding, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "triager_outlook", validation.VObj(
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "reason", V: validation.VStr(stripped)},
	))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(validation.KV{K: "outcome", V: validation.VStr(outcome)})
		if _, lerr := campaign.Log("finding.triager_outlook", &findingID, &data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
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
	ver.O = validation.SetOrAppend(ver.O, "shield_adjudication", validation.VObj(
		validation.KV{K: "extraction_despite_intent", V: validation.VBool(extracts)},
		validation.KV{K: "reasoning", V: validation.VStr(reasoning)},
		validation.KV{K: "at", V: validation.VStr(nowIso())},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(
			validation.KV{K: "extracts", V: validation.VBool(extracts)},
			validation.KV{K: "actor", V: validation.VStr(actor)},
		)
		if _, lerr := campaign.Log("finding.shield_adjudication", &findingID,
			&data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
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
	p.O = validation.SetOrAppend(p.O, "enforced_by_poc", validation.VStr(value))
	pre := objAt(*finding, "preconditions")
	pre.A[i] = p
	finding.O = validation.SetOrAppend(finding.O, "preconditions", pre)
	fid := objStr(*finding, "finding_id")
	if err := SaveThenLog(campaign, finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(
			validation.KV{K: "description", V: validation.VStr(loggedDesc)},
			validation.KV{K: "enforced", V: validation.VStr(value)},
		)
		if _, lerr := campaign.Log("finding.precondition_audited", &fid,
			&data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
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
	dedup.O = validation.SetOrAppend(dedup.O, "lineage_id", validation.VStr(lineageID))
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// MarkDuplicate is mark_duplicate: transition to DUPLICATE and record which
// finding it duplicates. The recording is transition's targeted-move half, so
// the dedup sweep and `move --of` cannot drift apart.
func MarkDuplicate(campaign *state.Campaign, findingID,
	ofFindingID string) (validation.Value, error) {
	return transition(campaign, findingID, "DUPLICATE",
		"technical/root-cause duplicate of "+ofFindingID,
		transitionOpts{actor: "dedup", duplicateOf: ofFindingID})
}

// recordDuplicateOf writes dedup.duplicate_of on the finding that just became
// a DUPLICATE. It is the only writer of that field. The write is folded into
// the transition's single SaveFinding (mutate here, save in transition) — a
// merge can never land as a durable status without its target.
func recordDuplicateOf(finding *validation.Value, ofFindingID string) {
	dedup := asDict(objAt(*finding, "dedup"))
	dedup.O = validation.SetOrAppend(dedup.O, "duplicate_of",
		validation.VStr(ofFindingID))
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
}

// clearDuplicateOf drops dedup.duplicate_of when a DUPLICATE is reopened. The
// dedup block itself stays (the schema requires it and the signatures in it
// are still true); only the merge pointer is cleared. A finding with nothing
// recorded is left untouched — not even an updated_at stamp beyond the
// transition's own single save. Mutation only; the caller saves once.
func clearDuplicateOf(finding *validation.Value) {
	dedup := asDict(objAt(*finding, "dedup"))
	kept := make([]validation.KV, 0, len(dedup.O))
	for _, kv := range dedup.O {
		if kv.K != "duplicate_of" {
			kept = append(kept, kv)
		}
	}
	if len(kept) == len(dedup.O) {
		return
	}
	dedup.O = kept
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
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
	dedup.O = validation.SetOrAppend(dedup.O, "possible_duplicate_of", lst)
	finding.O = validation.SetOrAppend(finding.O, "dedup", dedup)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(validation.KV{K: "of", V: validation.VStr(ofFindingID)})
		if _, lerr := campaign.Log("finding.possible_duplicate", &findingID,
			&data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
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
