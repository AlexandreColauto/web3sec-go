package findings

import (
	"fmt"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// IllegalTransition is IllegalTransition: raised when a status move violates
// the state machine or its gates.
type IllegalTransition struct{ Msg string }

func (e *IllegalTransition) Error() string { return e.Msg }

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
	fromStatus := validation.ObjStr(finding, "status")
	// A same-status move is a no-op — EXCEPT a targeted re-merge: a DUPLICATE
	// moved to DUPLICATE with a DIFFERENT --of must not exit 0 having
	// silently rewritten (or, worse, here: not rewritten) the recorded merge
	// pointer. The short-circuit therefore routes DUPLICATE through the
	// retarget guard below.
	if toStatus == fromStatus {
		if toStatus != "DUPLICATE" {
			return finding, nil
		}
		recorded := validation.ObjStr(validation.ObjAt(finding, "dedup"), "duplicate_of")
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
	// R3-3 (Morph r3 defect 3): STATUS_FLOOR was enforced ONLY at the
	// CONFIRMED gate — `move --to POSSIBLE` stamped an E0 finding with a
	// word, and a POSSIBLE row reads as human triage the ladder never
	// earned. The floor now gates every target status through the shared
	// deficit builder (ponytail: one guard in the shared writer; the
	// instrument already in the tree, not a new table read). CONFIRMED
	// keeps its richer gate bundle, which carries the same floor clause.
	// The floor is data, not a verdict: it is the same statement the
	// CONFIRMED gate makes, at the moment the stamp is applied.
	if toStatus != "CONFIRMED" {
		if deficit := EvidenceDeficit(finding, toStatus, campaign); deficit != nil {
			return validation.VNull(), &IllegalTransition{Msg: *deficit}
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
	fid := validation.ObjStr(finding, "finding_id")
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
	hist := validation.ObjAt(*finding, "history")
	if hist.Kind != validation.Arr {
		hist = validation.VArr()
	}
	hist.A = append(hist.A, validation.VObj(
		validation.KV{K: "at", V: validation.VStr(state.NowIso())},
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
	fid := validation.ObjStr(*finding, "finding_id")
	_, err := campaign.Log("finding.status", &fid, &data)
	return err
}
