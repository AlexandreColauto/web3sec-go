// assumptions.go: set_assumptions / assumption_transition /
// _assumption_by_id / _resolve_evidence_ref (webv2.findings).
//
// Invariant (enforced here, not by convention): an assumption's `status` can
// only move off UNKNOWN when the transition is passed at least one
// artifact/exec/evidence id that EXISTS in the campaign's evidence store.
// `model_belief` is advisory — it is recorded for training data, never
// consulted here. A transition without store-provenance raises, full stop.
package findings

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// SetAssumptions is set_assumptions: install (replace) the finding's
// assumption set. A freshly installed set must be all-UNKNOWN with empty
// support/contradictions — evidence-backed status is only ever REACHED
// through AssumptionTransition, which hard-checks store provenance.
// claimVersion nil is Python's claim_version=None.
func SetAssumptions(campaign *state.Campaign, findingID string,
	assumptions []validation.Value, claimVersion *int64,
	actor string) (validation.Value, error) {
	if actor == "" {
		actor = "proposer"
	}
	seen := map[string]struct{}{}
	for _, a := range assumptions {
		if err := validation.Validate(a, "assumption", 1); err != nil {
			return validation.VNull(), err
		}
		id := objStr(a, "id")
		if _, dup := seen[id]; dup {
			return validation.VNull(), fmt.Errorf("duplicate assumption id %s", id)
		}
		seen[id] = struct{}{}
	}
	if err := checkFreshAssumptions(assumptions, seen); err != nil {
		return validation.VNull(), err
	}
	installed := make([]validation.Value, len(assumptions))
	for i, a := range assumptions {
		installed[i] = withAssumptionDefaults(a)
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	finding.O = validation.SetOrAppend(finding.O, "assumptions",
		validation.VArr(installed...))
	if claimVersion != nil {
		if *claimVersion < 1 {
			return validation.VNull(), fmt.Errorf(
				"claim_version must be an integer >= 1")
		}
		finding.O = validation.SetOrAppend(finding.O, "claim_version",
			validation.VInt(*claimVersion))
	}
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	ids := sortedSetKeys(seen)
	data := validation.VObj(
		validation.KV{K: "count", V: validation.VInt(int64(len(assumptions)))},
		validation.KV{K: "ids", V: strArr(ids)},
		validation.KV{K: "claim_version", V: objAt(finding, "claim_version")},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)
	if _, err := campaign.Log("finding.assumptions", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// checkFreshAssumptions enforces the install-time invariants: UNKNOWN status,
// no support/contradictions, and dependencies that name a known id.
func checkFreshAssumptions(assumptions []validation.Value,
	seen map[string]struct{}) error {
	for _, a := range assumptions {
		id := objStr(a, "id")
		if st := objStr(a, "status"); st != "UNKNOWN" {
			return fmt.Errorf("assumption %s installed with status %s: new "+
				"assumptions start UNKNOWN; move them only through "+
				"assumption_transition with evidence-store provenance", id, st)
		}
		if pyTruthy(objAt(a, "support")) || pyTruthy(objAt(a, "contradictions")) {
			return fmt.Errorf("assumption %s installed with "+
				"support/contradictions: only the transition API may write "+
				"those", id)
		}
		deps := objAt(a, "dependencies")
		if deps.Kind != validation.Arr {
			continue
		}
		for _, dep := range deps.A {
			if _, ok := seen[dep.S]; !ok {
				return fmt.Errorf("assumption %s depends on unknown id %s",
					id, dep.S)
			}
		}
	}
	return nil
}

// withAssumptionDefaults is the Python setdefault loop, in the same key order.
func withAssumptionDefaults(a validation.Value) validation.Value {
	for _, k := range []string{"dependencies", "verification_options",
		"support", "contradictions"} {
		if _, ok := fieldAt(a, k); !ok {
			a.O = append(a.O, validation.KV{K: k, V: validation.VArr()})
		}
	}
	return a
}

// assumptionByID is _assumption_by_id.
func assumptionByID(finding validation.Value, assumptionID string) (validation.Value, error) {
	assumptions := objAt(finding, "assumptions")
	for _, a := range assumptions.A {
		if objStr(a, "id") == assumptionID {
			return a, nil
		}
	}
	ids := make([]string, 0, len(assumptions.A))
	for _, a := range assumptions.A {
		if a.Kind == validation.Obj {
			ids = append(ids, validation.PyReprStr(objStr(a, "id")))
		}
	}
	return validation.VNull(), fmt.Errorf("%s is not an assumption of this "+
		"finding (ids: [%s])", assumptionID, joinRaw(ids))
}

func joinRaw(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// resolveEvidenceRef is _resolve_evidence_ref: resolve one evidence reference
// to a real object in the campaign's evidence store. Returns which kind it
// was; a hallucinated citation is a rejection, not a warning.
func resolveEvidenceRef(campaign *state.Campaign, finding validation.Value,
	refID string) (string, error) {
	for _, e := range objAt(finding, "evidence").A {
		if objStr(e, "evidence_id") == refID || objStr(e, "artifact_id") == refID {
			return "evidence", nil
		}
	}
	if _, err := campaign.Artifact(refID); err == nil {
		return "artifact", nil
	}
	execs, err := state.AllExecs(campaign)
	if err != nil {
		return "", err
	}
	for _, rec := range execs {
		if objStr(rec, "exec_id") == refID {
			return "exec", nil
		}
	}
	return "", fmt.Errorf("evidence reference %s does not exist in the "+
		"campaign evidence store (no evidence item, registered artifact, or "+
		"EXEC record) — an assumption status can never move on model_belief "+
		"or a bare claim", validation.PyReprStr(refID))
}

// checkAssumptionMove is the move table plus the provenance hard-stop: a move
// off UNKNOWN without evidence ids is refused before anything is resolved.
func checkAssumptionMove(assumptionID, fromStatus, toStatus string,
	evidenceIDs []string) error {
	switch toStatus {
	case "UNKNOWN", "SUPPORTED", "REFUTED":
	default:
		return &IllegalTransition{Msg: fmt.Sprintf(
			"invalid assumption status %s", validation.PyReprStr(toStatus))}
	}
	if _, ok := assumptionLegalMoves[fromStatus][toStatus]; !ok {
		return &IllegalTransition{Msg: fmt.Sprintf(
			"assumption %s: %s -> %s is not a legal move (legal: %s)",
			assumptionID, fromStatus, toStatus,
			listRepr(sortedSetKeys(assumptionLegalMoves[fromStatus])))}
	}
	if toStatus != "UNKNOWN" && len(evidenceIDs) == 0 {
		return &IllegalTransition{Msg: fmt.Sprintf(
			"assumption %s: %s -> %s with no evidence ids — status can only "+
				"move on store-proven evidence, never on model_belief alone",
			assumptionID, fromStatus, toStatus)}
	}
	return nil
}

// resolveEvidenceKinds resolves every reference against the store (a
// hallucinated citation is a rejection, not a warning).
func resolveEvidenceKinds(campaign *state.Campaign, finding validation.Value,
	evidenceIDs []string) ([]string, error) {
	kinds := make([]string, 0, len(evidenceIDs))
	for _, ref := range evidenceIDs {
		kind, err := resolveEvidenceRef(campaign, finding, ref)
		if err != nil {
			return nil, err
		}
		kinds = append(kinds, kind)
	}
	return kinds, nil
}

// assumptionLegalMoves is the Python `legal` table.
var assumptionLegalMoves = map[string]map[string]struct{}{
	"UNKNOWN":   setOf("SUPPORTED", "REFUTED"),
	"SUPPORTED": setOf("REFUTED"),
	"REFUTED":   setOf("SUPPORTED"),
}

// AssumptionTransition is assumption_transition: the ONLY way an assumption's
// status changes. Every move off UNKNOWN requires evidenceIDs that EXIST in
// the campaign evidence store, checked hard against the store, never against
// the caller's word.
func AssumptionTransition(campaign *state.Campaign, findingID, assumptionID,
	toStatus string, evidenceIDs []string,
	actor string) (validation.Value, error) {
	if actor == "" {
		actor = "orchestrator"
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	assumption, err := assumptionByID(finding, assumptionID)
	if err != nil {
		return validation.VNull(), err
	}
	fromStatus := objStr(assumption, "status")
	if err := checkAssumptionMove(assumptionID, fromStatus, toStatus,
		evidenceIDs); err != nil {
		return validation.VNull(), err
	}
	kinds, err := resolveEvidenceKinds(campaign, finding, evidenceIDs)
	if err != nil {
		return validation.VNull(), err
	}
	if toStatus != "UNKNOWN" {
		assumption = recordAssumptionEvidence(assumption, toStatus, evidenceIDs)
		finding.O = replaceAssumption(finding, assumptionID, assumption)
	} else if len(evidenceIDs) == 0 {
		// re-opening to UNKNOWN is legal (new evidence invalidated the
		// earlier read) but still needs provenance so it is auditable.
		return validation.VNull(), &IllegalTransition{Msg: fmt.Sprintf(
			"assumption %s: re-opening to UNKNOWN requires the evidence id "+
				"that forced the re-open", assumptionID)}
	}
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	ids := make([]validation.Value, len(evidenceIDs))
	for i, s := range evidenceIDs {
		ids[i] = validation.VStr(s)
	}
	data := validation.VObj(
		validation.KV{K: "assumption", V: validation.VStr(assumptionID)},
		validation.KV{K: "from", V: validation.VStr(fromStatus)},
		validation.KV{K: "to", V: validation.VStr(toStatus)},
		validation.KV{K: "evidence_ids", V: validation.VArr(ids...)},
		validation.KV{K: "kinds", V: strArr(kinds)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
		validation.KV{K: "claim_version", V: objAt(finding, "claim_version")},
	)
	if _, err := campaign.Log("finding.assumption_transition", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// recordAssumptionEvidence appends the refs to support/contradictions (never
// twice) and sets the new status.
func recordAssumptionEvidence(assumption validation.Value, toStatus string,
	evidenceIDs []string) validation.Value {
	key := "contradictions"
	if toStatus == "SUPPORTED" {
		key = "support"
	}
	lst := objAt(assumption, key)
	if lst.Kind != validation.Arr {
		lst = validation.VArr()
	}
	have := map[string]struct{}{}
	for _, e := range lst.A {
		if e.Kind == validation.Str {
			have[e.S] = struct{}{}
		}
	}
	for _, ref := range evidenceIDs {
		if _, ok := have[ref]; !ok {
			lst.A = append(lst.A, validation.VStr(ref))
			have[ref] = struct{}{}
		}
	}
	assumption.O = validation.SetOrAppend(assumption.O, key, lst)
	assumption.O = validation.SetOrAppend(assumption.O, "status", validation.VStr(toStatus))
	return assumption
}

// replaceAssumption writes the mutated assumption back into the finding's
// assumptions list (Value is a copy; Python mutates the dict in place).
func replaceAssumption(finding validation.Value, assumptionID string,
	updated validation.Value) []validation.KV {
	assumptions := objAt(finding, "assumptions")
	for i, a := range assumptions.A {
		if objStr(a, "id") == assumptionID {
			assumptions.A[i] = updated
			break
		}
	}
	return validation.SetOrAppend(finding.O, "assumptions", assumptions)
}
