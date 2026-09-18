package boundary

import (
	"fmt"
	"slices"
	"sort"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// validateCriticVerdict is the critic cross-field block.
func validateCriticVerdict(payload validation.Value,
	campaign *state.Campaign) error {
	unknown := unknownRecommendedTools(payload)
	if len(unknown) > 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic verdict recommends unknown tool ids: %s",
			validation.PyListRepr(unknown))}
	}
	if campaign == nil {
		return nil
	}
	fid := validation.ObjStr(payload, "finding_id")
	finding, err := findings.LoadFinding(campaign, fid)
	if err != nil {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic verdict references unknown finding %s",
			validation.PyReprStr(fid))}
	}
	cur := validation.ObjAt(finding, "claim_version")
	claim := validation.ObjAt(payload, "claim_version")
	if cur.Kind != validation.Null && claim.Kind != validation.Null &&
		!valueEq(claim, cur) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"stale critic verdict: addresses claim_version %s but the "+
				"finding is at %s — re-run the critic against the current claim",
			scalarText(claim), scalarText(cur))}
	}
	curByID, ids := assumptionStatuses(finding)
	return validateCriticMoves(payload, campaign, finding, fid, curByID, ids)
}

// unknownRecommendedTools is the sorted distinct recommended_checks tool ids
// the registry does not know.
func unknownRecommendedTools(payload validation.Value) []string {
	unknown := []string{}
	checks := validation.ObjAt(payload, "recommended_checks")
	if checks.Kind != validation.Arr {
		return unknown
	}
	seen := map[string]bool{}
	for _, c := range checks.A {
		if c.Kind != validation.Obj {
			continue
		}
		id := validation.ObjStr(c, "tool_id")
		if !inRegistry(id) && !seen[id] {
			seen[id] = true
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// assumptionStatuses is the finding's current assumption statuses by id, plus
// the sorted id list (Python sorts for the error text).
func assumptionStatuses(finding validation.Value) (map[string]string, []string) {
	curByID := map[string]string{}
	ids := []string{}
	if as := validation.ObjAt(finding, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind == validation.Obj {
				id := validation.ObjStr(a, "id")
				curByID[id] = validation.ObjStr(a, "status")
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return curByID, ids
}

// validateCriticMoves pre-validates every assumption move so apply cannot fail
// halfway (atomicity): unknown ids, illegal transitions, and uncited or
// unresolvable evidence are boundary rejections, not partial applications.
func validateCriticMoves(payload validation.Value, campaign *state.Campaign,
	finding validation.Value, fid string, curByID map[string]string,
	ids []string) error {
	legal := map[string][]string{
		"UNKNOWN":   {"SUPPORTED", "REFUTED"},
		"SUPPORTED": {"REFUTED"},
		"REFUTED":   {"SUPPORTED"},
	}
	per := validation.ObjAt(payload, "per_assumption")
	if per.Kind != validation.Arr {
		return nil
	}
	for _, entry := range per.A {
		if entry.Kind != validation.Obj {
			continue
		}
		if err := validateCriticMove(entry, campaign, finding, fid, curByID,
			ids, legal); err != nil {
			return err
		}
	}
	return nil
}

// validateCriticMove is one per_assumption entry.
func validateCriticMove(entry validation.Value, campaign *state.Campaign,
	finding validation.Value, fid string, curByID map[string]string,
	ids []string, legal map[string][]string) error {
	aid := validation.ObjStr(entry, "assumption_id")
	fromStatus, known := curByID[aid]
	if !known {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic entry names assumption %s which is not an "+
				"assumption of %s (ids: %s)", validation.PyReprStr(aid),
			fid, validation.PyListRepr(ids))}
	}
	status := validation.ObjStr(entry, "status")
	if status == fromStatus {
		return nil
	}
	if !slices.Contains(legal[fromStatus], status) {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic entry for %s: %s -> %s is not a legal assumption move",
			aid, fromStatus, status)}
	}
	cited := validation.ObjAt(entry, "evidence_cited")
	if status == "UNKNOWN" {
		if cited.Kind == validation.Arr && len(cited.A) > 0 {
			return &BoundaryError{Msg: fmt.Sprintf(
				"critic entry for %s is UNKNOWN but cites evidence — "+
					"UNKNOWN is a claim of not-yet-checked, not a citation",
				aid)}
		}
		return nil
	}
	if cited.Kind != validation.Arr || len(cited.A) == 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"critic entry for %s moves the assumption without citing "+
				"evidence — the boundary does not trust belief", aid)}
	}
	for _, ref := range cited.A {
		if ref.Kind != validation.Str {
			continue
		}
		if err := findings.ResolveEvidenceRef(campaign, finding,
			ref.S); err != nil {
			return &BoundaryError{Msg: fmt.Sprintf(
				"critic entry for %s cites evidence the store does "+
					"not have: %v", aid, err)}
		}
	}
	return nil
}
