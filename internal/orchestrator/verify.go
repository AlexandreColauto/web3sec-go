// verify.go: phase 11 (INDEPENDENT_VERIFICATION).
package orchestrator

import (
	"sort"

	"websec/internal/findings"
	"websec/internal/validation"
)

// IndependentVerificationQueue is independent_verification_queue(): confirmed
// findings that still lack E6, ordered so the classes whose CONFIRMED floor IS
// E6 come first, then everything else confirmed (defence in depth).
//
// Pure view: listing the queue must not mutate the phase or stage ledger —
// `verify --queue` is a read, not a run. `mandatory` follows the CAMPAIGN's
// effective floor: a finding already at/above its class's floor needs no
// further verification to be gate-complete.
func (o *Orchestrator) IndependentVerificationQueue() (validation.Value, error) {
	all, err := findings.LoadAllFindings(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	out := []validation.Value{}
	for _, f := range all {
		status := strAt(f, "status")
		if status != "CONFIRMED" && status != "CHAIN" {
			continue
		}
		level, err := findings.FindingLevel(f)
		if err != nil {
			return validation.VNull(), err
		}
		if level == "E6" || level == "E7" {
			continue
		}
		class := strAt(asDict(validation.ObjAt(f, "root_cause")), "class")
		floor := findings.RequiredLevelForCampaign(o.C, "CONFIRMED", class)
		floorIdx, err := findings.LevelIndex(floor)
		if err != nil {
			return validation.VNull(), err
		}
		levelIdx, err := findings.LevelIndex(level)
		if err != nil {
			return validation.VNull(), err
		}
		out = append(out, validation.VObj(
			kvOf("finding_id", validation.ObjAt(f, "finding_id")),
			kvOf("title", validation.ObjAt(f, "title")),
			kvOf("evidence_level", validation.VStr(level)),
			kvOf("bug_class", validation.VStr(class)),
			kvOf("effective_floor", validation.VStr(floor)),
			kvOf("mandatory", validation.VBool(floorIdx > levelIdx)),
		))
	}
	// key = (not mandatory, evidence_level): mandatory first, then by level.
	sort.SliceStable(out, func(i, j int) bool {
		mi, mj := boolAt(out[i], "mandatory"), boolAt(out[j], "mandatory")
		if mi != mj {
			return mi
		}
		return strAt(out[i], "evidence_level") < strAt(out[j], "evidence_level")
	})
	return valueArr(out), nil
}

// VerifyIndependently is verify_independently(): record an independent
// reproduction (E6). The verifier must be a different named identity running a
// different execution than the one that produced the original evidence —
// reproduction.py enforces it.
func (o *Orchestrator) VerifyIndependently(findingID, execID, description,
	verifier string) (validation.Value, error) {
	out, err := rpAPI.MintIndependentEvidence(o.C, findingID, execID,
		description, verifier)
	if err != nil {
		return validation.VNull(), err
	}
	reason := findingID + " verified"
	if err := o.C.SetPhase("INDEPENDENT_VERIFICATION", reason); err != nil {
		return validation.VNull(), err
	}
	st, err := o.C.State()
	if err != nil {
		return validation.VNull(), err
	}
	stage := validation.ObjAt(validation.ObjAt(st, "stages"), "independent-reproduction")
	status := validation.ObjAt(stage, "status")
	open := status.Kind == validation.Null ||
		(status.Kind == validation.Str &&
			(status.S == "pending" || status.S == "needs-model"))
	if open {
		note := findingID + " verified by " + verifier
		if err := o.C.SetStage("independent-reproduction", "done",
			validation.VStr(note), ptr("model")); err != nil {
			return validation.VNull(), err
		}
	}
	return out, nil
}
