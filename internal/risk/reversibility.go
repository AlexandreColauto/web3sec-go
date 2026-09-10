// reversibility.go: the victim-perspective recoverability classification
// (IMPROVEMENTS E5). A finding whose damage the victim can never undo is a
// different class of bug from one a trusted party might repair — the
// validated_risk formula now carries that distinction as a named weight.
package risk

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ReversibilityModes is the closed set for finding.risk.reversibility.
var ReversibilityModes = []string{"irreversible", "trusted-party", "reversible"}

// RecordReversibility is record_reversibility: classify (or, with mode
// "none", clear) the finding's victim-perspective recoverability, then
// recalibrate so the validated score and band pick up the new weight. The
// decision is DATA on the finding (risk.reversibility) and is logged as one
// finding.reversibility_set event — the same discipline as
// findings.UnpriceableDecision and floors.set_floor_policy: a hand-edited
// field is visible next to the event trail that set it.
func RecordReversibility(campaign *state.Campaign, findingID, mode string) (validation.Value, error) {
	mode = pyStrip(mode)
	if mode != "" && mode != "none" {
		if _, ok := wReversibility[mode]; !ok {
			return validation.VNull(), fmt.Errorf(
				"reversibility must be one of %s (or 'none' to clear)",
				strings.Join(ReversibilityModes, ", "))
		}
	}
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ri, err := ensureObjField(&f.O, "risk")
	if err != nil {
		return validation.VNull(), err
	}
	riskV := f.O[ri].V
	cleared := false
	if mode == "" || mode == "none" {
		if _, had := fieldAt(riskV, "reversibility"); had {
			cleared = true
		}
		riskV.O = popKey(riskV.O, "reversibility")
	} else {
		riskV.O = validation.SetOrAppend(riskV.O, "reversibility", validation.VStr(mode))
	}
	f.O[ri].V = riskV
	if err := findings.SaveFinding(campaign, &f); err != nil {
		return validation.VNull(), err
	}
	if _, err := Calibrate(campaign, findingID); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "mode", V: validation.VStr(mode)},
		validation.KV{K: "cleared", V: validation.VBool(cleared)},
	)
	if _, err := campaign.Log("finding.reversibility_set", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return findings.LoadFinding(campaign, findingID)
}
