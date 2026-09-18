// Package briefing is webv2.briefing: the operator cockpit — one
// deterministic synthesis of the whole campaign, plus the attention ledger
// and the concrete prioritized next_actions list.
//
// Discipline (I1): this is a PURE VIEW. It mutates nothing — no phase
// moves, no stage ledger writes, no gate saves, no minting, no log events.
// The bounty gate runs with save=False; everything else is a load. A brief
// must be safe to run at any point, in any state, including an empty
// campaign.
package briefing

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// BuildBrief is build_brief: the full briefing. The former single body now
// drives the phase helpers in briefing_build.go, in the original order —
// each failure aborts the brief exactly as before.
func BuildBrief(campaign *state.Campaign, deepAudit bool,
	now *string) (validation.Value, error) {
	b, err := briefLoadBase(campaign, deepAudit, now)
	if err != nil {
		return validation.VNull(), err
	}
	b.collectProblems()

	hunt, err := b.huntSections()
	if err != nil {
		return validation.VNull(), err
	}

	brief, err := b.assembleBrief(hunt)
	if err != nil {
		return validation.VNull(), err
	}

	if err := b.setIntegrity(&brief); err != nil {
		return validation.VNull(), err
	}
	if err := b.setDivergence(&brief); err != nil {
		return validation.VNull(), err
	}
	b.setProbeSurface(&brief)
	b.setSurfaceLines(&brief)
	b.setDispositionReview(&brief)
	if err := b.setCriticality(&brief); err != nil {
		return validation.VNull(), err
	}
	if err := b.setAttention(&brief); err != nil {
		return validation.VNull(), err
	}
	if err := b.setNextActions(&brief); err != nil {
		return validation.VNull(), err
	}
	return brief, nil
}
