// slot.go: the discovery-slot charge point. Suspicion is free; the budget
// meters the moment a finding first RISES above the E0 baseline — the first
// above-E0 evidence or the first status promotion whose floor is above E0.
// The counter, its ceiling, and both key names are the pre-reform ones; only
// the charge point (and one display word) moved.
package findings

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// ConsumeSlotOnce charges the campaign's discovery budget for one finding,
// exactly once per finding, and only when the caller has established the
// finding ROSE above the E0 baseline. Bare hypotheses (HYPOTHESIS at E0 with
// no above-baseline evidence) never reach this — suspicion is free, the
// ceiling meters confirmed work instead. The finding carries the flag so the
// idempotency survives snapshots and re-loads.
func ConsumeSlotOnce(campaign *state.Campaign, finding *validation.Value) error {
	if objBool(*finding, "discovery_slot_consumed") {
		return nil
	}
	budget, err := campaign.Budget()
	if err != nil {
		return err
	}
	if objAt(budget, "discovery_findings_so_far").I >=
		objAt(budget, "max_discovery_findings").I {
		return fmt.Errorf("%s",
			"discovery budget exhausted — raise the ceiling (webv2 budget "+
				campaign.CampaignID+" --set-discovery N --actor NAME) or plan a new pass")
	}
	if err := campaign.ConsumeDiscoverySlot(); err != nil {
		return err
	}
	finding.O = validation.SetOrAppend(finding.O,
		"discovery_slot_consumed", validation.VBool(true))
	return nil
}

// risesAboveBaseline reports whether adding an item of this level (or
// promoting to this status) lifts the finding above E0 for the first time.
func risesAboveBaseline(finding validation.Value, level string) bool {
	li, err := LevelIndex(level)
	if err != nil {
		return false
	}
	e0, _ := LevelIndex("E0")
	if li <= e0 {
		return false
	}
	for _, it := range objAt(finding, "evidence").A {
		prev, err := LevelIndex(objStr(it, "level"))
		if err == nil && prev > e0 {
			return false // already rose before
		}
	}
	return !objBool(finding, "discovery_slot_consumed")
}

// statusBaselineIndex is the ladder position a STATUS occupies: the floor the
// status demands (STATUS_FLOOR). A status with no row — the terminal junk
// states (DISPROVED, DUPLICATE, OUT_OF_SCOPE, INFORMATIONAL, SUPERSEDED) —
// sits at the E0 baseline, so moving there is never a rise.
func statusBaselineIndex(status string) int {
	level, ok := STATUS_FLOOR[status]
	if !ok {
		return 0
	}
	i, err := LevelIndex(level)
	if err != nil {
		return 0
	}
	return i
}
