// autotune.go (G17 tactic batting average): policy-gated
// auto-deprioritization of statistically dead lenses.
//
// A lens trips when its verdict record is deep enough to trust and bad
// enough to act on:
//
//	policy.auto_tune (default false) AND n_planned >= 10 AND
//	wilson.upper(confirmed / n_planned) < 0.10
//
// A tripped lens's unstarted slots (the queue rows — WorkQueue already
// drops answered / not-applicable / deprioritized, so every row it emits
// is unstarted) demote to park with the reason line. Flag OFF (or no
// tripped lens, or no demotable row) leaves the queue byte-identical.
//
// Counts come from costs.LensYield — the T22 join, one source of truth
// shared with the briefing's batting-average render. ALL CI math goes
// through wilson (Interval for the gate, UpperPct for the reason text).
package planner

import (
	"fmt"
	"sort"

	"websec/internal/bounty"
	"websec/internal/costs"
	"websec/internal/state"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// AutoTuneMinPlanned is the depth floor: fewer planned verdicts than this
// and the record is too thin to trust, however bad it looks.
const AutoTuneMinPlanned = 10

// AutoTuneMaxUpper is the performance ceiling: the lens parks only when
// the Wilson 95% upper bound of confirmed/planned sits below this —
// precision this bad is evidence, not noise.
const AutoTuneMaxUpper = 0.10

// trippedLenses resolves the G17 gate: lens id -> reason line for every
// tripped lens. Nil when the policy flag is off (the common case — golden
// campaigns never set it) or when no lens trips. A LensYield failure
// propagates: a corrupt attribution store must not silently pass as a
// clean record.
func trippedLenses(campaign *state.Campaign) (map[string]string, error) {
	if !bounty.AutoTuneForCampaign(campaign) {
		return nil, nil
	}
	rows, err := costs.LensYield(campaign)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		lens := objStr(r, "lens")
		if lens == "" || lens == "unattributed" {
			continue
		}
		planned := int(numAt(r, "n_planned"))
		confirmed := int(numAt(r, "n_confirmed"))
		if planned < AutoTuneMinPlanned {
			continue
		}
		if _, hi := wilson.Interval(confirmed, planned); hi >=
			AutoTuneMaxUpper {
			continue
		}
		out[lens] = fmt.Sprintf("- lens %s: auto-deprioritized "+
			"(%d/%d confirmed, 95%% CI upper %s%%)", lens, confirmed,
			planned, wilson.UpperPct(confirmed, planned))
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// applyAutoTune demotes tripped lenses' unstarted queue rows to park. It
// returns true when at least one row moved (the caller then re-sorts with
// the deterministic order). Rows already parked are not touched: they
// were not demoted by this gate, so they carry no reason line.
func applyAutoTune(out []validation.Value, plan validation.Value,
	campaign *state.Campaign, tripped map[string]string) bool {
	rowLens := costs.ProbeRowLens(campaign)
	known := map[string]bool{}
	for _, l := range listOf(plan, "lenses") {
		known[objStr(l, "id")] = true
	}
	prioLens := map[string]string{}
	lensOfRow := map[int]string{}
	for _, p := range listOf(plan, "priorities") {
		prioLens[objStr(p, "id")] = costs.PrioLensBucket(p, rowLens,
			known)
	}
	moved := false
	for i, row := range out {
		if objStr(row, "slot") == "park" {
			continue
		}
		lens := prioLens[objStr(row, "priority_id")]
		reason, ok := tripped[lens]
		if !ok {
			continue
		}
		out[i].O = validation.SetOrAppend(out[i].O, "slot",
			validation.VStr("park"))
		out[i].O = validation.SetOrAppend(out[i].O, "reason",
			validation.VStr(reason))
		lensOfRow[i] = lens
		moved = true
	}
	if !moved {
		return false
	}
	// Deterministic order: the standing (slot, -risk) rule, then L-id,
	// then priority id — parked-last falls out of the slot order, and
	// the tail tiebreaks make the demoted block total (no stability
	// residue from the input order).
	order := map[string]int{"now": 0, "next": 1, "batch": 2, "park": 3}
	sort.SliceStable(out, func(i, j int) bool {
		si := order[objStr(out[i], "slot")]
		sj := order[objStr(out[j], "slot")]
		if si != sj {
			return si < sj
		}
		ri, rj := numAt(out[i], "risk"), numAt(out[j], "risk")
		if ri != rj {
			return ri > rj
		}
		li, lj := lensOfRow[i], lensOfRow[j]
		if li != lj {
			return li < lj
		}
		return objStr(out[i], "priority_id") <
			objStr(out[j], "priority_id")
	})
	return true
}
