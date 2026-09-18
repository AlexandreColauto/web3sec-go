package briefing

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/protocolgraph"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- bounty view -----------------------------------------------------------

// Bounty is _bounty: CONFIRMED findings through the gate (save=False — the
// brief must not write).
func Bounty(campaign *state.Campaign) (validation.Value, error) {
	st, err := campaign.State()
	if err != nil {
		return validation.VNull(), err
	}
	policyPath := validation.ObjStr(st, "policy_path")
	if policyPath == "" {
		return validation.VObj(kv("policy", validation.VNull()),
			kv("evaluated", validation.VArr())), nil
	}
	// r45: an unreadable policy file is NOT an absent policy. NotExist keeps
	// rendering policy:null (a campaign with no policy loaded); any other
	// stat error refuses naming the path, instead of claiming the operator
	// never loaded one.
	if _, serr := os.Stat(policyPath); serr != nil {
		if !os.IsNotExist(serr) {
			return validation.VNull(), fmt.Errorf(
				"the bounty policy %s cannot be read: %v", policyPath, serr)
		}
		return validation.VObj(kv("policy", validation.VNull()),
			kv("evaluated", validation.VArr())), nil
	}
	policy, err := bounty.LoadPolicy(policyPath)
	if err != nil {
		return validation.VNull(), err
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	type pair struct {
		key risk.WorkOrderKey
		row validation.Value
	}
	rows := []pair{}
	for _, f := range all {
		if !confirmedStatuses[validation.ObjStr(f, "status")] {
			continue
		}
		res, err := bounty.EvaluateBountyGate(campaign,
			validation.ObjStr(f, "finding_id"), policy, false)
		if err != nil {
			return validation.VNull(), err
		}
		blocking := listAt(res, "blocking_reasons")
		if blocking == nil {
			blocking = []validation.Value{}
		}
		key, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return validation.VNull(), err
		}
		rows = append(rows, pair{key, validation.VObj(
			kv("finding_id", validation.ObjAt(f, "finding_id")),
			kv("title", validation.ObjAt(f, "title")),
			kv("eligible", validation.ObjAt(res, "eligible")),
			kv("submission_ready", validation.ObjAt(res, "submission_ready")),
			kv("blocking_reasons", validation.VArr(blocking...)))})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i].key.Less(rows[j].key)
	})
	evaluated := make([]validation.Value, len(rows))
	for i, r := range rows {
		evaluated[i] = r.row
	}
	return validation.VObj(kv("policy", validation.VStr(filepath.Base(policyPath))),
		kv("evaluated", validation.VArr(evaluated...))), nil
}

// TrackedSurfaces is the G9 opaque-surface view: one display line per
// protocol-model component (`- <kind> <path|url>:
// <in_scope|out-of-scope><, paid>`, via protocolgraph.ComponentSurfaceLines).
// A missing model file (or a model with no components) yields no lines —
// the caller presence-gates on len, so a component-free campaign's brief
// bytes are unchanged. Findings may anchor on these surfaces; structidx
// never indexes them.
//
// r45a: a model that EXISTS but could not be read is NOT "no components": the
// old body returned nil for every stat/ReadJson error, so `chmod 000
// protocol_model.json` made the whole block disappear from the cockpit. The
// read failure is now a named UNAVAILABLE line this caller prints in place of
// the block; genuine absence still yields no lines at all.
func TrackedSurfaces(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	const what = "tracked surfaces unknown, not absent"
	if _, err := os.Stat(modelPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	return protocolgraph.ComponentSurfaceLines(model)
}

// ChainAssumptions is the G10 assumption-table view: one display line per
// AssumptionTable row plus one per gap, via the shared
// protocolgraph.RenderAssumptionLines builder (the same bytes the report
// renders, so the two can never drift apart).
//
// Presence-gated (the Task 4 law): the block renders ONLY when
// len(rows) > 0 AND (any row carries a non-null detail OR len(gaps) > 0).
// A row carries detail when any non-chain field is non-null. A chains-only
// legacy model (no assumptions, no BRIDGES-touch gaps) yields no lines —
// the caller gates on len, so a legacy campaign's brief bytes are
// unchanged. Findings never anchor on these lines; structidx never indexes
// them.
//
// r45a: a model that EXISTS but could not be read must not render as "no
// assumptions declared" — the same fold as TrackedSurfaces above, with the
// same fix: a named UNAVAILABLE line instead of a silently missing section.
func ChainAssumptions(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	const what = "the assumption table is unknown, not empty"
	if _, err := os.Stat(modelPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return []string{unavailableLine("protocol_model.json", err, what)}
	}
	rows, gaps := protocolgraph.AssumptionTable(model)
	if len(rows) == 0 {
		return nil
	}
	hasDetail := false
	for _, r := range rows {
		for _, pair := range r.O {
			if pair.K == "chain" {
				continue
			}
			if pair.V.Kind != validation.Null {
				hasDetail = true
				break
			}
		}
		if hasDetail {
			break
		}
	}
	if !hasDetail && len(gaps) == 0 {
		return nil
	}
	return protocolgraph.RenderAssumptionLines(rows, gaps)
}
