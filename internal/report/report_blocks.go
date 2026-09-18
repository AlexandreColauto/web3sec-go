// Protocol-model artifact blocks: the G9 tracked-but-opaque component
// surfaces and the G10 per-hop chain assumption table, both read from
// protocol_model.json and presence-gated.
package report

import (
	"path/filepath"

	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

// componentSurfacesBlock is the G9 tracked-but-opaque surfaces block: one
// line per protocol-model component (`- <kind> <path|url>:
// <in_scope|out-of-scope><, paid>`, via protocolgraph.ComponentSurfaceLines).
// Presence-gated (the additive convention): nil unless the campaign's
// model file exists AND carries a non-empty components list, so a
// component-free campaign gains no bytes. Findings may anchor on these
// surfaces; structidx never indexes them.
func componentSurfacesBlock(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if !fileExists(modelPath) {
		return nil
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return nil
	}
	lines := protocolgraph.ComponentSurfaceLines(model)
	if len(lines) == 0 {
		return nil
	}
	L := []string{"## Tracked-but-opaque surfaces", "",
		"> These surfaces are tracked for findings but opaque to " +
			"structidx: never indexed, never prescreened.", ""}
	L = append(L, lines...)
	L = append(L, "")
	return L
}

// chainAssumptionsBlock is the G10 per-hop assumption table: one line per
// AssumptionTable row plus one per gap, via the shared
// protocolgraph.RenderAssumptionLines builder (the same bytes the brief
// renders, so the two can never drift apart).
//
// Presence-gated (the Task 4 law, the additive convention): nil unless
// len(rows) > 0 AND (any row carries a non-null detail OR len(gaps) > 0),
// so a chains-only legacy campaign gains no bytes. A row carries detail
// when any non-chain field is non-null.
func chainAssumptionsBlock(campaign *state.Campaign) []string {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if !fileExists(modelPath) {
		return nil
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return nil
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
	lines := protocolgraph.RenderAssumptionLines(rows, gaps)
	if len(lines) == 0 {
		return nil
	}
	L := []string{"## Chain assumptions", "",
		"> Declared per-hop assumptions; gaps mark hops whose endpoints " +
			"declare nothing.", ""}
	L = append(L, lines...)
	L = append(L, "")
	return L
}
