// ingest_evidence.go: add_evidence — the post-mint evidence append and its
// gates (webv2.findings).
package findings

import (
	"fmt"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// AddEvidence is add_evidence: append one evidence item to a finding.
func AddEvidence(campaign *state.Campaign, findingID string,
	item validation.Value) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if inSet(TERMINAL, validation.ObjStr(finding, "status")) {
		return validation.VNull(), fmt.Errorf("finding %s is terminal (%s); "+
			"record post-mortem notes via learning.reflection_entry instead",
			findingID, validation.ObjStr(finding, "status"))
	}
	if a, ok := fieldAt(item, "artifact_id"); ok &&
		a.Kind != validation.Null && a.Kind != validation.Str {
		return validation.VNull(), fmt.Errorf(
			"evidence artifact_id must be a string or omitted")
	}
	it := validation.Value{Kind: validation.Obj,
		O: append([]validation.KV(nil), item.O...)}
	if pa, ok := fieldAt(it, "produced_at"); !ok ||
		pa.Kind == validation.Null {
		it.O = validation.SetOrAppend(it.O, "produced_at", validation.VStr(state.NowIso()))
	}
	if err := validateEvidenceItem(it); err != nil {
		return validation.VNull(), err
	}
	level := validation.ObjStr(it, "level")
	if err := checkExecGate(campaign, findingID, it, false); err != nil {
		return validation.VNull(), err
	}
	li, err := LevelIndex(level)
	if err != nil {
		return validation.VNull(), err
	}
	e4 := levelIndexValue("E4")
	if li >= e4 {
		if _, err := snapshot.AssertSnapshotCompatible(campaign, finding,
			true); err != nil {
			return validation.VNull(), err
		}
	}
	if err := enforceRiseGuardrail(campaign, finding, level, ""); err != nil {
		return validation.VNull(), err
	}
	// The first piece of evidence above the E0 baseline is the finding's
	// rise: it pays the discovery slot once (the flag on the finding makes
	// every later add free). Level-neutral adds pay nothing.
	if risesAboveBaseline(finding, level) {
		if err := ConsumeSlotOnce(campaign, &finding); err != nil {
			return validation.VNull(), err
		}
	}
	ev := validation.ObjAt(finding, "evidence")
	ev.A = append(ev.A, it)
	finding.O = validation.SetOrAppend(finding.O, "evidence", ev)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "evidence_id", V: validation.ObjAt(it, "evidence_id")},
		validation.KV{K: "level", V: validation.VStr(level)},
		validation.KV{K: "type", V: validation.ObjAt(it, "type")},
	)
	if _, err := campaign.Log("finding.evidence_added", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}
