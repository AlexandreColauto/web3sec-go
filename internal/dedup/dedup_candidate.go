// dedup_candidate.go: resolve_candidate split out of dedup.go — verdict
// recording, merge ordering and the corroboration tail.
package dedup

import (
	"fmt"
	"slices"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ResolveCandidate is resolve_candidate: adjudicate ONE flagged
// near-duplicate pair (a tier-3 flag) — "same" or "distinct".
//
// The sweep FLAGGED near-duplicate pairs and nothing consumed the flags —
// every candidate still burned a full PoC cycle until a human noticed. This
// is the missing verdict step. The judgment is recorded on BOTH sides of the
// pair (one call resolves the pair), which is what the dedup completion proof
// tracks. "same" additionally merges the younger finding into the older one
// (mark_duplicate) — the expensive cycle is skipped. "distinct" leaves both
// open; the note is the record of why.
func ResolveCandidate(campaign *state.Campaign, findingID, ofFindingID, verdict, note,
	actor string) (validation.Value, error) {
	if verdict != "same" && verdict != "distinct" {
		return validation.VNull(), fmt.Errorf(
			"verdict must be 'same' or 'distinct', got %s", validation.PyReprStr(verdict))
	}
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if !slices.Contains(valueStrings(getDeep(f, "dedup", "possible_duplicate_of")), ofFindingID) {
		// Python raises KeyError(inner); str(KeyError) is repr(inner), which
		// is what the CLI prints, so the error text is that repr.
		inner := fmt.Sprintf("%s has no candidate flag for %s; run the dedup sweep first",
			findingID, validation.PyReprStr(ofFindingID))
		return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(inner))
	}
	stripped := validation.PyStrip(note)
	if note != "" && len([]rune(stripped)) < 5 {
		return validation.VNull(), fmt.Errorf("a candidate verdict note, when given, must be substantive")
	}
	// Both sides are loaded before either is saved (Python builds the whole
	// ((f, of), (load(of), id)) tuple first).
	other, err := findings.LoadFinding(campaign, ofFindingID)
	if err != nil {
		return validation.VNull(), err
	}
	sides := []struct {
		side    validation.Value
		otherID string
	}{{f, ofFindingID}, {other, findingID}}
	sideVals := make([]*validation.Value, 0, len(sides))
	for k := range sides {
		side := setDeep(sides[k].side, validation.VStr(verdict), "dedup",
			"candidate_verdicts", sides[k].otherID)
		if note != "" {
			side = setDeep(side, validation.VStr(stripped), "dedup_meta",
				"candidate_notes", sides[k].otherID)
		}
		sides[k].side = side
		sideVals = append(sideVals, &sides[k].side)
	}
	data := validation.VObj(
		kv("of", validation.VStr(ofFindingID)),
		kv("verdict", validation.VStr(verdict)),
		kv("actor", validation.VStr(actor)),
	)
	// r18 P2: a refused resolve event used to leave BOTH sides stamped
	// with a verdict the ledger never recorded — the pair silently
	// merged in the files only. SaveThenLogMany lands both files with
	// the event or restores both.
	if err := findings.SaveThenLogMany(campaign, sideVals, func() error {
		_, lerr := campaign.Log("dedup.candidate_resolved", &findingID,
			&data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	if verdict == "same" {
		if err := mergeYounger(campaign, f, ofFindingID); err != nil {
			return validation.VNull(), err
		}
		// G1 corroboration law: exactly one side SAST-flagged => the resolved
		// same-root-cause pair is independent corroboration. Same-engine
		// pairs never corroborate — an independent method is the point.
		// Recorded AFTER mergeYounger, on the SURVIVOR, naming the other
		// (merged-away) side: the merge marks one side DUPLICATE and
		// LoadLiveFindings (what ranking reads) drops DUPLICATE records, so a
		// pre-merge write can land on a record no consumer ever sees —
		// exactly what happens when the SAST finding is the older side.
		// Reload both sides: the merge just changed them.
		one, err := findings.LoadFinding(campaign, findingID)
		if err != nil {
			return validation.VNull(), err
		}
		two, err := findings.LoadFinding(campaign, ofFindingID)
		if err != nil {
			return validation.VNull(), err
		}
		oneTooled := len(valueStrings(getDeep(one, "provenance", "sast_tools"))) > 0
		twoTooled := len(valueStrings(getDeep(two, "provenance", "sast_tools"))) > 0
		// The corroboration dies with the duplicate record: it is written ONLY
		// on a survivor that is itself tool-less (the non-tool side the SAST
		// finding corroborates). When the SAST finding is the older side it
		// survives, and a link written on it would name a merged-away model
		// record no consumer can read — the G1 law is directional, so that
		// case records nothing at all (no write, no event).
		_, survivor := pickYoungerOlder(one, two)
		survivorTooled :=
			len(valueStrings(getDeep(survivor, "provenance", "sast_tools"))) > 0
		if oneTooled != twoTooled && !survivorTooled {
			other := one
			if validation.ObjStr(survivor, "finding_id") == validation.ObjStr(one, "finding_id") {
				other = two
			}
			otherID := validation.ObjStr(other, "finding_id")
			sid := validation.ObjStr(survivor, "finding_id")
			corroborated := setDeep(survivor, validation.VStr(otherID),
				"dedup_meta", "corroborated_by")
			data := validation.VObj(kv("of", validation.VStr(otherID)))
			if err := findings.SaveThenLog(campaign, &corroborated,
				func() error {
					_, lerr := campaign.Log("dedup.corroborated", &sid,
						&data)
					return lerr
				}); err != nil {
				return validation.VNull(), err
			}
		}
	}
	return findings.LoadFinding(campaign, findingID)
}

// pickYoungerOlder is resolve_candidate's merge ordering: the older side by
// created_at survives; an exact created_at tie breaks to the lower finding_id
// (the same (created_at, finding_id) order LoadAllFindings sorts by). Returns
// (younger, older). resolve_candidate's merge and its corroboration link both
// consume it, so there is only one ordering rule.
func pickYoungerOlder(a, b validation.Value) (validation.Value, validation.Value) {
	ca, cb := validation.ObjStr(a, "created_at"), validation.ObjStr(b, "created_at")
	if ca < cb {
		return b, a
	}
	if ca > cb {
		return a, b
	}
	if validation.ObjStr(a, "finding_id") < validation.ObjStr(b, "finding_id") {
		return b, a
	}
	return a, b
}

// mergeYounger is resolve_candidate's `same` tail: reload the flagged
// partner, pick the younger side by created_at (ties -> higher finding_id, so
// the lower id survives), and merge it into the older one unless it is already
// DUPLICATE.
func mergeYounger(campaign *state.Campaign, f validation.Value, ofFindingID string) error {
	other, err := findings.LoadFinding(campaign, ofFindingID)
	if err != nil {
		return err
	}
	younger, older := pickYoungerOlder(f, other)
	if validation.ObjStr(younger, "status") == "DUPLICATE" {
		return nil
	}
	_, err = markDuplicateFunc(campaign, validation.ObjStr(younger, "finding_id"), validation.ObjStr(older, "finding_id"))
	return err
}
