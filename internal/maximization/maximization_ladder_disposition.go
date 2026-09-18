// Ladder disposition verbs: pin the maximal rung, complete, waive, reopen, and the ladder report.
package maximization

import (
	"fmt"
	"slices"
	"strings"
	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// SetMaximal is set_maximal: pin the finding's claim to a REPRODUCED rung.
func SetMaximal(c *state.Campaign, findingID, rungID string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	rungPtr, err := findRung(lad, rungID)
	if err != nil {
		return validation.VNull(), err
	}
	rung := *rungPtr
	if validation.ObjStr(rung, "status") != "reproduced" {
		return validation.VNull(), fmt.Errorf("rung %s is %s; the claim may "+
			"only pin to a REPRODUCED rung — an assumed rung is a hypothesis "+
			"about bigger impact, not a claim of it", rungID,
			validation.PyReprStr(validation.ObjStr(rung, "status")))
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	lad.O = validation.SetOrAppend(lad.O, "maximal_rung_id", validation.VStr(rungID))
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(state.NowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("claim_pinned"))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "maximal_rung_id", validation.VStr(rungID))
	mx.O = validation.SetOrAppend(mx.O, "claim_from", validation.VStr(rungID))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if v := validation.ObjAt(rung, "capital_usd"); v.Kind != validation.Null {
		attacker := validation.AsObj(validation.ObjAt(f, "attacker"))
		attacker.O = validation.SetOrAppend(attacker.O, "required_capital_usd", v)
		f.O = validation.SetOrAppend(f.O, "attacker", attacker)
	}
	if v := validation.ObjAt(rung, "extraction_ratio"); v.Kind != validation.Null {
		impact := validation.AsObj(validation.ObjAt(f, "economic_impact"))
		impact.O = validation.SetOrAppend(impact.O, "extraction_ratio", v)
		f.O = validation.SetOrAppend(f.O, "economic_impact", impact)
	}
	if err := findings.SaveFinding(c, &f); err != nil {
		// r41 P2: the ladder save above STANDS and the finding stamp did
		// not, so this refusal left the ladder doc pinning max R and the
		// finding's maximization block untouched, with no ladder.claim_pinned
		// event anywhere — a pin the ledger never heard of (the retry can
		// still record it, so the unlogged pin, not a burn, is the damage).
		// Restore the pair before returning, exactly like CompleteLadder's
		// r40 arm.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("capital_usd", validation.ObjAt(rung, "capital_usd")),
		kvOf("extraction_ratio", validation.ObjAt(rung, "extraction_ratio")))
	if _, err := c.Log("ladder.claim_pinned", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return f, nil
}

// CompleteLadder is complete_ladder: close the search — every axis explored,
// maximal rung set and reproduced.
func CompleteLadder(c *state.Campaign, findingID, actor string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	explored := listStrings(listOf(lad, "axes_explored"))
	unexplored := []string{}
	for _, a := range Axes {
		if !slices.Contains(explored, a) {
			unexplored = append(unexplored, a)
		}
	}
	if len(unexplored) > 0 {
		return validation.VNull(), fmt.Errorf("ladder not complete: "+
			"unexplored axes %s — add a rung or mark each with a written "+
			"not-applicable note (webv2 ladder explore)", validation.PyListRepr(unexplored))
	}
	maxID := validation.ObjStr(lad, "maximal_rung_id")
	if maxID == "" {
		return validation.VNull(), fmt.Errorf("no maximal rung pinned: "+
			"webv2 ladder set-maximal %s <rung_id> (must be a reproduced rung)",
			findingID)
	}
	rungPtr, err := findRung(lad, maxID)
	if err != nil {
		return validation.VNull(), err
	}
	if validation.ObjStr(*rungPtr, "status") != "reproduced" {
		return validation.VNull(), fmt.Errorf("maximal rung is not reproduced " +
			"— pin the claim to a reproduced rung or disprove the open rungs")
	}
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("complete")),
		kvOf("reason", validation.VNull()),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(state.NowIso()))))
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the r40 follow-up closed this verb's LoadFinding and
		// SaveFinding arms but not this one — the first write's own refusal
		// returned with the doc possibly ahead of the ledger.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// r40 follow-up: the ladder was ALREADY saved above, so this
		// refusal left it reading complete with no ledger event and no
		// stamped finding — the same gate-completes-with-zero-events burn
		// the WaiveLadder fix closed, one call site over. Restore the pair
		// before returning, like the ledger-refusal arm below.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("complete"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r40 follow-up: same shape — the ladder save stands, the finding
		// stamp did not, and no event was ever appended. Restore, so a
		// failed completion cannot leave a gate reading DONE.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(kvOf("actor", validation.VStr(actor)))
	if _, err := c.Log("ladder.complete", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return lad, nil
}

// WaiveLadder is waive_ladder: explicit, attributed, logged — the honest
// escape hatch. It also records a completion waiver for the finding id.
func WaiveLadder(c *state.Campaign, findingID, reason, actor string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("waived")),
		kvOf("reason", validation.VStr(strings.TrimSpace(reason))),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(state.NowIso()))))
	// r40 P1: WaiveLadder was the NINTH ladder write site and the only one
	// without the r18 unwind. It saved the ladder, stamped the finding and
	// only THEN called completion.Waive, so EVERY refusal of that call —
	// the >=10-char reason rule, an empty actor, or the ledger refusing
	// the completion.waived append — returned with both files already
	// rewritten: a ladder reading {"state":"waived"} that no ledger event
	// anchors, no waiver row (waivers.jsonl absent), and verify/audit
	// green over it. The refusal can land AFTER the pair is touched (the
	// rule lives in completion.Waive, which runs last by design — hoisting
	// it here would duplicate completion's validation and its Python
	// strip/len semantics), so the door is the class-wide one: snapshot
	// BOTH files before the first write and restore them on any refusal.
	// r42: the snapshot ABORTS here, before that first write, when either
	// file exists but cannot be read (the door that used to DELETE it).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("waived"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	if _, err := completion.Waive(c, "maximal-exploitation", findingID,
		reason, actor); err != nil {
		// r40 P1: the ledger refused the completion.waived append (its own
		// waiver row is unwound by state.AppendJsonlThenLog) or the
		// reason/actor rule fired before that append wrote anything. Either
		// way the ladder doc and the finding are already rewritten and must
		// come back: a refused waive must not leave a gate-completing state
		// anywhere (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return lad, nil
}

// ReopenLadder is reopen_ladder: un-close a closed (complete or waived)
// ladder so more work can be added. requireOpen refuses mutation of a
// COMPLETE ladder and points here; reopening is reasoned, attributed and
// logged. An already-open ladder needs no reopening. (B2: the escape hatch
// the requireOpen error message always advertised but never existed.)
func ReopenLadder(c *state.Campaign, findingID, reason, actor string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "disposition")), "state") == "open" {
		return validation.VNull(), fmt.Errorf("ladder is already open — " +
			"nothing to reopen")
	}
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return validation.VNull(), fmt.Errorf("reopening a closed ladder " +
			"needs a written reason (the audit trail, not a bypass)")
	}
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("open")),
		kvOf("reason", validation.VStr(trimmed)),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(state.NowIso()))))
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// r41 P2: the ladder was ALREADY saved above, so this refusal left
		// it reading "open" with no ladder.reopen event and no finding
		// stamp — the shape CompleteLadder closed at r40, one call site
		// over, and the retry's already-open early-return makes the missing
		// event unemittable forever. Restore the pair first.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("open"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r41 P2: the ladder save above STANDS, the finding stamp did not,
		// and no event was ever appended. The ladder now reads "open", so
		// the retry hits the already-open early-return: the reopen, its
		// reason and its actor would be permanently unrecorded. Restore the
		// pair (see restoreLadderPair) so the retry is a REAL reopen.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("reason", validation.VStr(trimmed)),
		kvOf("actor", validation.VStr(actor)))
	if _, err := c.Log("ladder.reopen", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return lad, nil
}

// LadderReport is ladder_report: the ladder with claim-vs-measured deltas.
func LadderReport(c *state.Campaign, findingID string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		fid := validation.VStr(findingID)
		if findingID == "" {
			fid = validation.VNull()
		}
		return validation.VObj(kvOf("finding_id", fid),
			kvOf("ladder", validation.VNull())), nil
	}
	lad := *ladPtr
	variants := listOf(lad, "variants").A
	base := variants[0]
	rungs := []validation.Value{}
	for _, r := range variants {
		row := validation.Value{Kind: validation.Obj,
			O: append([]validation.KV(nil), r.O...)}
		if b, ok := numAt(base, "capital_usd"); ok {
			if v, ok := numAt(r, "capital_usd"); ok {
				row.O = validation.SetOrAppend(row.O, "capital_delta_usd",
					validation.VFloat(v-b))
			}
		}
		if b, ok := numAt(base, "extraction_ratio"); ok {
			if v, ok := numAt(r, "extraction_ratio"); ok {
				row.O = validation.SetOrAppend(row.O, "extraction_delta",
					validation.VFloat(v-b))
			}
		}
		rungs = append(rungs, row)
	}
	maxID := validation.ObjStr(lad, "maximal_rung_id")
	var maximal validation.Value = validation.VNull()
	for _, r := range variants {
		if maxID != "" && validation.ObjStr(r, "rung_id") == maxID {
			maximal = r
			break
		}
	}
	explored := listStrings(listOf(lad, "axes_explored"))
	unexplored := []string{}
	for _, a := range Axes {
		if !slices.Contains(explored, a) {
			unexplored = append(unexplored, a)
		}
	}
	return validation.VObj(
		kvOf("finding_id", validation.VStr(findingID)),
		kvOf("ladder_id", validation.ObjAt(lad, "ladder_id")),
		kvOf("disposition", validation.ObjAt(lad, "disposition")),
		kvOf("axes_explored", validation.ObjAt(lad, "axes_explored")),
		kvOf("unexplored_axes", validation.StrArr(unexplored)),
		kvOf("rungs", validation.VArr(rungs...)),
		kvOf("maximal", maximal),
	), nil
}

// numAt is `v.get(key) is not None` + float(v).
func numAt(v validation.Value, key string) (float64, bool) {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Null {
		return 0, false
	}
	return numOf(x)
}
