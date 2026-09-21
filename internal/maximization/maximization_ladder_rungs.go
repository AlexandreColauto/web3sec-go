// Ladder rung verbs: add, explore, reproduce and disprove rungs, plus the rung lookup/replace helpers.
package maximization

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// AddVariant is add_variant: record a candidate rung. It is ASSUMED until
// reproduced or DISPROVED with a reason — an assumed rung never moves the
// claim.
func AddVariant(c *state.Campaign, findingID, name, description string,
	axes []string, capitalUSD, extractionRatio *float64, removed,
	added []string) (validation.Value, error) {
	for _, a := range axes {
		if !slices.Contains(Axes, a) {
			return validation.VNull(), fmt.Errorf(
				"unknown axis %s; the axes are %s", validation.PyReprStr(a),
				pyTupleRepr(Axes))
		}
	}
	if len(axes) == 0 {
		return validation.VNull(), fmt.Errorf("a variant must name the axis " +
			"(axes) it exploits — that is what makes the search auditable")
	}
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf(
			"no ladder for %s; webv2 ladder start %s first", noneText(findingID),
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	rung := newRung(name, description, axes, capitalUSD, extractionRatio,
		removed, added, "", nil, nil, "")
	variants := listOf(lad, "variants")
	variants.A = append(variants.A, rung)
	lad.O = validation.SetOrAppend(lad.O, "variants", variants)
	explored := listOf(lad, "axes_explored")
	for _, a := range axes {
		if !slices.Contains(listStrings(explored), a) {
			explored.A = append(explored.A, validation.VStr(a))
		}
	}
	lad.O = validation.SetOrAppend(lad.O, "axes_explored", explored)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the SaveLadder-error arm was the one return after this
		// verb's first write that skipped the unwind (SetMaximal,
		// WaiveLadder, ReopenLadder and StartLadder all restore here).
		// WriteJson is atomic, but a partial-visibility failure can still
		// leave the doc ahead of the ledger; restore the pair.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("rung_id", validation.ObjAt(rung, "rung_id")),
		kvOf("axes", validation.StrArr(axes)),
		kvOf("name", validation.VStr(name)))
	if _, err := c.Log("ladder.variant_added", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return rung, nil
}

// ExploreAxis is explore_axis: mark an axis explored WITHOUT a rung — when
// the honest answer is 'considered, not applicable', the note is the artifact.
func ExploreAxis(c *state.Campaign, findingID, axis, note string) (validation.Value, error) {
	if !slices.Contains(Axes, axis) {
		return validation.VNull(), fmt.Errorf("unknown axis %s; the axes are %s",
			idRepr(axis), pyTupleRepr(Axes))
	}
	if utf8.RuneCountInString(strings.TrimSpace(note)) < 10 {
		return validation.VNull(), fmt.Errorf("an axis marked not-applicable " +
			"needs a written reason (>=10 chars) — otherwise it is unexplored")
	}
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
	notes := validation.AsObj(validation.ObjAt(lad, "axis_notes"))
	notes.O = validation.SetOrAppend(notes.O, axis, validation.VStr(strings.TrimSpace(note)))
	lad.O = validation.SetOrAppend(lad.O, "axis_notes", notes)
	explored := listOf(lad, "axes_explored")
	if !slices.Contains(listStrings(explored), axis) {
		explored.A = append(explored.A, validation.VStr(axis))
	}
	lad.O = validation.SetOrAppend(lad.O, "axes_explored", explored)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: same arm as AddVariant's — the first write's own refusal
		// returned without the unwind.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("axis", validation.VStr(axis)),
		kvOf("note", validation.VStr(truncate(strings.TrimSpace(note), 200))))
	if _, err := c.Log("ladder.axis_explored", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return lad, nil
}

// truncate is Python's s[:n] over code points.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ReproduceRung is reproduce_rung: a rung counts when it runs. The mint
// enforces profile/exit/output/idempotence and writes the evidence item; the
// rung is bound to it afterwards.
func ReproduceRung(c *state.Campaign, findingID, rungID, execID string,
	evidenceType *string) (validation.Value, error) {
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
	desc := fmt.Sprintf("variant rung %s: %s", validation.ObjStr(rung, "name"),
		validation.ObjStr(rung, "description"))
	// r41 P1: MintReproEvidence writes the FINDING first —
	// findings.AddEvidence saves the evidence item and only THEN appends
	// finding.evidence_added, with no unwind of its own — so a refused
	// ledger returns from the mint with the item already ON the finding and
	// no event behind it. These baselines used to be captured AFTER the
	// mint (:638-639), which left that half-land outside this verb's unwind
	// window: a refused ladder.rung_reproduced kept the minted evidence and
	// its updated_at stamp, with zero events anywhere. Capture BOTH files
	// BEFORE the mint; a refused mint restores them.
	preMint, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := reproduction.MintReproEvidence(c, findingID, execID, desc,
		nil, evidenceType, ""); err != nil {
		return validation.VNull(), unwindLadderPair(preMint, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// The mint wrote this file moments ago, so this refusal means the
		// finding went missing under it: unwind the mint's half-land.
		return validation.VNull(), unwindLadderPair(preMint, err)
	}
	evID := ""
	for _, e := range listOf(f, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			evID = validation.ObjStr(e, "evidence_id")
			break
		}
	}
	rung.O = validation.SetOrAppend(rung.O, "status", validation.VStr("reproduced"))
	rung.O = validation.SetOrAppend(rung.O, "exec_id", validation.VStr(execID))
	if evID == "" {
		rung.O = validation.SetOrAppend(rung.O, "evidence_id", validation.VNull())
	} else {
		rung.O = validation.SetOrAppend(rung.O, "evidence_id", validation.VStr(evID))
	}
	rung.O = validation.SetOrAppend(rung.O, "reproduced_at", validation.VStr(state.NowIso()))
	if err := replaceRung(&lad, rung); err != nil {
		// Nothing to unwind: the ladder is still only in memory here, and
		// the mint's own finding file + finding.evidence_added pair is
		// already complete (see the window note below). Unreachable anyway
		// — findRung just proved the rung id exists.
		return validation.VNull(), err
	}
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(state.NowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("reproduced")),
		kvOf("exec_id", validation.VStr(execID))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// Re-capture the FINDING now that the mint's own finding.evidence_added
	// event has landed (the mint returns success only once both halves are
	// written): the item is then an authoritative file+event pair, and
	// restoring the file alone would orphan that event. The LADDER snapshot
	// above stands — nothing has written the ladder since it was captured.
	// An unreadable re-capture refuses here, before the ladder write.
	postMint := preMint
	postMint.fnd = prevFile(findings.FindingPath(c, findingID))
	if postMint.fnd.unreadable {
		return validation.VNull(), ladderSnapshotRefusal("finding", findingID,
			postMint.fnd)
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: this arm returned without the unwind too.
		return validation.VNull(), unwindLadderPair(postMint, err)
	}
	data := validation.VObj(
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("exec_id", validation.VStr(execID)))
	if _, err := c.Log("ladder.rung_reproduced", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(postMint, err)
	}
	return rung, nil
}

// findRung is _find_rung. The KeyError text is Python's: the CLI renders
// str(KeyError(msg)) — repr of the message — so the message is wrapped here.
func findRung(lad validation.Value, rungID string) (*validation.Value, error) {
	ids := []string{}
	for _, r := range listOf(lad, "variants").A {
		if validation.ObjStr(r, "rung_id") == rungID {
			out := r
			return &out, nil
		}
		ids = append(ids, validation.ObjStr(r, "rung_id"))
	}
	msg := fmt.Sprintf("unknown rung %s; rungs: %s", idRepr(rungID),
		validation.PyListRepr(ids))
	return nil, &keyError{msg: validation.PyReprStr(msg)}
}

// keyError is Python's KeyError: str(e) is repr(message).
type keyError struct{ msg string }

func (e *keyError) Error() string { return e.msg }

// replaceRung swaps the rung with the same rung_id back into variants.
func replaceRung(lad *validation.Value, rung validation.Value) error {
	variants := listOf(*lad, "variants")
	for i, r := range variants.A {
		if validation.ObjStr(r, "rung_id") == validation.ObjStr(rung, "rung_id") {
			variants.A[i] = rung
			lad.O = validation.SetOrAppend(lad.O, "variants", variants)
			return nil
		}
	}
	return fmt.Errorf("unknown rung %s", validation.PyReprStr(validation.ObjStr(rung, "rung_id")))
}

// DisproveRung is disprove_rung: a dead-end rung with a written reason is
// NEGATIVE KNOWLEDGE, queued as memory so the next campaign does not re-spend
// a PoC cycle on it.
func DisproveRung(c *state.Campaign, findingID, rungID, reason string) (validation.Value, error) {
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
	if utf8.RuneCountInString(strings.TrimSpace(reason)) < 10 {
		return validation.VNull(), fmt.Errorf("a disproof needs a written " +
			"reason — 'didn't work' is not knowledge")
	}
	rungPtr, err := findRung(lad, rungID)
	if err != nil {
		return validation.VNull(), err
	}
	rung := *rungPtr
	if validation.ObjStr(rung, "status") == "reproduced" {
		return validation.VNull(), fmt.Errorf("rung %s is reproduced; a "+
			"reproduced rung cannot be disproved — mint a fresh exec for the "+
			"corrected claim or open a new rung", rungID)
	}
	rung.O = validation.SetOrAppend(rung.O, "status", validation.VStr("disproved"))
	rung.O = validation.SetOrAppend(rung.O, "reason", validation.VStr(strings.TrimSpace(reason)))
	if err := replaceRung(&lad, rung); err != nil {
		return validation.VNull(), err
	}
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(state.NowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("disproved"))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the first write's own refusal skipped the unwind.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	fid := findingID
	negative := validation.VObj(kvOf("why_safe", validation.VStr(strings.TrimSpace(reason))))
	if _, err := queueMemory(c, MemoryRequest{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "maximal-exploitation dead end: " + validation.ObjStr(rung, "name") +
			" — " + validation.ObjStr(rung, "description"),
		FindingID:       &fid,
		EvidenceSummary: strings.TrimSpace(reason),
		Negative:        &negative,
	}); err != nil {
		// r41 P1: the ladder doc was ALREADY saved above reading
		// "disproved" (plus a history row), and the memory row is its own
		// file+event pair (learning.QueueMemory unwinds itself, r40), so
		// THIS refusal must not leave the ladder ahead of the ledger:
		// without the restore the ladder showed a disproof with zero
		// ladder.rung_disproved events and the retry re-stamped it.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(kvOf("rung_id", validation.VStr(rungID)))
	if _, err := c.Log("ladder.rung_disproved", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return rung, nil
}
