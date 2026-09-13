// amend.go: amend / supersede (G14a — the human-sanctioned new-verb
// exception). Filed findings can be corrected without lying to the hash
// chain: amend re-states a finding's claim in place (version bump + history
// + event, status NEVER moves), supersede retires an old finding in favor
// of a new one (old transitions to SUPERSEDED through Transition only;
// evidence is COPIED, never moved).
package findings

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// RejectedError is an operator-rejected amend/supersede: a usage-level
// refusal (no field flag, unknown class, terminal old finding,
// self-supersede). The CLI maps it to exit 2 with a `<verb> failed: ...`
// line, mirroring how cmd_move maps IllegalTransition.
type RejectedError struct{ Msg string }

func (e *RejectedError) Error() string { return e.Msg }

// AmendOpts carries amend's field flags. A set Has* flag (or a non-empty
// Note) selects the field; at least one must be set.
type AmendOpts struct {
	Title    string
	HasTitle bool
	Class    string
	HasClass bool
	Claim    string
	HasClaim bool
	Note     string
	Actor    string
}

// Amend is amend: correct a filed finding's title, bug class and/or claim
// text in place. Every successful amend bumps claim_version by 1 (absent
// counts as 0, so the first amend lands on 1), appends a history entry of
// the SAME shape mutateStatus writes ({at, from, to, reason, actor} with
// from == to — the status NEVER changes here), and logs finding.amended.
//
// --claim edits root_cause.description: that IS the claim text (the ingest
// path maps the model's claim onto title + root_cause.description; the
// schema has no root_cause.claim key). --class runs the same
// taxonomy.known_classes membership check the transition path reads through
// the taxonomyKnownClassesFunc seam; an unknown class is rejected before
// anything is written. --note rides the new history entry's reason as
// "amend: <keys> — <note>".
func Amend(campaign *state.Campaign, findingID string,
	opts AmendOpts) (validation.Value, error) {
	actor := opts.Actor
	if actor == "" {
		actor = "model"
	}
	if !opts.HasTitle && !opts.HasClass && !opts.HasClaim && opts.Note == "" {
		return validation.VNull(), &RejectedError{Msg: "amend needs at " +
			"least one of --title, --class, --claim, --note"}
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	status := objStr(finding, "status")
	changed := []string{}
	if opts.HasTitle {
		finding.O = validation.SetOrAppend(finding.O, "title",
			validation.VStr(opts.Title))
		changed = append(changed, "title")
	}
	if opts.HasClass {
		if _, ok := taxonomyKnownClassesFunc()[opts.Class]; !ok {
			return validation.VNull(), &RejectedError{Msg: fmt.Sprintf(
				"unknown bug class %s (not in taxonomy.known_classes)",
				validation.PyReprStr(opts.Class))}
		}
		rc := asDict(objAt(finding, "root_cause"))
		rc.O = validation.SetOrAppend(rc.O, "class",
			validation.VStr(opts.Class))
		finding.O = validation.SetOrAppend(finding.O, "root_cause", rc)
		// R3 (critic, resolved by the conversion law): re-classing a
		// CONFIRMED finding to a STRICTER-floor class does NOT invalidate
		// the status and is NOT refused — the floor recomputes on every
		// gate read, and the raised bar converts the row into mandatory
		// independent-verification work (briefing/rank surface it; the T6
		// advisory's own promise). What would be a lie is silence, so
		// cmd_amend prints the floor movement when it happens (the round-3
		// ruling: conversion, never invalidation — an earlier refusal here
		// contradicted the pinned work-order law and was removed).
		changed = append(changed, "class")
	}
	if opts.HasClaim {
		rc := asDict(objAt(finding, "root_cause"))
		rc.O = validation.SetOrAppend(rc.O, "description",
			validation.VStr(opts.Claim))
		finding.O = validation.SetOrAppend(finding.O, "root_cause", rc)
		changed = append(changed, "claim")
	}
	if len(changed) == 0 {
		// Note-only amend: the note is the change.
		changed = []string{"note"}
	}
	reason := "amend: " + strings.Join(changed, ", ")
	if opts.Note != "" {
		reason += " — " + opts.Note
	}
	// claim_version += 1 on every amend (finding.schema.json: "bump on
	// material re-state"). The critic's stale-check (boundary.go) compares
	// versions, so every amend re-stales verdicts pinned to the old claim.
	version := int64(1)
	if cur := objAt(finding, "claim_version"); cur.Kind == validation.Int {
		version = cur.I + 1
	}
	finding.O = validation.SetOrAppend(finding.O, "claim_version",
		validation.VInt(version))
	// History entry in the mutateStatus shape (from == to: amend never moves
	// status). No finding.status event: the status did not change, so
	// logging one would claim a transition that never happened.
	hist := objAt(finding, "history")
	if hist.Kind != validation.Arr {
		hist = validation.VArr()
	}
	hist.A = append(hist.A, validation.VObj(
		validation.KV{K: "at", V: validation.VStr(nowIso())},
		validation.KV{K: "from", V: validation.VStr(status)},
		validation.KV{K: "to", V: validation.VStr(status)},
		validation.KV{K: "reason", V: validation.VStr(reason)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	))
	finding.O = validation.SetOrAppend(finding.O, "history", hist)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	keys := make([]validation.Value, len(changed))
	for i, k := range changed {
		keys[i] = validation.VStr(k)
	}
	data := validation.VObj(
		validation.KV{K: "changed", V: validation.VArr(keys...)},
		validation.KV{K: "reason", V: validation.VStr(reason)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
		validation.KV{K: "claim_version", V: validation.VInt(version)},
	)
	if _, err := campaign.Log("finding.amended", &findingID, &data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// Supersede is supersede: retire an old finding in favor of a new one. The
// old finding transitions to SUPERSEDED through Transition ONLY (floor,
// history and event discipline intact — including the refusal when the old
// finding is already terminal). The new finding gains a COPY of every old
// evidence item, each stamped re_parented_from: <old id>; the old finding's
// evidence array is left byte-identical (append-only store). The link back
// rides the string channel dedup_meta.supersedes (the same additionalProps:
// string discipline corroborated_by uses). Logs finding.superseded.
//
// Gates: the old finding must not already be terminal, and new != old.
func Supersede(campaign *state.Campaign, newID, oldID,
	actor string) (validation.Value, error) {
	if actor == "" {
		actor = "model"
	}
	if newID == oldID {
		return validation.VNull(), &RejectedError{Msg: fmt.Sprintf(
			"cannot supersede a finding with itself (%s)", newID)}
	}
	old, err := LoadFinding(campaign, oldID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, terminal := TERMINAL[objStr(old, "status")]; terminal {
		return validation.VNull(), &RejectedError{Msg: fmt.Sprintf(
			"cannot supersede terminal finding %s (%s)",
			oldID, objStr(old, "status"))}
	}
	newFinding, err := LoadFinding(campaign, newID)
	if err != nil {
		return validation.VNull(), err
	}
	// R3 (critic): a SUPERSEDED (or otherwise terminal) finding may not
	// become the successor of anything — that is how 2-cycles retire a
	// pair onto each other and leave zero live findings behind. The old
	// side's terminality was always refused; the new side is the same
	// claim about existence.
	if _, terminal := TERMINAL[objStr(newFinding, "status")]; terminal {
		return validation.VNull(), &RejectedError{Msg: fmt.Sprintf(
			"cannot supersede %s with terminal finding %s (%s) — the "+
				"successor must be a live finding; a superseded row cannot "+
				"adopt anything, and this pair would cycle to zero live "+
				"findings", oldID, newID, objStr(newFinding, "status"))}
	}
	old, err = Transition(campaign, oldID, "SUPERSEDED",
		"superseded by "+newID, actor, "", false)
	if err != nil {
		return validation.VNull(), err
	}
	// Re-parent: COPY each old evidence item into the new finding, stamped
	// with its source. The old array is never touched.
	oldEv := objAt(old, "evidence")
	newEv := objAt(newFinding, "evidence")
	if newEv.Kind != validation.Arr {
		newEv = validation.VArr()
	}
	for _, it := range oldEv.A {
		cp := validation.Value{Kind: validation.Obj,
			O: append([]validation.KV(nil), it.O...)}
		cp.O = validation.SetOrAppend(cp.O, "re_parented_from",
			validation.VStr(oldID))
		newEv.A = append(newEv.A, cp)
	}
	newFinding.O = validation.SetOrAppend(newFinding.O, "evidence", newEv)
	dm := asDict(objAt(newFinding, "dedup_meta"))
	dm.O = validation.SetOrAppend(dm.O, "supersedes",
		validation.VStr(oldID))
	newFinding.O = validation.SetOrAppend(newFinding.O, "dedup_meta", dm)
	if err := SaveFinding(campaign, &newFinding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "old", V: validation.VStr(oldID)},
		validation.KV{K: "new", V: validation.VStr(newID)},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	)
	if _, err := campaign.Log("finding.superseded", &newID, &data); err != nil {
		return validation.VNull(), err
	}
	return newFinding, nil
}
