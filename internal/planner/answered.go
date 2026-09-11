package planner

import (
	"strings"

	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// AnsweredOpts is the optional tail of mark_answered (Python: reason=None,
// ref=None, actor="cli", anchor=None). Nil pointers are None.
// OverrideDismissal/OverrideReason are B4: the explicit, logged override of
// the dismissal gate on a high-risk row.
type AnsweredOpts struct {
	Reason *string
	Ref    *string
	Actor  string
	Anchor *string
	// PassesValue is B4 v3: for a sentinel-guarded probe row, the value that
	// passes the row's zero-check ("root != bytes32(0)" is not the truth of
	// the root). Closing such a row without naming it is refused unless the
	// disposition takes the explicit, logged override. Nil when --passes was
	// not given; the value is recorded on the priority as `passes`.
	PassesValue       *string
	OverrideDismissal bool
	OverrideReason    *string
	// OverrideLogged is an OUT parameter: the dismissal gate sets it to true
	// when it recorded a `probe.dismissal_overridden` for this closure. The
	// CLI prints that so the operator sees the override land instead of
	// having to trust that it did; callers with no interest pass nil. See
	// D1/B4 in docs/IMPROVEMENTS.md — G-01 was buried by a dismissal nobody
	// had to justify, so an override must be loud at the moment it happens
	// and durable afterwards (the event is the durable half).
	OverrideLogged *bool
}

// MarkAnswered is mark_answered: close (or re-open) a plan priority.
//
// A closure is a DECISION, not a state flip: it carries a reason and, when one
// exists, the evidence it rests on (a finding, an exec, an artifact, or a
// file#L anchor). `anchor` (A4) is how a PROBE row's disposition names the
// field it claims is safe. It is checked against the row's own probe enum AND
// against the row's real value (probes.row_anchor_value), then recorded as
// `probe.anchor = {field, value, ref}` with `ref` — the real file#L/value
// citation — becoming the closure's `closed_ref`. An anchor the probe never
// produced, or a `ref` that contradicts the anchor it claims, is rejected: the
// disposition has to be falsifiable. Non-probe priorities are unaffected.
func MarkAnswered(campaign *state.Campaign, plan validation.Value, priorityID,
	outcome string, opts AnsweredOpts) (validation.Value, error) {
	g, err := runAnsweredGates(campaign, plan, priorityID, outcome, opts,
		false)
	if err != nil {
		return validation.VNull(), err
	}
	ref, anchorRec, anchorSet := g.ref, g.anchorRec, g.anchorSet
	priorities := listOf(plan, "priorities")
	p := priorities[g.idx]
	closing := outcome == "answered" || outcome == "not-applicable" ||
		outcome == "deprioritized" || outcome == "blocked"
	p.O = validation.SetOrAppend(p.O, "status", validation.VStr(outcome))
	if closing {
		p = closePriority(p, opts, ref, anchorSet, anchorRec)
	} else {
		p = reopenPriority(p)
	}
	priorities[g.idx] = p
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(priorities...))
	if _, err := SavePlan(campaign, plan); err != nil {
		return validation.VNull(), err
	}
	data := statusData(outcome, opts, ref, anchorSet, anchorRec)
	if _, err := campaign.Log("plan.priority_status", &priorityID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// answeredGateOut is the resolved output of the shared answered-gate
// runner: the priority index, the (possibly anchor-rewritten) ref, and the
// probe.anchor record when one was resolved.
type answeredGateOut struct {
	idx       int
	ref       *string
	anchorRec validation.Value
	anchorSet bool
}

// runAnsweredGates is the ONE gate runner behind both MarkAnswered and the
// batch pre-flight: lookup → checkAnchorless → checkCitedRecords →
// resolveAnchor → the dismissal gate. Structural sharing, not a parity
// comment: a new gate added here applies to both callers, so the pre-flight
// cannot drift from apply. dry selects the dismissal-gate form —
// checkDismissalGateInner(..., dry=true) validates an override without
// recording it (pre-flight), dry=false records it (apply). The single-row
// event/apply semantics live in MarkAnswered, which is the only caller with
// dry=false.
func runAnsweredGates(campaign *state.Campaign, plan validation.Value,
	priorityID, outcome string, opts AnsweredOpts,
	dry bool) (answeredGateOut, error) {
	var out answeredGateOut
	closing := outcome == "answered" || outcome == "not-applicable" ||
		outcome == "deprioritized" || outcome == "blocked"
	idx, err := findPriority(plan, priorityID)
	if err != nil {
		return out, err
	}
	out.idx = idx
	p := listOf(plan, "priorities")[idx]
	prov, hasProv := probeProvenance(p)
	if err := checkAnchorless(priorityID, outcome, prov, hasProv,
		opts.Anchor); err != nil {
		return out, err
	}
	// B4 v3, next to the anchor rule and for the same reason: a probe row's
	// disposition has to be falsifiable. `--anchor` names the field the
	// closure claims is safe; for a sentinel-guarded row that is not enough —
	// the guard's own zero-check cannot express the truth of the value it
	// guards, so the closure has to name the value that DOES pass it.
	if err := checkSentinelPassesRow(campaign, outcome, prov, hasProv,
		opts); err != nil {
		return out, err
	}
	// Shape before policy: whether the citation is the RIGHT one (does this
	// --ref really name the anchor field it claims?) is a question about what
	// the author passed, and its message — "expected Rollup.sol#L45" — is the
	// one they can act on. Whether the ARGUMENT is good enough is the next
	// question, asked below.
	// A closure may rest on a finding, an exec record or a registered
	// invariant — never on a citation that does not exist. This runs before
	// the anchor rule so a fabricated ref is reported AS fabricated: the
	// anchor rule would otherwise answer "that is not the citation this field
	// claims", which is true but hides the more useful fact that the record
	// was never written.
	if err := checkCitedRecords(campaign, priorityID, outcome,
		opts); err != nil {
		return out, err
	}
	ref := opts.Ref
	if opts.Anchor != nil && closing {
		var anchorRec validation.Value
		var err error
		ref, anchorRec, err = resolveAnchor(campaign, priorityID, prov,
			hasProv, opts, ref)
		if err != nil {
			return out, err
		}
		out.anchorRec = anchorRec
		out.anchorSet = true
	}
	out.ref = ref
	if err := checkDismissalGateInner(campaign, priorityID, outcome, prov,
		hasProv, opts, dry); err != nil {
		return out, err
	}
	return out, nil
}

// closePriority stamps the closure provenance (and, for an anchored probe row,
// the anchor) onto a priority.
func closePriority(p validation.Value, opts AnsweredOpts, ref *string,
	anchorSet bool, anchorRec validation.Value) validation.Value {
	if opts.Reason != nil {
		p.O = validation.SetOrAppend(p.O, "closed_reason", validation.VStr(*opts.Reason))
	}
	if ref != nil {
		p.O = validation.SetOrAppend(p.O, "closed_ref", validation.VStr(*ref))
	}
	p.O = validation.SetOrAppend(p.O, "closed_at", validation.VStr(nowIso()))
	p.O = validation.SetOrAppend(p.O, "closed_by", validation.VStr(actorOr(opts.Actor)))
	// The value that passes the row's sentinel check is part of the closure
	// record — the same way closed_ref is. A value too short to be one is not
	// recorded (the rule refuses it where it matters, and the schema pins the
	// floor for the plan).
	if opts.PassesValue != nil &&
		len(strings.TrimSpace(*opts.PassesValue)) >= 3 {
		p.O = validation.SetOrAppend(p.O, "passes",
			validation.VStr(*opts.PassesValue))
	}
	if anchorSet {
		prov, _ := probeProvenance(p)
		prov.O = validation.SetOrAppend(prov.O, "anchor", anchorRec)
		p.O = validation.SetOrAppend(p.O, "probe", prov)
	}
	return p
}

// reopenPriority drops the closure provenance and any recorded probe anchor.
func reopenPriority(p validation.Value) validation.Value {
	for _, k := range []string{"closed_reason", "closed_ref", "closed_at",
		"closed_by", "passes"} {
		p.O = dropKey(p.O, k)
	}
	if prov, ok := probeProvenance(p); ok {
		prov.O = dropKey(prov.O, "anchor")
		p.O = validation.SetOrAppend(p.O, "probe", prov)
	}
	return p
}

// statusData is the plan.priority_status log payload.
func statusData(outcome string, opts AnsweredOpts, ref *string, anchorSet bool,
	anchorRec validation.Value) validation.Value {
	data := validation.VObj(
		kv("status", validation.VStr(outcome)),
		kv("reason", optStr(opts.Reason)),
		kv("ref", optStr(ref)),
		kv("actor", validation.VStr(actorOr(opts.Actor))),
	)
	if anchorSet {
		data.O = validation.SetOrAppend(data.O, "anchor", anchorRec)
	}
	return data
}

// probeProvenance is `p.get("probe") if isinstance(p.get("probe"), dict)
// else None`.
func probeProvenance(p validation.Value) (validation.Value, bool) {
	prov := objAt(p, "probe")
	if prov.Kind != validation.Obj {
		return validation.VNull(), false
	}
	return prov, true
}

// actorOr is Python's `actor="cli"` default.
func actorOr(actor string) string {
	if actor == "" {
		return "cli"
	}
	return actor
}

// checkAnchorless enforces that a probe-row disposition names its anchor. This
// is enforced HERE, not only in the CLI: `orchestrator.ingest(answers_priority=
// …)` is a real library caller, and an anchor-less closure used to discharge
// every row of an axis with a prose ref while the divergence gate then read
// `closed=True`. `blocked` is not a disposition (A3), so it stays anchor-free.
func checkAnchorless(priorityID, outcome string, prov validation.Value,
	hasProv bool, anchor *string) error {
	if !hasProv || anchor != nil || !inList(outcome, ProbeRowDispositioned) {
		return nil
	}
	allowed := probeAnchors(objStr(prov, "probe_id"))
	msg := "priority " + priorityID + " is probe row " +
		validation.PyReprStr(objStr(prov, "row_id")) + ": " +
		validation.PyReprStr(outcome) + " dispositions it, so the closure " +
		"must name the field it claims is safe — pass anchor=<field>"
	if len(allowed) > 0 {
		msg += " (one of " + strings.Join(allowed, ", ") + ")"
	}
	return errValue(msg)
}

// resolveAnchor is the A4 anchor block: surface lookup, enum check, value
// derivation and the falsifiable-ref comparison. It returns the (possibly
// rewritten) ref and the `probe.anchor` record.
func resolveAnchor(campaign *state.Campaign, priorityID string,
	prov validation.Value, hasProv bool, opts AnsweredOpts,
	ref *string) (*string, validation.Value, error) {
	if !hasProv {
		return nil, validation.VNull(), errValue("priority " + priorityID +
			" is not a probe row — --anchor only names the field a probe " +
			"disposition claims is safe")
	}
	anchor := *opts.Anchor
	rid := objStr(prov, "row_id")
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return nil, validation.VNull(), err
	}
	if surface == nil {
		return nil, validation.VNull(), errValue("priority " + priorityID +
			" cites probe row " + validation.PyReprStr(rid) +
			" but the campaign has no probe surface — run `webv2 probes " +
			campaign.CampaignID + " run` first")
	}
	row, ok := findRow(*surface, rid)
	if !ok {
		return nil, validation.VNull(), errValue("probe row " +
			validation.PyReprStr(rid) + " is not in the current surface — " +
			"re-run `webv2 probes " + campaign.CampaignID + " run --emit`")
	}
	probeID := objStr(row, "probe")
	if !PB().AnchorAllowed(probeID, anchor) {
		return nil, validation.VNull(), errValue("anchor " +
			validation.PyReprStr(anchor) + " is not produced by probe " +
			validation.PyReprStr(probeID) + "; allowed: " +
			pyAnchorsRepr(probeID))
	}
	value, err := PB().RowAnchorValue(row, anchor)
	if err != nil {
		return nil, validation.VNull(), err
	}
	index, err := PB().CampaignIndex(campaign)
	if err != nil {
		return nil, validation.VNull(), err
	}
	rendered, err := PB().AnchorRef(row, anchor, index)
	if err != nil {
		return nil, validation.VNull(), err
	}
	out := rendered
	if ref != nil && *ref != rendered {
		// B4: a refutation-backed ref (an existing exec record or a
		// registered invariant) is a legitimate closure basis on its own —
		// it backs the dismissal, while the anchor record above keeps its
		// own citation of the field the probe covered. Anything else is
		// still rejected: the disposition has to be falsifiable.
		if !refutationBacked(campaign, *ref) {
			return nil, validation.VNull(), errValue("a probe disposition's " +
				"--ref must be the anchor it claims: got " +
				validation.PyReprStr(*ref) + ", expected " +
				validation.PyReprStr(rendered) + " (" + anchor + ")")
		}
		out = *ref
	}
	rec := validation.VObj(
		kv("field", validation.VStr(anchor)),
		kv("value", value),
		kv("ref", validation.VStr(rendered)),
	)
	return &out, rec, nil
}

// findRow is `next((r for r in surface.get("rows") or [] if r.get("row_id") ==
// rid), None)`.
func findRow(surface validation.Value, rid string) (validation.Value, bool) {
	for _, r := range listOf(surface, "rows") {
		if objStr(r, "row_id") == rid {
			return r, true
		}
	}
	return validation.VNull(), false
}

// pyAnchorsRepr is f"{PB.PROBES.get(probe_id, {}).get('anchors')}" — a Python
// list repr, or "None" when the probe is not registered.
func pyAnchorsRepr(probeID string) string {
	spec, ok := PB().Probes[probeID]
	if !ok || spec.Anchors == nil {
		return "None"
	}
	return validation.PyRepr(strArr(*spec.Anchors))
}

// inList is `x in items`.
func inList(x string, items []string) bool {
	for _, it := range items {
		if it == x {
			return true
		}
	}
	return false
}

// SiblingOpts is the optional tail of sibling_rescan (Python: adjacent=None,
// clear=False, reason=None, actor="cli").
type SiblingOpts struct {
	Adjacent string
	Clear    bool
	Reason   *string
	Actor    string
}

// SiblingRescan is sibling_rescan: the DISPROVED-side mirror of
// findings._anchor_rescan. Disproving a finding that implicates a lifecycle
// family must name the adjacent unchecked property (spawns an open SIBLING
// priority the queue must drain) or attest it already clear. A non-lifecycle
// disproof is a no-op. Returns the new priority id, or "" for Python's None.
func SiblingRescan(campaign *state.Campaign, finding validation.Value,
	opts SiblingOpts) (string, error) {
	model := ModelOrEmpty(campaign)
	toks := FamiliesForFinding(model, finding)
	if len(toks) == 0 {
		return "", nil
	}
	fid := objStr(finding, "finding_id")
	actor := actorOr(opts.Actor)
	if opts.Clear {
		data := validation.VObj(
			kv("reason", optStr(opts.Reason)),
			kv("actor", validation.VStr(actor)),
			kv("families", strArr(sortedKeys(toks))),
		)
		if _, err := campaign.Log("plan.sibling_cleared", &fid,
			&data); err != nil {
			return "", err
		}
		return "", nil
	}
	if pyStrip(opts.Adjacent) == "" {
		return "", errValue(AdjacentRequiredMsg)
	}
	plan, err := LoadPlanReadonly(campaign)
	if err != nil {
		return "", err
	}
	prios := listOf(plan, "priorities")
	pid := qid(len(prios) + 1)
	for hasPriorityID(prios, pid) {
		pid = nextPriorityID(pid)
	}
	cls := findingClass(finding)
	prios = append(prios, validation.VObj(
		kv("id", validation.VStr(pid)),
		kv("question", validation.VStr("Check the adjacent unchecked "+
			"property: "+pyStrip(opts.Adjacent))),
		kv("risk", validation.VFloat(0.6)),
		kv("trajectories", strArr([]string{"lifecycle"})),
		kv("status", validation.VStr("open")),
		kv("bug_class", validation.VStr(cls)),
		kv("sibling_of", validation.VStr(fid)),
	))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(prios...))
	if _, err := SavePlan(campaign, plan); err != nil {
		return "", err
	}
	data := validation.VObj(
		kv("priority_id", validation.VStr(pid)),
		kv("adjacent", validation.VStr(pyStrip(opts.Adjacent))),
		kv("families", strArr(sortedKeys(toks))),
		kv("actor", validation.VStr(actor)),
	)
	if _, err := campaign.Log("plan.sibling_priority", &fid,
		&data); err != nil {
		return "", err
	}
	return pid, nil
}

// hasPriorityID is `any(p.get("id") == pid for p in prios)`.
func hasPriorityID(prios []validation.Value, pid string) bool {
	for _, p := range prios {
		if objStr(p, "id") == pid {
			return true
		}
	}
	return false
}

// nextPriorityID is n += 1; pid = f"Q-{n:03d}".
func nextPriorityID(pid string) string {
	n := 1
	if len(pid) > 2 {
		if v, ok := atoi(pid[2:]); ok {
			n = v
		}
	}
	return qid(n + 1)
}

// findingClass is `(finding.get("root_cause") or {}).get("class") or
// finding.get("bug_class")`, falling back to "logic-error" when it is not a
// canonical class.
func findingClass(finding validation.Value) string {
	rootCause := objAt(finding, "root_cause")
	cls := objAt(rootCause, "class")
	if !pyTruthyBigNonEmpty(cls) {
		cls = objAt(finding, "bug_class")
	}
	known := taxonomy.KnownClasses()
	if cls.Kind == validation.Str {
		if _, ok := known[cls.S]; ok {
			return cls.S
		}
	}
	return "logic-error"
}
