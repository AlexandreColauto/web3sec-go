package regression

import (
	"fmt"
	"unicode/utf8"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// controlKey is §3a's target kind for the already-exploited control target and
// the record key its block and its P1 handoff live under — one constant
// because the two uses are deliberately the same word, and because goconst
// counts every occurrence of a literal.
const controlKey = "control"

// ControlSpec is one already-exploited control target (§3a): separately
// sourced, pinned to a PRE-PATCH commit, with its own harness and the public
// loss figure plus its citation.
type ControlSpec struct {
	TargetID       string
	IncidentURL    string
	IncidentDate   string
	LossUSD        float64
	LossSource     string
	PostmortemURL  string
	PrePatchSHA    string
	PatchSHA       string
	HarnessRunner  string
	HarnessCommand string
}

// requireControlTarget is the target-side guard shared by RecordControl and
// RecordHandoff: the target must exist and must be the control target. The
// block is the control target's own artefact, so attaching it to a ScaBench
// row would be a record that looks sourced and belongs to nothing.
func requireControlTarget(c *state.Campaign, id string) (validation.Value, error) {
	target, ok, err := Target(c, id)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			id, c.CampaignID)
	}
	if got := validation.ObjStr(target, "kind"); got != controlKey {
		return validation.VNull(), fmt.Errorf(
			"target %s is kind %q — the control block belongs to a %s target",
			id, got, controlKey)
	}
	return target, nil
}

// checkControlSpec is RecordControl's refusals about the SPEC — the seven ways
// a control target could look finished while proving nothing. Split from
// RecordControl because the house rule caps a function at 30 lines and a
// cyclomatic complexity of 10, and the seven checks plus the writes exceed
// both in one body.
func checkControlSpec(spec ControlSpec) error {
	if spec.IncidentURL == "" || spec.IncidentDate == "" {
		return fmt.Errorf("the incident needs --incident-url and --incident-date: the control target is sourced from a published record, and an unsourced one is just a guess with a pin")
	}
	if spec.LossUSD <= 0 {
		return fmt.Errorf("incident loss_usd must be positive (got %v)", spec.LossUSD)
	}
	if spec.LossSource == "" {
		return fmt.Errorf("the incident needs a cited loss figure (loss_source / --loss-source): an uncited number is the fact this suite refuses everywhere else")
	}
	if !sha40Re.MatchString(spec.PrePatchSHA) {
		return fmt.Errorf("the pre-patch pin %q is not a 40-hex commit — §3a requires a pinned PRE-PATCH commit, and a ref is not a pin", spec.PrePatchSHA)
	}
	if !sha40Re.MatchString(spec.PatchSHA) {
		return fmt.Errorf("the patch pin %q is not a 40-hex commit", spec.PatchSHA)
	}
	if spec.PrePatchSHA == spec.PatchSHA {
		return fmt.Errorf("pre-patch and patch SHAs are the same commit (%s) — nobody pinned the vulnerable revision", spec.PrePatchSHA)
	}
	if spec.HarnessRunner == "" {
		return fmt.Errorf("the control target needs its own harness (--harness-runner): §3a is explicit that it will not run under ScaBench's baseline runner")
	}
	return nil
}

// incidentDoc builds the incident block: where the exploit is written down,
// when it happened, how much was lost, and where that figure came from.
func incidentDoc(spec ControlSpec) validation.Value {
	incident := validation.VObj(
		kv("url", validation.VStr(spec.IncidentURL)),
		kv("date", validation.VStr(spec.IncidentDate)),
		kv("loss_usd", validation.VFloat(spec.LossUSD)),
		kv("loss_source", validation.VStr(spec.LossSource)),
	)
	if spec.PostmortemURL != "" {
		incident.O = validation.SetOrAppend(incident.O, "postmortem_url",
			validation.VStr(spec.PostmortemURL))
	}
	return incident
}

// controlDoc builds the control block: the pre-patch pin, the patch it was
// fixed in, and the harness that is the control target's own.
func controlDoc(spec ControlSpec) validation.Value {
	harness := validation.VObj(kv("runner", validation.VStr(spec.HarnessRunner)))
	if spec.HarnessCommand != "" {
		harness.O = validation.SetOrAppend(harness.O, "command",
			validation.VStr(spec.HarnessCommand))
	}
	return validation.VObj(
		kv("pre_patch_sha", validation.VStr(spec.PrePatchSHA)),
		kv("patch_sha", validation.VStr(spec.PatchSHA)),
		kv("harness", harness),
	)
}

// RecordControl attaches the control block to an already-registered target of
// kind "control". Every refusal here is a way the control target could look
// finished while proving nothing.
func RecordControl(c *state.Campaign, spec ControlSpec) (validation.Value, error) {
	target, err := requireControlTarget(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if err := checkControlSpec(spec); err != nil {
		return validation.VNull(), err
	}
	doc := copyTargetWithKeys(target, []validation.KV{
		kv("incident", incidentDoc(spec)),
		kv(controlKey, controlDoc(spec)),
	})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("incident_url", validation.VStr(spec.IncidentURL)),
		kv("loss_usd", validation.VFloat(spec.LossUSD)),
		kv("pre_patch_sha", validation.VStr(spec.PrePatchSHA)),
		kv("patch_sha", validation.VStr(spec.PatchSHA)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.control.recorded", &tid, data)
}

// HandoffSpec is the P1 handoff: which confirmed finding on the control
// target, and the extractable figure P1's Task 10 spike consumes — OR the
// NAMED DECISION (Unpriceable + Ceiling + Reason) that no figure is
// defensible.
//
// The decision exists because the handoff could otherwise only be closed by
// inventing a number. T-7e2781f96e25's finding F-cfff3ebc0250 is CONFIRMED
// while its extractable_usd was REFUSED: c5ba1048
// (docs/gates/v16-P1-10b-fork-spike.md) measured that the 10b fork spike ran
// no attack — the target's own suite is stale against the fork block, and
// part of the run is an artifact of the free RPC tier — so no loss was
// measured and no figure is obtainable. The escape is the same shape
// risk.RecordUnpriceable writes on the finding's economic_impact, for the
// same reason: "a bare flag is not a decision".
type HandoffSpec struct {
	TargetID       string
	FindingID      string
	ExtractableUSD float64
	Source         string
	RecordedBy     string
	Unpriceable    bool
	Ceiling        string
	Reason         string
}

// checkHandoff is RecordHandoff's refusals about the FINDING and the figure —
// the P1 dependency stated as code. The finding must EXIST and be CONFIRMED,
// because P1's Phase 2 exit criterion says "one already-confirmed finding",
// and a handoff naming a POSSIBLE finding would re-create exactly the blocker
// this task exists to remove.
func checkHandoff(c *state.Campaign, spec HandoffSpec) error {
	finding, err := findings.LoadFinding(c, spec.FindingID)
	if err != nil {
		return fmt.Errorf(
			"handoff names finding %s, which this campaign does not have: %w",
			spec.FindingID, err)
	}
	if got := validation.ObjStr(finding, "status"); got != "CONFIRMED" {
		return fmt.Errorf(
			"finding %s has status %q, not CONFIRMED — the Phase 2 spike needs one already-confirmed finding, so a handoff for a %s finding would leave P1 Task 10 blocked",
			spec.FindingID, got, got)
	}
	if spec.Unpriceable {
		return checkUnpriceableHandoff(spec)
	}
	if spec.ExtractableUSD <= 0 {
		return fmt.Errorf("handoff extractable_usd must be positive (got %v)",
			spec.ExtractableUSD)
	}
	if spec.Source == "" {
		return fmt.Errorf("the handoff needs --source: how the extractable figure was derived")
	}
	return nil
}

// checkUnpriceableHandoff is the NAMED DECISION's own rule set, in the same
// spirit as risk.RecordUnpriceable: the decision is DATA, not a bypass, so it
// carries the capacity basis it was made against, a written reason and the
// actor who decided — and never a figure as well (the schema refuses the pair
// too; this is the Go layer's own message).
//
// The messages mirror RecordUnpriceable's wording deliberately: the operator
// meets the same decision on two records, so it must read the same.
func checkUnpriceableHandoff(spec HandoffSpec) error {
	if spec.ExtractableUSD != 0 {
		return fmt.Errorf("an unpriceable handoff must not carry extractable_usd (got %v): the escape records why no figure exists, not a figure",
			spec.ExtractableUSD)
	}
	if validation.PyStrip(spec.Ceiling) == "" {
		return fmt.Errorf("an unpriceable handoff must state the capacity basis it was made against (--ceiling)")
	}
	if utf8.RuneCountInString(validation.PyStrip(spec.Reason)) < 10 {
		return fmt.Errorf("an unpriceable handoff needs a written reason (>=10 chars): the point is the audit trail, not the bypass")
	}
	if validation.PyStrip(spec.RecordedBy) == "" {
		return fmt.Errorf("an unpriceable handoff must name its actor (who decided this): pass --actor")
	}
	// source stays required on this path too (the schema requires it
	// unconditionally), and it means the provenance of the DECISION here —
	// the refusal the figure came from — not of a number.
	if validation.PyStrip(spec.Source) == "" {
		return fmt.Errorf("an unpriceable handoff needs --source: what the refusal was read from")
	}
	return nil
}

// handoffDoc builds the handoff block the P1 spike reads. The key order
// follows the schema's own declaration order, and an unpriceable decision
// appends priceable/ceiling/reason where the figure would have been — with
// extractable_usd ABSENT, never a zero that would read as a measurement.
func handoffDoc(spec HandoffSpec) validation.Value {
	handoff := validation.VObj(kv("finding_id", validation.VStr(spec.FindingID)))
	if !spec.Unpriceable {
		handoff.O = validation.SetOrAppend(handoff.O, "extractable_usd",
			validation.VFloat(spec.ExtractableUSD))
	}
	handoff.O = validation.SetOrAppend(handoff.O, "source", validation.VStr(spec.Source))
	handoff.O = validation.SetOrAppend(handoff.O, "recorded_at",
		validation.VStr(state.NowIso()))
	if spec.RecordedBy != "" {
		handoff.O = validation.SetOrAppend(handoff.O, "recorded_by",
			validation.VStr(handoffActor(spec)))
	}
	if spec.Unpriceable {
		handoff.O = validation.SetOrAppend(handoff.O, "priceable", validation.VBool(false))
		handoff.O = validation.SetOrAppend(handoff.O, "ceiling",
			validation.VStr(validation.PyStrip(spec.Ceiling)))
		handoff.O = validation.SetOrAppend(handoff.O, "reason",
			validation.VStr(validation.PyStrip(spec.Reason)))
	}
	return handoff
}

// handoffActor is the unpriceable decision's attribution as it lands on the
// RECORD and on the LEDGER: one string, stripped once, so the audit's
// byte-comparison between the two cannot disagree with an honest write. The
// priceable form keeps the operator's bytes untouched (its actor is not
// reconciled against the log, and the pre-existing handoff payload is pinned).
func handoffActor(spec HandoffSpec) string {
	if !spec.Unpriceable {
		return spec.RecordedBy
	}
	return validation.PyStrip(spec.RecordedBy)
}

// handoffEventData is the handoff's one ledger event payload. An unpriceable
// decision logs the decision's own basis (priceable/ceiling/reason) and the
// ACTOR who decided, and NO extractable_usd key: the ledger must not carry a
// zero the projection does not hold, and a decision the log cannot attribute
// is a decision the audit cannot reconcile. RecordHandoff logs exactly one
// event — this is its payload, not a second event.
func handoffEventData(spec HandoffSpec) validation.Value {
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("finding_id", validation.VStr(spec.FindingID)),
	)
	if spec.Unpriceable {
		data.O = append(data.O,
			kv("priceable", validation.VBool(false)),
			kv("ceiling", validation.VStr(validation.PyStrip(spec.Ceiling))),
			kv("reason", validation.VStr(validation.PyStrip(spec.Reason))),
			kv("actor", validation.VStr(handoffActor(spec))))
	} else {
		data.O = append(data.O, kv("extractable_usd", validation.VFloat(spec.ExtractableUSD)))
	}
	data.O = append(data.O, kv("source", validation.VStr(spec.Source)))
	return data
}

// RecordHandoff records the control target's handoff: the one confirmed
// finding and the extractable figure that are P1 Task 10 Step 4's input, or
// the named unpriceable decision that stands in for a figure no measurement
// supports.
func RecordHandoff(c *state.Campaign, spec HandoffSpec) (validation.Value, error) {
	target, err := requireControlTarget(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !validation.HasKey(target, controlKey) {
		return validation.VNull(), fmt.Errorf(
			"control target %s has no control block yet — record the incident and the pre-patch pin first",
			spec.TargetID)
	}
	if err := checkHandoff(c, spec); err != nil {
		return validation.VNull(), err
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("handoff", handoffDoc(spec))})
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.control.handoff", &tid, handoffEventData(spec))
}

// copyTargetWithKeys returns the target document with extra keys appended in
// the order given, preserving every existing key's position (the ordered-JSON
// discipline: a rewrite must not reorder a record).
func copyTargetWithKeys(target validation.Value, extra []validation.KV) validation.Value {
	out := validation.VObj()
	out.O = append(out.O, target.O...)
	for _, kvp := range extra {
		out.O = validation.SetOrAppend(out.O, kvp.K, kvp.V)
	}
	return out
}
