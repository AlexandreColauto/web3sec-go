package regression

import (
	"fmt"

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
// target, and the extractable figure P1's Task 10 spike consumes.
type HandoffSpec struct {
	TargetID       string
	FindingID      string
	ExtractableUSD float64
	Source         string
	RecordedBy     string
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
	if spec.ExtractableUSD <= 0 {
		return fmt.Errorf("handoff extractable_usd must be positive (got %v)",
			spec.ExtractableUSD)
	}
	if spec.Source == "" {
		return fmt.Errorf("the handoff needs --source: how the extractable figure was derived")
	}
	return nil
}

// handoffDoc builds the handoff block the P1 spike reads.
func handoffDoc(spec HandoffSpec) validation.Value {
	handoff := validation.VObj(
		kv("finding_id", validation.VStr(spec.FindingID)),
		kv("extractable_usd", validation.VFloat(spec.ExtractableUSD)),
		kv("source", validation.VStr(spec.Source)),
		kv("recorded_at", validation.VStr(state.NowIso())),
	)
	if spec.RecordedBy != "" {
		handoff.O = validation.SetOrAppend(handoff.O, "recorded_by",
			validation.VStr(spec.RecordedBy))
	}
	return handoff
}

// RecordHandoff records the control target's handoff: the one confirmed
// finding and the extractable figure that are P1 Task 10 Step 4's input.
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
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("finding_id", validation.VStr(spec.FindingID)),
		kv("extractable_usd", validation.VFloat(spec.ExtractableUSD)),
		kv("source", validation.VStr(spec.Source)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.control.handoff", &tid, data)
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
