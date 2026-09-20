// transitions_verdicts.go: the finding verdict writers — set_critic_verdict,
// the triager outlook, set_shield_adjudication, and mark_precondition
// (webv2.findings).
package findings

import (
	"fmt"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// DefaultCriticActor is the writer convention the boundary critic sweep has
// always carried implicitly (R3-9c): a verdict with no named actor was
// written by the model. CLI and event share this ONE constant.
const DefaultCriticActor = "model"

// SetCriticVerdict is set_critic_verdict: record the hostile-critic verdict
// and its reasoning. R3-9c: and WHO wrote it — the CONFIRMED gate reads
// this record, so it must say whose judgment it captures. The actor is
// variadic rather than a sixth positional because every existing caller IS
// the model path (the boundary sweep, every test fixture that seeds a
// verdict to move a gate): a mandatory parameter would have been 30 edits
// all spelling "model". An absent or blank actor normalizes to
// DefaultCriticActor on the event — never an anonymous record. Only the
// FIRST variadic value is read; a second is a caller bug, not a committee.
func SetCriticVerdict(campaign *state.Campaign, findingID, verdict,
	reasoning string, actor ...string) (validation.Value, error) {
	switch verdict {
	case "pending", "confirmed", "possible", "disproved", "duplicate",
		"out_of_scope", "informational":
	default:
		return validation.VNull(), fmt.Errorf("invalid critic verdict %s",
			validation.PyReprStr(verdict))
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	// R3 (critic): a verdict is a claim about a finding that EXISTS —
	// adjudicate already refuses dead rows for exactly this reason, and
	// verdict must not be the exception that pollutes a SUPERSEDED or
	// DUPLICATE row's verification block with fresh opinions.
	if IsTerminal(validation.ObjStr(finding, "status")) { // r5: one law, one predicate
		return validation.VNull(), fmt.Errorf(
			"cannot record a critic verdict on terminal finding %s (%s) — "+
				"a verdict is a claim about a finding that exists; the "+
				"successor row carries its own verdict",
			findingID, validation.ObjStr(finding, "status"))
	}
	ver := asDict(validation.ObjAt(finding, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "critic_verdict", validation.VStr(verdict))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	meta := asDict(validation.ObjAt(finding, "dedup_meta"))
	meta.O = validation.SetOrAppend(meta.O, "critic_reasoning", validation.VStr(reasoning))
	finding.O = validation.SetOrAppend(finding.O, "dedup_meta", meta)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move) — file+event land together or not
		// at all.
		who := DefaultCriticActor
		if len(actor) > 0 && strings.TrimSpace(actor[0]) != "" {
			who = strings.TrimSpace(actor[0])
		}
		data := validation.VObj(
			validation.KV{K: "verdict", V: validation.VStr(verdict)},
			validation.KV{K: "actor", V: validation.VStr(who)})
		if _, lerr := campaign.Log("finding.critic", &findingID, &data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// TriagerOutlooks is the SINGLE source of the outlook enum (schema, CLI and
// the acceptance table must all agree with it; the sync assertions in
// risk/acceptance_test.go enforce it — a fourth consumer is forbidden to
// hardcode its own copy).
func TriagerOutlooks() []string { return []string{"likely", "uncertain", "unlikely"} }

// SetTriagerOutlook is the G6 companion of set_critic_verdict: record the
// critic's acceptance-likelihood call — WILL A TRIAGER ACCEPT AND PAY THIS —
// kept structurally separate from critic_verdict (truth) and
// bounty.accepted_risk (policy). Absent field = no call = no score effect.
func SetTriagerOutlook(campaign *state.Campaign, findingID, outcome,
	reason string) (validation.Value, error) {
	// Membership is checked against TriagerOutlooks() — the single source —
	// so a new enum member cannot be accepted by the schema/CLI and still be
	// rejected here (which would fail after SetCriticVerdict already wrote).
	outcomes := TriagerOutlooks()
	member := false
	for _, o := range outcomes {
		if o == outcome {
			member = true
			break
		}
	}
	if !member {
		return validation.VNull(), fmt.Errorf("invalid triager outlook %s "+
			"(choose: %s)", validation.PyReprStr(outcome),
			strings.Join(outcomes, ", "))
	}
	stripped := strings.TrimSpace(reason)
	if len([]rune(stripped)) < 15 {
		return validation.VNull(), fmt.Errorf("triager outlook reasoning must " +
			"be substantive (>= 15 chars) — 'probably fine' is not a call")
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ver := asDict(validation.ObjAt(finding, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "triager_outlook", validation.VObj(
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "reason", V: validation.VStr(stripped)},
	))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(validation.KV{K: "outcome", V: validation.VStr(outcome)})
		if _, lerr := campaign.Log("finding.triager_outlook", &findingID, &data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// SetShieldAdjudication is set_shield_adjudication: record the
// plausibility-shield adjudication — the protocol's docs call the mechanism
// INTENTIONAL, and this finding says the economic effect is (or is not)
// extraction DESPITE that intent.
func SetShieldAdjudication(campaign *state.Campaign, findingID string,
	extracts bool, reasoning, actor string) (validation.Value, error) {
	if actor == "" {
		actor = "orchestrator"
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ver := asDict(validation.ObjAt(finding, "verification"))
	if len([]rune(reasoning)) < 15 {
		return validation.VNull(), fmt.Errorf("shield adjudication reasoning " +
			"must be substantive (>= 15 chars) — 'it extracts' is not an " +
			"adjudication")
	}
	ver.O = validation.SetOrAppend(ver.O, "shield_adjudication", validation.VObj(
		validation.KV{K: "extraction_despite_intent", V: validation.VBool(extracts)},
		validation.KV{K: "reasoning", V: validation.VStr(reasoning)},
		validation.KV{K: "at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "actor", V: validation.VStr(actor)},
	))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	if err := SaveThenLog(campaign, &finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(
			validation.KV{K: "extracts", V: validation.VBool(extracts)},
			validation.KV{K: "actor", V: validation.VStr(actor)},
		)
		if _, lerr := campaign.Log("finding.shield_adjudication", &findingID,
			&data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// MarkPrecondition is mark_precondition: audit a precondition against the
// PoC — does the CODE enforce it? enforced_by_poc becomes "true"/"false" for
// the first precondition whose description matches (exact, else
// case-insensitive substring).
func MarkPrecondition(campaign *state.Campaign, findingID, description string,
	enforced bool) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	value := "false"
	if enforced {
		value = "true"
	}
	pre := validation.ObjAt(finding, "preconditions")
	for i, p := range pre.A {
		if p.Kind != validation.Obj {
			continue
		}
		if validation.ObjStr(p, "description") == description {
			return auditPrecondition(campaign, &finding, i, p, description, value)
		}
	}
	low := strings.ToLower(description)
	for i, p := range pre.A {
		if p.Kind != validation.Obj {
			continue
		}
		desc := strings.ToLower(validation.ObjStr(p, "description"))
		if strings.Contains(desc, low) || strings.Contains(low, desc) {
			return auditPrecondition(campaign, &finding, i, p,
				validation.ObjStr(p, "description"), value)
		}
	}
	return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(
		fmt.Sprintf("%s: no precondition matching %s", findingID,
			validation.PyReprStr(description))))
}

func auditPrecondition(campaign *state.Campaign, finding *validation.Value,
	i int, p validation.Value, loggedDesc, value string) (validation.Value, error) {
	p.O = validation.SetOrAppend(p.O, "enforced_by_poc", validation.VStr(value))
	pre := validation.ObjAt(*finding, "preconditions")
	pre.A[i] = p
	finding.O = validation.SetOrAppend(finding.O, "preconditions", pre)
	fid := validation.ObjStr(*finding, "finding_id")
	if err := SaveThenLog(campaign, finding, func() error {
		// r17: unwind law (see move).
		data := validation.VObj(
			validation.KV{K: "description", V: validation.VStr(loggedDesc)},
			validation.KV{K: "enforced", V: validation.VStr(value)},
		)
		if _, lerr := campaign.Log("finding.precondition_audited", &fid,
			&data); lerr != nil {
			return lerr
		}
		return nil
	}); err != nil {
		return validation.VNull(), err
	}
	return *finding, nil
}
