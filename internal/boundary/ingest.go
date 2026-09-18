package boundary

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// HypothesisOpts carries ingest_model_hypothesis's keyword arguments.
type HypothesisOpts struct {
	Stage   *string // nil = "discovery-specialist"
	Model   string  // "" = None
	Request validation.Value
}

// IngestModelHypothesis is ingest_model_hypothesis: validate the raw output
// against the hypothesis contract, then (only then) build the finding
// payload, install the assumptions, and record the memory utility signal.
func IngestModelHypothesis(campaign *state.Campaign, raw validation.Value,
	o HypothesisOpts) (validation.Value, error) {
	if err := ValidateResponse("proposer", "hypothesis", raw, campaign); err != nil {
		if _, logErr := RecordRejection(campaign, "proposer", "hypothesis",
			raw, err); logErr != nil {
			return validation.VNull(), logErr
		}
		return validation.VNull(), err
	}
	if err := logHypothesisRequest(campaign, o.Request); err != nil {
		return validation.VNull(), err
	}
	stage := "discovery-specialist"
	if o.Stage != nil {
		stage = *o.Stage
	}
	f, err := findings.IngestHypothesis(campaign, hypothesisPayload(raw),
		"model", stage, o.Model)
	if err != nil {
		return validation.VNull(), err
	}
	fid := validation.ObjStr(f, "finding_id")
	one := int64(1)
	if _, err := findings.SetAssumptions(campaign, fid, rawAssumptions(raw),
		&one, "proposer"); err != nil {
		return validation.VNull(), err
	}
	if err := logPlanReceived(campaign, fid, raw); err != nil {
		return validation.VNull(), err
	}
	if err := memoryUtility(campaign, fid, raw); err != nil {
		return validation.VNull(), err
	}
	return findings.LoadFinding(campaign, fid)
}

// logHypothesisRequest records the model request that produced the hypothesis
// (validated first: a malformed request is a boundary error, not a log row).
func logHypothesisRequest(campaign *state.Campaign,
	request validation.Value) error {
	if request.Kind != validation.Obj {
		return nil
	}
	if err := ValidateRequest(request); err != nil {
		return err
	}
	_, err := campaign.Log("model.request", nil, &request)
	return err
}

// hypothesisPayload is the finding payload the hypothesis contract maps onto:
// claim -> title and root_cause.description, target -> affected[0], attacker
// defaulted, exploit_sequence carried through only when non-empty.
func hypothesisPayload(raw validation.Value) validation.Value {
	target := validation.AsObj(validation.ObjAt(raw, "target"))
	attacker := validation.ObjAt(raw, "attacker")
	if attacker.Kind != validation.Obj {
		attacker = validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")})
	}
	if validation.ObjAt(attacker, "capabilities").Kind == validation.Null {
		attacker.O = append(attacker.O, validation.KV{K: "capabilities",
			V: validation.VArr()})
	}
	payload := validation.VObj(
		validation.KV{K: "title", V: validation.VStr(pyTrunc(
			validation.ObjStr(raw, "claim"), 300))},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.ObjAt(raw, "bug_class")},
			validation.KV{K: "description", V: validation.ObjAt(raw, "claim")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.ObjAt(target, "path")},
			validation.KV{K: "function", V: validation.ObjAt(target, "function")}))},
		validation.KV{K: "attacker", V: attacker})
	if seq := validation.ObjAt(raw, "exploit_sequence"); seq.Kind == validation.Arr &&
		len(seq.A) > 0 {
		payload.O = append(payload.O, validation.KV{K: "exploit_sequence", V: seq})
	}
	return payload
}

// rawAssumptions copies the model's assumption entries (the caller validates
// them already; SetAssumptions owns the state transition).
func rawAssumptions(raw validation.Value) []validation.Value {
	out := []validation.Value{}
	as := validation.ObjAt(raw, "assumptions")
	if as.Kind != validation.Arr {
		return out
	}
	for _, a := range as.A {
		out = append(out, copyValue(a))
	}
	return out
}

// logPlanReceived records model.plan_received with the step count and the
// sorted distinct tool ids of the initial plan (only when it has steps).
func logPlanReceived(campaign *state.Campaign, fid string,
	raw validation.Value) error {
	plan := validation.ObjAt(raw, "initial_plan")
	if plan.Kind != validation.Arr || len(plan.A) == 0 {
		return nil
	}
	tools := map[string]bool{}
	for _, s := range plan.A {
		if s.Kind == validation.Obj {
			tools[validation.ObjStr(s, "tool_id")] = true
		}
	}
	names := make([]string, 0, len(tools))
	for t := range tools {
		names = append(names, t)
	}
	sort.Strings(names)
	data := validation.VObj(
		validation.KV{K: "steps", V: validation.VInt(int64(len(plan.A)))},
		validation.KV{K: "tools", V: validation.StrArr(names)})
	_, err := campaign.Log("model.plan_received", &fid, &data)
	return err
}

// ApplyCriticVerdict is apply_critic_verdict: validate the full contract, then
// apply each per-assumption classification through
// findings.assumption_transition and the final verdict through
// set_critic_verdict.
func ApplyCriticVerdict(campaign *state.Campaign, findingID string,
	raw validation.Value, actor string) (validation.Value, error) {
	if actor == "" {
		actor = "critic"
	}
	if err := ValidateResponse("critic", "critic_verdict", raw, campaign); err != nil {
		if _, logErr := RecordRejection(campaign, "critic", "critic_verdict",
			raw, err); logErr != nil {
			return validation.VNull(), logErr
		}
		return validation.VNull(), err
	}
	applied := []string{}
	if err := applyAssumptionMoves(campaign, findingID, raw, actor,
		&applied); err != nil {
		if _, logErr := RecordRejection(campaign, "critic", "critic_verdict",
			raw, err); logErr != nil {
			return validation.VNull(), logErr
		}
		return validation.VNull(), &BoundaryError{Msg: fmt.Sprintf(
			"critic verdict rejected at apply time (assumptions moved: %s): %v",
			validation.PyListRepr(applied), err)}
	}
	reasoning := composeReasoning(raw)
	if _, err := findings.SetCriticVerdict(campaign, findingID,
		validation.ObjStr(raw, "verdict"), reasoning); err != nil {
		return validation.VNull(), err
	}
	return findings.LoadFinding(campaign, findingID)
}

// applyAssumptionMoves runs the per-assumption transitions (Python's
// documented residual gap: a mid-loop failure leaves applied moves committed).
func applyAssumptionMoves(campaign *state.Campaign, findingID string,
	raw validation.Value, actor string, applied *[]string) error {
	finding, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return err
	}
	curByID := map[string]string{}
	if as := validation.ObjAt(finding, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind == validation.Obj {
				curByID[validation.ObjStr(a, "id")] = validation.ObjStr(a, "status")
			}
		}
	}
	per := validation.ObjAt(raw, "per_assumption")
	if per.Kind != validation.Arr {
		return nil
	}
	for _, entry := range per.A {
		if entry.Kind != validation.Obj {
			continue
		}
		aid := validation.ObjStr(entry, "assumption_id")
		status := validation.ObjStr(entry, "status")
		if status == "UNKNOWN" {
			continue
		}
		if curByID[aid] == status {
			continue
		}
		cited := []string{}
		if c := validation.ObjAt(entry, "evidence_cited"); c.Kind == validation.Arr {
			for _, ref := range c.A {
				if ref.Kind == validation.Str {
					cited = append(cited, ref.S)
				}
			}
		}
		if _, err := findings.AssumptionTransition(campaign, findingID, aid,
			status, cited, actor); err != nil {
			return err
		}
		*applied = append(*applied, aid)
	}
	return nil
}

// composeReasoning is the "; "-joined reasoning string (capped at 2000).
func composeReasoning(raw validation.Value) string {
	parts := []string{}
	if per := validation.ObjAt(raw, "per_assumption"); per.Kind == validation.Arr {
		for _, e := range per.A {
			if e.Kind != validation.Obj {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s:%s (%s)",
				validation.ObjStr(e, "assumption_id"), validation.ObjStr(e, "status"),
				validation.ObjStr(e, "note")))
		}
	}
	reasoning := strings.Join(parts, "; ")
	if mp := validation.ObjAt(raw, "missing_proof"); mp.Kind == validation.Arr &&
		len(mp.A) > 0 {
		items := []string{}
		for i, m := range mp.A {
			if i >= 3 {
				break
			}
			if m.Kind == validation.Str {
				items = append(items, m.S)
			}
		}
		reasoning += " | missing: " + strings.Join(items, "; ")
	}
	return pyTrunc(reasoning, 2000)
}

// SubmitReproducerRequest is submit_reproducer_request: validate, then hand
// the EXACT validated request back to the harness for execution. The request
// is logged with its input hash.
func SubmitReproducerRequest(campaign *state.Campaign,
	raw validation.Value) (validation.Value, error) {
	if err := ValidateResponse("reproducer", "reproducer_request", raw,
		campaign); err != nil {
		if _, logErr := RecordRejection(campaign, "reproducer",
			"reproducer_request", raw, err); logErr != nil {
			return validation.VNull(), logErr
		}
		return validation.VNull(), err
	}
	fid := validation.ObjStr(raw, "finding_id")
	data := validation.VObj(
		validation.KV{K: "snapshot_id", V: validation.ObjAt(raw, "snapshot_id")},
		validation.KV{K: "execution_profile", V: validation.ObjAt(raw, "execution_profile")},
		validation.KV{K: "min_evidence_level",
			V: validation.ObjAt(validation.AsObj(validation.ObjAt(raw, "success_criteria")), "min_evidence_level")},
		validation.KV{K: "request_sha256", V: validation.VStr(ContextHash(raw))})
	if _, err := campaign.Log("model.reproducer_request", &fid, &data); err != nil {
		return validation.VNull(), err
	}
	return raw, nil
}

// asObj returns an object or an empty one.

// copyValue is a deep copy of a Value (Python's dict(a)).
func copyValue(v validation.Value) validation.Value {
	switch v.Kind {
	case validation.Obj:
		out := validation.VObj()
		for _, kv := range v.O {
			out.O = append(out.O, validation.KV{K: kv.K,
				V: copyValue(kv.V)})
		}
		return out
	case validation.Arr:
		out := make([]validation.Value, len(v.A))
		for i := range v.A {
			out[i] = copyValue(v.A[i])
		}
		return validation.VArr(out...)
	}
	return v
}
