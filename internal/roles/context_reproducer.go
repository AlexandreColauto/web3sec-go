// context_reproducer.go: the reproducer context bundle split out of
// context.go — build_reproducer_context, its claim projection and the
// blocking-assumption extraction.
package roles

import (
	"fmt"
	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// BuildReproducerContext is build_reproducer_context.
func BuildReproducerContext(campaign *state.Campaign,
	findingID string) (validation.Value, error) {
	finding, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	status := validation.ObjStr(finding, "status")
	if status != "CONFIRMED" && status != "PROVISIONALLY_VALID" &&
		status != "POSSIBLE" {
		return validation.VNull(), fmt.Errorf("%s is in status %s; the "+
			"reproducer context is built only for confirmed/near-confirmed "+
			"claims", findingID, status)
	}
	rc := validation.AsObj(validation.ObjAt(finding, "root_cause"))
	class := validation.ObjStr(rc, "class")
	repro := validation.AsObj(validation.ObjAt(validation.AsObj(validation.ObjAt(finding, "verification")), "reproduction"))
	required := blockingAssumptions(finding)
	snap, err := snapshotBlock(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	profiles := []validation.Value{}
	for _, p := range sandbox.Profiles {
		profiles = append(profiles, validation.VStr(p))
	}
	bundle := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("reproducer")},
		validation.KV{K: "campaign_id", V: validation.VStr(campaign.CampaignID)},
		validation.KV{K: "claim", V: reproducerClaim(finding, required)},
		validation.KV{K: "deployment", V: validation.AsObj(validation.ObjAt(finding, "snapshot_ids"))},
		validation.KV{K: "active_snapshot", V: snap},
		validation.KV{K: "reproduction_state", V: repro},
		validation.KV{K: "permitted_execution_profiles", V: validation.VArr(profiles...)},
		validation.KV{K: "success_criteria", V: validation.VObj(
			validation.KV{K: "exit_status", V: validation.VInt(0)},
			validation.KV{K: "min_evidence_level", V: validation.VStr(
				findings.RequiredLevelForCampaign(campaign, "POSSIBLE", class))},
			validation.KV{K: "snapshot_pinned", V: validation.VBool(true)},
			validation.KV{K: "record_via", V: validation.VStr(
				"reproduction.record_attempt / findings.add_evidence")})},
		validation.KV{K: "task", V: validation.VObj(
			validation.KV{K: "response_schema",
				V: validation.VStr("reproducer_request")},
			validation.KV{K: "response_schema_file",
				V: validation.VStr("model_response.schema.json")})},
	)
	if err := AssertClean(bundle, "reproducer"); err != nil {
		return validation.VNull(), err
	}
	return bundle, nil
}

// reproducerClaim is the claim the reproducer may see: the bug's own facts,
// never the critic's verdict or the bounty fields (AssertClean enforces the
// boundary; this shape is what the doc's §4.1 column allows).
func reproducerClaim(finding validation.Value,
	required []validation.Value) validation.Value {
	rc := validation.AsObj(validation.ObjAt(finding, "root_cause"))
	econ := validation.AsObj(validation.ObjAt(finding, "economic_impact"))
	return validation.VObj(
		validation.KV{K: "finding_id", V: validation.ObjAt(finding, "finding_id")},
		validation.KV{K: "title", V: validation.ObjAt(finding, "title")},
		validation.KV{K: "claim_version", V: validation.ObjAt(finding, "claim_version")},
		validation.KV{K: "root_cause", V: projectKeys(rc, []string{
			"class", "cwe", "description", "mechanism"})},
		validation.KV{K: "affected", V: orEmpty(finding, "affected")},
		validation.KV{K: "attacker", V: orEmptyObj(finding, "attacker")},
		validation.KV{K: "invariant", V: orEmptyObj(finding, "invariant")},
		validation.KV{K: "exploit_sequence", V: orEmpty(finding, "exploit_sequence")},
		validation.KV{K: "economic_impact", V: projectKeys(econ, []string{
			"asset", "max_loss_usd", "extractable_usd", "blast_radius",
			"mechanism", "extraction_ratio", "price_basis"})},
		validation.KV{K: "required_assumptions",
			V: validation.VArr(required...)})
}

// blockingAssumptions is the assumption entries the reproduction must satisfy
// (blocking == true), in the finding's order.
func blockingAssumptions(finding validation.Value) []validation.Value {
	required := []validation.Value{}
	as := validation.ObjAt(finding, "assumptions")
	if as.Kind != validation.Arr {
		return required
	}
	for _, a := range as.A {
		if a.Kind == validation.Obj &&
			validation.ObjAt(a, "blocking").Kind == validation.Bool &&
			validation.ObjAt(a, "blocking").B {
			required = append(required, a)
		}
	}
	return required
}

// projectKeys is {k: v for k in keys if v is present} — the allow-list shape
// the reproducer bundle uses for root_cause and economic_impact.
func projectKeys(v validation.Value, keys []string) validation.Value {
	out := validation.VObj()
	for _, k := range keys {
		if x := validation.ObjAt(v, k); x.Kind != validation.Null {
			out.O = append(out.O, validation.KV{K: k, V: x})
		}
	}
	return out
}
