// context_critic.go: the critic context bundle split out of context.go —
// build_critic_context, the claim/evidence projections and invariant
// verification state.
package roles

import (
	"sort"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// permittedChecks is _permitted_checks: union of the tool ids the model
// recommended per assumption.
func permittedChecks(finding validation.Value) []string {
	tools := map[string]bool{}
	if as := validation.ObjAt(finding, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind != validation.Obj {
				continue
			}
			if opts := validation.ObjAt(a, "verification_options"); opts.Kind == validation.Arr {
				for _, o := range opts.A {
					if o.Kind == validation.Str {
						tools[o.S] = true
					}
				}
			}
		}
	}
	out := make([]string, 0, len(tools))
	for t := range tools {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// criticClaim is _critic_claim: fresh serialization of the claim under
// review, allow-listed — no proposer narrative.
func criticClaim(finding validation.Value) validation.Value {
	rc := validation.AsObj(validation.ObjAt(finding, "root_cause"))
	econ := validation.AsObj(validation.ObjAt(finding, "economic_impact"))
	inv := validation.AsObj(validation.ObjAt(finding, "invariant"))
	invOut := validation.VObj()
	for _, k := range []string{"id", "statement", "documented_ref",
		"violation_demonstrated"} {
		if v := validation.ObjAt(inv, k); v.Kind != validation.Null {
			invOut.O = append(invOut.O, validation.KV{K: k, V: v})
		}
	}
	econOut := validation.VObj()
	for _, k := range []string{"asset", "max_loss_usd", "extractable_usd",
		"blast_radius", "extraction_ratio", "price_basis"} {
		if v := validation.ObjAt(econ, k); v.Kind != validation.Null {
			econOut.O = append(econOut.O, validation.KV{K: k, V: v})
		}
	}
	return validation.VObj(
		validation.KV{K: "finding_id", V: validation.ObjAt(finding, "finding_id")},
		validation.KV{K: "title", V: validation.ObjAt(finding, "title")},
		validation.KV{K: "claim_version", V: validation.ObjAt(finding, "claim_version")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.ObjAt(rc, "class")},
			validation.KV{K: "cwe", V: validation.ObjAt(rc, "cwe")})},
		validation.KV{K: "affected", V: orEmpty(finding, "affected")},
		validation.KV{K: "attacker", V: orEmptyObj(finding, "attacker")},
		validation.KV{K: "invariant", V: invOut},
		validation.KV{K: "security_invariants", V: orEmpty(finding, "security_invariants")},
		validation.KV{K: "economic_impact", V: econOut},
		validation.KV{K: "assumptions", V: orEmpty(finding, "assumptions")})
}

// minimalEvidence is _minimal_evidence: identity, level, type, provenance
// pins — the tool's own report, never the proposer's narrative.
func minimalEvidence(finding validation.Value) validation.Value {
	out := []validation.Value{}
	if ev := validation.ObjAt(finding, "evidence"); ev.Kind == validation.Arr {
		for _, e := range ev.A {
			if e.Kind != validation.Obj {
				continue
			}
			item := validation.VObj()
			for _, k := range []string{"evidence_id", "level", "type",
				"artifact_id", "command", "description", "sandbox_profile",
				"snapshot_id", "produced_at"} {
				if v := validation.ObjAt(e, k); v.Kind != validation.Null {
					item.O = append(item.O, validation.KV{K: k, V: v})
				}
			}
			out = append(out, item)
		}
	}
	return validation.VArr(out...)
}

// invariantVerificationBlock is _invariant_verification_block: the
// verification state of every invariant the claim hangs off.
func invariantVerificationBlock(campaign *state.Campaign,
	finding validation.Value) (validation.Value, error) {
	links, err := invariants.LoadLinks(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	reg := validation.ObjAt(links, "invariants")
	if reg.Kind != validation.Obj {
		return validation.VArr(), nil
	}
	normReg := map[string]validation.Value{}
	for _, kv := range reg.O {
		if kv.V.Kind == validation.Obj {
			normReg[invariants.NormalizeInvID(kv.K)] = kv.V
		}
	}
	out := []validation.Value{}
	for _, iid := range findings.InvariantIDs(finding) {
		e, ok := normReg[iid]
		if !ok {
			continue
		}
		stmt := validation.ObjStr(e, "statement")
		if stmt == "" {
			stmt = "(statement not recorded — legacy/migrated entry)"
		}
		status := validation.ObjStr(e, "status")
		if status == "" {
			status = "UNVERIFIED"
		}
		source := validation.ObjStr(e, "source")
		if source == "" {
			source = "model"
		}
		out = append(out, validation.VObj(
			validation.KV{K: "id", V: validation.VStr(iid)},
			validation.KV{K: "statement", V: validation.VStr(stmt)},
			validation.KV{K: "status", V: validation.VStr(status)},
			validation.KV{K: "source", V: validation.VStr(source)}))
	}
	return validation.VArr(out...), nil
}

// BuildCriticContext is build_critic_context.
func BuildCriticContext(campaign *state.Campaign,
	findingID string) (validation.Value, error) {
	finding, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	baseline := validation.ObjAt(finding, "attacker")
	if baseline.Kind != validation.Obj {
		baseline = validation.VObj()
	}
	invVer, err := invariantVerificationBlock(campaign, finding)
	if err != nil {
		return validation.VNull(), err
	}
	forkDiff, err := freshArtifact(campaign, "fork_diff.json", 12000)
	if err != nil {
		return validation.VNull(), err
	}
	seqReqs, err := sequenceRequirements(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	var seqReq validation.Value = validation.VNull()
	for _, r := range seqReqs {
		if validation.ObjStr(r, "finding_id") == findingID {
			seqReq = validation.VObj(
				validation.KV{K: "finding_id", V: validation.ObjAt(r, "finding_id")},
				validation.KV{K: "steps", V: validation.ObjAt(r, "steps")},
				validation.KV{K: "n_actors",
					V: validation.VInt(int64(len(validation.ObjAt(r, "actors").A)))},
				validation.KV{K: "note", V: validation.ObjAt(r, "note")})
			break
		}
	}
	bundle := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("critic")},
		validation.KV{K: "campaign_id", V: validation.VStr(campaign.CampaignID)},
		validation.KV{K: "claim", V: criticClaim(finding)},
		validation.KV{K: "attacker_baseline", V: baseline},
		validation.KV{K: "evidence", V: minimalEvidence(finding)},
		validation.KV{K: "snapshot_ids", V: validation.AsObj(validation.ObjAt(finding, "snapshot_ids"))},
		validation.KV{K: "permitted_checks",
			V: validation.StrArr(permittedChecks(finding))},
		validation.KV{K: "fork_diff", V: forkDiff},
		validation.KV{K: "invariant_verification", V: invVer},
		validation.KV{K: "sequence_requirement", V: seqReq},
		validation.KV{K: "benign_actor_audit", V: benignActorAuditBlock(campaign, finding)},
		validation.KV{K: "task", V: validation.VObj(
			validation.KV{K: "per_assumption", V: validation.VStr(
				"classify each assumption SUPPORTED, REFUTED, or UNKNOWN " +
					"and cite evidence or explain the gap")},
			validation.KV{K: "final_question", V: validation.VStr(
				"does the verified assumption set actually imply the " +
					"claimed security-property violation and attacker " +
					"outcome? if not, identify the smallest missing " +
					"proposition")},
			validation.KV{K: "response_schema",
				V: validation.VStr("critic_verdict")},
			validation.KV{K: "response_schema_file",
				V: validation.VStr("model_response.schema.json")})},
	)
	// Python deletes a None benign_actor_audit; omitting it keeps the order.
	if v := validation.ObjAt(bundle, "benign_actor_audit"); v.Kind == validation.Null {
		bundle = removeKey(bundle, "benign_actor_audit")
	}
	if err := AssertClean(bundle, "critic"); err != nil {
		return validation.VNull(), err
	}
	return bundle, nil
}
