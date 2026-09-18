// context.go: the proposer context bundle — build_proposer_context, the
// blocks it gathers and the wire shape it emits.
package roles

import (
	"path/filepath"
	"websec/internal/corpus"
	"websec/internal/findings"
	"websec/internal/playbooks"
	"websec/internal/state"
	"websec/internal/validation"
)

// proposerBlocks is everything build_proposer_context injects, gathered
// before the bundle is assembled.
type proposerBlocks struct {
	playbook, snap, neg, shared, surface validation.Value
	policy, stats, valueFlow, prescreen  validation.Value
	forkDiff, recency, protoModel, plan  validation.Value
	st                                   validation.Value
	seqReqs, summaries                   []validation.Value
	active                               *string
}

// BuildProposerContext is build_proposer_context.
func BuildProposerContext(campaign *state.Campaign,
	bugClass *string) (validation.Value, error) {
	b, err := gatherProposerBlocks(campaign, bugClass)
	if err != nil {
		return validation.VNull(), err
	}
	return proposerBundle(campaign, b)
}

// gatherProposerBlocks collects the proposer's context blocks in the order
// build_proposer_context reads them (a failing read reports its own error).
func gatherProposerBlocks(campaign *state.Campaign,
	bugClass *string) (proposerBlocks, error) {
	var b proposerBlocks
	b.playbook = validation.VNull()
	var err error
	if bugClass != nil {
		pb, found, err := playbooks.PlaybookForClass(*bugClass)
		if err != nil {
			return b, err
		}
		if found {
			b.playbook = pb
		}
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return b, err
	}
	if b.st, err = campaign.State(); err != nil {
		return b, err
	}
	if b.snap, err = snapshotBlock(campaign); err != nil {
		return b, err
	}
	if b.neg, err = knownNonIssues(campaign, bugClass, 12); err != nil {
		return b, err
	}
	if b.shared, err = corpus.SharedMemoryBlock(campaign, bugClass, 20); err != nil {
		return b, err
	}
	if b.surface, err = corpus.CorpusSurfaceBlock(campaign, 10, 20); err != nil {
		return b, err
	}
	if b.policy, err = campaignPolicy(campaign); err != nil {
		return b, err
	}
	if b.stats, err = freshIndexStats(campaign, 4000); err != nil {
		return b, err
	}
	for _, a := range []struct {
		dst  *validation.Value
		name string
	}{
		{&b.valueFlow, "value_flow.json"},
		{&b.prescreen, "archetype_prescreen.json"},
		{&b.forkDiff, "fork_diff.json"},
		{&b.recency, "recency.json"},
	} {
		if *a.dst, err = freshArtifact(campaign, a.name, 12000); err != nil {
			return b, err
		}
	}
	if b.seqReqs, err = sequenceRequirements(campaign); err != nil {
		return b, err
	}
	if b.protoModel, b.plan, err = proposerArtifacts(campaign); err != nil {
		return b, err
	}
	for i, f := range all {
		if i >= 80 {
			break
		}
		b.summaries = append(b.summaries, findingSummary(f))
	}
	if b.active, err = campaign.ActiveSnapshotIDOrNone(); err != nil {
		return b, err
	}
	return b, nil
}

// proposerArtifacts is the two bounded-JSON artifacts: the protocol model
// (20k cap) and the campaign plan (8k cap).
func proposerArtifacts(campaign *state.Campaign) (validation.Value,
	validation.Value, error) {
	protoModel, err := boundedJSON(filepath.Join(campaign.ArtifactsDir,
		"protocol_model.json"), 20000)
	if err != nil {
		return validation.VNull(), validation.VNull(), err
	}
	plan, err := boundedJSON(filepath.Join(campaign.ArtifactsDir,
		"campaign_plan.json"), 8000)
	if err != nil {
		return validation.VNull(), validation.VNull(), err
	}
	return protoModel, plan, nil
}

// proposerBundle is the wire shape, plus the simulation directive when the
// playbook carries one, then the role-isolation check.
func proposerBundle(campaign *state.Campaign,
	b proposerBlocks) (validation.Value, error) {
	bundle := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "campaign_id", V: validation.VStr(campaign.CampaignID)},
		validation.KV{K: "target", V: validation.VObj(
			validation.KV{K: "program", V: validation.ObjAt(b.st, "program")},
			validation.KV{K: "active_snapshot_id", V: nullableStr(b.active)})},
		validation.KV{K: "snapshot", V: b.snap},
		validation.KV{K: "playbook", V: b.playbook},
		validation.KV{K: "negative_memory", V: b.neg},
		validation.KV{K: "shared_memory", V: b.shared},
		validation.KV{K: "corpus_surface", V: b.surface},
		validation.KV{K: "campaign_policy", V: b.policy},
		validation.KV{K: "structural_index_stats", V: b.stats},
		validation.KV{K: "value_flow", V: b.valueFlow},
		validation.KV{K: "archetype_prescreen", V: b.prescreen},
		validation.KV{K: "fork_diff", V: b.forkDiff},
		validation.KV{K: "recency", V: b.recency},
		validation.KV{K: "sequence_requirements", V: validation.VArr(b.seqReqs...)},
		validation.KV{K: "protocol_model", V: b.protoModel},
		validation.KV{K: "campaign_plan", V: b.plan},
		validation.KV{K: "existing_findings", V: validation.VArr(b.summaries...)},
		validation.KV{K: "request", V: validation.VObj(
			validation.KV{K: "response_schemas",
				V: validation.VArr(validation.VStr("hypothesis"),
					validation.VStr("plan"))},
			validation.KV{K: "response_schema_file",
				V: validation.VStr("model_response.schema.json")})},
	)
	if directive := simulationDirectiveBlock(b.playbook); directive.Kind != validation.Null {
		bundle.O = append(bundle.O, validation.KV{K: "simulation_directive", V: directive})
	}
	if err := AssertClean(bundle, "proposer"); err != nil {
		return validation.VNull(), err
	}
	return bundle, nil
}
