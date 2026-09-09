package roles

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/corpus"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/learning"
	"websec/internal/playbooks"
	"websec/internal/sandbox"
	"websec/internal/sequencepoc"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// sequenceRequirements is _sequence_requirements: live findings whose
// declared exploit_sequence needs a multi-tx PoC. ONE helper consumed by BOTH
// bundles — parity is test-pinned. Advisory only.
func sequenceRequirements(campaign *state.Campaign) ([]validation.Value, error) {
	live, err := findings.LoadLiveFindings(campaign)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, f := range live {
		if !sequencepoc.IsSequenceRequired(f) {
			continue
		}
		seq := objAt(f, "exploit_sequence")
		steps := 0
		actorSet := map[string]bool{}
		if seq.Kind == validation.Arr {
			steps = len(seq.A)
			for _, s := range seq.A {
				if s.Kind != validation.Obj {
					continue
				}
				if a := objAt(s, "actor"); a.Kind == validation.Str &&
					a.S != "" {
					actorSet[a.S] = true
				}
			}
		}
		actors := make([]string, 0, len(actorSet))
		for a := range actorSet {
			actors = append(actors, a)
		}
		sort.Strings(actors)
		note := fmt.Sprintf("declared exploit_sequence has %d steps / %d "+
			"actor(s) — a single-call PoC cannot cover it; attempt T4 with "+
			"`webv2 sequence run`", steps, len(actors))
		out = append(out, validation.VObj(
			validation.KV{K: "finding_id", V: objAt(f, "finding_id")},
			validation.KV{K: "steps", V: validation.VInt(int64(steps))},
			validation.KV{K: "actors", V: strArr(actors)},
			validation.KV{K: "note", V: validation.VStr(note)}))
	}
	return out, nil
}

// simulationDirectiveBlock is _simulation_directive_block: the
// simulation-mode prior for per-class proposer passes (spec 3.2 §4.2).
func simulationDirectiveBlock(playbook validation.Value) validation.Value {
	if playbook.Kind != validation.Obj {
		return validation.VNull()
	}
	if objStr(playbook, "investigation_mode") != "adversarial-simulation" {
		return validation.VNull()
	}
	sim := objAt(playbook, "simulation")
	if sim.Kind != validation.Obj {
		return validation.VNull()
	}
	ref := objAt(sim, "expectation_violated")
	statement := ""
	if invs := objAt(playbook, "invariants"); invs.Kind == validation.Arr {
		for _, i := range invs.A {
			if i.Kind == validation.Obj && sameScalar(objAt(i, "id"), ref) {
				statement = objStr(i, "statement")
				break
			}
		}
	}
	return validation.VObj(
		validation.KV{K: "mode", V: validation.VStr("adversarial-simulation")},
		validation.KV{K: "stage_prompt",
			V: validation.VStr("prompts/50_adversarial_simulation.md")},
		validation.KV{K: "simulation", V: sim},
		validation.KV{K: "expectation", V: validation.VObj(
			validation.KV{K: "id", V: ref},
			validation.KV{K: "statement", V: validation.VStr(statement)})},
		validation.KV{K: "note", V: validation.VStr("this class is hunted as " +
			"a game-theoretic simulation, not code reading: model the cast, " +
			"their capital and rationality, the ordering freedoms, and " +
			"propose strategy profiles that violate the documented " +
			"expectation; exploit_sequence steps must be attributed to " +
			"named actors")})
}

// benignActorAuditBlock is _benign_actor_audit_block: advisory value-echo
// flags for findings whose class has a simulation-mode playbook.
func benignActorAuditBlock(campaign *state.Campaign,
	finding validation.Value) validation.Value {
	cls := objStr(objAt(finding, "root_cause"), "class")
	if cls == "" {
		return validation.VNull()
	}
	pb, found, err := playbooks.PlaybookForClass(cls)
	if err != nil || !found {
		return validation.VNull()
	}
	sim := objAt(pb, "simulation")
	if sim.Kind != validation.Obj {
		return validation.VNull()
	}
	cast := map[string]string{}
	if actors := objAt(sim, "actors"); actors.Kind == validation.Arr {
		for _, a := range actors.A {
			if a.Kind != validation.Obj {
				continue
			}
			if name := objAt(a, "name"); name.Kind == validation.Str {
				cast[name.S] = objStr(a, "behavior_class")
			}
		}
	}
	flags := sequencepoc.BenignActorAudit(objAt(finding, "exploit_sequence"), cast)
	if len(flags) == 0 {
		return validation.VNull()
	}
	return validation.VArr(flags...)
}

// findingSummary is _finding_summary: the only shape of an existing finding
// a role other than its owner ever sees.
func findingSummary(f validation.Value) validation.Value {
	levels := []validation.Value{}
	if ev := objAt(f, "evidence"); ev.Kind == validation.Arr {
		for _, e := range ev.A {
			levels = append(levels, objAt(e, "level"))
		}
	}
	return validation.VObj(
		validation.KV{K: "finding_id", V: objAt(f, "finding_id")},
		validation.KV{K: "title", V: objAt(f, "title")},
		validation.KV{K: "status", V: objAt(f, "status")},
		validation.KV{K: "trajectory", V: objAt(f, "trajectory")},
		validation.KV{K: "bug_class", V: objAt(objAt(f, "root_cause"), "class")},
		validation.KV{K: "evidence_levels", V: validation.VArr(levels...)})
}

// knownNonIssues is _known_non_issues: the negative-memory block. Prior
// observations that are NOT proof of safety, each surfaced with its retrieval
// metadata.
func knownNonIssues(campaign *state.Campaign, bugClass *string,
	limit int) (validation.Value, error) {
	negative := rankNegative(negativeRows(devRows(loadMemoryRows(campaign))),
		bugClass)
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	activePin := ""
	if active != nil {
		activePin = *active
	}
	summarized := []validation.Value{}
	for i, row := range negative {
		if i >= limit {
			break
		}
		summarized = append(summarized, summarizeNonIssue(row, activePin))
	}
	return validation.VObj(
		validation.KV{K: "authoritative", V: validation.VBool(false)},
		validation.KV{K: "label", V: validation.VStr(
			"KNOWN NON-ISSUES (prior observations; not proof of safety)")},
		validation.KV{K: "override_rule", V: validation.VStr("If a prior is " +
			"believed to no longer apply, state which assumption differs " +
			"from it (name the assumption id and the prior's memory_id in " +
			"differs_from_memory). A materially different hypothesis is " +
			"never suppressed by this block.")},
		validation.KV{K: "staleness_note", V: validation.VStr("rows with " +
			"pin_diverged=true were learned against a different snapshot " +
			"pin: their code-reality claims are suspect until re-checked " +
			"against the active pin. rows with policy_contingent=true go " +
			"stale when the program's threshold or the protocol's TVL " +
			"changes.")},
		validation.KV{K: "known_non_issues", V: validation.VArr(summarized...)},
	), nil
}

// loadMemoryRows is every candidate row: campaign-local memory/MEM-*.json in
// name order, then the shared store (wrapped {scope, program_key, row}
// entries unwrapped to the flat shape).
func loadMemoryRows(campaign *state.Campaign) []validation.Value {
	rows := []validation.Value{}
	memDir := filepath.Join(campaign.Dir, "memory")
	if entries, err := os.ReadDir(memDir); err == nil {
		names := []string{}
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(e.Name(), "MEM-") &&
				strings.HasSuffix(e.Name(), ".json") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			row, err := validation.ReadJson(filepath.Join(memDir, n))
			if err != nil {
				continue
			}
			rows = append(rows, row)
		}
	}
	if wrapped, err := sharedmem.LoadSharedMemory(campaign.Root); err == nil {
		for _, w := range wrapped {
			if w.Kind == validation.Obj {
				if r := objAt(w, "row"); r.Kind != validation.Null {
					rows = append(rows, r)
					continue
				}
			}
			rows = append(rows, w)
		}
	}
	return rows
}

// devRows is the leakage-partition guard: held-out/training rows are
// evaluation data and must NEVER surface in proposer-context injection.
// Absent partition == 'dev'.
func devRows(rows []validation.Value) []validation.Value {
	dev := []validation.Value{}
	for _, r := range rows {
		if r.Kind != validation.Obj {
			continue
		}
		p := objAt(r, "partition")
		if p.Kind == validation.Null || (p.Kind == validation.Str &&
			p.S == "dev") {
			dev = append(dev, r)
		}
	}
	return dev
}

// negativeRows is the rows whose status is a known non-issue.
func negativeRows(dev []validation.Value) []validation.Value {
	negative := []validation.Value{}
	for _, r := range dev {
		st := objAt(r, "status")
		if st.Kind == validation.Str && contains(NegativeStatuses, st.S) {
			negative = append(negative, r)
		}
	}
	return negative
}

// rankNegative is the deterministic recall order: same-bug-class rows first,
// then created_at ascending.
func rankNegative(negative []validation.Value,
	bugClass *string) []validation.Value {
	sort.SliceStable(negative, func(i, j int) bool {
		ci, cj := int64(1), int64(1)
		if bugClass != nil && objStr(negative[i], "bug_class") == *bugClass {
			ci = 0
		}
		if bugClass != nil && objStr(negative[j], "bug_class") == *bugClass {
			cj = 0
		}
		if ci != cj {
			return ci < cj
		}
		return objStr(negative[i], "created_at") < objStr(negative[j], "created_at")
	})
	return negative
}

// summarizeNonIssue is one surfaced row: bounded text, the retrieval metadata
// the model needs to judge applicability (pin divergence, policy contingency,
// schema version), never the raw record.
func summarizeNonIssue(row validation.Value, activePin string) validation.Value {
	rejectionClass := objAt(row, "rejection_class")
	if rejectionClass.Kind == validation.Null {
		rc := learning.RejectionClassForStatus(objStr(row, "status"))
		if rc != "" {
			rejectionClass = validation.VStr(rc)
		}
	}
	rowPin := objStr(row, "snapshot_id")
	// deciding_propositions is passed through VERBATIM for v2 rows (Python:
	// `row.get("deciding_propositions") if schema_version >= 2 else []`), so
	// an absent/None field serializes as null, not [] — the v2 schema makes
	// the distinction load-bearing for the boundary's differs_from_memory
	// check. v1 rows carry no proposition structure and always emit [].
	deciding := validation.VArr()
	if sv := objAt(row, "schema_version"); sv.Kind == validation.Int &&
		sv.I >= 2 {
		deciding = objAt(row, "deciding_propositions")
	}
	policyContingent := false
	if rejectionClass.Kind == validation.Str {
		policyContingent = rejectionClass.S == "below-threshold"
	}
	return validation.VObj(
		validation.KV{K: "memory_id", V: objAt(row, "memory_id")},
		validation.KV{K: "status", V: objAt(row, "status")},
		validation.KV{K: "rejection_class", V: rejectionClass},
		validation.KV{K: "bug_class", V: objAt(row, "bug_class")},
		validation.KV{K: "cwe", V: objAt(row, "cwe")},
		validation.KV{K: "pattern",
			V: validation.VStr(truncate(objStr(row, "pattern"), 300))},
		validation.KV{K: "evidence_summary",
			V: validation.VStr(truncate(objStr(row, "evidence_summary"), 200))},
		validation.KV{K: "deciding_propositions", V: deciding},
		validation.KV{K: "pin_diverged",
			V: validation.VBool(rowPin != "" && activePin != "" &&
				rowPin != activePin)},
		validation.KV{K: "policy_contingent", V: validation.VBool(policyContingent)},
		validation.KV{K: "schema_version",
			V: defaultedInt(objAt(row, "schema_version"), 1)})
}

// permittedChecks is _permitted_checks: union of the tool ids the model
// recommended per assumption.
func permittedChecks(finding validation.Value) []string {
	tools := map[string]bool{}
	if as := objAt(finding, "assumptions"); as.Kind == validation.Arr {
		for _, a := range as.A {
			if a.Kind != validation.Obj {
				continue
			}
			if opts := objAt(a, "verification_options"); opts.Kind == validation.Arr {
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
	rc := asObj(objAt(finding, "root_cause"))
	econ := asObj(objAt(finding, "economic_impact"))
	inv := asObj(objAt(finding, "invariant"))
	invOut := validation.VObj()
	for _, k := range []string{"id", "statement", "documented_ref",
		"violation_demonstrated"} {
		if v := objAt(inv, k); v.Kind != validation.Null {
			invOut.O = append(invOut.O, validation.KV{K: k, V: v})
		}
	}
	econOut := validation.VObj()
	for _, k := range []string{"asset", "max_loss_usd", "extractable_usd",
		"blast_radius", "extraction_ratio", "price_basis"} {
		if v := objAt(econ, k); v.Kind != validation.Null {
			econOut.O = append(econOut.O, validation.KV{K: k, V: v})
		}
	}
	return validation.VObj(
		validation.KV{K: "finding_id", V: objAt(finding, "finding_id")},
		validation.KV{K: "title", V: objAt(finding, "title")},
		validation.KV{K: "claim_version", V: objAt(finding, "claim_version")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: objAt(rc, "class")},
			validation.KV{K: "cwe", V: objAt(rc, "cwe")})},
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
	if ev := objAt(finding, "evidence"); ev.Kind == validation.Arr {
		for _, e := range ev.A {
			if e.Kind != validation.Obj {
				continue
			}
			item := validation.VObj()
			for _, k := range []string{"evidence_id", "level", "type",
				"artifact_id", "command", "description", "sandbox_profile",
				"snapshot_id", "produced_at"} {
				if v := objAt(e, k); v.Kind != validation.Null {
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
	reg := objAt(links, "invariants")
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
		stmt := objStr(e, "statement")
		if stmt == "" {
			stmt = "(statement not recorded — legacy/migrated entry)"
		}
		status := objStr(e, "status")
		if status == "" {
			status = "UNVERIFIED"
		}
		source := objStr(e, "source")
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
			validation.KV{K: "program", V: objAt(b.st, "program")},
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

// BuildCriticContext is build_critic_context.
func BuildCriticContext(campaign *state.Campaign,
	findingID string) (validation.Value, error) {
	finding, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	baseline := objAt(finding, "attacker")
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
		if objStr(r, "finding_id") == findingID {
			seqReq = validation.VObj(
				validation.KV{K: "finding_id", V: objAt(r, "finding_id")},
				validation.KV{K: "steps", V: objAt(r, "steps")},
				validation.KV{K: "n_actors",
					V: validation.VInt(int64(len(objAt(r, "actors").A)))},
				validation.KV{K: "note", V: objAt(r, "note")})
			break
		}
	}
	bundle := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("critic")},
		validation.KV{K: "campaign_id", V: validation.VStr(campaign.CampaignID)},
		validation.KV{K: "claim", V: criticClaim(finding)},
		validation.KV{K: "attacker_baseline", V: baseline},
		validation.KV{K: "evidence", V: minimalEvidence(finding)},
		validation.KV{K: "snapshot_ids", V: asObj(objAt(finding, "snapshot_ids"))},
		validation.KV{K: "permitted_checks",
			V: strArr(permittedChecks(finding))},
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
	if v := objAt(bundle, "benign_actor_audit"); v.Kind == validation.Null {
		bundle = removeKey(bundle, "benign_actor_audit")
	}
	if err := AssertClean(bundle, "critic"); err != nil {
		return validation.VNull(), err
	}
	return bundle, nil
}

// BuildReproducerContext is build_reproducer_context.
func BuildReproducerContext(campaign *state.Campaign,
	findingID string) (validation.Value, error) {
	finding, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	status := objStr(finding, "status")
	if status != "CONFIRMED" && status != "PROVISIONALLY_VALID" &&
		status != "POSSIBLE" {
		return validation.VNull(), fmt.Errorf("%s is in status %s; the "+
			"reproducer context is built only for confirmed/near-confirmed "+
			"claims", findingID, status)
	}
	rc := asObj(objAt(finding, "root_cause"))
	class := objStr(rc, "class")
	repro := asObj(objAt(asObj(objAt(finding, "verification")), "reproduction"))
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
		validation.KV{K: "deployment", V: asObj(objAt(finding, "snapshot_ids"))},
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
	rc := asObj(objAt(finding, "root_cause"))
	econ := asObj(objAt(finding, "economic_impact"))
	return validation.VObj(
		validation.KV{K: "finding_id", V: objAt(finding, "finding_id")},
		validation.KV{K: "title", V: objAt(finding, "title")},
		validation.KV{K: "claim_version", V: objAt(finding, "claim_version")},
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
	as := objAt(finding, "assumptions")
	if as.Kind != validation.Arr {
		return required
	}
	for _, a := range as.A {
		if a.Kind == validation.Obj &&
			objAt(a, "blocking").Kind == validation.Bool &&
			objAt(a, "blocking").B {
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
		if x := objAt(v, k); x.Kind != validation.Null {
			out.O = append(out.O, validation.KV{K: k, V: x})
		}
	}
	return out
}

// ---- small shared helpers -------------------------------------------------

func asObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

func orEmpty(v validation.Value, key string) validation.Value {
	x := objAt(v, key)
	if x.Kind == validation.Arr {
		return x
	}
	return validation.VArr()
}

func orEmptyObj(v validation.Value, key string) validation.Value {
	x := objAt(v, key)
	if x.Kind == validation.Obj {
		return x
	}
	return validation.VObj()
}

func removeKey(v validation.Value, key string) validation.Value {
	out := validation.VObj()
	for _, kv := range v.O {
		if kv.K != key {
			out.O = append(out.O, kv)
		}
	}
	return out
}

func strArr(xs []string) validation.Value {
	out := make([]validation.Value, len(xs))
	for i, x := range xs {
		out[i] = validation.VStr(x)
	}
	return validation.VArr(out...)
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// truncate is Python's `s[:n]`: a CHARACTER slice, not a byte slice. The
// reference clips pattern/evidence_summary with `[:300]`/`[:200]`, so a
// multi-byte rune straddling the budget must not shorten the cut (the same
// rule roles.truncatedMarker documents for _bounded_json).
func truncate(s string, n int) string {
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func defaultedInt(v validation.Value, def int64) validation.Value {
	if v.Kind == validation.Int {
		return v
	}
	return validation.VInt(def)
}

func sameScalar(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I
	case validation.Null:
		return true
	}
	return false
}

// KnownNonIssues is _known_non_issues through the exported seam the model
// boundary's memory-utility signal uses.
func KnownNonIssues(campaign *state.Campaign, bugClass *string,
	limit int) (validation.Value, error) {
	return knownNonIssues(campaign, bugClass, limit)
}
