// status.go: the operator's bounded view and the deterministic next-action
// guidance.
package orchestrator

import (
	"path/filepath"

	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

// Status is status(): the bounded view an operator reads on every pass. It
// must never be O(artifact size), so stage notes are truncated to
// STATUS_NOTE_CAP unless verbose asks for the full (still-capped) note; the
// full content lives in the state file / artifacts.
func (o *Orchestrator) Status(verbose bool) (validation.Value, error) {
	st, err := o.C.State()
	if err != nil {
		return validation.VNull(), err
	}
	counts, err := statusCounts(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	cov, err := statusCoverage(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	view, err := statusStages(st, verbose)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kvOf("campaign_id", validation.VStr(o.C.CampaignID)),
		kvOf("program", objAt(st, "program")),
		kvOf("phase", objAt(st, "phase")),
		kvOf("pass", objAt(objAt(st, "budget"), "pass")),
		kvOf("active_snapshot", objAt(st, "active_snapshot_id")),
		kvOf("findings", validation.VObj(counts...)),
		kvOf("coverage_summary", cov),
		kvOf("stages", validation.VObj(view...)),
	), nil
}

// statusCounts is the finding-status histogram in first-seen order.
func statusCounts(c *state.Campaign) ([]validation.KV, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	counts := []validation.KV{}
	index := map[string]int{}
	for _, f := range all {
		s := objAt(f, "status")
		if s.Kind != validation.Str {
			// Python: counts[f["status"]] raises KeyError('status').
			return nil, errText(validation.PyReprStr("status"))
		}
		if i, ok := index[s.S]; ok {
			counts[i].V = validation.VInt(counts[i].V.I + 1)
			continue
		}
		index[s.S] = len(counts)
		counts = append(counts, kvOf(s.S, validation.VInt(1)))
	}
	return counts, nil
}

// statusCoverage reads the coverage summary, or an empty object.
func statusCoverage(c *state.Campaign) (validation.Value, error) {
	cov := validation.VObj()
	covPath := filepath.Join(c.ArtifactsDir, "coverage.json")
	if !fileExists(covPath) {
		return cov, nil
	}
	doc, err := validation.ReadJson(covPath)
	if err != nil {
		return validation.VNull(), err
	}
	if s := objAt(doc, "summary"); s.Kind == validation.Obj {
		cov = s
	}
	return cov, nil
}

// statusStages is the bounded stage view: notes are truncated to
// STATUS_NOTE_CAP unless verbose asks for the full (still-capped) note.
func statusStages(st validation.Value, verbose bool) ([]validation.KV, error) {
	stages := objAt(st, "stages")
	view := make([]validation.KV, 0, len(stages.O))
	for _, entry := range stages.O {
		e := copyObj(entry.V)
		if e.Kind == validation.Obj {
			note := objAt(e, "note")
			noteStr := ""
			if note.Kind == validation.Str {
				noteStr = note.S
			}
			if !verbose && runeLen(noteStr) > StatusNoteCap {
				short := string([]rune(noteStr)[:StatusNoteCap]) +
					" …[truncated; use --verbose]"
				e.O = validation.SetOrAppend(e.O, "note", validation.VStr(short))
			}
		}
		view = append(view, kvOf(entry.K, e))
	}
	return view, nil
}

// NextActions is next_actions(): deterministic guidance — what can run right
// now.
//
// The PHASE decides which stage we are in (the skeleton); the stage's
// COMPLETION PROOF decides what is actually missing (the teeth). A proof that
// holds means the operator can just pipeline.run() — the stage auto-completes
// from its artifacts. And when the phase says COMPLETE or HALTED while an
// authoritative proof is still open, the open proofs are surfaced: the phase
// is a projection, the proof is the truth.
func NextActions(c *state.Campaign) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	phase := strAt(st, "phase")
	actions := phaseActions(phase)

	// proof teeth for the stage the phase is in
	if stage, ok := stageForPhase(phase); ok {
		proof, err := completion.ProofStatus(c, stage)
		if err != nil {
			return validation.VNull(), err
		}
		if proof.Kind == validation.Obj {
			if pyTruthy(objAt(proof, "done")) {
				actions = append(actions, "["+stage+"] completion proof holds — "+
					"pipeline.run() auto-completes the stage")
			} else {
				missing := listAt(proof, "missing")
				if len(missing) > 4 {
					missing = missing[:4]
				}
				for _, m := range missing {
					actions = append(actions, "["+stage+" missing] "+pyStr(m))
				}
			}
		}
	}

	// phase says done, proofs disagree: say so, up front
	if phase == "COMPLETE" || phase == "HALTED" {
		allProofs, err := completion.AllProofStatus(c)
		if err != nil {
			return validation.VNull(), err
		}
		openProofs := []string{}
		for _, pr := range allProofs.O {
			if pr.V.Kind != validation.Obj {
				continue
			}
			if !pyTruthy(objAt(pr.V, "authoritative")) ||
				pyTruthy(objAt(pr.V, "done")) {
				continue
			}
			missing := listAt(pr.V, "missing")
			if len(missing) > 2 {
				missing = missing[:2]
			}
			openProofs = append(openProofs, "["+pr.K+" open] "+
				joinActions(strList(missing)))
		}
		if len(openProofs) > 0 {
			actions = append([]string{"phase says done but completion proofs " +
				"are open — close them (or waive with a reason) first:"}, actions...)
			if len(openProofs) > 6 {
				openProofs = openProofs[:6]
			}
			actions = append(actions, openProofs...)
		}
	}
	return strArr(actions), nil
}

// phaseActions is the phase -> action-sentence catalog of next_actions.
func phaseActions(phase string) []string {
	switch phase {
	case "SCOPE":
		return []string{"orchestrator.scope(policy_path=...)",
			"orchestrator.snapshot(target=...)"}
	case "SNAPSHOT":
		return []string{"orchestrator.snapshot(target=...)"}
	case "STRUCTURAL_INDEX":
		return []string{"orchestrator.build_structural_index()"}
	case "PROTOCOL_INTELLIGENCE":
		return []string{"run protocol-model prompt via adapter.build_context",
			"orchestrator.load_protocol_model(model_dict)"}
	case "CAMPAIGN_PLANNING":
		return []string{"orchestrator.plan()"}
	case "DISCOVERY":
		return []string{
			"orchestrator.discovery_context(stage=...) per queued priority",
			"orchestrator.ingest(payload) per specialist result",
			"orchestrator.triage_all()"}
	case "CANDIDATE_INTEL":
		return []string{"orchestrator.run_dedup()",
			"LLM normalization pass, then dedup.resolve_candidate(...) per " +
				"flagged pair"}
	case "HOSTILE_REVIEW":
		return []string{"orchestrator.critic_context()",
			"findings.set_critic_verdict(...) per candidate"}
	case "REPRODUCTION":
		return []string{"orchestrator.reproduction_queue()",
			"reproduction.record_attempt(...) / mint_repro_evidence(...)"}
	case "CHAINING":
		return []string{"orchestrator.chaining()",
			"chain_engine.materialize_chain(...) on confirmed sets"}
	case "MAXIMAL_EXPLOITATION":
		return []string{"run the maximal-exploitation prompt via " +
			"adapter.build_context",
			"webv2 ladder start/add/explore/repro/set-maximal/complete per " +
				"CONFIRMED finding (or webv2 ladder waive with a written reason)"}
	case "RISK_CALIBRATION":
		return []string{"orchestrator.calibrate_all()"}
	case "BOUNTY_GATE":
		return []string{"orchestrator.bounty_gate_all()",
			"`webv2 gate explain <check>` for any failing check"}
	case "REPORTING":
		return []string{"report.generate(campaign)"}
	case "LEARNING":
		return []string{"learning.queue_memory(...) then human approve_memory()",
			"learning.reflection_entry(...)"}
	}
	return []string{"campaign complete or halted"}
}

// stageForPhase is next((sid for sid, _, ph in STAGES if ph == phase), None).
func stageForPhase(phase string) (string, bool) {
	for _, s := range pipeline.Stages {
		if s.Phase == phase {
			return s.ID, true
		}
	}
	return "", false
}
