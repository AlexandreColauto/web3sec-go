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
		kvOf("program", validation.ObjAt(st, "program")),
		kvOf("phase", validation.ObjAt(st, "phase")),
		kvOf("pass", validation.ObjAt(validation.ObjAt(st, "budget"), "pass")),
		kvOf("active_snapshot", validation.ObjAt(st, "active_snapshot_id")),
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
		s := validation.ObjAt(f, "status")
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
	if s := validation.ObjAt(doc, "summary"); s.Kind == validation.Obj {
		cov = s
	}
	return cov, nil
}

// statusStages is the bounded stage view: notes are truncated to
// STATUS_NOTE_CAP unless verbose asks for the full (still-capped) note.
func statusStages(st validation.Value, verbose bool) ([]validation.KV, error) {
	stages := validation.ObjAt(st, "stages")
	view := make([]validation.KV, 0, len(stages.O))
	for _, entry := range stages.O {
		e := copyObj(entry.V)
		if e.Kind == validation.Obj {
			note := validation.ObjAt(e, "note")
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
// holds means the operator can just run the pipeline — the stage
// auto-completes from its artifacts. And when the phase says COMPLETE or
// HALTED while an authoritative proof is still open, the open proofs are
// surfaced: the phase is a projection, the proof is the truth.
//
// LAW (Task 7): every line this function returns is a COPYABLE command —
// `webv2 <verb> …`, verb in the CLI's dispatch registry, no parenthesised
// Python-API pseudo-call, no prose. The list is read by an operator (and by
// `webv2 brief`) as a work order; a line that cannot be pasted into a shell is
// bookkeeping friction, which is exactly what this guidance exists to remove.
// The consequence is deliberate: the per-item proof detail the old catalog
// printed inline ("[discovery missing] Q-001: …") is no longer inlined — the
// proof command the line names (`webv2 prove <campaign> --stage <stage>`)
// prints it verbatim, and a trailing `# n missing` comment keeps the size of
// the gap visible without breaking copyability.
func NextActions(c *state.Campaign) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	phase := strAt(st, "phase")
	cid := c.CampaignID
	if cid == "" {
		cid = "<campaign>"
	}
	actions := phaseActions(phase, cid)

	// proof teeth for the stage the phase is in
	if stage, ok := stageForPhase(phase); ok {
		proof, err := completion.ProofStatus(c, stage)
		if err != nil {
			return validation.VNull(), err
		}
		if proof.Kind == validation.Obj {
			if pyTruthyBigNonEmpty(validation.ObjAt(proof, "done")) {
				actions = append(actions, "webv2 run "+cid+"  # "+stage+
					" proof holds; the stage auto-completes")
			} else {
				actions = append(actions, proofCommand(cid, stage,
					len(listAt(proof, "missing"))))
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
			if !pyTruthyBigNonEmpty(validation.ObjAt(pr.V, "authoritative")) ||
				pyTruthyBigNonEmpty(validation.ObjAt(pr.V, "done")) {
				continue
			}
			openProofs = append(openProofs, proofCommand(cid, pr.K,
				len(listAt(pr.V, "missing"))))
		}
		if len(openProofs) > 0 {
			actions = append([]string{"webv2 prove " + cid +
				"  # phase says done but completion proofs are open"}, actions...)
			if len(openProofs) > 6 {
				openProofs = openProofs[:6]
			}
			actions = append(actions, openProofs...)
		}
	}
	return validation.StrArr(actions), nil
}

// proofCommand is one copyable proof line: the command that prints the exact
// missing items, plus the count so the size of the gap is visible at a glance.
func proofCommand(cid, stage string, missing int) string {
	return "webv2 prove " + cid + " --stage " + stage + "  # " +
		itoa(missing) + " missing"
}

// phaseActions is the phase -> copyable-command catalog of next_actions.
//
// Every entry is a `webv2` command an operator can paste; the campaign id is
// interpolated so the line needs no editing. Metavariables in angle brackets
// are the arguments the operator must supply (the same house style the lens
// routing lines use); the flags and positional shapes are the ones the CLI's
// own parsers accept — `internal/orchestrator/next_actions_cli_test.go` feeds
// each emitted line back through the dispatcher to prove it.
func phaseActions(phase, cid string) []string {
	switch phase {
	case "SCOPE":
		return []string{"webv2 scope " + cid + " --policy <policy.json>",
			"webv2 snap " + cid + " <target>"}
	case "SNAPSHOT":
		return []string{"webv2 snap " + cid + " <target>"}
	case "STRUCTURAL_INDEX":
		return []string{"webv2 index " + cid + " --src <src>"}
	case "PROTOCOL_INTELLIGENCE":
		return []string{"webv2 run " + cid,
			"webv2 model " + cid + " <model.json>"}
	case "CAMPAIGN_PLANNING":
		return []string{"webv2 plan " + cid + " <plan.json>"}
	case "DISCOVERY":
		return []string{"webv2 run " + cid,
			"webv2 plan " + cid,
			"webv2 ingest " + cid + " --json-file <payload.json>",
			"webv2 prioritize " + cid}
	case "CANDIDATE_INTEL":
		return []string{"webv2 dedup " + cid,
			"webv2 resolve-candidate " + cid + " <finding> <other>" +
				" --verdict <same-or-distinct> --note <note>"}
	case "HOSTILE_REVIEW":
		return []string{"webv2 run " + cid,
			"webv2 verdict " + cid + " <finding> --verdict <verdict>" +
				" --reason <reason>"}
	case "REPRODUCTION":
		// mint closes the phase proof (it records the reproduction attempt
		// + its evidence, which proofs2.go reads); repro-queue is the
		// read-only view of the same queue, so it follows.
		return []string{"webv2 mint " + cid + " <finding> --exec <EXEC-id>" +
			" --description <description>",
			"webv2 repro-queue " + cid}
	case "CHAINING":
		return []string{"webv2 chains " + cid,
			"webv2 chain " + cid + " <finding> <other>"}
	case "MAXIMAL_EXPLOITATION":
		return []string{"webv2 run " + cid,
			"webv2 ladder " + cid + " start <finding>",
			"webv2 ladder " + cid + " waive <finding> --reason <reason>" +
				" --actor <actor>"}
	case "INDEPENDENT_VERIFICATION":
		// The phase proof (completion/proofs2.go, independent-verification)
		// needs verification.independent_reproduction.status == "matches"
		// with a named verifier — written only by reproduction.
		// MintIndependentEvidence, reachable from the CLI solely through
		// `verify --exec` (cmd_verify.go: --exec requires --verifier and
		// --description). So `verify` LEADS: it is the command whose recorded
		// effect the proof reads. `mint` follows as the follow-up that
		// records the FORGE evidence the independent run traces to (it
		// cannot set the proof's field, so it must not lead); `run` drives
		// the stage.
		return []string{"webv2 verify " + cid + " --finding <finding>" +
			" --exec <EXEC-id> --verifier <verifier>" +
			" --description <description>",
			"webv2 mint " + cid + " <finding> --exec <EXEC-id>" +
				" --description <description>",
			"webv2 run " + cid}
	case "RISK_CALIBRATION":
		// `rank` is read-only by contract (cmd_rank.go: nothing is written):
		// on its own it cannot advance the phase. The proof
		// (proofs2.go, risk-calibration) reads risk.validated.band per
		// CONFIRMED finding, and risk-calibration is a deterministic
		// pipeline stage — `run` is the command that closes it, exactly as
		// for the sibling stage phases. rank stays as the informational
		// score view.
		return []string{"webv2 run " + cid,
			"webv2 rank " + cid}
	case "MAINNET_FORK_POC":
		// exec produces the fork run; the proof (proofs2.go,
		// mainnet-fork-poc) needs a PROVEN fork-test mint tracing to it, so
		// the mint follow-up carries the type the proof reads.
		return []string{"webv2 exec " + cid + " --command <command>" +
			" --profile <profile>",
			"webv2 mint " + cid + " <finding> --exec <EXEC-id>" +
				" --description <description> --type fork-test"}
	case "BOUNTY_GATE":
		return []string{"webv2 gate " + cid,
			"webv2 gate --explain <check>"}
	case "REPORTING":
		return []string{"webv2 report " + cid}
	case "LEARNING":
		return []string{"webv2 memory " + cid + " --reflect <text>",
			"webv2 memory " + cid + " --approve <memory-id>"}
	}
	return []string{"webv2 status " + cid + "  # campaign complete or halted"}
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
