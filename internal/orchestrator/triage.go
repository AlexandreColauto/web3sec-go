// triage.go: phases 7 (CANDIDATE_INTEL), 9 (REPRODUCTION), 10 (CHAINING) and
// 12 (RISK_CALIBRATION / BOUNTY_GATE) — the batch views and sweeps.
package orchestrator

import (
	"sort"

	"websec/internal/bounty"
	"websec/internal/dedup"
	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/risk"
	"websec/internal/validation"
)

// TriageAll is triage_all(): deterministic pre-triage — prior risk + decision
// rule for every open hypothesis, ordered by descending prior score. Model
// triage (legacy Stage 17) refines this.
func (o *Orchestrator) TriageAll() (validation.Value, error) {
	live, err := findings.LoadLiveFindings(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	out := []validation.Value{}
	for _, f := range live {
		if strAt(f, "status") != "HYPOTHESIS" {
			continue
		}
		row, err := triageRow(f)
		if err != nil {
			return validation.VNull(), err
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return numAt(objAt(out[i], "prior"), "score") >
			numAt(objAt(out[j], "prior"), "score")
	})
	if err := o.C.SetStage("hypothesis-triage", "done", validation.VNull(),
		ptr("deterministic")); err != nil {
		return validation.VNull(), err
	}
	return valueArr(out), nil
}

// triageRow is one finding's deterministic triage row.
func triageRow(f validation.Value) (validation.Value, error) {
	class := "unclassified"
	if rc := objAt(asDict(objAt(f, "root_cause")), "class"); rc.Kind == validation.Str {
		class = rc.S
	}
	att := asDict(objAt(f, "attacker"))
	// A recorded memory consultation that names at least one memory row is
	// the historical-analog signal (the graph-memory successor of the
	// retired corpus lookup).
	checks := listAt(asDict(objAt(f, "provenance")), "memory_checks")
	historical := false
	for _, c := range checks {
		if c.Kind == validation.Obj && pyTruthyBigNonEmpty(objAt(c, "memory_ids")) {
			historical = true
			break
		}
	}
	var invariantID *string
	if inv := objAt(asDict(objAt(f, "invariant")), "id"); inv.Kind == validation.Str {
		id := inv.S
		invariantID = &id
	}
	var capital *float64
	switch cap := objAt(att, "required_capital_usd"); cap.Kind {
	case validation.Flt:
		v := cap.F
		capital = &v
	case validation.Int:
		v := numAt(att, "required_capital_usd")
		capital = &v
	}
	prior := risk.PriorRisk(class, !pyTruthyBigNonEmpty(objAt(att, "required_privileges")),
		true, historical, invariantID, capital)
	cost := risk.ValidationCost(class, true, false)
	slot := planner.DecisionRule(numAt(prior, "score"), cost)
	return validation.VObj(
		kvOf("finding_id", objAt(f, "finding_id")),
		kvOf("prior", prior),
		kvOf("validation_cost", validation.VStr(cost)),
		kvOf("queue_slot", validation.VStr(slot)),
	), nil
}

// RunDedup is run_dedup(): the deterministic dedup sweep, then hand the
// tier-2/3 signature normalization to the model.
func (o *Orchestrator) RunDedup() (validation.Value, error) {
	if err := o.C.SetPhase("CANDIDATE_INTEL", "dedup sweep"); err != nil {
		return validation.VNull(), err
	}
	report, err := dedup.RunDedup(o.C, true)
	if err != nil {
		return validation.VNull(), err
	}
	note := "run LLM normalization then set tier-2/3 signatures"
	if err := o.C.SetStage("dedup-normalization", "needs-model",
		validation.VStr(note), nil); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

// ReproductionQueue is reproduction_queue(): order candidates for repro —
// cheapest tier first, prior risk descending.
func (o *Orchestrator) ReproductionQueue() (validation.Value, error) {
	triage, err := o.TriageAll()
	if err != nil {
		return validation.VNull(), err
	}
	prios := map[string]float64{}
	for _, t := range triage.A {
		prios[strAt(t, "finding_id")] = numAt(objAt(t, "prior"), "score")
	}
	live, err := findings.LoadLiveFindings(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	cands := []validation.Value{}
	for _, f := range live {
		status := strAt(f, "status")
		if status != "POSSIBLE" && status != "PROVISIONALLY_VALID" {
			continue
		}
		repro := asDict(objAt(asDict(objAt(f, "verification")), "reproduction"))
		raw := objAt(repro, "attempts")
		nAttempts := 0
		if raw.Kind == validation.Arr {
			nAttempts = len(raw.A)
		}
		nextTier, err := nextTierOrT0(repro)
		if err != nil {
			return validation.VNull(), err
		}
		fid := strAt(f, "finding_id")
		prior := 0.4
		if p, ok := prios[fid]; ok {
			prior = p
		}
		seqRequired := seqAPI.IsSequenceRequired(f)
		cand := validation.VObj(
			kvOf("finding_id", validation.VStr(fid)),
			kvOf("next_tier", validation.VStr(nextTier)),
			kvOf("attempts", validation.VInt(int64(nAttempts))),
			kvOf("prior", validation.VFloat(prior)),
			kvOf("sequence_required", validation.VBool(seqRequired)),
		)
		if seqRequired {
			steps, actors := declaredSequence(f)
			// I1: on-disk findings are unvalidated — mirror the verifier's
			// isinstance guard (a string entry has no .get).
			note := "declared exploit_sequence: " + itoa(len(steps)) + " steps / " +
				itoa(actors) + " actor(s) — a single-call PoC cannot cover it; " +
				"attempt T4 with `webv2 sequence run`"
			cand.O = append(cand.O, kvOf("note", validation.VStr(note)))
		}
		cands = append(cands, cand)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		pi, pj := numAt(cands[i], "prior"), numAt(cands[j], "prior")
		if pi != pj {
			return pi > pj
		}
		return intAt(cands[i], "attempts") < intAt(cands[j], "attempts")
	})
	reason := itoa(len(cands)) + " candidates"
	if err := o.C.SetPhase("REPRODUCTION", reason); err != nil {
		return validation.VNull(), err
	}
	return valueArr(cands), nil
}

// Chaining is chaining(): the capability graph report.
func (o *Orchestrator) Chaining() (validation.Value, error) {
	if err := o.C.SetPhase("CHAINING", "capability graph"); err != nil {
		return validation.VNull(), err
	}
	return ceAPI.ChainReport(o.C)
}

// CalibrateAll is calibrate_all(): 3-pass risk calibration for every live
// finding that carries risk (CONFIRMED, CHAIN, POSSIBLE).
func (o *Orchestrator) CalibrateAll() (validation.Value, error) {
	live, err := findings.LoadLiveFindings(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	out := []validation.Value{}
	for _, f := range live {
		switch strAt(f, "status") {
		case "CONFIRMED", "CHAIN", "POSSIBLE":
			calibrated, err := risk.Calibrate(o.C, strAt(f, "finding_id"))
			if err != nil {
				return validation.VNull(), err
			}
			out = append(out, calibrated)
		}
	}
	if err := o.C.SetPhase("RISK_CALIBRATION", itoa(len(out))+" calibrated"); err != nil {
		return validation.VNull(), err
	}
	return valueArr(out), nil
}

// BountyGateAll is bounty_gate_all(): evaluate the policy gate for every
// CONFIRMED/CHAIN finding. A campaign without a registered policy raises —
// the gate is never silently skipped.
func (o *Orchestrator) BountyGateAll() (validation.Value, error) {
	st, err := o.C.State()
	if err != nil {
		return validation.VNull(), err
	}
	policyPath := strAt(st, "policy_path")
	if policyPath == "" || !fileExists(policyPath) {
		return validation.VNull(), orchestrationError(
			"bounty gate requires a policy; run scope(policy_path=...) first")
	}
	policy, err := bounty.LoadPolicy(policyPath)
	if err != nil {
		return validation.VNull(), err
	}
	all, err := findings.LoadAllFindings(o.C)
	if err != nil {
		return validation.VNull(), err
	}
	out := []validation.Value{}
	for _, f := range all {
		switch strAt(f, "status") {
		case "CONFIRMED", "CHAIN":
			fid := strAt(f, "finding_id")
			gate, err := bounty.EvaluateBountyGate(o.C, fid, policy, true)
			if err != nil {
				return validation.VNull(), err
			}
			// Python: {"finding_id": fid, **gate} — a key present in both
			// keeps the FIRST position and takes the gate's value.
			row := validation.VObj(kvOf("finding_id", validation.VStr(fid)))
			for _, kv := range gate.O {
				row.O = validation.SetOrAppend(row.O, kv.K, kv.V)
			}
			out = append(out, row)
		}
	}
	if err := o.C.SetPhase("BOUNTY_GATE", itoa(len(out))+" evaluated"); err != nil {
		return validation.VNull(), err
	}
	return valueArr(out), nil
}
