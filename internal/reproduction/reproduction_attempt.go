package reproduction

import (
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// The attempt ledger: record_attempt, its guidance ladder, the mint-fail
// rollback and attempt_and_mint. Split from reproduction.go (same package).

// RecordOpts mirrors record_attempt's keyword-only arguments.
type RecordOpts struct {
	FailureClass *string
	FreshContext bool
	Command      *string
	ArtifactID   *string
	ExecID       *string
	Notes        string
	Tier         *string
}

// RecordAttempt is record_attempt: append one reproduction attempt, enforce
// the budget, and return the orchestrator guidance.
func RecordAttempt(c *state.Campaign, findingID, outcome string,
	opts RecordOpts) (validation.Value, error) {
	switch outcome {
	case "reproduced", "failed", "blocked", "falsified":
	default:
		return validation.VNull(), mintErrf(
			"unknown attempt outcome %s; expected one of reproduced / failed "+
				"/ blocked / falsified", validation.PyReprStr(outcome))
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	budget, err := c.Budget()
	if err != nil {
		return validation.VNull(), err
	}
	maxAttempts := intOf(validation.ObjAt(budget, "max_repro_attempts_per_finding"))
	maxRetries := intOf(validation.ObjAt(budget, "max_fresh_context_retries"))

	ver := asDict(validation.ObjAt(f, "verification"))
	repro := asDict(validation.ObjAt(ver, "reproduction"))
	attempts := validation.ObjAt(repro, "attempts")
	if attempts.Kind != validation.Arr {
		attempts = validation.VArr()
	}
	// record_attempt's `repro.setdefault("attempts", [])` runs BEFORE the
	// tier write, so on a fresh reproduction dict "attempts" is the FIRST
	// key and "tier_reached" follows it. JSON key order is part of the
	// byte-exact artifact contract (readers and the event chain depend on
	// it), so the insertion must happen here and not after the tier block
	// (golden v3 caught the divergence 2026-09-09).
	repro = setKey(repro, "attempts", attempts)
	if len(attempts.A) >= maxAttempts {
		return validation.VNull(), mintErrf(
			"reproduction budget exhausted for %s (%d attempts)", findingID,
			maxAttempts)
	}
	if opts.ExecID != nil && *opts.ExecID != "" {
		for _, a := range attempts.A {
			if validation.ObjStr(a, "artifact_id") == *opts.ExecID {
				return validation.VNull(), mintErrf(
					"exec %s was already cited by an earlier attempt on %s; a "+
						"re-run must produce a NEW exec — citing the same run "+
						"again does not add a new attempt", *opts.ExecID, findingID)
			}
		}
	}
	if opts.Tier != nil {
		tier := *opts.Tier
		idx := tierIndex(tier)
		if idx < 0 {
			return validation.VNull(), mintErrf("unknown reproduction tier %s",
				validation.PyReprStr(tier))
		}
		current := TierOf(repro)
		if idx < tierIndex(current) {
			return validation.VNull(), mintErrf(
				"tier ladder is monotonic: refusing to drop %s -> %s without "+
					"a recorded reason (re-pin and start the rung above "+
					"instead)", current, tier)
		}
		repro = setKey(repro, "tier_reached", validation.VStr(tier))
	}

	artifact := validation.VNull()
	switch {
	case opts.ArtifactID != nil:
		artifact = validation.VStr(*opts.ArtifactID)
	case opts.ExecID != nil:
		artifact = validation.VStr(*opts.ExecID)
	}
	var failure validation.Value = validation.VNull()
	if opts.FailureClass != nil {
		failure = validation.VStr(*opts.FailureClass)
	}
	var command validation.Value = validation.VNull()
	if opts.Command != nil {
		command = validation.VStr(*opts.Command)
	}
	attempt := validation.VObj(
		validation.KV{K: "attempt_id", V: validation.VStr(
			"ATT-" + shortID(6))},
		validation.KV{K: "fresh_context", V: validation.VBool(opts.FreshContext)},
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "failure_class", V: failure},
		validation.KV{K: "command", V: command},
		validation.KV{K: "artifact_id", V: artifact},
		validation.KV{K: "notes", V: validation.VStr(opts.Notes)},
	)
	attempts.A = append(attempts.A, attempt)
	repro = setKey(repro, "attempts", attempts)
	repro = setKey(repro, "status", validation.VStr(map[string]string{
		"reproduced": "reproduced", "failed": "attempted",
		"blocked": "blocked", "falsified": "falsified"}[outcome]))
	ver = setKey(ver, "reproduction", repro)
	f = setKey(f, "verification", ver)
	// r18 P2 sweep: an attempt recorded on the finding but not the ledger
	// silently consumes the retry BUDGET (attempt count) with no audit.
	data := validation.VObj(
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "failure_class", V: failure},
		validation.KV{K: "attempt", V: validation.VInt(int64(len(attempts.A)))},
	)
	if err := findings.SaveThenLog(c, &f, func() error {
		_, lerr := c.Log("repro.attempt", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return guidanceFor(outcome, repro, attempts, opts, budget, maxRetries), nil
}

// guidanceFor is record_attempt's guidance ladder.
func guidanceFor(outcome string, repro, attempts validation.Value,
	opts RecordOpts, budget validation.Value, maxRetries int) validation.Value {
	if outcome == "reproduced" {
		level := "E4"
		if tier := TierOf(repro); tier == "T3" || tier == "T4" {
			level = "E5"
		}
		var execV validation.Value = validation.VNull()
		if opts.ExecID != nil {
			execV = validation.VStr(*opts.ExecID)
		}
		return validation.VObj(
			validation.KV{K: "action", V: validation.VStr("mint-evidence")},
			validation.KV{K: "level", V: validation.VStr(level)},
			validation.KV{K: "fresh_context", V: validation.VBool(false)},
			validation.KV{K: "exec_id", V: execV},
			validation.KV{K: "how", V: validation.VStr(
				"mint_repro_evidence(campaign, finding_id, exec_id=..., " +
					"description=...)")},
		)
	}
	action := "stop"
	fresh := false
	switch {
	case outcome == "falsified":
		action = "hypothesis-dead"
	case opts.FailureClass != nil && inSet(hypothesisWrongClasses,
		*opts.FailureClass) && len(attempts.A) >= 2:
		action, fresh = "hypothesis-likely-dead", true
	case opts.FailureClass != nil && inSet(freshContextClasses,
		*opts.FailureClass):
		action, fresh = "retry", true
	case len(attempts.A) >= maxRetries+1:
		action, fresh = "escalate-model", true
	}
	_ = budget
	return validation.VObj(
		validation.KV{K: "action", V: validation.VStr(action)},
		validation.KV{K: "fresh_context", V: validation.VBool(fresh)},
	)
}

// reproductionState is _reproduction_state.
func reproductionState(f validation.Value) validation.Value {
	ver := validation.ObjAt(f, "verification")
	if ver.Kind != validation.Obj {
		return validation.VObj()
	}
	repro := validation.ObjAt(ver, "reproduction")
	if repro.Kind != validation.Obj {
		return validation.VObj()
	}
	return repro
}

// undoAttempt is _undo_attempt: roll back the attempt attempt_and_mint just
// recorded when the mint then fails. The exec citation is the scarce
// resource.
func undoAttempt(c *state.Campaign, findingID string, priorStatus,
	priorTier *string) error {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return err
	}
	ver := asDict(validation.ObjAt(f, "verification"))
	verHadRepro := validation.ObjAt(ver, "reproduction").Kind == validation.Obj
	repro := reproductionState(f)
	attempts := validation.ObjAt(repro, "attempts")
	if attempts.Kind == validation.Arr && len(attempts.A) > 0 {
		attempts.A = attempts.A[:len(attempts.A)-1]
		if len(attempts.A) == 0 {
			repro = dropKey(repro, "attempts")
		} else {
			repro = setKey(repro, "attempts", attempts)
		}
	}
	if priorStatus == nil {
		repro = dropKey(repro, "status")
	} else {
		repro = setKey(repro, "status", validation.VStr(*priorStatus))
	}
	if priorTier == nil {
		repro = dropKey(repro, "tier_reached")
	} else {
		repro = setKey(repro, "tier_reached", validation.VStr(*priorTier))
	}
	// Python's repro is the very dict inside ver, so emptying it in place
	// leaves `"reproduction": {}` behind; only a reproduction key that never
	// existed stays absent.
	if len(repro.O) > 0 || verHadRepro {
		ver = setKey(ver, "reproduction", repro)
	}
	f = setKey(f, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		return err
	}
	data := validation.VObj(validation.KV{K: "reason", V: validation.VStr(
		"mint failed after attempt recorded; the exec citation is preserved " +
			"for the retry")})
	_, err = c.Log("repro.attempt_rolled_back", &findingID, &data)
	return err
}

// AttemptAndMint is attempt_and_mint: record a successful attempt AND mint
// its evidence in one call. If the mint fails after the attempt is recorded,
// the attempt is rolled back so the exec citation is not burned.
func AttemptAndMint(c *state.Campaign, findingID, execID, description string,
	tier, evidenceType *string) (validation.Value, error) {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	prior := reproductionState(f)
	priorStatus, priorTier := optField(prior, "status"), optField(prior,
		"tier_reached")
	// A re-cite of an exec an earlier attempt already cited is NOT a new
	// attempt — it is a second evidence type for the same run
	// (feedback-triage A2). record_attempt refuses reused execs by design
	// (a re-run must be a NEW exec); skipping it here lets the (exec, type)
	// idempotency check in mint_repro_evidence decide: same type is a
	// no-op, a different type mints.
	execCited := false
	for _, a := range validation.ObjAt(prior, "attempts").A {
		if validation.ObjStr(a, "artifact_id") == execID {
			execCited = true
			break
		}
	}
	if !execCited {
		guidance, err := RecordAttempt(c, findingID, "reproduced",
			RecordOpts{ExecID: &execID, Tier: tier})
		if err != nil {
			return validation.VNull(), err
		}
		if validation.ObjStr(guidance, "action") != "mint-evidence" {
			rollErr := undoAttempt(c, findingID, priorStatus, priorTier)
			if rollErr != nil {
				return validation.VNull(), rollErr
			}
			return validation.VNull(), mintErrf(
				"attempt recorded but guidance is %s, not mint-evidence — "+
					"check the attempt's exec/tier", validation.PyReprStr(
					validation.ObjStr(guidance, "action")))
		}
	}
	out, err := MintReproEvidence(c, findingID, execID, description, tier,
		evidenceType)
	if err != nil {
		if !execCited {
			if rollErr := undoAttempt(c, findingID, priorStatus, priorTier); rollErr != nil {
				return validation.VNull(), rollErr
			}
		}
		return validation.VNull(), err
	}
	return out, nil
}
