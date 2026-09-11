// Package reproduction ports webv2.reproduction: tiered reproduction as a
// search problem, the attempt ledger, and the E4/E5/E6 minting paths.
//
// Key property (from the Python docstring): a FAILED attempt is a structured
// record, not a dead end. When an attempt fails with
// failure_class=environment/setup, the retry is mandated as FRESH CONTEXT.
package reproduction

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// TierOrder is TIER_ORDER.
var TierOrder = []string{"none", "T0", "T1", "T2", "T3", "T4"}

// freshContextClasses is _FRESH_CONTEXT_CLASSES.
var freshContextClasses = map[string]struct{}{
	"environment": {}, "setup": {}, "precondition-unmet": {},
}

// hypothesisWrongClasses is _HYPOTHESIS_WRONG_CLASSES.
var hypothesisWrongClasses = map[string]struct{}{
	"logic": {}, "hypothesis-wrong": {},
}

// MintableTypes is _MINTABLE_TYPES: the evidence types a reproduction mint
// may claim (mirrors the schema enum).
var MintableTypes = []string{"reasoning", "static-analysis", "reachability",
	"unit-test", "foundry-test", "fuzz", "invariant-test", "symbolic-witness",
	"fork-test", "trace", "balance-delta", "differential", "historical-analog",
	"manual"}

// MintError is the ValueError/RuntimeError/KeyError family cmd_mint maps to
// `mint failed: ...` + exit 2. Everything else (a missing exec record, a
// missing finding) is the generic exit-1 handler's business.
type MintError struct{ Msg string }

func (e *MintError) Error() string { return e.Msg }

func mintErrf(format string, a ...any) error {
	return &MintError{Msg: fmt.Sprintf(format, a...)}
}

// mintWrap marks an error from the evidence gate as mint-class (Python's
// add_evidence raises ValueError, which cmd_mint catches).
func mintWrap(err error) error {
	if err == nil {
		return nil
	}
	var me *MintError
	if errors.As(err, &me) {
		return err
	}
	return &MintError{Msg: err.Error()}
}

// TierOf is tier_of.
func TierOf(repro validation.Value) string {
	if repro.Kind != validation.Obj {
		return "none"
	}
	for _, kv := range repro.O {
		if kv.K == "tier_reached" {
			if kv.V.Kind == validation.Str {
				return kv.V.S
			}
			return "none"
		}
	}
	return "none"
}

// NextTier is next_tier: the next rung, or None at the end (Python's
// ValueError for a tier name that is not in TIER_ORDER).
func NextTier(current string) (string, bool, error) {
	for i, tier := range TierOrder {
		if tier == current {
			if i+1 < len(TierOrder) {
				return TierOrder[i+1], true, nil
			}
			return "", false, nil
		}
	}
	return "", false, fmt.Errorf("%s is not in list",
		validation.PyReprStr(current))
}

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
	maxAttempts := intOf(objAt(budget, "max_repro_attempts_per_finding"))
	maxRetries := intOf(objAt(budget, "max_fresh_context_retries"))

	ver := asDict(objAt(f, "verification"))
	repro := asDict(objAt(ver, "reproduction"))
	attempts := objAt(repro, "attempts")
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
			if objStr(a, "artifact_id") == *opts.ExecID {
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
	if err := findings.SaveFinding(c, &f); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "failure_class", V: failure},
		validation.KV{K: "attempt", V: validation.VInt(int64(len(attempts.A)))},
	)
	if _, err := c.Log("repro.attempt", &findingID, &data); err != nil {
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

// EffectiveEvidenceType is the type a mint would record for (tier arg,
// finding): the explicit --type wins, else the tier-derived default
// (E4→foundry-test, E5→fork-test). Shared by the idempotency checks so the
// CLI fast path and the library mint can never disagree.
func EffectiveEvidenceType(tier, evidenceType *string, f validation.Value) string {
	recorded := TierOf(asDict(objAt(asDict(objAt(f, "verification")), "reproduction")))
	claimTier := recorded
	if tier != nil {
		claimTier = *tier
	}
	level := "E4"
	if claimTier == "T3" || claimTier == "T4" {
		level = "E5"
	}
	etype := "foundry-test"
	if level == "E5" {
		etype = "fork-test"
	}
	if evidenceType != nil {
		etype = *evidenceType
	}
	return etype
}

// MintReproEvidence is mint_repro_evidence. Idempotent per (exec, type): an
// exec can back at most ONE evidence item per finding PER EVIDENCE TYPE —
// the same exec may back a second item of a different type (feedback-triage
// A2: the reference keyed on exec alone, so a second type silently never
// landed and the economic floors demanded a duplicate run).
func MintReproEvidence(c *state.Campaign, findingID, execID, description string,
	tier, evidenceType *string) (validation.Value, error) {
	setMintNotice("")
	if evidenceType != nil && !inList(MintableTypes, *evidenceType) {
		return validation.VNull(), mintErrf("unknown evidence type %s; one of %s",
			validation.PyReprStr(*evidenceType), tupleRepr(MintableTypes))
	}
	rec, err := sandbox.LoadExec(c, execID)
	if err != nil {
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	etype := EffectiveEvidenceType(tier, evidenceType, f)
	for _, e := range objAt(f, "evidence").A {
		if objStr(e, "artifact_id") == execID && objStr(e, "type") == etype {
			return f, nil // same exec already minted this type: nothing to do
		}
	}
	profile := objStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return validation.VNull(), mintErrf(
			"exec %s ran under %s; E4+ evidence requires a container/VM "+
				"profile — re-run the repro sandboxed", execID,
			validation.PyReprStr(profile))
	}
	exit := objAt(rec, "exit_status")
	if !(exit.Kind == validation.Int && exit.I == 0) {
		return validation.VNull(), mintErrf(
			"exec %s exited with status %s; a run that did not succeed is not "+
				"a reproduction — fix the PoC and re-run before minting evidence",
			execID, pyReprScalar(exit))
	}
	if strings.TrimSpace(sandbox.ExecOutput(rec)) == "" {
		return validation.VNull(), mintErrf(
			"exec %s exited 0 with EMPTY captured output; a run that printed "+
				"nothing cannot demonstrate a reproduction — verify the exec "+
				"actually ran (check image entrypoint/command wiring) and "+
				"re-run before minting evidence", execID)
	}
	if prob := sandbox.ExecOutputProblem(rec); prob != nil {
		return validation.VNull(), mintErrf("exec %s: %s", execID, *prob)
	}
	repro := asDict(objAt(asDict(objAt(f, "verification")), "reproduction"))
	recorded := TierOf(repro)
	if tier != nil {
		if tierIndex(*tier) > tierIndex(recorded) {
			return validation.VNull(), mintErrf(
				"cannot mint at tier %s: the highest recorded attempt tier is "+
					"%s — record the higher-tier attempt first (record_attempt "+
					"/ attempt_and_mint)", *tier, validation.PyReprStr(recorded))
		}
	}
	claimTier := recorded
	if tier != nil {
		claimTier = *tier
	}
	level := "E4"
	if claimTier == "T3" || claimTier == "T4" {
		level = "E5"
	}
	// etype was derived above (EffectiveEvidenceType) for the idempotency
	// check — the same value, so the minted item and the no-op decision
	// always agree.
	item := evidenceItem(execID, level, etype, description, rec, f)
	item, notice := applyMintAdvisories(c, item, f, rec)
	setMintNotice(notice)
	out, err := findings.AddEvidence(c, findingID, item)
	return out, mintWrap(err)
}

// evidenceItem builds the E4/E5 evidence dict in Python's key order.
func evidenceItem(execID, level, etype, description string, rec,
	f validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr("EV-" + shortID(8))},
		validation.KV{K: "level", V: validation.VStr(level)},
		validation.KV{K: "type", V: validation.VStr(etype)},
		validation.KV{K: "artifact_id", V: validation.VStr(execID)},
		validation.KV{K: "description", V: validation.VStr(description)},
		validation.KV{K: "command", V: validation.VStr(objStr(rec, "command"))},
		validation.KV{K: "produced_at", V: validation.VStr(nowIso())},
		validation.KV{K: "sandbox_profile", V: validation.VStr(
			objStr(rec, "profile"))},
		validation.KV{K: "snapshot_id", V: objAt(objAt(f, "snapshot_ids"),
			"source")},
	)
}

// reproductionState is _reproduction_state.
func reproductionState(f validation.Value) validation.Value {
	ver := objAt(f, "verification")
	if ver.Kind != validation.Obj {
		return validation.VObj()
	}
	repro := objAt(ver, "reproduction")
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
	ver := asDict(objAt(f, "verification"))
	verHadRepro := objAt(ver, "reproduction").Kind == validation.Obj
	repro := reproductionState(f)
	attempts := objAt(repro, "attempts")
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
	for _, a := range objAt(prior, "attempts").A {
		if objStr(a, "artifact_id") == execID {
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
		if objStr(guidance, "action") != "mint-evidence" {
			rollErr := undoAttempt(c, findingID, priorStatus, priorTier)
			if rollErr != nil {
				return validation.VNull(), rollErr
			}
			return validation.VNull(), mintErrf(
				"attempt recorded but guidance is %s, not mint-evidence — "+
					"check the attempt's exec/tier", validation.PyReprStr(
					objStr(guidance, "action")))
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

// MintIndependentEvidence is mint_independent_evidence: mint E6, enforcing
// independence (fresh exec, named verifier, different reporter).
func MintIndependentEvidence(c *state.Campaign, findingID, execID, description,
	verifier string) (validation.Value, error) {
	if verifier == "" {
		return validation.VNull(), mintErrf(
			"independent verification requires a named verifier identity")
	}
	rec, err := sandbox.LoadExec(c, execID)
	if err != nil {
		return validation.VNull(), err
	}
	profile := objStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return validation.VNull(), mintErrf(
			"exec %s ran under %s; E6 requires a container/VM/fork profile",
			execID, validation.PyReprStr(profile))
	}
	exit := objAt(rec, "exit_status")
	if !(exit.Kind == validation.Int && exit.I == 0) {
		return validation.VNull(), mintErrf(
			"exec %s exited with status %s; an independent reproduction that "+
				"failed proves nothing", execID, pyReprScalar(exit))
	}
	if strings.TrimSpace(sandbox.ExecOutput(rec)) == "" {
		return validation.VNull(), mintErrf(
			"exec %s exited 0 with EMPTY captured output; a run that printed "+
				"nothing cannot demonstrate an independent reproduction — "+
				"verify the exec actually ran and re-run before minting evidence",
			execID)
	}
	if prob := sandbox.ExecOutputProblem(rec); prob != nil {
		return validation.VNull(), mintErrf("exec %s: %s", execID, *prob)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	cited := []string{}
	for _, e := range objAt(f, "evidence").A {
		if aid := objStr(e, "artifact_id"); aid != "" {
			cited = append(cited, aid)
		}
	}
	for _, aid := range cited {
		if aid == execID {
			return validation.VNull(), mintErrf(
				"exec %s already backs evidence on %s; an independent "+
					"reproduction must be a fresh execution", execID, findingID)
		}
	}
	priorReporters := map[string]struct{}{}
	for _, aid := range cited {
		if !strings.HasPrefix(aid, "EXEC-") {
			continue
		}
		pr, err := sandbox.LoadExec(c, aid)
		if err != nil {
			continue
		}
		if rb := objStr(pr, "reported_by"); rb != "" {
			priorReporters[rb] = struct{}{}
		}
	}
	if _, ok := priorReporters[verifier]; ok {
		return validation.VNull(), mintErrf(
			"verifier %s already produced the original reproduction — "+
				"independence requires a different identity",
			validation.PyReprStr(verifier))
	}
	reporter := objStr(rec, "reported_by")
	if reporter != "" && len(priorReporters) > 0 {
		if _, ok := priorReporters[reporter]; ok {
			return validation.VNull(), mintErrf(
				"verifier %s already produced the original reproduction — "+
					"independence requires a different reporter",
				validation.PyReprStr(reporter))
		}
	}
	item := validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr("EV-" + shortID(8))},
		validation.KV{K: "level", V: validation.VStr("E6")},
		validation.KV{K: "type", V: validation.VStr("differential")},
		validation.KV{K: "artifact_id", V: validation.VStr(execID)},
		validation.KV{K: "description", V: validation.VStr(
			"independent reproduction by " + verifier + ": " + description)},
		validation.KV{K: "command", V: validation.VStr(objStr(rec, "command"))},
		validation.KV{K: "produced_at", V: validation.VStr(nowIso())},
		validation.KV{K: "sandbox_profile", V: validation.VStr(profile)},
		validation.KV{K: "snapshot_id", V: objAt(objAt(f, "snapshot_ids"),
			"source")},
	)
	out, err := findings.AddEvidence(c, findingID, item)
	if err != nil {
		return validation.VNull(), mintWrap(err)
	}
	ver := asDict(objAt(out, "verification"))
	ver = setKey(ver, "independent_reproduction", validation.VObj(
		validation.KV{K: "status", V: validation.VStr("matches")},
		validation.KV{K: "verifier", V: validation.VStr(verifier)},
		validation.KV{K: "artifact_id", V: validation.VStr(execID)},
		validation.KV{K: "discrepancies", V: validation.VArr()},
	))
	out = setKey(out, "verification", ver)
	if err := findings.SaveFinding(c, &out); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "verifier", V: validation.VStr(verifier)},
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
	)
	if _, err := c.Log("repro.independent", &findingID, &data); err != nil {
		return validation.VNull(), err
	}
	return out, nil
}

// --- helpers ----------------------------------------------------------------

func tierIndex(tier string) int {
	for i, t := range TierOrder {
		if t == tier {
			return i
		}
	}
	return -1
}

func inSet(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

func inList(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// tupleRepr is Python's repr of a tuple of strings.
func tupleRepr(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyReprScalar is Python's repr for the JSON scalars an exec field holds.
func pyReprScalar(v validation.Value) string {
	if v.Kind == validation.Str {
		return validation.PyReprStr(v.S)
	}
	return validation.PyRepr(v)
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

// asDict is Python's `x if isinstance(x, dict) else {}` used by the
// setdefault chains (a fresh dict that the caller then stores).
func asDict(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return validation.Value{Kind: validation.Obj,
			O: append([]validation.KV(nil), v.O...)}
	}
	return validation.VObj()
}

func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := validation.Value{Kind: validation.Obj, O: append(
		[]validation.KV(nil), v.O...)}
	for i := range out.O {
		if out.O[i].K == key {
			out.O[i].V = val
			return out
		}
	}
	out.O = append(out.O, validation.KV{K: key, V: val})
	return out
}

func dropKey(v validation.Value, key string) validation.Value {
	out := validation.Value{Kind: validation.Obj}
	for _, kv := range v.O {
		if kv.K != key {
			out.O = append(out.O, kv)
		}
	}
	return out
}

func optField(v validation.Value, key string) *string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		s := f.S
		return &s
	}
	return nil
}

func intOf(v validation.Value) int {
	if v.Kind == validation.Int {
		return int(v.I)
	}
	return 0
}

func shortID(n int) string {
	parts := strings.SplitN(state.NewID("x", n), "-", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// nowIso is state's unexported nowIso re-implemented here (the twin-clock
// contract: WEBV2_NOW pins it verbatim, else UTC microseconds with +00:00).
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// --- G15 PoC quality gate at mint (Task 23) ---------------------------------
//
// Two fail-open advisories ride the minted evidence item as metadata. They
// never block the mint: every degraded path below resolves to "mint
// without the advisory" (or a not-applicable marker), never to a refusal.
//
//   - reruns: opt-in via VerifyReruns (`mint --verify-reruns`, default OFF)
//     and only for E4-capable profiles. The recorded command is re-run
//     rerunAttempts times; exit-vector (exit status + stdout hash) equality
//     across runs decides "3/3" vs "flaky n/3", with the rerun exec ids
//     appended as the audit join ("3/3 (execs EXEC-a,EXEC-b,EXEC-c)").
//     A missing container runtime resolves to "not-applicable" plus a
//     CLI warning line.
//   - fork_stale: always on (freshness is data, not judgment). The pinned
//     snapshot's fork_timestamp (fallback: created_at) is compared against
//     the exec's started_at; age beyond forkStaleDays, or a null
//     fork_timestamp, marks the item stale with a reason marker first
//     ("stale: no snapshot data recorded" / "stale: fork timestamp
//     missing" / "stale: pinned N days ago"). Fresh snapshots gain no key.

// rerunAttempts is the G15 rerun count (policy-tunable = code const).
const rerunAttempts = 3

// forkStaleDays is the G15 fork-freshness threshold in days
// (policy-tunable = code const for now; campaign_state wiring is G13's
// budget block's job later).
const forkStaleDays = 7

// VerifyReruns gates the 3x-rerun variance advisory. Set by
// `mint --verify-reruns`; default false (flag OFF = zero behavior change
// on the reruns half).
var VerifyReruns bool

// ErrRerunUnavailable is the docker-absent sentinel: the rerun seam
// reports it (via errors.Is) when no container runtime can run the rerun.
var ErrRerunUnavailable = errors.New(
	"container runtime unavailable for reruns")

// defaultRerunExecutor is the real sandbox.Run call behind the seam. It
// returns the rerun's own exec_id first: the audit join for variance
// reruns lives on the EVIDENCE item (`reruns:"3/3 (execs EXEC-a,...)"`),
// never on the exec record (see rerunAdvisory).
var defaultRerunExecutor = func(c *state.Campaign, profile,
	command string) (string, int, []byte, error) {
	sb, err := sandbox.NewSandbox(c, profile)
	if err != nil {
		var ue *sandbox.UnavailableError
		if errors.As(err, &ue) {
			return "", 0, nil, ErrRerunUnavailable
		}
		return "", 0, nil, err
	}
	rec, err := sb.Run(command, sandbox.RunOpts{})
	if err != nil {
		return "", 0, nil, err
	}
	exit := 0
	if e := objAt(rec, "exit_status"); e.Kind == validation.Int {
		exit = int(e.I)
	}
	out, err := os.ReadFile(objStr(rec, "stdout_path"))
	if err != nil {
		out = []byte(sandbox.ExecOutput(rec))
	}
	return objStr(rec, "exec_id"), exit, out, nil
}

// rerunExecutor is the G15 executor seam: re-run command under profile,
// reporting the rerun's exec_id, exit status and captured stdout.
// Tests swap it for stubbed flaky/deterministic outputs (stubs return
// synthetic EXEC- ids so the evidence join is exercised); a docker-absent
// runtime surfaces as ErrRerunUnavailable.
var rerunExecutor = defaultRerunExecutor

// SetRerunExecutor installs the rerun seam (nil restores the default).
// Cross-package CLI tests use this; in-package tests swap the var.
func SetRerunExecutor(fn func(*state.Campaign, string,
	string) (string, int, []byte, error)) {
	if fn == nil {
		fn = defaultRerunExecutor
	}
	rerunExecutor = fn
}

// sha256Hex is _sha's digest half: hex sha256 over bytes (the same hashing
// the exec record's artifact_hashes use).
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// origStdoutHash is the cited exec's stdout hash: the recorded
// artifact_hashes entry when present (byte-identical to what the ledger
// hashed), else the hash of the captured output.
func origStdoutHash(rec validation.Value) string {
	if h := objStr(objAt(rec, "artifact_hashes"), "stdout.log"); h != "" {
		return h
	}
	return sha256Hex([]byte(sandbox.ExecOutput(rec)))
}

// rerunsText renders the variance value with its audit join: the base
// verdict plus the rerun exec ids in run order, so an auditor can walk
// from the evidence item to the exact EXEC records that back it. With no
// ids (only possible when every rerun errored before producing an exec)
// the bare base verdict stands alone.
func rerunsText(match int, ids []string) string {
	base := fmt.Sprintf("flaky %d/%d", match, rerunAttempts)
	if match == rerunAttempts {
		base = fmt.Sprintf("%d/%d", rerunAttempts, rerunAttempts)
	}
	if len(ids) == 0 {
		return base
	}
	return base + " (execs " + strings.Join(ids, ",") + ")"
}

// rerunAdvisory runs the variance gate. It returns the advisory string for
// the evidence item ("3/3 (execs ...)", "flaky n/3 (execs ...)",
// "not-applicable", or "" when the gate does not apply) and whether the
// docker-absent warning line is owed.
// "" with warn=false means flag off or a non-E4 profile: no key gained,
// no warning.
//
// Provenance rail (fix round 1): sandbox.RunOpts offers NO
// provenance-capable field — its exact shape is {Workdir *string,
// FindingID *string, ArtifactID *string, Timeout int, Env []EnvVar} — and
// a locally-executed record hardcodes origin="locally-executed" with
// reported_by=null. FindingID/ArtifactID are linkage ids (repurposing
// them corrupts joins), Env/Workdir change execution semantics, and the
// command text must not be mutated. So rerun execs carry no per-record
// marker; the audit join is the exec-id list in the evidence value, and
// the cited original exec record is never rewritten by the mint path.
func rerunAdvisory(c *state.Campaign, rec validation.Value) (string, bool) {
	if !VerifyReruns {
		return "", false
	}
	profile := objStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return "", false
	}
	command := objStr(rec, "command")
	wantExit := 0
	if e := objAt(rec, "exit_status"); e.Kind == validation.Int {
		wantExit = int(e.I)
	}
	wantHash := origStdoutHash(rec)
	match := 0
	ids := []string{}
	for i := 0; i < rerunAttempts; i++ {
		execID, exit, out, err := rerunExecutor(c, profile, command)
		if err != nil {
			if errors.Is(err, ErrRerunUnavailable) {
				return "not-applicable", true
			}
			continue // fail-open: a failed rerun is a non-match
		}
		if execID != "" {
			ids = append(ids, execID)
		}
		if exit == wantExit && sha256Hex(out) == wantHash {
			match++
		}
	}
	return rerunsText(match, ids), false
}

// parseStamp parses the twin-clock timestamps (WEBV2_NOW pins them
// verbatim; else UTC microseconds with +00:00).
func parseStamp(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.999999999Z07:00", s)
}

// forkBlockText renders the snapshot's fork_block, or "unknown" when the
// pin carries none (null chain, absent key, non-numeric).
func forkBlockText(chain validation.Value) string {
	b := objAt(chain, "fork_block")
	if b.Kind == validation.Int {
		return strconv.FormatInt(b.I, 10)
	}
	if b.Kind == validation.Str && b.S != "" {
		return b.S
	}
	return "unknown"
}

// forkStaleText renders the fork_stale message: a reason marker FIRST
// (so null-chain, null-timestamp and genuine-age staleness are mutually
// distinguishable) followed by the detail text. Reason is one of:
// "no snapshot data recorded" (null/absent chain), "fork timestamp
// missing" (chain pin without fork_timestamp), "pinned N days ago"
// (genuine age beyond the window), or "pinned <raw timestamp>" (a present
// but unparseable timestamp — stale by the fail-open law, with no day
// count claimed).
func forkStaleText(reason, date, block string) string {
	return fmt.Sprintf("stale: %s \u2014 snapshot pinned %s fork_block "+
		"%s \u2014 re-pin with snap + re-mint", reason, date, block)
}

// forkStaleAdvisory is the always-on freshness half: "" when the pinned
// snapshot is fresh (no key is gained), else the fork_stale message. It
// never errors and never blocks the mint — without a source pin, or with
// an unreadable snapshot file, there is nothing to judge against, so the
// item stays silent.
func forkStaleAdvisory(c *state.Campaign, f,
	rec validation.Value) string {
	srcID := objStr(objAt(f, "snapshot_ids"), "source")
	if srcID == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(c.Dir, "snapshots", srcID,
		"snapshot.json"))
	if err != nil {
		return ""
	}
	snap, err := validation.ParseOrdered(raw)
	if err != nil {
		return ""
	}
	chain := objAt(snap, "chain")
	block := forkBlockText(chain)
	pinned := ""
	if ts := objAt(chain, "fork_timestamp"); ts.Kind == validation.Str &&
		ts.S != "" {
		pinned = ts.S
	}
	if pinned == "" {
		// Null chain or null fork_timestamp: stale, dated by what the
		// pin does carry (created_at) or "unknown" — with the reason
		// named so the two data-absent shapes stay distinguishable.
		date := objStr(snap, "created_at")
		if date == "" {
			date = "unknown"
		}
		reason := "fork timestamp missing"
		if chain.Kind != validation.Obj {
			reason = "no snapshot data recorded"
		}
		return forkStaleText(reason, date, block)
	}
	tFork, err := parseStamp(pinned)
	tExec, err2 := parseStamp(objStr(rec, "started_at"))
	if err != nil || err2 != nil {
		return forkStaleText("pinned "+pinned, pinned, block)
	}
	age := tExec.Sub(tFork)
	if age > time.Duration(forkStaleDays)*24*time.Hour {
		return forkStaleText(fmt.Sprintf("pinned %d days ago",
			int(age.Hours()/24)), pinned, block)
	}
	return ""
}

var mintNoticeMu sync.Mutex
var lastMintNotice string

func setMintNotice(n string) {
	mintNoticeMu.Lock()
	defer mintNoticeMu.Unlock()
	lastMintNotice = n
}

// TakeMintNotice returns the fail-open advisory notice from the most
// recent mint on this process ("" when none) and clears it. cmd_mint
// prints it as a stderr warning line.
func TakeMintNotice() string {
	mintNoticeMu.Lock()
	defer mintNoticeMu.Unlock()
	n := lastMintNotice
	lastMintNotice = ""
	return n
}

// applyMintAdvisories attaches the G15 advisories to a fresh evidence
// item: reruns only when the flag + profile gates hold, fork_stale
// whenever the pin reads stale. It returns the item and the CLI warning
// line ("" when none is owed).
func applyMintAdvisories(c *state.Campaign, item, f,
	rec validation.Value) (validation.Value, string) {
	warn := ""
	if r, w := rerunAdvisory(c, rec); r != "" {
		item = setKey(item, "reruns", validation.VStr(r))
		if w {
			warn = "warning: reruns not-applicable " +
				"(container runtime unavailable) \u2014 evidence " +
				"minted without variance data"
		}
	}
	if s := forkStaleAdvisory(c, f, rec); s != "" {
		item = setKey(item, "fork_stale", validation.VStr(s))
	}
	return item, warn
}
