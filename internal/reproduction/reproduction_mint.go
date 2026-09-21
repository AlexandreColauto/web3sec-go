package reproduction

import (
	"slices"
	"strings"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// Evidence minting: mint_repro_evidence with its (exec, type) idempotency
// and mint_independent_evidence (E6). Split from reproduction.go (same package).

// EffectiveEvidenceType is the type a mint would record for (tier arg,
// finding): the explicit --type wins, else the tier-derived default
// (E4→foundry-test, E5→fork-test). Shared by the idempotency checks so the
// CLI fast path and the library mint can never disagree — and delegated to
// findings.MintEvidenceLevelType, the SAME derivation the ingest exec_ref
// path uses (wave N, T2: one source, two verbs).
func EffectiveEvidenceType(tier, evidenceType *string, f validation.Value) string {
	claimTier := findings.RecordedReproTier(f)
	if tier != nil {
		claimTier = *tier
	}
	_, etype := findings.MintEvidenceLevelType(claimTier, evidenceType)
	return etype
}

// MintReproEvidence is mint_repro_evidence. Idempotent per (exec, type): an
// exec can back at most ONE evidence item per finding PER EVIDENCE TYPE —
// the same exec may back a second item of a different type (feedback-triage
// A2: the reference keyed on exec alone, so a second type silently never
// landed and the economic floors demanded a duplicate run).
//
// pocTier is the v1.6 §2.2 two-tier declaration ("" = untiered, the
// pre-v1.6 shape). The §2.2 ordering law is enforced HERE, in the shared
// write path, so `mint`, the ladder and Phase 5's maximization loop all
// inherit it; cmd_mint's pre-check only exists to give a better message.
func MintReproEvidence(c *state.Campaign, findingID, execID, description string,
	tier, evidenceType *string, pocTier string) (validation.Value, error) {
	setMintNotice("")
	if evidenceType != nil && !slices.Contains(MintableTypes, *evidenceType) {
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
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID && validation.ObjStr(e, "type") == etype {
			return f, nil // same exec already minted this type: nothing to do
		}
	}
	// The exec-record gate is findings.ValidateExecRecord — the SAME function
	// the ingest exec_ref path runs (wave N, T2: single source of truth). Mint
	// keeps its MintError class and its LoadExec error unwrapped, so cmd_mint
	// still prints `mint failed: ...` / the generic exit-1 handler unchanged.
	if err := findings.ValidateExecRecord(execID, rec); err != nil {
		return validation.VNull(), mintErrf("%s", err.Error())
	}
	repro := asDict(validation.ObjAt(asDict(validation.ObjAt(f, "verification")), "reproduction"))
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
	level, _ := findings.MintEvidenceLevelType(claimTier, evidenceType)
	// §2.2 ordering law, in the WRITE path (findings.ValidatePocTierOrder):
	// a fork-dependent hypothesis may not be maximized before its existence
	// tier is on the finding. Fork-independent findings are exempt.
	if err := findings.ValidatePocTierOrder(f, pocTier); err != nil {
		return validation.VNull(), err
	}
	// etype was derived above (EffectiveEvidenceType) for the idempotency
	// check — the same value, so the minted item and the no-op decision
	// always agree.
	item := findings.MintedExecEvidenceItem(execID, level, etype, description,
		rec, f, pocTier)
	item, notice := applyMintAdvisories(c, item, f, rec)
	setMintNotice(notice)
	out, err := findings.AddEvidence(c, findingID, item)
	return out, mintWrap(err)
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
	profile := validation.ObjStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return validation.VNull(), mintErrf(
			"exec %s ran under %s; E6 requires a container/VM/fork profile",
			execID, validation.PyReprStr(profile))
	}
	exit := validation.ObjAt(rec, "exit_status")
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
	for _, e := range validation.ObjAt(f, "evidence").A {
		if aid := validation.ObjStr(e, "artifact_id"); aid != "" {
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
		if rb := validation.ObjStr(pr, "reported_by"); rb != "" {
			priorReporters[rb] = struct{}{}
		}
	}
	if _, ok := priorReporters[verifier]; ok {
		return validation.VNull(), mintErrf(
			"verifier %s already produced the original reproduction — "+
				"independence requires a different identity",
			validation.PyReprStr(verifier))
	}
	reporter := validation.ObjStr(rec, "reported_by")
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
		validation.KV{K: "command", V: validation.VStr(validation.ObjStr(rec, "command"))},
		validation.KV{K: "produced_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "sandbox_profile", V: validation.VStr(profile)},
		validation.KV{K: "snapshot_id", V: validation.ObjAt(validation.ObjAt(f, "snapshot_ids"),
			"source")},
	)
	out, err := findings.AddEvidence(c, findingID, item)
	if err != nil {
		return validation.VNull(), mintWrap(err)
	}
	ver := asDict(validation.ObjAt(out, "verification"))
	ver = setKey(ver, "independent_reproduction", validation.VObj(
		validation.KV{K: "status", V: validation.VStr("matches")},
		validation.KV{K: "verifier", V: validation.VStr(verifier)},
		validation.KV{K: "artifact_id", V: validation.VStr(execID)},
		validation.KV{K: "discrepancies", V: validation.VArr()},
	))
	out = setKey(out, "verification", ver)
	data := validation.VObj(
		validation.KV{K: "verifier", V: validation.VStr(verifier)},
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
	)
	// r18 P2 sweep: independent-verification stamped without its event is
	// the E6 wash — a VERIFIED_BY row the queue can never confirm.
	if err := findings.SaveThenLog(c, &out, func() error {
		_, lerr := c.Log("repro.independent", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return out, nil
}
