// exec_evidence.go: the ONE exec-record gate and the ONE minted-item builder
// shared by `mint` (internal/reproduction) and the ingest exec_ref path.
//
// WHY this file exists: mint loads an EXEC ledger record, validates it, and
// materializes an E4/E5 evidence item from it; `ingest` must attach the item
// that a payload evidence item with "exec_ref" cites. Forking either half
// would let the two verbs disagree about what a reproduction is, so both call
// the functions below (reproduction imports findings; findings can never
// import reproduction without a cycle).
//
// INGEST PHASE ORDER (wave N, T2 ruling): the WHOLE payload is schema
// validated first (findings.IngestHypothesis), THEN the exec_ref ledger checks
// run (truths here), THEN the gate math (rise guardrail + discovery slot). A
// schema typo therefore can never be masked by an exec-ledger refusal — and a
// ledger refusal can never be masked by gate math.
//
// Presence-gated: an item that does not carry exec_ref never reaches this
// file; it keeps the pre-T2 ingest rule (execution evidence is refused
// outright, because the ledger is the only door to E4+).
package findings

import (
	"fmt"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// ReproTierOf is reproduction.tier_of: the tier a reproduction block records,
// "none" when the block or the key is missing or unreadable. It lives here
// because BOTH findings (the ingest exec_ref path) and reproduction (mint)
// need the same reader.
func ReproTierOf(repro validation.Value) string {
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

// RecordedReproTier is tier_of over a FINDING: the tier its
// verification.reproduction block records.
func RecordedReproTier(f validation.Value) string {
	return ReproTierOf(objAt(objAt(f, "verification"), "reproduction"))
}

// MintEvidenceLevelType is the claim-tier -> (level, type) derivation mint
// applies, extracted so the ingest exec_ref path lands the item mint would
// have minted: a T3/T4 claim is fork-level (E5/fork-test), every other claim
// is local (E4/foundry-test). explicitType is mint's --type and wins over the
// level-derived default.
func MintEvidenceLevelType(claimTier string,
	explicitType *string) (level, etype string) {
	level = "E4"
	if claimTier == "T3" || claimTier == "T4" {
		level = "E5"
	}
	etype = "foundry-test"
	if level == "E5" {
		etype = "fork-test"
	}
	if explicitType != nil {
		etype = *explicitType
	}
	return level, etype
}

// ValidateExecRecord is the exec-record gate `mint` has always run before it
// attaches an E4+ item, unchanged: the record must come from an E4-capable
// sandbox profile, it must have SUCCEEDED (exit 0 with captured output), and
// its output must not trip the forge-meaningfulness check. The messages are
// mint's, byte for byte — mint wraps the returned error in its MintError
// class, ingest names it as a refusal.
func ValidateExecRecord(execID string, rec validation.Value) error {
	profile := objStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return fmt.Errorf("exec %s ran under %s; E4+ evidence requires a "+
			"container/VM profile — re-run the repro sandboxed", execID,
			validation.PyReprStr(profile))
	}
	exit := objAt(rec, "exit_status")
	if !(exit.Kind == validation.Int && exit.I == 0) {
		return fmt.Errorf("exec %s exited with status %s; a run that did not "+
			"succeed is not a reproduction — fix the PoC and re-run before "+
			"minting evidence", execID, pyReprScalar(exit))
	}
	if strings.TrimSpace(sandbox.ExecOutput(rec)) == "" {
		return fmt.Errorf("exec %s exited 0 with EMPTY captured output; a run "+
			"that printed nothing cannot demonstrate a reproduction — verify "+
			"the exec actually ran (check image entrypoint/command wiring) and "+
			"re-run before minting evidence", execID)
	}
	if prob := sandbox.ExecOutputProblem(rec); prob != nil {
		return fmt.Errorf("exec %s: %s", execID, *prob)
	}
	return nil
}

// MintedExecEvidenceItem builds the E4/E5 evidence dict mint records for an
// exec, in Python's key order: the id is a fresh EV- id, the metadata comes
// from the exec record, the snapshot pin from the finding.
func MintedExecEvidenceItem(execID, level, etype, description string, rec,
	f validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr(state.NewID("EV", 8))},
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

// execFindingMatch is _verify_exec_reference's binding rule: an exec bound to
// this finding — or to no finding at all (a generic run) — may back its
// evidence; an exec bound to ANOTHER finding may not. One rule, both readers
// (add_evidence's E4+ gate and the ingest exec_ref gate).
func execFindingMatch(rec validation.Value, findingID string) bool {
	f := objAt(rec, "finding_id")
	return f.Kind == validation.Null ||
		(f.Kind == validation.Str && f.S == findingID)
}

// IngestExecRefEvidence is the ingest exec_ref happy path: the payload item
// cites an EXEC the campaign ledger already holds, so ingest attaches the item
// MINT would have minted for that exec. The ledger trio is enforced here, in
// THIS order:
//
//	unknown exec_ref      -> refuse, naming the ref and the citation;
//	bound elsewhere       -> refuse: the exec-finding binding stays, the
//	                         operator re-runs the exec under the survivor;
//	not SUCCEEDED         -> refuse with mint's own exec-record gate message
//	                         (profile / exit status / empty output).
//
// The binding check deliberately runs BEFORE the exec-record gate. An exec
// bound to another finding is refused even when its record would also fail the
// record gate, because the binding is the more actionable fact: re-running the
// identical PoC under this finding is pointless while the ledger row still
// names the other one, so the record's own defects would send the operator to
// fix the wrong thing. A binding refusal therefore MASKS a failure the record
// gate would have reported — the record is still there to be read once the
// binding is corrected.
//
// finding is the payload being ingested (it supplies the snapshot pin); the
// returned item is the minted shape, so exec_ref itself never lands on the
// finding.
func IngestExecRefEvidence(c *state.Campaign, findingID string, finding,
	item validation.Value) (validation.Value, error) {
	ref := objStr(item, "exec_ref")
	eid := pyStr(objAt(item, "evidence_id"))
	rec, err := sandbox.LoadExec(c, ref)
	if err != nil {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"cites exec_ref %s, which this campaign's ledger does not hold "+
			"(%s)", eid, validation.PyReprStr(ref), err)
	}
	if !execFindingMatch(rec, findingID) {
		return validation.VNull(), fmt.Errorf("ingest refused: exec_ref %s is "+
			"bound to finding %s, not %s — an exec backs only the finding it "+
			"ran under; re-run it with --finding %s to cite it here", ref,
			validation.PyRepr(objAt(rec, "finding_id")), findingID, findingID)
	}
	if err := ValidateExecRecord(ref, rec); err != nil {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"exec_ref %s: %s", eid, ref, err)
	}
	level, etype := MintEvidenceLevelType(RecordedReproTier(finding), nil)
	// I-4 (critic round 1): the derivation is authoritative — mint's own
	// answer for this exec and finding — but a payload that DECLARED a
	// different type/level must not be quietly rewritten (the recorded
	// provenance feeds EVIDENCE_TYPE_GROUPS gate reads). Refuse, naming the
	// derived pair, so the author re-files with the truth or mints with
	// --type. Absent declarations are the happy path.
	if dt := objStr(item, "type"); dt != "" && dt != etype {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"declares type %s, but exec_ref %s derives %s for this finding "+
			"(the derivation governs — cite it honestly or use `webv2 mint "+
			"--type`)", objStr(item, "evidence_id"), validation.PyReprStr(dt),
			ref, validation.PyReprStr(etype))
	}
	if dl := objStr(item, "level"); dl != "" && dl != level {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"declares level %s, but exec_ref %s derives %s for this finding "+
			"(the derivation governs — cite it honestly)",
			objStr(item, "evidence_id"), validation.PyReprStr(dl), ref,
			validation.PyReprStr(level))
	}
	return MintedExecEvidenceItem(ref, level, etype,
		objStr(item, "description"), rec, finding), nil
}

// pyReprScalar is Python's repr for the JSON scalars an exec field holds
// (str quoted, everything else via PyRepr) — the exec-gate messages use it.
func pyReprScalar(v validation.Value) string {
	if v.Kind == validation.Str {
		return validation.PyReprStr(v.S)
	}
	return validation.PyRepr(v)
}
