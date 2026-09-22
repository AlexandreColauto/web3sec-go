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
	"strconv"
	"strings"
	"unicode/utf8"

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
	return ReproTierOf(validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction"))
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

// TruncatedCapture is one stream an exec record's output_capture marks
// TRUNCATED (P2-2): which stream, the cap the record kept, and the true
// byte total when the record carries one (null when output was withheld).
type TruncatedCapture struct {
	Stream   string // "stdout" or "stderr"
	Cap      int64  // output_capture.cap_bytes
	Total    int64  // output_capture.<stream>_total_bytes (when an int)
	HasTotal bool
}

// Kept is the payload byte count the record's own accounting holds for a
// truncated stream: the cap. The sandbox keeps the first cap_bytes of the
// payload and appends the marker line on disk (sandbox.truncationMarker),
// so a record that says truncated=true says kept == cap_bytes.
func (tc TruncatedCapture) Kept() int64 { return tc.Cap }

// Accounting renders the observed capture accounting — the exact state the
// record states and nothing more: which stream is marked truncated, how
// many bytes were kept of how many total, or that the true total is not in
// the record (output withheld).
func (tc TruncatedCapture) Accounting() string {
	total := strconv.FormatInt(tc.Total, 10)
	if !tc.HasTotal {
		total = "None (output withheld — the true byte count is not in " +
			"the record)"
	}
	return fmt.Sprintf("%s capture marked truncated: kept %d of %s bytes "+
		"(cap_bytes %d, %s_truncated=true)", tc.Stream, tc.Kept(), total,
		tc.Cap, tc.Stream)
}

// ExecTruncatedCapture reads the record's output_capture object and returns
// the FIRST stream the record itself marks truncated (stdout before
// stderr — the order the record lists them), or nil when the record marks
// no truncated stream. A record without output_capture (the externally-
// reported registrations) claims no truncation: the ledger never claims
// what did not happen.
//
// This is the reader BOTH consumers share (ValidateExecRecord — mint's
// exec-record gate and the ingest exec_ref path — and the verify
// --harness-result binder in cmd_verify_harness.go), so no evidence
// consumer can hold a second opinion about a truncated capture.
func ExecTruncatedCapture(rec validation.Value) *TruncatedCapture {
	oc := validation.ObjAt(rec, "output_capture")
	if oc.Kind != validation.Obj {
		return nil
	}
	for _, stream := range []string{"stdout", "stderr"} {
		marked := validation.ObjAt(oc, stream+"_truncated")
		if marked.Kind != validation.Bool || !marked.B {
			continue
		}
		tc := TruncatedCapture{Stream: stream}
		if cap := validation.ObjAt(oc, "cap_bytes"); cap.Kind == validation.Int {
			tc.Cap = cap.I
		}
		if total := validation.ObjAt(oc, stream+"_total_bytes"); total.Kind ==
			validation.Int {
			tc.Total, tc.HasTotal = total.I, true
		}
		return &tc
	}
	return nil
}

// ValidateExecRecord is the exec-record gate `mint` has always run before it
// attaches an E4+ item: the record must come from an E4-capable sandbox
// profile, its exit status must match the record's DECLARED EXPECTATION
// (absent expected_outcome means "pass" — today's exit-0 rule, byte-for-byte),
// its output must not trip the forge-meaningfulness check, and (P2-2) a
// capture the record marks truncated is refused outright.
//
// Under expected_outcome "fail" (v16 §5.3 route 2) the run is admitted only
// when ALL THREE hold: exit_status is NON-ZERO; expected_failure is present,
// clears the specificity floor (>= 8 characters, not the literal "FAIL") and
// appears on a captured PER-TEST failure line — the token [FAIL for a
// forge-like command, the plain substring FAIL for an arbitrary harness
// (sandbox.FailureSignatureOnFailLine); and sandbox.ClassifyFailure reports
// class "logic" — the already-existing authority on whether the run was a
// real test failure, reused here rather than duplicated. Infrastructure
// causes (environment, setup, unknown, none) are refused even when the
// signature matches.
//
// The messages are mint's, byte for byte — mint wraps the returned error in
// its MintError class, ingest names it as a refusal.
func ValidateExecRecord(execID string, rec validation.Value) error {
	if err := checkExecExpectationShape(execID, rec); err != nil {
		return err
	}
	if err := checkExecProfile(execID, rec); err != nil {
		return err
	}
	if err := checkExecExit(execID, rec); err != nil {
		return err
	}
	if err := checkExecOutputNonEmpty(execID, rec); err != nil {
		return err
	}
	if err := checkExecCaptureComplete(execID, rec); err != nil {
		return err
	}
	if prob := sandbox.ExecOutputProblem(rec); prob != nil {
		return fmt.Errorf("exec %s: %s", execID, *prob)
	}
	if sandbox.ExecExpectedOutcome(rec) == sandbox.EXPECT_FAIL {
		return checkExpectedFailure(execID, rec)
	}
	return nil
}

// checkExecExpectationShape refuses the two record shapes the schema itself
// forbids (defense in depth for hand-edited ledger rows, which are read
// without schema validation): an unreadable expected_outcome, and a declared
// failure signature under any expectation other than "fail". No-op for every
// record without the new keys — the load-bearing backward-compatibility
// property.
func checkExecExpectationShape(execID string, rec validation.Value) error {
	outcome := validation.ObjStr(rec, "expected_outcome")
	if outcome != "" && outcome != sandbox.EXPECT_PASS &&
		outcome != sandbox.EXPECT_FAIL {
		return fmt.Errorf("exec %s: expected_outcome %s is not one of "+
			"'pass' | 'fail' — an unreadable expectation admits nothing "+
			"— re-register the exec with a valid value", execID,
			validation.PyReprStr(outcome))
	}
	if sig := sandbox.ExecExpectedFailure(rec); sig != "" &&
		outcome != sandbox.EXPECT_FAIL {
		shown := outcome
		if shown == "" {
			shown = "(absent)"
		}
		return fmt.Errorf("exec %s: expected_failure %s is declared under "+
			"expected_outcome %s — a failure signature is required under "+
			"'fail' and forbidden otherwise; a signature on a run expected "+
			"to pass is a contradiction the record cannot carry",
			execID, validation.PyReprStr(sig), shown)
	}
	return nil
}

// checkExecProfile is ValidateExecRecord's profile gate (unchanged).
func checkExecProfile(execID string, rec validation.Value) error {
	profile := validation.ObjStr(rec, "profile")
	if _, ok := sandbox.E4_PROFILES[profile]; !ok {
		return fmt.Errorf("exec %s ran under %s; E4+ evidence requires a "+
			"container/VM profile — re-run the repro sandboxed", execID,
			validation.PyReprStr(profile))
	}
	return nil
}

// checkExecExit compares exit_status against the record's declared
// expectation: under "pass" (the default) exit must be 0 — today's rule and
// message, byte for byte; under "fail" exit must be NON-ZERO, and a run
// that succeeded cannot demonstrate the expected failure.
func checkExecExit(execID string, rec validation.Value) error {
	exit := validation.ObjAt(rec, "exit_status")
	if sandbox.ExecExpectedOutcome(rec) == sandbox.EXPECT_FAIL {
		if exit.Kind == validation.Int && exit.I != 0 {
			return nil
		}
		return fmt.Errorf("exec %s: expected_outcome is 'fail' but "+
			"exit_status is %s — an expected-failure reproduction must exit "+
			"NON-ZERO; a run that succeeded does not demonstrate the "+
			"expected failure — re-run the repro, or declare the "+
			"expectation as pass if this run was meant to succeed",
			execID, pyReprScalar(exit))
	}
	if !(exit.Kind == validation.Int && exit.I == 0) {
		return fmt.Errorf("exec %s exited with status %s; a run that did not "+
			"succeed is not a reproduction — fix the PoC and re-run before "+
			"minting evidence", execID, pyReprScalar(exit))
	}
	return nil
}

// checkExecOutputNonEmpty is the emptiness gate: under "pass" its message is
// today's, byte for byte; under "fail" a non-empty capture is equally
// required (a FAIL line with the signature cannot exist on silence).
func checkExecOutputNonEmpty(execID string, rec validation.Value) error {
	if strings.TrimSpace(sandbox.ExecOutput(rec)) != "" {
		return nil
	}
	if sandbox.ExecExpectedOutcome(rec) == sandbox.EXPECT_FAIL {
		return fmt.Errorf("exec %s: expected_outcome is 'fail' but the "+
			"captured output is EMPTY (exit status %s) — an empty capture "+
			"can never show the declared signature on a FAIL line — verify "+
			"the exec actually ran and re-run before minting evidence",
			execID, pyReprScalar(validation.ObjAt(rec, "exit_status")))
	}
	return fmt.Errorf("exec %s exited 0 with EMPTY captured output; a run "+
		"that printed nothing cannot demonstrate a reproduction — verify "+
		"the exec actually ran (check image entrypoint/command wiring) and "+
		"re-run before minting evidence", execID)
}

// checkExecCaptureComplete is the P2-2 truncation refusal (moved verbatim):
// a capture the record itself marks TRUNCATED is unfit for evidence —
// whichever stream, whatever the kept bytes look like. The meaningfulness
// verdict was computed over the KEPT bytes only, and the run's verdict lines
// could sit past the cap in either direction: their absence AND their
// presence are both unprovable from a truncated capture (exec.go's own
// comment — "a truncated log can never pass as complete" — was falsified by
// the mint path until this gate read the flag; the RUNBOOK's "truncated logs
// are rejected" is true again). The refusal names the observed capture
// accounting: which stream, kept vs total. Runs BEFORE the meaningfulness
// check and before the expected-failure check: a truncated capture cannot
// argue its kept prefix either way.
func checkExecCaptureComplete(execID string, rec validation.Value) error {
	tc := ExecTruncatedCapture(rec)
	if tc == nil {
		return nil
	}
	return fmt.Errorf("exec %s: %s — the output verdict was computed "+
		"over the kept bytes only, and the run's verdict lines could "+
		"sit past the cap (their absence AND their presence are "+
		"unprovable), so a truncated capture is unfit for evidence — "+
		"re-run with output under the cap", execID, tc.Accounting())
}

// minFailureSignatureLen is the specificity floor on expected_failure,
// mirrored by the schema's minLength (8) so the Go gate never depends on the
// schema being the only line. It counts Unicode code points — the same unit
// JSON Schema's minLength uses — so the two checks agree on a non-ASCII
// signature too.
const minFailureSignatureLen = 8

// checkExpectedFailure is admission predicate 2's record half under
// expected_outcome "fail" (the exit half is checkExecExit): the declared
// signature must clear the specificity floor, must occur on a captured
// PER-TEST failure line (sandbox.FailureSignatureOnFailLine — for a
// forge-like command the token [FAIL, never the suite summary, and not the
// whole output blob where a comment or a printed string could satisfy it),
// and the run must classify as class "logic". No signature nameable, no
// mint: there is deliberately no bypass.
func checkExpectedFailure(execID string, rec validation.Value) error {
	sig := sandbox.ExecExpectedFailure(rec)
	if sig == "" {
		return fmt.Errorf("exec %s: expected_outcome is 'fail' but "+
			"expected_failure is missing — the failure signature must be "+
			"declared at exec time, before the run; a record that says "+
			"'fail' without naming the failure proves nothing", execID)
	}
	if err := checkFailureSignatureSpecificity(execID, sig); err != nil {
		return err
	}
	if !sandbox.FailureSignatureOnFailLine(rec, sig) {
		return fmt.Errorf("exec %s: expected_failure %s does not appear on "+
			"any captured per-test failure line — the declared signature "+
			"must be seen on a line carrying the failure marker the run's "+
			"harness prints (for a forge-like command that is the token "+
			"[FAIL, never the suite summary) and must be at least %d "+
			"characters long (declared before the run, checked now)",
			execID, validation.PyReprStr(sig), minFailureSignatureLen)
	}
	return checkFailureClassIsLogic(execID, rec)
}

// checkFailureSignatureSpecificity refuses the degenerate signatures the
// review measured through ValidateExecRecord: a signature shorter than the
// floor (schema minLength 8), and the literal "FAIL" — a tautology every
// failing line satisfies, which is what made the operator's pre-committed
// signature unfalsifiable. The check is on the TRIMMED signature: whitespace
// padding buys no specificity.
func checkFailureSignatureSpecificity(execID, sig string) error {
	trimmed := strings.TrimSpace(sig)
	if utf8.RuneCountInString(trimmed) >= minFailureSignatureLen &&
		!strings.EqualFold(trimmed, "FAIL") {
		return nil
	}
	return fmt.Errorf("exec %s: expected_failure %s is too weak — the "+
		"declared signature must be at least %d characters and may not be "+
		"the literal \"FAIL\"; it must name the failure on a per-test "+
		"failure line (for a forge-like command, a line carrying the token "+
		"[FAIL), because a signature every failing line satisfies names no "+
		"failure at all (declared before the run, checked now)",
		execID, validation.PyReprStr(sig), minFailureSignatureLen)
}

// checkFailureClassIsLogic reuses sandbox.ClassifyFailure — the
// already-existing authority on whether the run was a real test failure —
// and admits only class "logic" ("the harness ran and the hypothesis lost a
// round — this is the only class that argues the finding"). Every other
// class, including the infrastructure causes, is refused even when the
// signature matches: a typo, a missing dependency or a down daemon is
// satisfied by an absent-guard signature just as well as an absent guard.
func checkFailureClassIsLogic(execID string, rec validation.Value) error {
	res := sandbox.ClassifyFailure(rec)
	cls := validation.ObjStr(res, "class")
	if cls == "logic" {
		return nil
	}
	return fmt.Errorf("exec %s: the failure classified as class %s (%s) — "+
		"only class 'logic' may back an expected-failure reproduction; "+
		"infrastructure causes (environment, setup, unknown, none) are "+
		"refused even when the signature matches", execID,
		validation.PyReprStr(cls), validation.ObjStr(res, "note"))
}

// MintedExecEvidenceItem builds the E4/E5 evidence dict mint records for an
// exec, in Python's key order: the id is a fresh EV- id, the metadata comes
// from the exec record, the snapshot pin from the finding. pocTier is the
// v1.6 §2.2 two-tier declaration and lands ONLY when non-empty, so every
// pre-existing (untiered) evidence item keeps its exact bytes.
func MintedExecEvidenceItem(execID, level, etype, description string, rec,
	f validation.Value, pocTier string) validation.Value {
	item := validation.VObj(
		validation.KV{K: "evidence_id", V: validation.VStr(state.NewID("EV", 8))},
		validation.KV{K: "level", V: validation.VStr(level)},
		validation.KV{K: "type", V: validation.VStr(etype)},
		validation.KV{K: "artifact_id", V: validation.VStr(execID)},
		validation.KV{K: "description", V: validation.VStr(description)},
		validation.KV{K: "command", V: validation.VStr(validation.ObjStr(rec, "command"))},
		validation.KV{K: "produced_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "sandbox_profile", V: validation.VStr(
			validation.ObjStr(rec, "profile"))},
		validation.KV{K: "snapshot_id", V: validation.ObjAt(validation.ObjAt(f, "snapshot_ids"),
			"source")},
	)
	if pocTier != "" {
		item.O = validation.SetOrAppend(item.O, "poc_tier",
			validation.VStr(pocTier))
	}
	return item
}

// execFindingMatch is _verify_exec_reference's binding rule: an exec bound to
// this finding — or to no finding at all (a generic run) — may back its
// evidence; an exec bound to ANOTHER finding may not. One rule, both readers
// (add_evidence's E4+ gate and the ingest exec_ref gate).
func execFindingMatch(rec validation.Value, findingID string) bool {
	f := validation.ObjAt(rec, "finding_id")
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
	ref := validation.ObjStr(item, "exec_ref")
	eid := validation.PyStr(validation.ObjAt(item, "evidence_id"))
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
			validation.PyRepr(validation.ObjAt(rec, "finding_id")), findingID, findingID)
	}
	if err := ValidateExecRecord(ref, rec); err != nil {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"exec_ref %s: %s", eid, ref, err)
	}
	// v16 §4.1: the ledger's anchor, checked AFTER ValidateExecRecord — the
	// record's own word must first be admissible (a record that is not
	// admitted needs no tamper verdict), and then the anchor decides
	// whether that word was the one committed to at exec time. It cannot
	// live inside ValidateExecRecord: that signature has no campaign to
	// read the ledger from.
	if err := sandbox.VerifyExecRecordAnchor(c, ref, rec); err != nil {
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
	if dt := validation.ObjStr(item, "type"); dt != "" && dt != etype {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"declares type %s, but exec_ref %s derives %s for this finding "+
			"(the derivation governs — cite it honestly or use `webv2 mint "+
			"--type`)", validation.ObjStr(item, "evidence_id"), validation.PyReprStr(dt),
			ref, validation.PyReprStr(etype))
	}
	if dl := validation.ObjStr(item, "level"); dl != "" && dl != level {
		return validation.VNull(), fmt.Errorf("ingest refused: evidence %s "+
			"declares level %s, but exec_ref %s derives %s for this finding "+
			"(the derivation governs — cite it honestly)",
			validation.ObjStr(item, "evidence_id"), validation.PyReprStr(dl), ref,
			validation.PyReprStr(level))
	}
	// I-3 (critic round 1): a declared poc_tier is refused for the same reason
	// as the type/level lies above — this item LANDS as mint would have minted
	// it, and mint records the tier from --poc-tier, so the payload's word
	// would be dropped without a trace (the silent-drop failure mode the
	// two-tier law exists to remove).
	if err := refuseDeclaredPocTier(item, "this item lands as `mint` would "+
		"have minted exec_ref "+ref+" (untiered)"); err != nil {
		return validation.VNull(), err
	}
	return MintedExecEvidenceItem(ref, level, etype,
		validation.ObjStr(item, "description"), rec, finding, ""), nil
}

// pyReprScalar is Python's repr for the JSON scalars an exec field holds
// (str quoted, everything else via PyRepr) — the exec-gate messages use it.
func pyReprScalar(v validation.Value) string {
	if v.Kind == validation.Str {
		return validation.PyReprStr(v.S)
	}
	return validation.PyRepr(v)
}
