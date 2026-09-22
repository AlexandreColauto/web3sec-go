// expect.go: the exec record's declared expectation (v16 §5.3 route 2) —
// expected_outcome / expected_failure, the two keys that let an ABSENT-GUARD
// defect back E4+ evidence honestly.
//
// The gate has always encoded an expectation; it hardcoded expected = pass
// (exit 0, green suite). These keys make it explicit ON THE RECORD, declared
// at exec time before the run — a --expect accepted at mint time would let
// the operator write the expectation after seeing the result, which is the
// failure mode the whole design exists to close.
//
// Absent means "pass": every pre-existing record keeps its exact bytes and
// its exact behaviour. "fail" alone cannot mint — it needs expected_failure,
// a signature that must appear on a captured PER-TEST failure line (see
// FailureSignatureOnFailLine) and a run the failure classifier calls class
// 'logic'. No signature nameable, no mint: there is deliberately no "no
// signature available" escape hatch.
package sandbox

import (
	"strings"

	"websec/internal/validation"
)

// The two values expected_outcome may carry (the schema's enum). Absent —
// or anything a hand-edited record invents — reads as EXPECT_PASS, so a
// record can only gain fail's privileges by declaring them.
const (
	EXPECT_PASS = "pass"
	EXPECT_FAIL = "fail"
)

// ExecExpectedOutcome is the record's declared expectation: EXPECT_FAIL only
// when the record says so, everything else (absent, explicit pass, junk)
// as EXPECT_PASS. Fail-closed in both directions: legacy records behave
// exactly as before, and a tampered value never unlocks the fail path.
func ExecExpectedOutcome(rec validation.Value) string {
	if validation.ObjStr(rec, "expected_outcome") == EXPECT_FAIL {
		return EXPECT_FAIL
	}
	return EXPECT_PASS
}

// ExecExpectedFailure is the declared failure signature — "" when the
// record carries none (absence and the empty string are the same claim:
// no signature, which admits nothing under EXPECT_FAIL).
func ExecExpectedFailure(rec validation.Value) string {
	return validation.ObjStr(rec, "expected_failure")
}

// applyExecExpectation stamps the operator's PRE-RUN declaration into the
// record the first write already carries (runWriteInitialRecord), so the
// expectation is on disk before the payload executes. Empty values write
// nothing: absent keys keep the legacy shape byte-for-byte.
func applyExecExpectation(rec validation.Value, opts RunOpts) validation.Value {
	if opts.Expect != "" {
		rec = setKey(rec, "expected_outcome", validation.VStr(opts.Expect))
	}
	if opts.ExpectFailure != "" {
		rec = setKey(rec, "expected_failure", validation.VStr(opts.ExpectFailure))
	}
	return rec
}

// forgeFailToken is the PER-TEST failure marker a forge-like command prints:
// a bracket, then FAIL. Only the token is pinned — forge renders
// `[FAIL: ...]` and `[FAIL. Reason: ...]` across versions, and pinning the
// separator that follows is exactly the brittleness this rule avoids.
const forgeFailToken = "[FAIL"

// FailureSignatureOnFailLine is the expected-failure admission predicate's
// line half: some single captured line carries BOTH the declared signature
// and a failure marker that a REAL per-test failure produces.
//
// D1 (adversarial review): the marker is NOT "any line containing FAIL".
// Forge's SUITE SUMMARY line — `Suite result: FAILED. 0 passed; 5 failed;
// ...` — contains FAIL, so a signature like "Suite result" satisfied the old
// check on a suite that named no failing test, and the operator's
// pre-committed signature stopped being falsifiable. For a FORGE-LIKE
// command the line must carry forge's per-test token ([FAIL), which the
// summary line never does. A NON-forge-like command keeps the plain FAIL
// substring: no better marker exists for an arbitrary harness.
//
// The classifier decision (class 'logic') is NOT made here — it lives in
// ClassifyFailure, the single authority on whether a run was a real test
// failure, and the caller applies it after this check.
func FailureSignatureOnFailLine(rec validation.Value, sig string) bool {
	marker := "FAIL"
	if commandIsForgeLike(rec) {
		marker = forgeFailToken
	}
	for _, line := range strings.Split(ExecOutput(rec), "\n") {
		if strings.Contains(line, marker) && strings.Contains(line, sig) {
			return true
		}
	}
	return false
}
