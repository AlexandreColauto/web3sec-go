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
// a signature that must appear on a captured line also containing the
// case-sensitive substring FAIL, and a run the failure classifier calls
// class 'logic'. No signature nameable, no mint: there is deliberately no
// "no signature available" escape hatch.
package sandbox

import "websec/internal/validation"

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
