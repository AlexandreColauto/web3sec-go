package findings

// v16 P1-10a §5.3 route 2 — the expectation-aware exec-record gate.
//
// The two decisions, final: expected_outcome ("pass" | "fail", ABSENT MEANS
// "pass" — every legacy record keeps its exact bytes and behaviour) and
// expected_failure (REQUIRED under "fail", FORBIDDEN otherwise). Under
// "fail" a record is admitted only when ALL THREE hold: non-zero exit,
// expected_failure present on a captured PER-TEST failure line — the token
// [FAIL for a forge-like command, the plain substring FAIL for an arbitrary
// harness — after clearing the specificity floor (>= 8 characters, not the
// literal "FAIL"), and sandbox.ClassifyFailure reporting class "logic" — the
// already-existing authority, reused rather than duplicated.
//
// The load-bearing test is BACKWARD COMPAT: a record with no
// expected_outcome must behave exactly as before, byte for byte.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// The three fixture outputs. Each is checked against the REAL classifier
// below, so a classifier or regex drift fails loudly instead of silently
// weakening the admission tests.
const (
	// logicOut is the absent-guard shape: a forge suite failing BECAUSE
	// the guard never fired — counters present, [FAIL] lines, and the
	// declared signature sitting on a FAIL line.
	logicOut = "[FAIL] testFakeMarket() MarketNotListed was not raised — " +
		"expected revert (block: 99811375)\n" +
		"Suite result: FAILED. 0 passed; 5 failed; 0 skipped; 0 pending\n" +
		"Ran 5 tests for test/DebtManager.t.sol:DebtManagerTest\n"
	// infraOut is the shape that must NEVER mint under "fail": the
	// signature matches on a FAIL line, but the run died on infrastructure.
	infraOut = "[FAIL] testFakeMarket() MarketNotListed was not raised " +
		"(block: 99811375)\n" +
		"no such image: ghcr.io/foundry-rs/foundry:latest\n" +
		"Suite result: FAILED. 0 passed; 1 failed\n" +
		"Ran 1 test for test/DebtManager.t.sol\n"
	// wrongLineOut carries the signature only on a comment line that does
	// NOT contain FAIL — a comment or printed string must not satisfy the
	// check.
	wrongLineOut = "[FAIL] testFakeMarket() expected revert did not happen " +
		"(block: 99811375)\n" +
		"// guard MarketNotListed should have refused the call\n" +
		"Suite result: FAILED. 0 passed; 1 failed\n" +
		"Ran 1 test for test/DebtManager.t.sol\n"
	// greenOut is today's passing suite.
	greenOut = "Ran 1 test in 3ms (test suite successful)\n" +
		"Suite result: ok. 1 passed; 0 failed; 0 skipped; 0 pending\n"
	// summaryOnlyOut is D1's measured-defect fixture: forge's SUITE SUMMARY
	// block naming NO per-test failure, yet carrying FAIL substrings (the
	// summary's FAILED, and a bare FAIL: counter line). The pre-fix gate
	// admitted "FAIL", "a", "test" and "Suite result" against it — the
	// whole point of the specificity floor and the per-test marker.
	summaryOnlyOut = "MarketNotListed was not raised — expected revert " +
		"(block: 99811375)\n" +
		"Suite result: FAILED. 0 passed; 5 failed; 0 skipped; 0 pending\n" +
		"Ran 5 tests for test/DebtManager.t.sol:DebtManagerTest\n" +
		"FAIL: 5 tests failed\n"
	// plainFailOut is an ARBITRARY (non-forge) harness: no [FAIL token
	// exists there, so the plain FAIL substring stays the marker.
	plainFailOut = "FAIL SomeHarnessFailure: expected revert did not occur\n"
	// the declared signature the fixtures carry.
	declaredSig = "MarketNotListed"
)

// stampExpect rewrites the on-disk exec record with the expectation keys a
// `webv2 exec --expect ...` registration carries, and returns the updated
// record (the caller must use the RETURNED value — appending keys can move
// the backing array).
func stampExpect(t *testing.T, c *state.Campaign, rec validation.Value,
	kvs ...validation.KV) validation.Value {
	t.Helper()
	rec.O = append(rec.O, kvs...)
	p := filepath.Join(c.ExecsDir, validation.ObjStr(rec, "exec_id"),
		"exec_record.json")
	if err := validation.WriteJson(p, rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// TestFailureFixturesClassifyAsDesigned pins the CLASSIFIER's answer for the
// fixtures (the admission rule leans on it — if this fails, the gate is not
// testing what it claims).
func TestFailureFixturesClassifyAsDesigned(t *testing.T) {
	c := ingestCamp(t)
	logic := testExec(t, c, "docker-networkless", "", 1, logicOut)
	if got := validation.ObjStr(sandbox.ClassifyFailure(logic),
		"class"); got != "logic" {
		t.Fatalf("logic fixture classifies as %q, want \"logic\" — the "+
			"harness ran and the hypothesis lost a round", got)
	}
	infra := testExec(t, c, "docker-networkless", "", 1, infraOut)
	if got := validation.ObjStr(sandbox.ClassifyFailure(infra),
		"class"); got != "environment" {
		t.Fatalf("infrastructure fixture classifies as %q, want "+
			"\"environment\" — the refusal case must be infrastructure",
			got)
	}
}

// TestValidateExecRecordExpectation is the table for design tests 1–7 plus
// the missing-signature and unreadable-outcome shapes: every branch of the
// admission predicate, one record each.
// execExpectCase is one row of TestValidateExecRecordExpectation's table
// (hoisted with the table so the test body stays under the funlen cap).
type execExpectCase struct {
	name     string
	outcome  string // "" = key absent
	sig      string
	stampSig bool // stamp expected_failure even when "" (illegal shape)
	exit     int64
	stdout   string
	command  string // "" = testExec's forge command
	wantErr  string // "" = ADMITTED; byte-exact when exact
	exact    bool
}

// execExpectCases is the admission table: one row per predicate branch.
var execExpectCases = []execExpectCase{
	// 1. BACKWARD COMPAT (load-bearing): absent expectation behaves
	// exactly as before, refusal text BYTE-FOR-BYTE the existing one.
	{name: "1a absent + exit 0 + green -> admitted",
		exit: 0, stdout: greenOut},
	{name: "1b absent + exit 1 -> refused byte-for-byte",
		exit: 1, stdout: logicOut,
		wantErr: "exited with status 1; a run that did not succeed is " +
			"not a reproduction — fix the PoC and re-run before " +
			"minting evidence",
		exact: true},
	// 9. explicit "pass" is the absent case's twin (same bytes).
	{name: "9 explicit pass + exit 1 -> the same refusal",
		outcome: sandbox.EXPECT_PASS, exit: 1, stdout: logicOut,
		wantErr: "exited with status 1; a run that did not succeed is " +
			"not a reproduction — fix the PoC and re-run before " +
			"minting evidence",
		exact: true},
	// 2. fail + signature on a FAIL line + non-zero exit + class
	// logic => ADMITTED (the case the change exists for).
	{name: "2 fail + sig on FAIL line + exit 1 + logic -> admitted",
		outcome: sandbox.EXPECT_FAIL, sig: declaredSig,
		exit: 1, stdout: logicOut},
	// 3. fail + signature absent from the output => refused.
	{name: "3 fail + signature absent -> refused",
		outcome: sandbox.EXPECT_FAIL, sig: "TotallyDifferentGuard",
		exit: 1, stdout: logicOut,
		wantErr: "does not appear on any captured per-test failure line"},
	// 4. fail + signature present but NOT on a line containing FAIL
	// => refused (a comment cannot satisfy the check).
	{name: "4 fail + signature on a non-FAIL line -> refused",
		outcome: sandbox.EXPECT_FAIL, sig: declaredSig,
		exit: 1, stdout: wrongLineOut,
		wantErr: "does not appear on any captured per-test failure line"},
	// 5. fail + infrastructure class => refused even when the
	// signature matches.
	{name: "5 fail + class environment -> refused",
		outcome: sandbox.EXPECT_FAIL, sig: declaredSig,
		exit: 1, stdout: infraOut,
		wantErr: "classified as class 'environment'"},
	// 6. pass + expected_failure => contradiction, rejected (not
	// ignored), and the ABSENT case with a signature is equally a
	// contradiction (absent means pass).
	{name: "6 pass + expected_failure -> contradiction",
		outcome: sandbox.EXPECT_PASS, sig: declaredSig,
		exit: 0, stdout: greenOut,
		wantErr: "contradiction"},
	{name: "6b absent outcome + expected_failure -> contradiction",
		sig: declaredSig, exit: 0, stdout: greenOut,
		wantErr: "contradiction"},
	// 7. fail + exit_status 0 => refused.
	{name: "7 fail + exit 0 -> refused",
		outcome: sandbox.EXPECT_FAIL, sig: declaredSig,
		exit: 0, stdout: logicOut,
		wantErr: "expected_outcome is 'fail' but exit_status is 0"},
	// 8. fail without a declared signature => refused (no
	// signature-less bypass, by design).
	{name: "8 fail + missing expected_failure -> refused",
		outcome: sandbox.EXPECT_FAIL, exit: 1, stdout: logicOut,
		wantErr: "expected_failure is missing"},
	// 9b. an unreadable outcome admits nothing.
	{name: "9b junk outcome -> refused",
		outcome: "banana", exit: 0, stdout: greenOut,
		wantErr: "is not one of 'pass' | 'fail'"},
	// D1 (adversarial review): the degenerate signatures the review
	// MEASURED as admitted against summaryOnlyOut — a suite that names no
	// per-test failure. All must now be refused. Row 2 above is the
	// companion row proving a genuine per-test signature is still
	// admitted.
	{name: "D1a signature \"FAIL\" -> refused (tautology)",
		outcome: sandbox.EXPECT_FAIL, sig: "FAIL",
		exit: 1, stdout: summaryOnlyOut,
		wantErr: "may not be the literal \"FAIL\""},
	{name: "D1b signature \"a\" -> refused (below the floor)",
		outcome: sandbox.EXPECT_FAIL, sig: "a",
		exit: 1, stdout: summaryOnlyOut,
		wantErr: "must be at least 8 characters"},
	{name: "D1c signature \"test\" -> refused (below the floor)",
		outcome: sandbox.EXPECT_FAIL, sig: "test",
		exit: 1, stdout: summaryOnlyOut,
		wantErr: "must be at least 8 characters"},
	{name: "D1d signature \"Suite result\" -> refused (summary line)",
		outcome: sandbox.EXPECT_FAIL, sig: "Suite result",
		exit: 1, stdout: summaryOnlyOut,
		wantErr: "does not appear on any captured per-test failure line"},
	{name: "D1e signature \"fail\" -> refused (EqualFold)",
		outcome: sandbox.EXPECT_FAIL, sig: "fail",
		exit: 1, stdout: summaryOnlyOut,
		wantErr: "may not be the literal \"FAIL\""},
	{name: "D1f whitespace-padded \"  FAIL  \" -> refused (trimmed)",
		outcome: sandbox.EXPECT_FAIL, sig: "  FAIL  ",
		exit: 1, stdout: summaryOnlyOut,
		wantErr: "may not be the literal \"FAIL\""},
	// D1 (non-forge): an arbitrary harness has no [FAIL token, so the
	// plain FAIL substring stays its marker — a signature on such a line
	// is still admitted.
	{name: "D1g non-forge command + sig on a plain FAIL line -> admitted",
		outcome: sandbox.EXPECT_FAIL, sig: "SomeHarnessFailure",
		command: "python harness.py", exit: 1, stdout: plainFailOut},
}

func TestValidateExecRecordExpectation(t *testing.T) {
	for _, c := range execExpectCases {
		t.Run(c.name, func(t *testing.T) {
			camp := ingestCamp(t)
			rec := testExec(t, camp, "docker-networkless", "", c.exit,
				c.stdout)
			if c.command != "" {
				rec.O = validation.SetOrAppend(rec.O, "command",
					validation.VStr(c.command))
			}
			if c.outcome != "" || c.sig != "" || c.stampSig {
				rec = stampExpect(t, camp, rec,
					validation.KV{K: "expected_outcome",
						V: validation.VStr(c.outcome)},
					validation.KV{K: "expected_failure",
						V: validation.VStr(c.sig)})
			}
			id := validation.ObjStr(rec, "exec_id")
			assertAdmission(t, c.wantErr, c.exact, id,
				ValidateExecRecord(id, rec))
		})
	}
}

// assertAdmission is one table row's verdict: "" = ADMITTED, exact =
// byte-for-byte equality, otherwise a contains check.
func assertAdmission(t *testing.T, wantErr string, exact bool, id string,
	err error) {
	t.Helper()
	switch {
	case wantErr == "" && err != nil:
		t.Fatalf("record must be ADMITTED under the declared "+
			"expectation; got: %v", err)
	case wantErr != "" && err == nil:
		t.Fatalf("record must be refused (want %q); got nil", wantErr)
	case wantErr != "" && exact:
		want := "exec " + id + " " + wantErr
		if err.Error() != want {
			t.Fatalf("refusal drifted byte-for-byte:\n got %q\nwant %q",
				err.Error(), want)
		}
	case wantErr != "" && !strings.Contains(err.Error(), wantErr):
		t.Fatalf("refusal %q does not contain %q", err.Error(), wantErr)
	}
}

// TestVerifyExecReferenceExpectation pins the THIRD pass-only gate: the
// E4+ add_evidence path re-checks exit/output itself, so without this branch
// an admitted expected-failure record would still die on "must cite a run
// that succeeded" and the whole change would have no end-to-end path. Under
// "fail" it defers to ValidateExecRecord (one rule, one opinion); under
// "pass" today's message stays byte-for-byte.
func TestVerifyExecReferenceExpectation(t *testing.T) {
	c := ingestCamp(t)
	const fid = "F-000000000001"

	// admitted: fail record satisfies the full rule through the E4+ gate
	rec := testExec(t, c, "docker-networkless", "", 1, logicOut)
	rec = stampExpect(t, c, rec,
		validation.KV{K: "expected_outcome", V: validation.VStr("fail")},
		validation.KV{K: "expected_failure", V: validation.VStr(declaredSig)})
	item := execEvidenceItem(rec, "E4", "unit-test", "absent guard", "EV-1")
	if err := verifyExecReference(c, item, "docker-networkless", fid); err != nil {
		t.Fatalf("the admitted expected-failure record must pass the E4+ "+
			"gate end to end; got: %v", err)
	}

	// backward compat: a legacy record with exit 1 keeps today's message,
	// byte for byte
	legacy := testExec(t, c, "docker-networkless", "", 1, logicOut)
	legacyItem := execEvidenceItem(legacy, "E4", "unit-test", "neg", "EV-2")
	err := verifyExecReference(c, legacyItem, "docker-networkless", fid)
	if err == nil {
		t.Fatal("a legacy non-zero-exit record must still be refused")
	}
	want := "exec " + validation.ObjStr(legacy, "exec_id") +
		" exited with status 1; E4+ evidence must cite a run that succeeded"
	if err.Error() != want {
		t.Fatalf("refusal drifted byte-for-byte:\n got %q\nwant %q",
			err.Error(), want)
	}

}

// TestVerifyExecReferenceUnsignedRefused: the shape the schema can never
// write (a bare "fail") is defended at read time on the E4+ path too.
func TestVerifyExecReferenceUnsignedRefused(t *testing.T) {
	c := ingestCamp(t)
	const fid = "F-000000000001"
	unsigned := testExec(t, c, "docker-networkless", "", 1, logicOut)
	unsigned = stampExpect(t, c, unsigned,
		validation.KV{K: "expected_outcome", V: validation.VStr("fail")})
	uItem := execEvidenceItem(unsigned, "E4", "unit-test", "neg", "EV-3")
	err := verifyExecReference(c, uItem, "docker-networkless", fid)
	if err == nil || !strings.Contains(err.Error(),
		"expected_failure is missing") {
		t.Fatalf("unsigned fail record must be refused with the missing "+
			"signature refusal; got: %v", err)
	}
}

// The two D1 refusal texts, verbatim (error text is a pinned surface; the
// single %s is the declared signature's Python repr).
const (
	wantWeakSignatureRefusal = "expected_failure %s is too weak — the " +
		"declared signature must be at least 8 characters and may not be " +
		"the literal \"FAIL\"; it must name the failure on a per-test " +
		"failure line (for a forge-like command, a line carrying the token " +
		"[FAIL), because a signature every failing line satisfies names no " +
		"failure at all (declared before the run, checked now)"
	wantNoPerTestRefusal = "expected_failure %s does not appear on any " +
		"captured per-test failure line — the declared signature must be " +
		"seen on a line carrying the failure marker the run's harness " +
		"prints (for a forge-like command that is the token [FAIL, never " +
		"the suite summary) and must be at least 8 characters long " +
		"(declared before the run, checked now)"
)

// TestExpectedFailureRefusalsPinnedVerbatim pins the two new D1 refusals
// byte-for-byte, so a reworded message is a loud failure rather than a
// silent contract drift.
func TestExpectedFailureRefusalsPinnedVerbatim(t *testing.T) {
	cases := []struct {
		name, sig, want string
	}{
		{"specificity floor", "FAIL", wantWeakSignatureRefusal},
		{"no per-test failure line", "Suite result", wantNoPerTestRefusal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			camp := ingestCamp(t)
			rec := testExec(t, camp, "docker-networkless", "", 1,
				summaryOnlyOut)
			rec = stampExpect(t, camp, rec,
				validation.KV{K: "expected_outcome",
					V: validation.VStr(sandbox.EXPECT_FAIL)},
				validation.KV{K: "expected_failure",
					V: validation.VStr(c.sig)})
			id := validation.ObjStr(rec, "exec_id")
			err := ValidateExecRecord(id, rec)
			if err == nil {
				t.Fatal("a degenerate signature must be refused")
			}
			want := "exec " + id + ": " +
				fmt.Sprintf(c.want, validation.PyReprStr(c.sig))
			if err.Error() != want {
				t.Fatalf("refusal drifted byte-for-byte:\n got %q\nwant %q",
					err.Error(), want)
			}
		})
	}
}
