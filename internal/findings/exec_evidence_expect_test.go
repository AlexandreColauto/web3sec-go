package findings

// v16 P1-10a §5.3 route 2 — the expectation-aware exec-record gate.
//
// The two decisions, final: expected_outcome ("pass" | "fail", ABSENT MEANS
// "pass" — every legacy record keeps its exact bytes and behaviour) and
// expected_failure (REQUIRED under "fail", FORBIDDEN otherwise). Under
// "fail" a record is admitted only when ALL THREE hold: non-zero exit,
// expected_failure present on a line that also contains the case-sensitive
// substring FAIL, and sandbox.ClassifyFailure reporting class "logic" —
// the already-existing authority, reused rather than duplicated.
//
// The load-bearing test is BACKWARD COMPAT: a record with no
// expected_outcome must behave exactly as before, byte for byte.

import (
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
		wantErr: "does not appear on any captured line containing the " +
			"substring FAIL"},
	// 4. fail + signature present but NOT on a line containing FAIL
	// => refused (a comment cannot satisfy the check).
	{name: "4 fail + signature on a non-FAIL line -> refused",
		outcome: sandbox.EXPECT_FAIL, sig: declaredSig,
		exit: 1, stdout: wrongLineOut,
		wantErr: "does not appear on any captured line containing the " +
			"substring FAIL"},
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
}

func TestValidateExecRecordExpectation(t *testing.T) {
	for _, c := range execExpectCases {
		t.Run(c.name, func(t *testing.T) {
			camp := ingestCamp(t)
			rec := testExec(t, camp, "docker-networkless", "", c.exit,
				c.stdout)
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
