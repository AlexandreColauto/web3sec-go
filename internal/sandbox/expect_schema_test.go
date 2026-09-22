package sandbox

// v16 P1-10a §5.3: the sandbox_execution schema carries the two expectation
// keys — enum-typed, conditionally required/forbidden. The write path
// validates the schema on every record write (validation.WriteJson with the
// schema name), so THESE assertions ARE the write-path enforcement: no
// record can be registered carrying the contradiction or a bare "fail".

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// schemaExecRecord is a minimal record satisfying every required key of
// sandbox_execution (exec_id, campaign_id, profile, command, policy_verdict,
// started_at) plus the keys under test.
func schemaExecRecord(kvs ...validation.KV) validation.Value {
	base := []validation.KV{
		kv("exec_id", validation.VStr("EXEC-abc123")),
		kv("campaign_id", validation.VStr("C-0000000001")),
		kv("profile", validation.VStr("fork-runner")),
		kv("command", validation.VStr("forge test --match-test testFakeMarket")),
		kv("policy_verdict", validation.VObj(
			kv("allowed", validation.VBool(true)))),
		kv("started_at", validation.VStr("2026-09-22T00:00:00+00:00")),
	}
	return validation.VObj(append(base, kvs...)...)
}

func expectKV(outcome, sig string) []validation.KV {
	kvs := []validation.KV{}
	if outcome != "" {
		kvs = append(kvs, kv("expected_outcome", validation.VStr(outcome)))
	}
	if sig != "" {
		kvs = append(kvs, kv("expected_failure", validation.VStr(sig)))
	}
	return kvs
}

// TestExecSchemaExpectationKeys is design test 8: a record carrying both
// keys validates; a bad enum value fails; expected_failure under pass fails
// (and so does the absent-outcome form — absent means pass); "fail" without
// a signature fails; an empty signature fails.
// execSchemaCases is TestExecSchemaExpectationKeys' table (hoisted to
// package level so the test body stays under the funlen cap).
var execSchemaCases = []struct {
	name    string
	outcome string
	sig     string
	raw     validation.KV // hostile/hand-built shapes bypass expectKV
	wantErr string        // "" = must VALIDATE
}{
	{"both keys (fail + signature) validate",
		"fail", "MarketNotListed", validation.KV{}, ""},
	{"legacy record with no new keys validates",
		"", "", validation.KV{}, ""},
	{"explicit pass with no signature validates",
		"pass", "", validation.KV{}, ""},
	{"bad enum value fails",
		"banana", "", validation.KV{},
		"not one of"},
	{"expected_failure under pass fails",
		"pass", "MarketNotListed", validation.KV{},
		"'pass' is not one of ['fail']"},
	{"expected_failure with NO outcome fails (absent means pass)",
		"", "", validation.KV{K: "expected_failure",
			V: validation.VStr("MarketNotListed")},
		"expected_outcome"},
	{"fail without expected_failure fails (required)",
		"fail", "", validation.KV{},
		"expected_failure"},
	{"empty expected_failure fails (minLength)",
		"", "", validation.KV{K: "expected_outcome",
			V: validation.VStr("fail")},
		"expected_failure"},
	{"empty expected_failure under fail fails",
		"fail", "", validation.KV{K: "expected_failure",
			V: validation.VStr("")},
		"is too short"},
	// D1: the specificity floor is a SCHEMA law too (minLength 8), so a
	// degenerate signature cannot even be written — the Go gate's floor is
	// defense in depth for hand-edited ledger rows.
	{"8-character signature validates (floor is inclusive)",
		"fail", "abcdefgh", validation.KV{}, ""},
	{"4-character signature fails (minLength 8)",
		"fail", "FAIL", validation.KV{}, "is too short"},
}

func TestExecSchemaExpectationKeys(t *testing.T) {
	for _, c := range execSchemaCases {
		t.Run(c.name, func(t *testing.T) {
			runSchemaCase(t, c)
		})
	}
}

// runSchemaCase is the per-case body (extracted so the table-driven test
// stays under the house cognitive-complexity cap).
func runSchemaCase(t *testing.T, c struct {
	name, outcome, sig string
	raw                validation.KV
	wantErr            string
}) {
	t.Helper()
	kvs := expectKV(c.outcome, c.sig)
	if c.raw.K != "" {
		kvs = append(kvs, c.raw)
	}
	err := validation.Validate(schemaExecRecord(kvs...),
		"sandbox_execution", 5)
	assertSchemaVerdict(t, err, c.wantErr)
}

// assertSchemaVerdict is "" = must validate; otherwise err must carry the
// fragment.
func assertSchemaVerdict(t *testing.T, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Fatalf("record must validate; got: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("record must FAIL validation (want %q); got nil", wantErr)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("validation error %q does not contain %q",
			err.Error(), wantErr)
	}
}
