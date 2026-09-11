// g10_test.go: Task 3 (G10) — sig_verify_no_separator and
// merkle_verify_without_depth_gate. Fixture files under testdata/ are
// canonical; the inline copies in archetypes_test.go's trees map keep the
// discrimination matrix self-contained.
package archetypes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// fixtureTree indexes one testdata fixture as a one-file src tree.
func fixtureTree(t *testing.T, dir, file string) validation.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", dir, file))
	if err != nil {
		t.Fatal(err)
	}
	idx, _ := makeTree(t, string(raw))
	return idx
}

// evalSingleCheck loads the archetype and evaluates its (single) check.
func evalSingleCheck(t *testing.T, aid string, idx validation.Value) (string, string) {
	t.Helper()
	arch, err := LoadArchetypeByName(aid)
	if err != nil {
		t.Fatal(err)
	}
	checks := listAt(arch, "checks")
	if len(checks) != 1 {
		t.Fatalf("%s has %d checks, want 1", aid, len(checks))
	}
	res, detail, err := EvaluatePrecondition(checks[0], idx)
	if err != nil {
		t.Fatal(err)
	}
	return res, detail
}

func TestSigVerifyNoSeparatorBuggyHits(t *testing.T) {
	idx := fixtureTree(t, "sigverify", "buggy.sol")
	res, detail := evalSingleCheck(t, "signature-no-separator", idx)
	if res != "present" {
		t.Fatalf("buggy sigverify: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "verify") {
		t.Fatalf("finding detail %q does not name the function", detail)
	}
}

func TestSigVerifyNoSeparatorCleanMisses(t *testing.T) {
	idx := fixtureTree(t, "sigverify", "clean.sol")
	res, detail := evalSingleCheck(t, "signature-no-separator", idx)
	if res != "absent" {
		t.Fatalf("clean sigverify: result = %q (%s), want absent", res, detail)
	}
}

// TestSigVerifyUintChainIdCheckedMisses is the T3 precision fix: a plain
// uint256 chainId param leaves no marker in the selector (paramTypes is
// types-only, parser.go:446), but the param-uses entry carries
// ConceptKeys("chainId") = ["chain","chain:id","id"] — the "chain:id" bigram
// is separator evidence once colons are stripped. A require against
// block.chainid must therefore MISS.
func TestSigVerifyUintChainIdCheckedMisses(t *testing.T) {
	idx := fixtureTree(t, "sigverify", "chainid_checked.sol")
	res, detail := evalSingleCheck(t, "signature-no-separator", idx)
	if res != "absent" {
		t.Fatalf("chainid-checked sigverify: result = %q (%s), want absent", res, detail)
	}
}

// TestSigVerifyUintChainIdUnusedHits guards the evidence semantics: a
// chainId param that the body never references emits no kind=="param"
// uses-entry (parser.go:847-851), so there is no separator evidence and the
// hit stands.
func TestSigVerifyUintChainIdUnusedHits(t *testing.T) {
	idx := fixtureTree(t, "sigverify", "chainid_unused.sol")
	res, detail := evalSingleCheck(t, "signature-no-separator", idx)
	if res != "present" {
		t.Fatalf("chainid-unused sigverify: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "verify") {
		t.Fatalf("finding detail %q does not name the function", detail)
	}
}

func TestMerkleVerifyWithoutDepthGateBuggyHits(t *testing.T) {
	idx := fixtureTree(t, "merkleproof", "buggy.sol")
	res, detail := evalSingleCheck(t, "proof-accepted-without-depth-gate", idx)
	if res != "present" {
		t.Fatalf("buggy merkleproof: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "verifyProof") {
		t.Fatalf("finding detail %q does not name the function", detail)
	}
}

func TestMerkleVerifyWithoutDepthGateCleanMisses(t *testing.T) {
	idx := fixtureTree(t, "merkleproof", "clean.sol")
	res, detail := evalSingleCheck(t, "proof-accepted-without-depth-gate", idx)
	if res != "absent" {
		t.Fatalf("clean merkleproof: result = %q (%s), want absent", res, detail)
	}
}

func TestArchetypeSchemaRejectsUnknownCheckType(t *testing.T) {
	bad := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("bad-arch")},
		validation.KV{K: "name", V: validation.VStr("Bad")},
		validation.KV{K: "criticality", V: validation.VStr("high")},
		validation.KV{K: "checks", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "type", V: validation.VStr("not_a_real_check")},
			),
		)},
	)
	if err := validation.Validate(bad, "archetype", 1); err == nil {
		t.Fatal("schema accepted a check object with an unknown type string")
	}
}

func TestAvailableArchetypesIncludesG10IDs(t *testing.T) {
	got, err := AvailableArchetypes()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"signature-no-separator", "proof-accepted-without-depth-gate"} {
		if !containsStr(got, want) {
			t.Fatalf("AvailableArchetypes() = %v, missing %s", got, want)
		}
	}
}
