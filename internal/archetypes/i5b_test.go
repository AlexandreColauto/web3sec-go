// i5b_test.go: Wave I Task 4 (I5b) — merkle_proof_no_length_check and
// verifier_default_on. Fixture files under testdata/ are canonical; the inline
// trees below pin the evidence semantics the two evaluators are allowed to
// read (selector shape, guard text, writes_storage writer shape, authz gates).
//
// HONESTY: the structural index carries NO state-variable values and NO
// initializers (parser.go:1059-1061 — a state-variable node is
// {id,kind,name,path,line}; pyState drops the initializer at parser.go:87), and
// it carries NO parameter NAMES on a function node — a function's evidence is
// its selector (name + TYPE list only, parser.go:1139). So:
//
//   - merkle_proof_no_length_check claims "this names-matched function's
//     selector carries an array/bytes-shaped type and none of its own guard
//     conditions mention `length`". It does NOT claim the path check is wrong;
//     a length check delegated to a callee or spelled in a modifier body is
//     invisible (modifier bodies are appended to reads/writes but not to
//     `guards`, parser.go:1121-1132).
//   - verifier_default_on claims "this trust-marked state flag is written by a
//     construct|init|setup-shaped function that carries no authorization
//     modifier". It does NOT claim the flag is written TRUE: writes_storage
//     records the write, never the literal.
//
// Both are HINT-only shape claims, exactly like every other check here.
package archetypes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestMerkleProofNoLengthCheckBuggyHits(t *testing.T) {
	idx := fixtureTree(t, "merklepath", "buggy.sol")
	res, detail := evalSingleCheck(t, "merkle-proof-no-length-check", idx)
	if res != "present" {
		t.Fatalf("buggy merklepath: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "verifyProof") {
		t.Fatalf("finding detail %q does not name the function", detail)
	}
}

func TestMerkleProofNoLengthCheckCleanMisses(t *testing.T) {
	idx := fixtureTree(t, "merklepath", "clean.sol")
	res, detail := evalSingleCheck(t, "merkle-proof-no-length-check", idx)
	if res != "absent" {
		t.Fatalf("clean merklepath: result = %q (%s), want absent", res, detail)
	}
}

// TestMerkleProofNoLengthCheckLengthGuardMisses: the guard text is the whole
// evidence — any guard on the path mentioning `length` suppresses the hit,
// whatever variable it is spelled on.
func TestMerkleProofNoLengthCheckLengthGuardMisses(t *testing.T) {
	idx, _ := makeTree(t, `
contract Withdrawal {
    mapping(bytes32 => bool) public processed;
    function proveWithdrawal(bytes32[] memory proof, bytes32 root) external {
        require(proof.length == 32, "bad path length");
        processed[root] = true;
    }
}
`)
	res, detail := evalSingleCheck(t, "merkle-proof-no-length-check", idx)
	if res != "absent" {
		t.Fatalf("length guard missed: %q (%s)", res, detail)
	}
}

// TestMerkleProofNoLengthCheckRequiresPathParam: the names list is not enough
// on its own — the selector must carry an array/bytes-shaped type. A scalar
// `uint256` path argument is not a merkle path.
func TestMerkleProofNoLengthCheckRequiresPathParam(t *testing.T) {
	idx, _ := makeTree(t, `
contract Scalar {
    function verifyProof(uint256 x, uint256 root) external {
        require(x == root, "bad proof");
    }
}
`)
	res, detail := evalSingleCheck(t, "merkle-proof-no-length-check", idx)
	if res != "absent" {
		t.Fatalf("scalar parameter matched: %q (%s)", res, detail)
	}
}

// TestMerkleProofNoLengthCheckMissingNamesFailsLoud: the discriminator is
// required exactly as it is for the other name-driven checks.
func TestMerkleProofNoLengthCheckMissingNamesFailsLoud(t *testing.T) {
	idx, _ := makeTree(t, "contract P { function verifyProof(bytes32[] memory proof) external {} }")
	check := validation.VObj(
		validation.KV{K: "type", V: validation.VStr("merkle_proof_no_length_check")})
	if _, _, err := EvaluatePrecondition(check, idx); err == nil {
		t.Fatal("a check with no 'names' must fail loud")
	} else if !strings.Contains(err.Error(), "merkle_proof_no_length_check") {
		t.Fatalf("error %q does not name the check type", err)
	}
}

func TestVerifierDefaultOnBuggyHits(t *testing.T) {
	idx := fixtureTree(t, "verifier", "buggy.sol")
	res, detail := evalSingleCheck(t, "verifier-default-on", idx)
	if res != "present" {
		t.Fatalf("buggy verifier: result = %q (%s), want present", res, detail)
	}
	if !strings.Contains(detail, "verified") {
		t.Fatalf("finding detail %q does not name the state flag", detail)
	}
}

func TestVerifierDefaultOnCleanMisses(t *testing.T) {
	idx := fixtureTree(t, "verifier", "clean.sol")
	res, detail := evalSingleCheck(t, "verifier-default-on", idx)
	if res != "absent" {
		t.Fatalf("clean verifier: result = %q (%s), want absent", res, detail)
	}
}

// TestVerifierDefaultOnRequiresInitShapedWriter: a flag written by an ordinary
// admin function is not a default-on trust root — the WRITER shape is the
// evidence, and "configure" is neither construct- nor init- nor setup-shaped.
func TestVerifierDefaultOnRequiresInitShapedWriter(t *testing.T) {
	idx, _ := makeTree(t, `
contract Registry {
    bool public approved;
    function configure() external { approved = true; }
}
`)
	res, detail := evalSingleCheck(t, "verifier-default-on", idx)
	if res != "absent" {
		t.Fatalf("non-initializer writer matched: %q (%s)", res, detail)
	}
}

// TestVerifierDefaultOnGuardedInitWriterMisses: the authz guard on the writer
// is the second half of the evidence. An `onlyOwner initialize()` is a
// deliberate trust-root setup, not a default-on one.
func TestVerifierDefaultOnGuardedInitWriterMisses(t *testing.T) {
	idx, _ := makeTree(t, `
contract Registry {
    bool public whitelisted;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function initialize() external onlyOwner { whitelisted = true; }
}
`)
	res, detail := evalSingleCheck(t, "verifier-default-on", idx)
	if res != "absent" {
		t.Fatalf("guarded initializer matched: %q (%s)", res, detail)
	}
}

// TestVerifierDefaultOnIsValueBlind is the value-blindness pin: a constructor
// that writes `isValid = false` matches identically to one that writes `true`,
// because the index records the write and never the literal. The check claims
// a SHAPE (a default-on-shaped writer), never a value.
func TestVerifierDefaultOnIsValueBlind(t *testing.T) {
	idx, _ := makeTree(t, `
contract Registry {
    bool public isValid;
    constructor() { isValid = false; }
}
`)
	res, detail := evalSingleCheck(t, "verifier-default-on", idx)
	if res != "present" {
		t.Fatalf("result = %q (%s), want present (shape claim only)", res, detail)
	}
	if strings.Contains(detail, "false") {
		t.Fatalf("detail %q leaked a value — the index has none", detail)
	}
}

// TestVerifierDefaultOnMissingNamesFailsLoud mirrors the other name-driven
// checks.
func TestVerifierDefaultOnMissingNamesFailsLoud(t *testing.T) {
	idx, _ := makeTree(t, "contract V { bool public verified; }")
	check := validation.VObj(
		validation.KV{K: "type", V: validation.VStr("verifier_default_on")})
	if _, _, err := EvaluatePrecondition(check, idx); err == nil {
		t.Fatal("a check with no 'names' must fail loud")
	} else if !strings.Contains(err.Error(), "verifier_default_on") {
		t.Fatalf("error %q does not name the check type", err)
	}
}

// TestI5bSchemaRejectsUnusedKey: the two new oneOf variants carry exactly the
// discriminator keys their evaluators consume — a key a type ignores is
// rejected at load, never silently filtered (the same law the G10/I5a
// variants follow).
func TestI5bSchemaRejectsUnusedKey(t *testing.T) {
	for _, tc := range []struct{ ctype, extra string }{
		{"merkle_proof_no_length_check", "pattern: \"x\""},
		{"verifier_default_on", "var_pattern: \"x\""},
	} {
		t.Run(tc.ctype, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.yaml")
			body := "id: bad-key-arch\nname: Bad Key\ncriticality: high\n" +
				"checks:\n  - type: " + tc.ctype + "\n" +
				"    names: [\"a\"]\n    " + tc.extra + "\n"
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadArchetype(p); err == nil {
				t.Fatalf("%s: an unused key must fail loud", tc.ctype)
			} else if !strings.Contains(err.Error(), tc.ctype) {
				t.Fatalf("error %q does not name the check type", err)
			}
		})
	}
}
