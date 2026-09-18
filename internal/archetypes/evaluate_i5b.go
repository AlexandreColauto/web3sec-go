// evaluate_i5b.go: the I5b bridge predicates split out of evaluate.go —
// merkle_proof_no_length_check and verifier_default_on.
package archetypes

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// I5b: merkle-path + default-on-verifier bridge predicates.
//
// VALUE-BLINDNESS (governs both checks below, and it is not a caveat we can
// engineer away). The structural index does not carry what these two checks
// would need to be verdicts:
//
//   - a function node carries no PARAMETER NAMES and no parameter values — its
//     only signature evidence is the selector, name + TYPE list
//     (parser.go:1139), and `uses` records referenced-parameter concept keys,
//     never the parameter's declared name;
//   - a state-variable node is {id,kind,name,path,line} (parser.go:1059-1061)
//     and pyState drops the initializer (parser.go:87), so a write is visible
//     only as "this function writes this name", never as the assigned value.
//
// So merkle_proof_no_length_check claims "this names-matched function's
// selector carries an array/bytes-shaped type and none of its own guard
// conditions mention `length`" — never "the path check is wrong". And
// verifier_default_on claims "this trust-marked flag is written by a
// construct|init|setup-shaped function with no authorization modifier" — never
// "the flag is true". Both are HINT-only shape claims, exactly like every
// other check here.

// pathSelectorMarkers is the hardcoded array/bytes evidence for
// merkle_proof_no_length_check, read as case-insensitive substrings of the
// selector. HONESTY: the evidence is the selector TEXT, kept literal to the
// plan — a fixed-size `bytes32` / `bytesNN` parameter satisfies the "bytes"
// marker just as a dynamic `bytes` path does, because the index carries the
// joined type list (`name(type,type)`, parser.go:1139) with no per-parameter
// binding, and this check does not re-derive one. Documented false-hit class,
// not a guess.
var pathSelectorMarkers = []string{"[]", "bytes"}

// lengthMarker is the completeness-check evidence: a guard whose condition text
// mentions it means the path length IS consulted somewhere on this function's
// own execution path. Guard text is the FIRST top-level require/assert argument
// or a reverting `if` condition (extractGuards parser.go:746-796) — a length
// test delegated to a callee or spelled in a modifier body emits no guard here
// (modifier bodies feed reads/writes only, parser.go:1121-1132) and reads as
// unchecked. Documented false hit, not silence.
var lengthMarker = []string{"length"}

// initShapedMarkers is the initializer-writer vocabulary for
// verifier_default_on: a trust flag written by a constructor / initializer is
// defaulted at birth, whereas the same write in an ordinary admin function is
// a deliberate, post-deployment act.
var initShapedMarkers = []string{"construct", "init", "setup"}

// evalMerkleProofNoLengthCheck is merkle_proof_no_length_check: a function
// whose name carries a listed marker, whose selector carries an array/bytes
// parameter type, and whose own guards never mention `length`.
//
// `names` is consumed like every other marker list here (case-insensitive
// substring), not as an exact set: the shipped defaults name entry-point
// families (`verifyProof`, `proveWithdrawal`, `relayMessage`), and a target's
// concrete name (`verifyWithdrawalProof`) is expected to match.
func evalMerkleProofNoLengthCheck(check, index validation.Value) (string, string, error) {
	markers := strValues(listAt(check, "names"))
	if len(markers) == 0 {
		return "", "", fmt.Errorf("check type 'merkle_proof_no_length_check': " +
			"missing required key 'names'")
	}
	hits := []string{}
	for _, n := range structidx.Nodes(index, "function") {
		if !containsLower(validation.ObjStr(n, "name"), markers) {
			continue
		}
		if !containsLower(validation.ObjStr(n, "selector"), pathSelectorMarkers) {
			continue
		}
		if guardsMentionLength(n) {
			continue
		}
		hits = append(hits, validation.ObjStr(n, "name"))
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "no-length-check: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no length-unchecked proof path among " + validation.PyListRepr(markers), nil
}

// guardsMentionLength reports whether any require/assert/reverting-if condition
// of the function mentions the length marker — the "completeness check exists
// somewhere on this path" evidence.
func guardsMentionLength(n validation.Value) bool {
	for _, g := range listAt(n, "guards") {
		if containsLower(validation.ObjStr(g, "text"), lengthMarker) {
			return true
		}
	}
	return false
}

// evalVerifierDefaultOn is verifier_default_on: a state flag whose name carries
// a trust-granting marker that is written by a construct|init|setup-shaped
// function carrying no authorization modifier — the Nomad shape, a trust root
// that is on at deployment.
//
// Evidence, all of it structural:
//
//   - the writer's name matches the initializer vocabulary (case-insensitive
//     substring, so `constructor` and `initialize` both match);
//   - the writer is unguarded: no `guarded_by` entry reads as an authorization
//     modifier (structidx.IsAuthzGuard, concepts.go:37 — ownership, roles,
//     admin, guardian, ...). A `constructor` has no modifiers by construction,
//     so a constructor writer always satisfies this arm;
//   - `writes_storage` names the marked flag. That list is built from the
//     writer's OWN contract's declared state variables (parser.go:1144-1151),
//     so the hit is a same-contract write by construction — no separate
//     contract-scoping lookup is needed, unlike the I5a threshold check.
//
// VALUE-BLINDNESS: `writes_storage` records the write, never the literal, so
// `verified = true` and `verified = false` in a constructor are
// indistinguishable here. This check reports the SHAPE (an init-shaped,
// unguarded writer for a trust-marked flag), and the hit names the flag only.
func evalVerifierDefaultOn(check, index validation.Value) (string, string, error) {
	markers := strValues(listAt(check, "names"))
	if len(markers) == 0 {
		return "", "", fmt.Errorf("check type 'verifier_default_on': " +
			"missing required key 'names'")
	}
	hits := []string{}
	seen := map[string]bool{}
	for _, f := range structidx.Nodes(index, "function") {
		if !containsLower(validation.ObjStr(f, "name"), initShapedMarkers) {
			continue
		}
		if !unguarded(f) {
			continue
		}
		for _, w := range strValues(listAt(f, "writes_storage")) {
			if seen[w] || !containsLower(w, markers) {
				continue
			}
			seen[w] = true
			hits = append(hits, w)
		}
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "default-on: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no default-on trust flag among " + validation.PyListRepr(markers), nil
}
