// evaluate_i5a.go: the I5a bridge predicates split out of evaluate.go —
// threshold_without_enforcement and relayer_single_key.
package archetypes

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// I5a: threshold + relayer-key bridge predicates.
//
// VALUE-BLINDNESS (governs both checks below, and it is not a caveat we can
// engineer away): a state-variable node in the structural index is
// {id, kind, name, path, line} — no value, no declared type, no initializer.
// parser.go:1059-1061 builds it from the pyState capture without anything
// else, and pyState itself drops the initializer (`(?:=\s*[^;]+)?`,
// parser.go:87). So neither check may claim anything about a value:
//
//   - threshold_without_enforcement says "this marker-named state variable is
//     mentioned by NO require/assert/reverting-if in its own contract". It does
//     NOT say the threshold is too low, wrong, or even set.
//   - relayer_single_key says "this gated entry point's key evidence is ONE
//     relayer-marked state variable and nothing else". It does NOT say that
//     key can move a message, that it is an address, or that the comparison
//     against it is correct.
//
// Both are HINT-only shape claims, exactly like every other check here.

// contractOf is the contract node id owning a member node: member ids are
// "<contract id>.<member name>" (parser.go:1060 state vars, :1127 functions)
// and a contract id is "<path>#<ContractName>", which never contains a dot.
func contractOf(n validation.Value) string {
	id := validation.ObjStr(n, "id")
	if i := strings.LastIndexByte(id, '.'); i >= 0 {
		return id[:i]
	}
	return id
}

// strValues extracts the string members of a value list.
func strValues(values []validation.Value) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v.Kind == validation.Str {
			out = append(out, v.S)
		}
	}
	return out
}

// anyContainsLower reports whether haystacks contain needle as a
// case-insensitive substring.
func anyContainsLower(haystacks []string, needle string) bool {
	low := strings.ToLower(needle)
	for _, h := range haystacks {
		if strings.Contains(strings.ToLower(h), low) {
			return true
		}
	}
	return false
}

// evalThresholdWithoutEnforcement is threshold_without_enforcement: a state
// variable whose name carries a threshold marker, in a contract that mentions
// it in no guard condition anywhere.
//
// Evidence: the contract's OWN function nodes and their `guards` entries
// (require/assert conditions and reverting `if`s, extractGuards
// parser.go:746). Two honest limits ride along:
//
//   - Guards are extracted from a function's own body. A gate spelled inside a
//     MODIFIER is appended to the reads/writes lists but never to `guards`
//     (parser.go:1121-1132), so a threshold consulted only by a modifier is
//     invisible here and this check reports a false hit. The bridge shapes
//     this predicate exists for consult the threshold inline.
//   - Inherited enforcement lives on the base contract's function nodes, so a
//     derived contract that relies on a base-class guard reads as unenforced.
//     Scoping to the owning contract is deliberate (the operator's question is
//     "does THIS contract's execution path consult it"), and it is why the
//     hit names the variable, never the verdict.
func evalThresholdWithoutEnforcement(check, index validation.Value) (string, string, error) {
	markers := strValues(listAt(check, "names"))
	if len(markers) == 0 {
		return "", "", fmt.Errorf("check type 'threshold_without_enforcement': " +
			"missing required key 'names'")
	}
	hits := []string{}
	seen := map[string]bool{}
	for _, v := range structidx.Nodes(index, "state-variable") {
		name := validation.ObjStr(v, "name")
		if !containsLower(name, markers) {
			continue
		}
		guards := []string{}
		for _, f := range structidx.Nodes(index, "function") {
			if contractOf(f) != contractOf(v) {
				continue
			}
			for _, g := range listAt(f, "guards") {
				guards = append(guards, validation.ObjStr(g, "text"))
			}
		}
		if anyContainsLower(guards, name) {
			continue
		}
		if !seen[name] {
			seen[name] = true
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "unenforced: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no unenforced threshold state var among " + validation.PyListRepr(markers), nil
}

// coSignerMarkers is the SECOND-key vocabulary for relayer_single_key: a relay
// gate that also consults a signer set, an owner, a multisig, a council or a
// guardian is not a single-key gate. Hardcoded (no check-level override — a
// per-check list here would be YAGNI until a target needs it), documented, and
// compared case-insensitively as a name substring.
var coSignerMarkers = []string{"signer", "owner", "multisig", "council",
	"guardian"}

// relayGate reports whether an entry point carries a relay gate: an
// AUTHORIZATION modifier by the parser's own vocabulary
// (structidx.IsAuthzGuard — authzHints, concepts.go:37), or a modifier whose
// NAME carries a relayer marker. The second arm matters: "relayer" is not in
// the parser's authz vocabulary, so `onlyRelayer` alone would not count, and
// a relay gate spelled that way is exactly the shape this check exists for.
func relayGate(n validation.Value, markers []string) bool {
	for _, m := range listAt(n, "guarded_by") {
		if m.Kind != validation.Str {
			continue
		}
		if structidx.IsAuthzGuard(m.S) || containsLower(m.S, markers) {
			return true
		}
	}
	return false
}

// evalRelayerSingleKey is relayer_single_key: an authz/relay-gated entry point
// whose whole key evidence is ONE relayer-marked state variable of its own
// contract and no second distinct signer/owner reference.
//
// Evidence read, all of it structural:
//
//   - guarded_by must carry a relay gate (relayGate above);
//   - reads_storage must name exactly one same-contract state variable whose
//     name carries a relayer marker. reads_storage is built from the
//     contract's own declared state variables (parser.go:1121-1132), so a
//     listed entry IS a state variable; but it is computed over the function
//     body PLUS every applied modifier body, which means the index cannot
//     distinguish "the gate consults this key" from "the body reads it". The
//     check claims CONSULTED, never CHECKED.
//   - no second distinct signer/owner reference: no co-signer-marked state
//     variable of the same contract is read by the entry point, and none is
//     named in one of its own guard texts.
//
// A state variable's declared TYPE is not in the index (see the
// value-blindness note above), so "address" is part of the shape's name, not
// of the evidence: a `uint256 relayer` would match identically.
func evalRelayerSingleKey(check, index validation.Value) (string, string, error) {
	markers := strValues(listAt(check, "names"))
	if len(markers) == 0 {
		return "", "", fmt.Errorf("check type 'relayer_single_key': " +
			"missing required key 'names'")
	}
	hits := []string{}
	for _, n := range structidx.ExternalSurface(index) {
		if !relayGate(n, markers) {
			continue
		}
		keyReads := []string{}
		coSigner := false
		for _, r := range listAt(n, "reads_storage") {
			if r.Kind != validation.Str {
				continue
			}
			if containsLower(r.S, markers) {
				keyReads = append(keyReads, r.S)
				continue
			}
			if containsLower(r.S, coSignerMarkers) {
				coSigner = true
			}
		}
		if len(dedupeStrings(keyReads)) != 1 {
			continue
		}
		if coSigner || guardNamesCoSigner(n, index) {
			continue
		}
		hits = append(hits, validation.ObjStr(n, "name"))
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "single-key: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no single-relayer gate among " + validation.PyListRepr(markers), nil
}

// guardNamesCoSigner reports whether any guard text of the entry point names a
// co-signer-marked state variable of its own contract — the second, distinct
// signer/owner reference that separates a co-signed gate from a single-key
// one.
func guardNamesCoSigner(n validation.Value, index validation.Value) bool {
	cosigners := []string{}
	for _, v := range structidx.Nodes(index, "state-variable") {
		if contractOf(v) != contractOf(n) {
			continue
		}
		if name := validation.ObjStr(v, "name"); containsLower(name, coSignerMarkers) {
			cosigners = append(cosigners, name)
		}
	}
	if len(cosigners) == 0 {
		return false
	}
	for _, g := range listAt(n, "guards") {
		if text := validation.ObjStr(g, "text"); text != "" && containsLower(text, cosigners) {
			return true
		}
	}
	return false
}
