// evaluate_sig_depth.go: the signature/selector predicates split out of
// evaluate.go — sig_verify_no_separator and merkle_verify_without_depth_gate.
package archetypes

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// separatorMarkers is the hardcoded chain/domain separator marker list for
// sig_verify_no_separator. Compared lowercase-contains against the structidx
// selector (name + "(" + paramTypes + ")" — types only, parser.go:446): a
// check-level override key is YAGNI, so the list lives here, documented.
// "domainSeparator" (camelCase UDVT) and "domain_separator" (snake_case) are
// both live needles for the raw selector text; normSepMarkers below is the
// same list folded for concept-key comparison.
var separatorMarkers = []string{"chainid", "domainSeparator",
	"domain_separator"}

// normSepMarkers folds separatorMarkers through normSepKey so the param-uses
// evidence check compares like with like.
var normSepMarkers = func() map[string]bool {
	out := map[string]bool{}
	for _, m := range separatorMarkers {
		out[normSepKey(m)] = true
	}
	return out
}()

// normSepKey lowercases a separator marker or concept key after stripping
// the concept-join colons (and underscores, which splitIdent consumes, so
// they can never appear in a key): ConceptKeys("chainId") is
// ["chain","chain:id","id"] (splitIdent parser.go:623-644, conceptSet
// :668-697, ConceptKeys :711-719) and only normSepKey("chain:id") ==
// "chainid" matches — a naive containsLower misses the bigram. The same
// fold maps "domain:separator" onto "domainseparator".
func normSepKey(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "_", "")
	return s
}

// usesSeparatorParam reports whether any kind=="param" uses-entry of the
// function carries separator evidence: a concept key folding onto a
// separator marker. Param uses-entries are emitted per referenced parameter
// with ConceptKeys(paramName) (parser.go:847-851), so a plain
// `uint256 chainId` used in `require(chainId == block.chainid)` suppresses
// the hit even though the selector `verify(bytes,address,uint256)` is
// marker-free. An unreferenced chainId emits no entry — name alone is not
// evidence.
func usesSeparatorParam(n validation.Value) bool {
	for _, u := range listAt(n, "uses") {
		if validation.ObjStr(u, "kind") != "param" {
			continue
		}
		for _, k := range listAt(u, "concept_keys") {
			if k.Kind != validation.Str {
				continue
			}
			if normSepMarkers[normSepKey(k.S)] {
				return true
			}
		}
	}
	return false
}

// evalSigVerifyNoSeparator is sig_verify_no_separator: a listed function
// whose selector carries no separator marker AND whose param uses carry no
// separator concept evidence. `names` is consumed exactly like
// unguarded_function_exists (exact set match, not a regex).
func evalSigVerifyNoSeparator(check, index validation.Value) (string, string, error) {
	names := stringSet(listAt(check, "names"))
	if len(names) == 0 {
		return "", "", fmt.Errorf("check type 'sig_verify_no_separator': " +
			"missing required key 'names'")
	}
	var hits []string
	for _, n := range structidx.Nodes(index, "function") {
		name := validation.ObjStr(n, "name")
		if !names[name] {
			continue
		}
		if containsLower(validation.ObjStr(n, "selector"), separatorMarkers) {
			continue
		}
		if usesSeparatorParam(n) {
			continue
		}
		hits = append(hits, name)
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "no-separator: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no separator-less verify function among " + validation.PyListRepr(validation.SortedKeys(names)), nil
}

// depthMarkers is the hardcoded finality-depth marker list for
// merkle_verify_without_depth_gate: a marker in the selector OR in
// reads_storage means the code gates on finality somewhere — no hit.
var depthMarkers = []string{"confir", "final", "depth", "checkpoint", "epoch", "finalized"}

// evalMerkleVerifyWithoutDepthGate is merkle_verify_without_depth_gate: a
// function whose name contains a listed substring, whose selector carries no
// depth marker, and whose reads_storage names no depth-marked state.
func evalMerkleVerifyWithoutDepthGate(check, index validation.Value) (string, string, error) {
	var names []string
	for _, v := range listAt(check, "names") {
		if v.Kind == validation.Str {
			names = append(names, v.S)
		}
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("check type 'merkle_verify_without_depth_gate': " +
			"missing required key 'names'")
	}
	var hits []string
	for _, n := range structidx.Nodes(index, "function") {
		if !containsSubstr(validation.ObjStr(n, "name"), names) {
			continue
		}
		if containsLower(validation.ObjStr(n, "selector"), depthMarkers) {
			continue
		}
		gated := false
		for _, r := range listAt(n, "reads_storage") {
			if r.Kind == validation.Str && containsLower(r.S, depthMarkers) {
				gated = true
				break
			}
		}
		if gated {
			continue
		}
		hits = append(hits, validation.ObjStr(n, "name"))
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "no-depth-gate: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no depth-gateless proof function among " + validation.PyListRepr(names), nil
}
