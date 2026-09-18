// evaluate_checks.go: the base structural predicates split out of
// evaluate.go — name/function presence, delegatecall, entry writes and
// external-call patterns.
package archetypes

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// evalNamePresence covers state_var_exists / function_exists: a node matches
// when its name is listed or the optional pattern matches.
func evalNamePresence(t string, check, index validation.Value) (string, string, error) {
	// Python's labels are not a pluralization: "state vars" (abbreviated)
	// but "functions" — the detail string is part of the artifact bytes.
	kind := "state-variable"
	presentPrefix, absentMsg := "state vars: ", "no matching state variable"
	if t == "function_exists" {
		kind = "function"
		presentPrefix, absentMsg = "functions: ", "no matching function"
	}
	names := stringSet(listAt(check, "names"))
	pat, err := optionalPattern(check, "pattern", "check type '"+t+"'")
	if err != nil {
		return "", "", err
	}
	if len(names) == 0 && pat == nil {
		return "", "", fmt.Errorf("check type %q: missing required "+
			"discriminator: need 'names' and/or 'pattern'", t)
	}
	var hits []string
	for _, n := range structidx.Nodes(index, kind) {
		name := validation.ObjStr(n, "name")
		if names[name] || (pat != nil && pat.MatchString(name)) {
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", presentPrefix + strings.Join(hits, ", "), nil
	}
	return "absent", absentMsg, nil
}

// evalUnguardedFunction is unguarded_function_exists.
func evalUnguardedFunction(check, index validation.Value) (string, string, error) {
	names := stringSet(listAt(check, "names"))
	if len(names) == 0 {
		return "", "", fmt.Errorf("check type 'unguarded_function_exists': " +
			"missing required key 'names'")
	}
	var hits []string
	for _, n := range structidx.Nodes(index, "function") {
		name := validation.ObjStr(n, "name")
		if names[name] && unguarded(n) {
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "unguarded: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no unguarded function among " + validation.PyListRepr(validation.SortedKeys(names)), nil
}

// evalDelegatecallPresent is delegatecall_present.
func evalDelegatecallPresent(index validation.Value) (string, string) {
	count := 0
	for _, e := range listAt(index, "edges") {
		if validation.ObjStr(e, "rel") == "delegatecalls" {
			count++
		}
	}
	if count > 0 {
		return "present", fmt.Sprintf("%d delegatecall edge(s)", count)
	}
	return "absent", "no delegatecall edge"
}

// evalUnguardedEntryWrites is unguarded_entry_writes.
func evalUnguardedEntryWrites(check, index validation.Value) (string, string, error) {
	pat, err := optionalPattern(check, "var_pattern",
		"check type 'unguarded_entry_writes' key 'var_pattern'")
	if err != nil {
		return "", "", err
	}
	if pat == nil {
		return "", "", fmt.Errorf("check type 'unguarded_entry_writes': " +
			"missing required key 'var_pattern'")
	}
	var eps []string
	for _, n := range structidx.ExternalSurface(index) {
		if !unguarded(n) {
			continue
		}
		// C0: the reconciled writer list — the parser's writes_storage omits
		// statement-level writes, so the raw list misses real writer functions.
		if anyMatchStr(pat, structidx.WritersOf(index, n)) {
			eps = append(eps, validation.ObjStr(n, "name"))
		}
	}
	if len(eps) > 0 {
		sort.Strings(eps)
		return "present", "entry points: " + strings.Join(eps, ", "), nil
	}
	return "absent", "no unguarded entry point writes a matching var", nil
}

// evalExternalCallPattern is external_call_pattern (first five call sites).
func evalExternalCallPattern(check, index validation.Value) (string, string, error) {
	pat, err := optionalPattern(check, "pattern",
		"check type 'external_call_pattern' key 'pattern'")
	if err != nil {
		return "", "", err
	}
	if pat == nil {
		return "", "", fmt.Errorf("check type 'external_call_pattern': " +
			"missing required key 'pattern'")
	}
	var hits []string
	for _, n := range structidx.Nodes(index, "function") {
		calls := append(listAt(n, "calls_external"), listAt(n, "delegatecalls")...)
		if anyMatch(pat, calls) {
			hits = append(hits, validation.ObjStr(n, "id"))
		}
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		if len(hits) > 5 {
			hits = hits[:5]
		}
		return "present", "call sites: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no external call matches the pattern", nil
}
