// evaluate.go: the deterministic predicates — evaluate_precondition,
// near_matches and the bigram-Jaccard scorer. Every check is a pure function
// over the structural index: if every check holds, this shape of critical bug
// is structurally present in the tree. HINT-only — a match is a search
// directive, never evidence.
package archetypes

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// checkTypes is CHECK_TYPES: the closed set of predicate kinds.
var checkTypes = []string{"state_var_exists", "function_exists",
	"unguarded_function_exists", "delegatecall_present",
	"unguarded_entry_writes", "external_call_pattern"}

// checkKeys is _CHECK_KEYS: the discriminator keys each check type consumes.
// A check carrying a key its type does not use is a silent-filter bug (the
// key is ignored); a check missing a key its type reads is a KeyError at
// evaluate time. Both fail loud at load.
var checkKeys = map[string]map[string]bool{
	"state_var_exists":          {"names": true, "pattern": true},
	"function_exists":           {"names": true, "pattern": true},
	"unguarded_function_exists": {"names": true},
	"delegatecall_present":      {},
	"unguarded_entry_writes":    {"var_pattern": true},
	"external_call_pattern":     {"pattern": true},
}

// EvaluatePrecondition is evaluate_precondition: one archetype check against
// the index, returning ("present"|"absent", detail). Deterministic; no model
// involved. A malformed check returns an error naming the type and key —
// never a bare panic — so one bad predicate cannot abort the whole prescreen
// with an unactionable traceback.
func EvaluatePrecondition(check, index validation.Value) (string, string, error) {
	t := objStr(check, "type")
	switch t {
	case "state_var_exists", "function_exists":
		return evalNamePresence(t, check, index)
	case "unguarded_function_exists":
		return evalUnguardedFunction(check, index)
	case "delegatecall_present":
		res, detail := evalDelegatecallPresent(index)
		return res, detail, nil
	case "unguarded_entry_writes":
		return evalUnguardedEntryWrites(check, index)
	case "external_call_pattern":
		return evalExternalCallPattern(check, index)
	}
	return "", "", fmt.Errorf("unknown check type %s", validation.PyReprStr(t))
}

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
		name := objStr(n, "name")
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
		name := objStr(n, "name")
		if names[name] && unguarded(n) {
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "unguarded: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no unguarded function among " + pyListRepr(sortedKeys(names)), nil
}

// evalDelegatecallPresent is delegatecall_present.
func evalDelegatecallPresent(index validation.Value) (string, string) {
	count := 0
	for _, e := range listAt(index, "edges") {
		if objStr(e, "rel") == "delegatecalls" {
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
		if anyMatch(pat, listAt(n, "writes_storage")) {
			eps = append(eps, objStr(n, "name"))
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
			hits = append(hits, objStr(n, "id"))
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

// NearMatches is near_matches: top-k identifiers the check ALMOST matched —
// false-miss visibility. Candidate pool per check type; score is the max
// bigram-Jaccard over the check's literal tokens.
func NearMatches(check, index validation.Value, k int) []string {
	t := objStr(check, "type")
	var cands []string
	switch t {
	case "state_var_exists", "unguarded_entry_writes":
		for _, n := range structidx.Nodes(index, "state-variable") {
			cands = append(cands, objStr(n, "name"))
		}
	case "function_exists", "unguarded_function_exists":
		for _, n := range structidx.Nodes(index, "function") {
			cands = append(cands, objStr(n, "name"))
		}
	case "external_call_pattern":
		for _, n := range structidx.Nodes(index, "function") {
			for _, c := range listAt(n, "calls_external") {
				if c.Kind == validation.Str {
					cands = append(cands, c.S)
				}
			}
		}
	default:
		return nil
	}
	lits := checkLiterals(check)
	if len(lits) == 0 {
		return nil
	}
	type scored struct {
		score float64
		name  string
	}
	var rows []scored
	for _, c := range dedupeStrings(cands) {
		best := 0.0
		for _, lit := range lits {
			if j := Jaccard(c, lit); j > best {
				best = j
			}
		}
		rows = append(rows, scored{best, c})
	}
	// Python: sorted((score, c) for ...), reverse=True) — score desc, then
	// the identifier desc (tuple comparison under reverse).
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].name > rows[j].name
	})
	if len(rows) > k {
		rows = rows[:k]
	}
	out := []string{}
	for _, r := range rows {
		if r.score > 0.25 {
			out = append(out, r.name)
		}
	}
	return out
}

// Jaccard is _jaccard: bigram-Jaccard similarity of two identifiers.
func Jaccard(a, b string) float64 {
	A, B := bigrams(a), bigrams(b)
	inter, union := 0, len(B)
	for k := range A {
		if B[k] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0.0
	}
	return float64(inter) / float64(union)
}

// bigrams is _bigrams: the lowercased 2-gram set, the whole string when it is
// one rune or shorter.
func bigrams(s string) map[string]bool {
	rs := []rune(strings.ToLower(s))
	out := map[string]bool{}
	if len(rs) > 1 {
		for i := 0; i+1 < len(rs); i++ {
			out[string(rs[i:i+2])] = true
		}
		return out
	}
	out[string(rs)] = true
	return out
}

// checkLiterals is _check_literals: the literal identifiers a check looks
// for (for near-matching) — its names plus every >3-char identifier token in
// its regex keys.
func checkLiterals(check validation.Value) []string {
	lits := []string{}
	for _, n := range listAt(check, "names") {
		if n.Kind == validation.Str {
			lits = append(lits, n.S)
		}
	}
	for _, key := range []string{"pattern", "var_pattern"} {
		if v := objAt(check, key); v.Kind == validation.Str {
			for _, t := range wordRe.FindAllString(v.S, -1) {
				if len(t) > 3 {
					lits = append(lits, t)
				}
			}
		}
	}
	return lits
}

// wordRe is re.findall(r"[A-Za-z_]\w*", text) — \w is ASCII here, which is
// what every shipped pattern contains.
var wordRe = regexp.MustCompile(`[A-Za-z_]\w*`)

// compileRegex is _compile_regex: an invalid pattern is an error naming where
// it came from — never a bare regexp error.
func compileRegex(pattern, context string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid regex %s: %s",
			context, validation.PyReprStr(pattern), err)
	}
	return re, nil
}

// optionalPattern compiles check[key] when present (nil when absent).
func optionalPattern(check validation.Value, key, context string) (*regexp.Regexp, error) {
	v := objAt(check, key)
	if v.Kind != validation.Str {
		return nil, nil
	}
	return compileRegex(v.S, context)
}

// unguarded is _unguarded: no authorization modifier in guarded_by.
func unguarded(n validation.Value) bool {
	for _, m := range listAt(n, "guarded_by") {
		if m.Kind == validation.Str && structidx.IsAuthzGuard(m.S) {
			return false
		}
	}
	return true
}

// anyMatch is any(pat.search(v) for v in values).
func anyMatch(pat *regexp.Regexp, values []validation.Value) bool {
	for _, v := range values {
		if v.Kind == validation.Str && pat.MatchString(v.S) {
			return true
		}
	}
	return false
}

func stringSet(values []validation.Value) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		if v.Kind == validation.Str {
			out[v.S] = true
		}
	}
	return out
}

func dedupeStrings(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pyListRepr renders a []string the way Python's repr() does.
func pyListRepr(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

func listAt(v validation.Value, key string) []validation.Value {
	x := objAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}
