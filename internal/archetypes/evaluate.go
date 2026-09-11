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
	"websec/internal/textsim"
	"websec/internal/validation"
)

// checkTypes is CHECK_TYPES: the closed set of predicate kinds.
var checkTypes = []string{"state_var_exists", "function_exists",
	"unguarded_function_exists", "delegatecall_present",
	"unguarded_entry_writes", "external_call_pattern",
	"sig_verify_no_separator", "merkle_verify_without_depth_gate",
	"threshold_without_enforcement", "relayer_single_key"}

// checkKeys is _CHECK_KEYS: the discriminator keys each check type consumes.
// A check carrying a key its type does not use is a silent-filter bug (the
// key is ignored); a check missing a key its type reads is a KeyError at
// evaluate time. Both fail loud at load.
var checkKeys = map[string]map[string]bool{
	"state_var_exists":                 {"names": true, "pattern": true},
	"function_exists":                  {"names": true, "pattern": true},
	"unguarded_function_exists":        {"names": true},
	"delegatecall_present":             {},
	"unguarded_entry_writes":           {"var_pattern": true},
	"external_call_pattern":            {"pattern": true},
	"sig_verify_no_separator":          {"names": true},
	"merkle_verify_without_depth_gate": {"names": true},
	"threshold_without_enforcement":    {"names": true},
	"relayer_single_key":               {"names": true},
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
	case "sig_verify_no_separator":
		return evalSigVerifyNoSeparator(check, index)
	case "merkle_verify_without_depth_gate":
		return evalMerkleVerifyWithoutDepthGate(check, index)
	case "threshold_without_enforcement":
		return evalThresholdWithoutEnforcement(check, index)
	case "relayer_single_key":
		return evalRelayerSingleKey(check, index)
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
		// C0: the reconciled writer list — the parser's writes_storage omits
		// statement-level writes, so the raw list misses real writer functions.
		if anyMatchStr(pat, structidx.WritersOf(index, n)) {
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
		if objStr(u, "kind") != "param" {
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
		name := objStr(n, "name")
		if !names[name] {
			continue
		}
		if containsLower(objStr(n, "selector"), separatorMarkers) {
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
	return "absent", "no separator-less verify function among " + pyListRepr(sortedKeys(names)), nil
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
		if !containsSubstr(objStr(n, "name"), names) {
			continue
		}
		if containsLower(objStr(n, "selector"), depthMarkers) {
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
		hits = append(hits, objStr(n, "name"))
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "no-depth-gate: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no depth-gateless proof function among " + pyListRepr(names), nil
}

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
	id := objStr(n, "id")
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
		name := objStr(v, "name")
		if !containsLower(name, markers) {
			continue
		}
		guards := []string{}
		for _, f := range structidx.Nodes(index, "function") {
			if contractOf(f) != contractOf(v) {
				continue
			}
			for _, g := range listAt(f, "guards") {
				guards = append(guards, objStr(g, "text"))
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
	return "absent", "no unenforced threshold state var among " + pyListRepr(markers), nil
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
		hits = append(hits, objStr(n, "name"))
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		return "present", "single-key: " + strings.Join(hits, ", "), nil
	}
	return "absent", "no single-relayer gate among " + pyListRepr(markers), nil
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
		if name := objStr(v, "name"); containsLower(name, coSignerMarkers) {
			cosigners = append(cosigners, name)
		}
	}
	if len(cosigners) == 0 {
		return false
	}
	for _, g := range listAt(n, "guards") {
		if text := objStr(g, "text"); text != "" && containsLower(text, cosigners) {
			return true
		}
	}
	return false
}

// containsLower reports whether strings.ToLower(s) contains any marker
// (lowercased) — the case-insensitive marker match both G10 checks share.
func containsLower(s string, markers []string) bool {
	l := strings.ToLower(s)
	for _, m := range markers {
		if strings.Contains(l, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// containsSubstr reports whether name contains any of the needles.
func containsSubstr(name string, needles []string) bool {
	for _, nd := range needles {
		if strings.Contains(name, nd) {
			return true
		}
	}
	return false
}

// NearMatches is near_matches: top-k identifiers the check ALMOST matched —
// false-miss visibility. Candidate pool per check type; score is the max
// bigram-Jaccard over the check's literal tokens.
func NearMatches(check, index validation.Value, k int) []string {
	t := objStr(check, "type")
	var cands []string
	switch t {
	case "state_var_exists", "unguarded_entry_writes",
		"threshold_without_enforcement", "relayer_single_key":
		for _, n := range structidx.Nodes(index, "state-variable") {
			cands = append(cands, objStr(n, "name"))
		}
	case "function_exists", "unguarded_function_exists",
		"sig_verify_no_separator", "merkle_verify_without_depth_gate":
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
//
// The rule itself lives in internal/textsim. evalstore's I1b near-dup scan
// needs the SAME function, and evalstore cannot import this package (this
// package reaches evalstore through structidx -> orchestrator -> risk), so
// the leaf owns the implementation and this name stays the archetypes-facing
// alias. One implementation, two callers, no second copy to drift.
func Jaccard(a, b string) float64 { return textsim.Jaccard(a, b) }

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

// anyMatchStr is anyMatch over a []string.
func anyMatchStr(pat *regexp.Regexp, values []string) bool {
	for _, v := range values {
		if pat.MatchString(v) {
			return true
		}
	}
	return false
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
