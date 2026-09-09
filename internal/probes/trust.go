package probes

import (
	"regexp"
	"sort"
	"strings"

	"websec/internal/validation"
)

// authzHints is _AUTHZ_HINTS: an authorization gate is a modifier whose name
// looks like one; anything else (nonReentrant, whenNotPaused, lock) is not a
// gate and must not demote an unprivileged row to "unresolvable".
var authzHints = []string{
	"only", "auth", "admin", "govern", "owner", "role", "keeper", "guardian",
	"pauser", "minter", "staker", "sequencer", "verifier", "messenger",
	"gateway", "rollup", "counterpart", "whitelist", "allowlist", "signer",
	"operator", "manager", "controller",
}

// insideBoundary is _INSIDE_BOUNDARY: mechanisms inside the protocol boundary
// by construction — tier 0 with no model needed.
var insideBoundary = []string{"rollup", "gateway", "counterpart", "messenger",
	"staker"}

// attackerTrust is _ATTACKER_TRUST: trust values that put an actor inside the
// attacker model.
var attackerTrust = map[string]struct{}{"semi-trusted": {}, "adversarial": {},
	"untrusted": {}}

// glueTokens is _GLUE_TOKENS, dropped before matching.
var glueTokens = map[string]struct{}{"only": {}, "by": {}, "role": {},
	"call": {}, "the": {}, "is": {}}

// normTokens is _norm_tokens: camelCase/snake_case -> lower-case tokens with
// the `only`/glue words dropped, so `onlyActiveStaker` and `active_staker`
// normalize alike. Python splits with `(?<!^)(?=[A-Z])|_`.
func normTokens(name string) []string {
	s := strings.TrimLeft(strip(name), "_")
	parts := splitCamel(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		t := strings.ToLower(p)
		if _, glue := glueTokens[t]; glue {
			continue
		}
		out = append(out, t)
	}
	return out
}

// splitCamel is re.split(r"(?<!^)(?=[A-Z])|_", s): split before each uppercase
// letter that is not at the start, and on underscores.
func splitCamel(s string) []string {
	var out []string
	var cur strings.Builder
	for i, r := range s {
		if r == '_' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		if r >= 'A' && r <= 'Z' && i > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteRune(r)
	}
	out = append(out, cur.String())
	return out
}

// isAuthzModifier is _is_authz_modifier: any hint is a substring.
func isAuthzModifier(modifier string) bool {
	low := strings.ToLower(modifier)
	for _, h := range authzHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// actorEntry is one _actor_table row.
type actorEntry struct {
	id     string
	tokens []string
	trust  validation.Value
}

// actorTable is _actor_table(model), sorted by id.
func actorTable(model validation.Value) []actorEntry {
	out := []actorEntry{}
	for _, a := range vObjList(model, "actors") {
		if vStr(a, "id") == "" {
			continue
		}
		out = append(out, actorEntry{id: vStr(a, "id"),
			tokens: normTokens(vStr(a, "id")), trust: vGet(a, "trust")})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// privilegeAlias is one _privilege_aliases row.
type privilegeAlias struct {
	tokens []string
	role   string
	actor  string
	trust  validation.Value
}

// privilegeAliases is _privilege_aliases(model): `privileges[].mechanism`
// names the modifier, `role` names the actor.
func privilegeAliases(model validation.Value) []privilegeAlias {
	actors := map[string]actorEntry{}
	for _, a := range actorTable(model) {
		actors[a.id] = a
	}
	out := []privilegeAlias{}
	for _, p := range vObjList(model, "privileges") {
		mech := vStr(p, "mechanism")
		role := vStr(p, "role")
		if mech == "" {
			continue
		}
		actor, ok := actors[role]
		al := privilegeAlias{tokens: normTokens(mech), role: role}
		if ok {
			al.actor = actor.id
			al.trust = actor.trust
		}
		out = append(out, al)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if c := compareTokenSlices(a.tokens, b.tokens); c != 0 {
			return c < 0
		}
		return a.role < b.role
	})
	return out
}

// compareTokenSlices is Python's tuple comparison over two token lists.
func compareTokenSlices(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// tokensMatch is _tokens_match: one token set inside the other.
func tokensMatch(a, b []string) bool {
	sa, sb := map[string]struct{}{}, map[string]struct{}{}
	for _, t := range a {
		sa[t] = struct{}{}
	}
	for _, t := range b {
		sb[t] = struct{}{}
	}
	if len(sa) == 0 || len(sb) == 0 {
		return false
	}
	return subset(sa, sb) || subset(sb, sa)
}

func subset(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// gateResult is resolve_gate's dict, in Python's key order.
type gateResult struct {
	modifier       string
	tokens         []string
	actor          *string
	trust          validation.Value
	mechanism      string
	insideBoundary bool
	resolved       bool
	tier           int
}

func (g gateResult) value() validation.Value {
	actor := validation.VNull()
	if g.actor != nil {
		actor = validation.VStr(*g.actor)
	}
	trust := g.trust
	if trust.Kind == 0 {
		trust = validation.VNull()
	}
	return validation.VObj(
		validation.KV{K: "modifier", V: validation.VStr(g.modifier)},
		validation.KV{K: "tokens", V: strArr(g.tokens)},
		validation.KV{K: "actor", V: actor},
		validation.KV{K: "trust", V: trust},
		validation.KV{K: "mechanism", V: validation.VStr(g.mechanism)},
		validation.KV{K: "inside_boundary", V: validation.VBool(g.insideBoundary)},
		validation.KV{K: "resolved", V: validation.VBool(g.resolved)},
		validation.KV{K: "tier", V: validation.VInt(int64(g.tier))},
	)
}

// tierForTrust is the trust -> tier map: attacker trust is 0, trusted is 2,
// anything else is the explicit middle.
func tierForTrust(trust validation.Value) int {
	if trust.Kind == validation.Str {
		if _, bad := attackerTrust[trust.S]; bad {
			return 0
		}
		if trust.S == "trusted" {
			return 2
		}
	}
	return 1
}

// resolveGate is resolve_gate: resolve one gate modifier through the model.
// Deterministic: the most specific token match wins, ties broken by actor id.
func resolveGate(modifier string, model validation.Value) gateResult {
	tokens := normTokens(modifier)
	res := gateResult{modifier: modifier, tokens: tokens, mechanism: modifier,
		tier: 1, trust: validation.VNull()}
	var best *actorEntry
	var bestScore int
	var bestID string
	for _, actor := range actorTable(model) {
		if compareTokenSlices(actor.tokens, tokens) == 0 {
			a := actor
			best = &a
			break
		}
		if tokensMatch(tokens, actor.tokens) {
			// Python's score tuple is (overlap, actor id): the LARGER id
			// wins a tie.
			score, id := len(intersectSet(tokens, actor.tokens)), actor.id
			if best == nil || score > bestScore ||
				(score == bestScore && id > bestID) {
				a := actor
				best = &a
				bestScore, bestID = score, id
			}
		}
	}
	if best != nil {
		id := best.id
		res.actor, res.trust = &id, best.trust
		res.resolved = true
		res.tier = tierForTrust(best.trust)
		return res
	}
	for _, alias := range privilegeAliases(model) {
		if tokensMatch(tokens, alias.tokens) && alias.actor != "" {
			id := alias.actor
			res.actor, res.trust = &id, alias.trust
			res.resolved = true
			res.tier = tierForTrust(alias.trust)
			res.mechanism = "privileges[].mechanism"
			return res
		}
	}
	for _, t := range tokens {
		for _, in := range insideBoundary {
			if t == in {
				res.insideBoundary, res.resolved = true, true
				res.tier = 0
				res.mechanism = "inside-boundary"
				return res
			}
		}
	}
	return res
}

func intersectSet(a, b []string) map[string]struct{} {
	sb := map[string]struct{}{}
	for _, t := range b {
		sb[t] = struct{}{}
	}
	out := map[string]struct{}{}
	for _, t := range a {
		if _, ok := sb[t]; ok {
			out[t] = struct{}{}
		}
	}
	return out
}

// TierOfGate is tier_of_gate: 0 = unprivileged or attacker-reachable gate,
// 1 = unresolvable modifier or no model (explicitly middle), 2 = every gate
// resolves to a trusted role. The weakest gate wins.
func TierOfGate(modifiers []string, model validation.Value) int {
	gates := []string{}
	for _, m := range modifiers {
		if isAuthzModifier(m) {
			gates = append(gates, m)
		}
	}
	if len(gates) == 0 {
		return 0
	}
	best := resolveGate(gates[0], model).tier
	for _, g := range gates[1:] {
		if t := resolveGate(g, model).tier; t < best {
			best = t
		}
	}
	return best
}

// GateLabel is gate_label: the display tag for a row — `unprivileged` or the
// gate modifier(s), sorted and comma-joined.
func GateLabel(modifiers []string, model validation.Value) string {
	gates := []string{}
	for _, m := range modifiers {
		if isAuthzModifier(m) {
			gates = append(gates, m)
		}
	}
	if len(gates) == 0 {
		return "unprivileged"
	}
	sort.Strings(gates)
	return strings.Join(gates, ",")
}

// ResolveGate is resolve_gate as a Value (the test/CLI surface).
func ResolveGate(modifier string, model validation.Value) validation.Value {
	return resolveGate(modifier, model).value()
}

// wordBoundarySearch is re.search(rf"\b{re.escape(needle)}\b", haystack).
func wordBoundarySearch(needle, haystack string) bool {
	if needle == "" {
		return false
	}
	re, err := regexp.Compile(`\b` + regexp.QuoteMeta(needle) + `\b`)
	if err != nil {
		return false
	}
	return re.MatchString(haystack)
}
