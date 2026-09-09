package probes

import (
	"sort"

	"websec/internal/validation"
)

// groupState is one (contract, function, line) group during the collapse: the
// representative row, the union of its concepts and — for
// assertion-strength — the asserter preference that justified the row.
type groupState struct {
	row      validation.Value
	concepts []string
	pref     *asserterPref
}

// addConcept is `group["concepts"].add(c)`.
func (g *groupState) addConcept(c string) {
	for _, have := range g.concepts {
		if have == c {
			return
		}
	}
	g.concepts = append(g.concepts, c)
}

// asserterPref is _asserter_pref: which assertion site a merged row names.
type asserterPref struct {
	negClass     int
	negTokens    int
	negOverlap   int
	asserter     string
	asserterLine int
}

func (a asserterPref) less(b asserterPref) bool {
	if a.negClass != b.negClass {
		return a.negClass < b.negClass
	}
	if a.negTokens != b.negTokens {
		return a.negTokens < b.negTokens
	}
	if a.negOverlap != b.negOverlap {
		return a.negOverlap < b.negOverlap
	}
	if a.asserter != b.asserter {
		return a.asserter < b.asserter
	}
	return a.asserterLine < b.asserterLine
}

// asserterPrefOf is _asserter_pref(raw_row): strongest class first, then the
// most specific concept key, then the asserter whose own name shares a token
// with that concept, then name order.
func asserterPrefOf(raw validation.Value) asserterPref {
	conceptTokens := map[string]struct{}{}
	for _, t := range splitColon(vStr(raw, "concept")) {
		conceptTokens[t] = struct{}{}
	}
	asserterTokens := map[string]struct{}{}
	for _, t := range splitCamel(vStr(raw, "asserter")) {
		if t != "" {
			asserterTokens[lower(t)] = struct{}{}
		}
	}
	return asserterPref{
		negClass:     -vInt(raw, "assert_class"),
		negTokens:    -len(conceptTokens),
		negOverlap:   -len(intersectSet(keysOf(asserterTokens), keysOf(conceptTokens))),
		asserter:     vStr(raw, "asserter"),
		asserterLine: vInt(raw, "asserter_line"),
	}
}

// mergeAssertion is _merge_assertion.
func mergeAssertion(group *groupState, raw validation.Value) {
	group.addConcept(vStr(raw, "concept"))
	pref := asserterPrefOf(raw)
	if group.pref == nil || pref.less(*group.pref) {
		p := pref
		group.pref = &p
		vSet(&group.row, "asserter", validation.VStr(pref.asserter))
		vSet(&group.row, "asserter_line", validation.VInt(int64(pref.asserterLine)))
		vSet(&group.row, "assert_class", vGet(raw, "assert_class"))
	}
	own := vInt(group.row, "own_class")
	if rawOwn := vInt(raw, "own_class"); rawOwn < own {
		vSet(&group.row, "own_class", validation.VInt(int64(rawOwn)))
	}
	if g := vInt(raw, "assertion_gap"); g > vInt(group.row, "assertion_gap") {
		vSet(&group.row, "assertion_gap", validation.VInt(int64(g)))
	}
	if vInt(raw, "tier") < vInt(group.row, "tier") ||
		(vInt(raw, "tier") == vInt(group.row, "tier") &&
			vStr(raw, "gate") == "unprivileged") {
		vSet(&group.row, "tier", vGet(raw, "tier"))
		vSet(&group.row, "gate", validation.VStr(vStr(raw, "gate")))
	}
}

// mergeFirst is _merge_first.
func mergeFirst(group *groupState, raw validation.Value) {
	group.addConcept(vStr(raw, "concept"))
	if g := vInt(raw, "assertion_gap"); g > vInt(group.row, "assertion_gap") {
		vSet(&group.row, "assertion_gap", validation.VInt(int64(g)))
	}
	if vInt(raw, "tier") < vInt(group.row, "tier") {
		vSet(&group.row, "tier", vGet(raw, "tier"))
		vSet(&group.row, "gate", validation.VStr(vStr(raw, "gate")))
	}
}

// splitColon is Python's key.split(":").
func splitColon(s string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	return append(out, cur)
}

// keysOf is set(keys) as a slice (order irrelevant for the intersection).
func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
