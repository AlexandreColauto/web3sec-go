// Invariant findings and tests — link_finding, link_test and the coverage roll-ups (split from invariants.go; pure structural move).

package invariants

import (
	"fmt"
	"slices"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// LinkFinding is link_finding: attach a finding to an invariant.
func LinkFinding(c *state.Campaign, invariantID, findingID string,
	violated bool) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !validation.HasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := validation.ObjAt(reg, invariantID)
	findings := getOr(entry, "findings", validation.VArr())
	if !containsValue(findings, validation.VStr(findingID)) {
		findings.A = append(findings.A, validation.VStr(findingID))
	}
	entry.O = validation.SetOrAppend(entry.O, "findings", findings)
	if violated {
		entry.O = validation.SetOrAppend(entry.O, "test_status", validation.VStr("violated"))
		entry.O = validation.SetOrAppend(entry.O, "violated_by", validation.VStr(findingID))
	}
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(state.NowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	data := validation.VObj(
		pair("finding", validation.VStr(findingID)),
		pair("violated", validation.VBool(violated)),
	)
	// r40: test_status "violated" (and violated_by) is a gate-read flip —
	// coverage and uncovered_critical draw from it. Unwind on refusal.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.linked_finding", &invariantID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// LinkTest is link_test: register a test artifact against an invariant.
func LinkTest(c *state.Campaign, invariantID, artifactID string) (validation.Value, error) {
	if _, err := c.Artifact(artifactID); err != nil {
		return validation.VNull(), err
	}
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !validation.HasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := validation.ObjAt(reg, invariantID)
	tests := getOr(entry, "tests", validation.VArr())
	if !containsValue(tests, validation.VStr(artifactID)) {
		tests.A = append(tests.A, validation.VStr(artifactID))
	}
	entry.O = validation.SetOrAppend(entry.O, "tests", tests)
	ts := getOr(entry, "test_status", validation.VStr("untested"))
	if ts.Kind == validation.Str && (ts.S == "untested" || ts.S == "untestable") {
		entry.O = validation.SetOrAppend(entry.O, "test_status", validation.VStr("held"))
	}
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(state.NowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	data := validation.VObj(pair("artifact", validation.VStr(artifactID)))
	// r40: the test_status flip to "held" is a gate-read state change.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.linked_test", &invariantID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

func containsValue(arr validation.Value, want validation.Value) bool {
	for _, e := range arr.A {
		if e.Kind == want.Kind && e.S == want.S && e.I == want.I && e.B == want.B {
			return true
		}
	}
	return false
}

func unknownInvariant(id string) error {
	return fmt.Errorf("unknown invariant %s", validation.PyReprStr(id))
}

// ---- coverage ------------------------------------------------------------

// Coverage is coverage: the registry's test-axis roll-up.
func Coverage(c *state.Campaign) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	counts := make(map[string]int)
	var order []string
	for _, s := range Statuses {
		counts[s] = 0
		order = append(order, s)
	}
	for _, e := range reg.O {
		key := countKey(getOr(e.V, "test_status", validation.VStr("untested")))
		if _, seen := counts[key]; !seen {
			order = append(order, key)
		}
		counts[key]++
	}
	kvs := make([]validation.KV, len(order))
	for i, k := range order {
		kvs[i] = pair(k, validation.VInt(int64(counts[k])))
	}
	total := len(reg.O)
	tested := counts["held"] + counts["violated"]
	ratio := validation.VFloat(0)
	if total > 0 {
		ratio = validation.VFloat(validation.PythonRound(
			float64(tested)/float64(total), 3))
	}
	return validation.VObj(
		pair("total", validation.VInt(int64(total))),
		pair("statuses", validation.VObj(kvs...)),
		pair("test_coverage_ratio", ratio),
		pair("violated_invariants", validation.StrArr(sortedByStatus(reg, "violated"))),
		pair("uncovered", validation.StrArr(sortedByStatus(reg, "untested", "untestable"))),
	), nil
}

// countKey is the JSON object key Python's dict uses for a test_status
// value (json.dumps renders None as "null", bools lowercase, ints digits).
func countKey(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "null"
	case validation.Bool:
		if v.B {
			return "true"
		}
		return "false"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return validation.PyRepr(v)
}

// sortedByStatus is the sorted registry keys whose test_status is one of
// want.
func sortedByStatus(reg validation.Value, want ...string) []string {
	var out []string
	for _, e := range reg.O {
		ts := getOr(e.V, "test_status", validation.VStr("untested"))
		if ts.Kind == validation.Str && slices.Contains(want, ts.S) {
			out = append(out, e.K)
		}
	}
	sort.Strings(out)
	return out
}

// UncoveredCritical is uncovered_critical: critical/high invariants with no
// test and no finding — the planner's next round draws from this.
func UncoveredCritical(c *state.Campaign, model validation.Value) ([]validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return nil, err
	}
	reg := regOf(links)
	norm := map[string]validation.Value{}
	for _, e := range reg.O {
		if e.V.Kind == validation.Obj {
			norm[NormalizeInvID(e.K)] = e.V
		}
	}
	out := []validation.Value{}
	for _, inv := range validation.ObjAt(model, "invariants").A {
		idV, ok := fieldAt(inv, "id")
		if !ok {
			return nil, fmt.Errorf("'id'")
		}
		e, ok := norm[NormalizeInvID(validation.PyStr(idV))]
		if !ok || len(e.O) == 0 {
			continue
		}
		ts := getOr(e, "test_status", validation.VStr("untested"))
		if ts.Kind != validation.Str || !slices.Contains([]string{"untested", "untestable"}, ts.S) {
			continue
		}
		sev := validation.ObjAt(inv, "severity_if_broken")
		if sev.Kind != validation.Str || !slices.Contains([]string{"critical", "high"}, sev.S) {
			continue
		}
		out = append(out, validation.VObj(
			pair("invariant_id", idV),
			pair("statement", validation.ObjAt(inv, "statement")),
			pair("applies_to", getOr(inv, "applies_to", validation.VArr())),
		))
	}
	return out, nil
}

// ---- verification axis ---------------------------------------------------
