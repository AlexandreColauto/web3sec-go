// Section 14: unpriceable decisions — economic_impact.priceable=false is a
// NAMED decision (risk.RecordUnpriceable) that the CONFIRMED gate accepts in
// place of an E7 quantification. The finding file is the projection; the log
// is the record — a priceable=false the log never recorded, or whose ceiling
// the log disagrees with, is a hand-edit, caught exactly like a hand-edited
// floor policy. Message-for-message with audit.py section 14.
//
// Python's code order puts this section 14th, after probe_surface; sections
// 7-13 are not ported yet, so it is registered last (see register.go) and
// must stay last until those land ahead of it.
package sections

import (
	"fmt"
	"math/big"
	"path/filepath"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// Unpriceable is audit.py section 14: {checked, problems, ok}.
func Unpriceable(c *state.Campaign) (validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return validation.Value{}, err
	}
	var decisions []validation.Value
	for _, e := range events {
		switch objStr(e, "type") {
		case "finding.unpriceable", "finding.impact_recorded":
			decisions = append(decisions, e)
		}
	}
	var problems []validation.Value
	checked := 0
	for _, p := range findingFiles(c) {
		fdata, err := validation.ReadJson(p)
		if err != nil {
			// unreadable/invalid: section 4 already reports it
			continue
		}
		imp := objAt(fdata, "economic_impact")
		if imp.Kind != validation.Obj {
			continue
		}
		if pv := objAt(imp, "priceable"); pv.Kind != validation.Bool || pv.B {
			continue
		}
		checked++
		fid := objStr(fdata, "finding_id")
		if fid == "" {
			fid = strings.TrimSuffix(filepath.Base(p), ".json")
		}
		var mine []validation.Value
		for _, e := range decisions {
			if objStr(e, "ref") == fid {
				mine = append(mine, e)
			}
		}
		if len(mine) == 0 {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"finding %s records economic_impact.priceable=false with "+
					"no finding.unpriceable event — the decision was "+
					"hand-edited", fid)))
			continue
		}
		last := mine[len(mine)-1]
		if objStr(last, "type") != "finding.unpriceable" {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"finding %s records economic_impact.priceable=false but "+
					"the log's latest impact decision is a priced "+
					"finding.impact_recorded — projection drifted from "+
					"the log", fid)))
			continue
		}
		recorded := objAt(objAt(last, "data"), "ceiling")
		ceiling := objAt(imp, "ceiling")
		if !pyEqual(recorded, ceiling) {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"finding %s records ceiling %s but the log's last "+
					"finding.unpriceable event cites %s — projection "+
					"drifted from the log", fid, validation.PyRepr(ceiling),
				validation.PyRepr(recorded))))
		}
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(checked))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// pyEqual is Python == on two decoded JSON values: numbers compare across
// int/float, containers element-wise, objects key-insensitively to order.
// (A ceiling is a string by schema, but this section reads files the schema
// check may already have failed, so the comparison stays faithful.)
func pyEqual(a, b validation.Value) bool {
	if isNumKind(a) && isNumKind(b) {
		return ratOf(a).Cmp(ratOf(b)) == 0
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	case validation.Str:
		return a.S == b.S
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !pyEqual(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, kv := range a.O {
			if !pyEqual(kv.V, objAt(b, kv.K)) {
				return false
			}
		}
		return true
	}
	return false
}

func isNumKind(v validation.Value) bool {
	return v.Kind == validation.Int || v.Kind == validation.Flt
}

// ratOf is the exact rational value of a JSON number (Int keeps its big
// decimal text; Flt is the exact binary value, as Python's float is).
func ratOf(v validation.Value) *big.Rat {
	if v.Kind == validation.Int {
		if v.Big != "" {
			if r, ok := new(big.Rat).SetString(v.Big); ok {
				return r
			}
			return new(big.Rat)
		}
		return new(big.Rat).SetInt64(v.I)
	}
	r := new(big.Rat)
	if r.SetFloat64(v.F) == nil {
		return new(big.Rat)
	}
	return r
}
