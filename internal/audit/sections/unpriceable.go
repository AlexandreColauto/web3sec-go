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
		switch validation.ObjStr(e, "type") {
		case "finding.unpriceable", "finding.impact_recorded":
			decisions = append(decisions, e)
		}
	}
	var problems []validation.Value
	checked := 0
	// r43a: findingFiles refuses on a finding store it cannot list; that
	// refusal must reach the audit as a refusal rather than this section
	// silently checking zero findings.
	files, err := findingFiles(c)
	if err != nil {
		return validation.Value{}, err
	}
	for _, p := range files {
		fdata, err := validation.ReadJson(p)
		if err != nil {
			// unreadable/invalid: section 4 already reports it
			continue
		}
		imp := validation.ObjAt(fdata, "economic_impact")
		if imp.Kind != validation.Obj {
			continue
		}
		if pv := validation.ObjAt(imp, "priceable"); pv.Kind != validation.Bool || pv.B {
			continue
		}
		checked++
		fid := validation.ObjStr(fdata, "finding_id")
		if fid == "" {
			fid = strings.TrimSuffix(filepath.Base(p), ".json")
		}
		var mine []validation.Value
		for _, e := range decisions {
			if validation.ObjStr(e, "ref") == fid {
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
		if validation.ObjStr(last, "type") != "finding.unpriceable" {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"finding %s records economic_impact.priceable=false but "+
					"the log's latest impact decision is a priced "+
					"finding.impact_recorded — projection drifted from "+
					"the log", fid)))
			continue
		}
		recorded := validation.ObjAt(validation.ObjAt(last, "data"), "ceiling")
		ceiling := validation.ObjAt(imp, "ceiling")
		if !pyEqual(recorded, ceiling) {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"finding %s records ceiling %s but the log's last "+
					"finding.unpriceable event cites %s — projection "+
					"drifted from the log", fid, validation.PyRepr(ceiling),
				validation.PyRepr(recorded))))
		}
	}
	// r6: the mirror direction. The loop above polices a FILE decision the
	// LOG contradicts; a decision ERASED from the file (priceable true or
	// absent) while the chain's last word is still finding.unpriceable is
	// the same hand-edit seen from the other side — prices.json got both
	// ghost and lost rows from day one, the finding file gets its now. The
	// gate already refuses to credit an erased decision (it reads the
	// file); what was missing was that the AUDIT stays silent about it.
	for _, e := range decisions {
		if validation.ObjStr(e, "type") != "finding.unpriceable" {
			continue
		}
		fid := validation.ObjStr(e, "ref")
		fdata, ok := findingFileOf(c, fid)
		if !ok {
			continue // findings section reports the missing file
		}
		imp := validation.ObjAt(fdata, "economic_impact")
		if imp.Kind == validation.Obj {
			if pv := validation.ObjAt(imp, "priceable"); pv.Kind == validation.Bool &&
				!pv.B {
				continue // the decision still stands in the file
			}
		}
		// But was it later retracted the proper way? The decisions list is
		// log order; this event's own finding's LAST impact decision wins.
		last := ""
		for _, e2 := range decisions {
			if validation.ObjStr(e2, "ref") == fid {
				last = validation.ObjStr(e2, "type")
			}
		}
		if last != "finding.unpriceable" {
			continue
		}
		problems = append(problems, validation.VStr(fmt.Sprintf(
			"finding %s: the log's last impact decision is a recorded "+
				"unpriceable, but the file does not carry it "+
				"(priceable false absent?) — the decision was erased by "+
				"hand-edit", fid)))
	}
	// 'checked' keeps its ported meaning (files examined); the mirror
	// scan reports, it does not inflate the counter.
	return validation.VObj(
		KV("checked", validation.VInt(int64(checked))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// findingFileOf resolves a finding id to its stored file; the path is
// deterministic (F-<hex>.json), the id inside is double-checked.
func findingFileOf(c *state.Campaign, fid string) (validation.Value, bool) {
	v, err := validation.ReadJson(filepath.Join(c.FindingsDir, fid+".json"))
	if err != nil {
		return validation.Value{}, false
	}
	if validation.ObjStr(v, "finding_id") != fid {
		return validation.Value{}, false
	}
	return v, true
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
		// Verify the key sets are identical: objAt returns VNull for an
		// ABSENT key, so without this a differing null-valued key (e.g.
		// {a:null} vs {b:null}) would compare equal.
		bkeys := make(map[string]bool, len(b.O))
		for _, kv := range b.O {
			bkeys[kv.K] = true
		}
		for _, kv := range a.O {
			if !bkeys[kv.K] {
				return false
			}
			if !pyEqual(kv.V, validation.ObjAt(b, kv.K)) {
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
