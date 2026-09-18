// Ladder-facing gate checks: maximal exploitation (check7) and the
// precondition audit (check10), plus the ladder disposition helper.

package bounty

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ladderDisposition is _ladder_disposition: (state, ladder) where the state
// defaults to "open" and "missing" means no ladder row at all.
func ladderDisposition(campaign *state.Campaign,
	f validation.Value) (string, validation.Value, error) {
	lad, err := loadLadderFunc(campaign, validation.ObjStr(f, "finding_id"))
	if err != nil {
		return "", validation.VNull(), err
	}
	if lad.Kind == validation.Null {
		return "missing", validation.VNull(), nil
	}
	stateV := validation.ObjAt(validation.ObjAt(lad, "disposition"), "state")
	st := "open"
	if pyTruthyBigNonEmpty(stateV) {
		st = validation.PyStr(stateV)
	}
	return st, lad, nil
}

// maximalAxes is the five axes a closed ladder must have explored.
var maximalAxes = []string{"capital-minimization", "precondition-removal",
	"role-conflation", "ordering-permutation", "cap-saturation"}

// check7 is maximal exploitation (A) — a CONFIRMED finding ships its MAXIMAL
// claim: every ladder rung the operator believed in is either reproduced (and
// pinned) or disproved, all five axes explored, the ladder closed — or the
// closure is an explicit, named waiver.
func (g *gate) check7() error {
	if validation.ObjStr(g.f, "status") != "CONFIRMED" {
		return nil
	}
	disposition, lad, err := ladderDisposition(g.campaign, g.f)
	if err != nil {
		return err
	}
	switch disposition {
	case "complete":
		g.add("maximal-exploitation", "pass",
			"ladder closed (maximal: "+validation.PyStr(validation.ObjAt(lad, "maximal_rung_id"))+")", "")
	case "waived":
		reason := validation.ObjAt(validation.ObjAt(lad, "disposition"), "reason")
		if !pyTruthyBigNonEmpty(reason) {
			reason = validation.VStr("")
		}
		g.add("maximal-exploitation", "pass", "ladder waived: "+
			headRunes(validation.PyStr(reason), 80), "")
	case "missing":
		g.add("maximal-exploitation", "fail", "no variant ladder — the claim "+
			"may still be a base-rung artifact (run-1: 50% at $2.5k claimed; "+
			"100% at 1 wei true)", "")
		g.blockers = append(g.blockers,
			"variant ladder missing for a CONFIRMED finding")
	default:
		explored := validation.ObjAt(lad, "axes_explored")
		var openAxes []string
		for _, a := range maximalAxes {
			if !inStringList(explored, a) {
				openAxes = append(openAxes, a)
			}
		}
		detail := "ladder " + disposition
		if len(openAxes) > 0 {
			detail += "; unexplored axes: " + validation.PyListRepr(openAxes)
		}
		g.add("maximal-exploitation", "fail", detail, "")
		g.blockers = append(g.blockers,
			"variant ladder not closed (complete or waived)")
	}
	return nil
}

// falsePreconditions is f.get("preconditions", []) filtered to the audited
// "the code never enforces this" rows.
func falsePreconditions(f validation.Value) []validation.Value {
	var out []validation.Value
	for _, p := range validation.ObjAt(f, "preconditions").A {
		if validation.ObjStr(p, "enforced_by_poc") == "false" {
			out = append(out, p)
		}
	}
	return out
}

// removedPreconditions is every variant's removed_preconditions, flattened.
func removedPreconditions(lad validation.Value) []string {
	var out []string
	for _, v := range validation.ObjAt(lad, "variants").A {
		for _, r := range validation.ObjAt(v, "removed_preconditions").A {
			if r.Kind == validation.Str {
				out = append(out, r.S)
			}
		}
	}
	return out
}

// check10 is the precondition audit (C) — every precondition the PoC ASSUMED
// but the code never enforced must be closed: removed by a ladder rung, or
// covered by the ladder's waiver.
func (g *gate) check10() error {
	falsePre := falsePreconditions(g.f)
	if len(falsePre) == 0 {
		g.add("precondition-audit", "pass", "", "")
		return nil
	}
	disposition, lad, err := ladderDisposition(g.campaign, g.f)
	if err != nil {
		return err
	}
	if disposition == "waived" {
		g.add("precondition-audit", "pass", fmt.Sprintf(
			"%d code-unenforced precondition(s) covered by the ladder waiver",
			len(falsePre)), "")
		return nil
	}
	removed := removedPreconditions(lad)
	var openPre []string
	for _, p := range falsePre {
		desc := validation.ObjStr(p, "description")
		closed := false
		for _, r := range removed {
			if strings.Contains(desc, r) || strings.Contains(r, desc) {
				closed = true
				break
			}
		}
		if !closed {
			openPre = append(openPre, desc)
		}
	}
	if len(openPre) > 0 {
		g.add("precondition-audit", "fail", "precondition(s) the code never "+
			"enforces, unaddressed by any ladder rung: "+
			strings.Join(openPre, "; "), "")
		g.blockers = append(g.blockers,
			"unaudited preconditions unaddressed by the ladder")
		return nil
	}
	g.add("precondition-audit", "pass", fmt.Sprintf(
		"all %d code-unenforced preconditions addressed by ladder rungs",
		len(falsePre)), "")
	return nil
}
