// Evidence-sufficiency gate check (check6): required vs. reached evidence
// tier, fork-repro and economic-quantification clauses.

package bounty

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/validation"
)

// needLevel is req.get("min_evidence_level", "E4") with the ValueError text
// level_index raises for a non-string level.
func needLevel(req validation.Value) (string, error) {
	v := getDefault(req, "min_evidence_level", validation.VStr("E4"))
	if v.Kind == validation.Str {
		return v.S, nil
	}
	return "", fmt.Errorf("unknown evidence level %s; the ladder is %s",
		validation.PyRepr(v), strings.Join(findings.EVIDENCE_ORDER, "/"))
}

// check6 is evidence sufficiency (policy-level, stricter than the CONFIRMED
// floor).
func (g *gate) check6() error {
	req := validation.ObjAt(g.policy, "poc_requirements")
	need, err := needLevel(req)
	if err != nil {
		return err
	}
	have, err := findings.FindingLevel(g.f)
	if err != nil {
		return err
	}
	hi, err := findings.LevelIndex(have)
	if err != nil {
		return err
	}
	ni, err := findings.LevelIndex(need)
	if err != nil {
		return err
	}
	if hi >= ni {
		g.add("evidence-sufficient", "pass",
			fmt.Sprintf("%s >= required %s", have, need), "")
	} else {
		g.add("evidence-sufficient", "fail",
			fmt.Sprintf("%s < required %s", have, need), "")
		g.blockers = append(g.blockers,
			fmt.Sprintf("evidence %s below program floor %s", have, need))
	}
	if err := g.check6Fork(req); err != nil {
		return err
	}
	return g.check6Economic(req)
}

// check6Fork is the require_fork_repro clause of check 6.
func (g *gate) check6Fork(req validation.Value) error {
	if !pyTruthyBigNonEmpty(validation.ObjAt(req, "require_fork_repro")) {
		return nil
	}
	repro := validation.ObjAt(validation.ObjAt(g.f, "verification"), "reproduction")
	tier := getDefault(repro, "tier_reached", validation.VStr("none"))
	if tier.Kind == validation.Str && (tier.S == "T3" || tier.S == "T4") {
		g.add("fork-repro", "pass", "tier "+tier.S, "")
		return nil
	}
	g.add("fork-repro", "fail", "repro tier "+validation.PyStr(tier)+
		", program requires T3+", "")
	g.blockers = append(g.blockers, "program requires fork-based reproduction")
	return nil
}

// check6Economic is the require_economic_quantification clause of check 6.
func (g *gate) check6Economic(req validation.Value) error {
	if !pyTruthyBigNonEmpty(validation.ObjAt(req, "require_economic_quantification")) {
		return nil
	}
	usd := validation.ObjAt(validation.ObjAt(g.f, "economic_impact"), "extractable_usd")
	floor := validation.ObjAt(req, "min_extractable_usd")
	ok := usd.Kind != validation.Null
	if ok && floor.Kind != validation.Null {
		got, okGot := pyFloat(usd)
		want, okWant := pyFloat(floor)
		ok = okGot && okWant && got >= want
	}
	if ok {
		g.add("economic-quantified", "pass", "", "")
		return nil
	}
	g.add("economic-quantified", "fail", "extractable_usd missing or below floor", "")
	g.blockers = append(g.blockers,
		"economic impact not quantified to program floor")
	return nil
}
