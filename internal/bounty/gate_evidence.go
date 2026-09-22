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
	if err := g.check6Economic(req); err != nil {
		return err
	}
	return g.check6ExploitContract(req)
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

// evidenceTypeClass is check6ExploitContract's classification of one member of
// the finding schema's evidence_item type enum. The discriminator is the
// clause's own spec (docs/superpowers/plans/2026-09-21-v16-p1-p2-record-and-
// evidence.md): a RUNNABLE exploit contract is one a TRIAGER CAN EXECUTE —
// "not a trace, a reasoning note or a static-analysis hit".
// framework-plan-v1.6.md:315,417 uses the same word of the PoC a report
// carries ("runnable pinned-block fork PoC").
//
// Runnable therefore means the type names an artifact the triager runs
// themselves (a test, a harness, a contract). It does NOT mean the item was
// produced by a run: every item may cite an exec, and a trace cites one by
// construction — a recorded command is a recording, not the contract.
//
// symbolic-witness and differential are the two judgement calls. The repo's
// rule is "is there a documented re-run command?". symbolic-witness has one
// (RUNBOOK: a mapped counterexample writes the runnable bridged PoC that
// `webv2 sequence run` consumes, and `minicertora <C.sol> <INV.mspec>` replays
// the rule); differential has none (its only mention is the group table —
// framework-plan-v1.6.md:209 defines it as a comparison, "diff vs prior audited
// version"), so it is a comparison result, not a contract.
type evidenceTypeClass struct {
	runnable bool
	why      string
}

// evidenceTypeClasses classifies EVERY member of
// assets/schema/finding.schema.json ->
// definitions.evidence_item.properties.type.enum.
// TestExploitContractTableCoversTheWholeEnum reads that enum and fails unless
// this table's key set is EXACTLY the enum's member set, so a fifteenth member
// cannot be added without someone classifying it here.
var evidenceTypeClasses = map[string]evidenceTypeClass{
	"reasoning":         {false, "a reasoning note — the spec names it as not runnable"},
	"static-analysis":   {false, "an analysis hit — the spec names it as not runnable"},
	"reachability":      {false, "an E2 static verdict on whether a path is reachable, with no artifact to run"},
	"unit-test":         {true, "a test file the triager executes"},
	"foundry-test":      {true, "a forge test the triager executes"},
	"fuzz":              {true, "a fuzz harness the triager executes"},
	"invariant-test":    {true, "an invariant harness the triager executes"},
	"symbolic-witness":  {true, "a counterexample with a documented replay: minicertora <C.sol> <INV.mspec>, or the bridged poc via `webv2 sequence run`"},
	"fork-test":         {true, "a forge test the triager executes against the pinned fork"},
	"trace":             {false, "a trace — the spec names it as not runnable"},
	"balance-delta":     {false, "a measured delta: a result about a run, minted with no command"},
	"differential":      {false, "a comparison verdict between two runs — a result, with no documented re-run command"},
	"historical-analog": {false, "an analogy to a past incident — a note, not an artifact"},
	"manual":            {false, "a human attestation — not a machine artifact"},
}

// check6ExploitContract is the require_exploit_contract clause of check 6: the
// program asks for a RUNNABLE exploit contract a triager can execute, not a
// trace, a reasoning note or a static-analysis hit. Absent/false is a no-op,
// so no existing campaign's check set changes. An unclassified type (one this
// build has never seen) is not runnable: the table is pinned to the schema
// enum, and the clause fails closed on the unknown.
func (g *gate) check6ExploitContract(req validation.Value) error {
	if !pyTruthyBigNonEmpty(validation.ObjAt(req, "require_exploit_contract")) {
		return nil
	}
	for _, e := range validation.ObjAt(g.f, "evidence").A {
		if evidenceTypeClasses[validation.ObjStr(e, "type")].runnable {
			g.add("exploit-contract", "pass",
				"runnable contract "+validation.ObjStr(e, "evidence_id"), "")
			return nil
		}
	}
	g.add("exploit-contract", "fail", "no runnable exploit contract", "")
	// The refusal names NO set: a parenthetical list of accepted types goes
	// stale the moment the vocabulary moves, and a stale list in a record is
	// exactly the false statement this clause exists to avoid.
	g.blockers = append(g.blockers,
		"program requires a runnable exploit contract: evidence a triager can execute")
	return nil
}
