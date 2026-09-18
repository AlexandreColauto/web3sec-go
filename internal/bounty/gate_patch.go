// The patch/immunization gate check (check12): verification, prose or
// none, per the program's patch clause (IMPROVEMENTS D8).

package bounty

// check12 is the patch clause (IMPROVEMENTS D8): what the TARGET PROGRAM
// asks for, not one framework-wide bar.
//
//	verification (the default when poc_requirements.patch_clause is absent) —
//	  the patch BLOCKS the fork PoC and all 3 boundary mutations. A patch that
//	  only blocks a unit test is not a patch.
//	prose — a written recommendation on the finding
//	  (verification.recommendation, >= minRecommendationRunes) clears it; the
//	  boundary-mutation record becomes an advisory line, not a blocker.
//	none — the program does not ask for a fix; nothing is required.
//
// Like its siblings, an explicit waiver (stage "immunization") records the
// check as passed-waived rather than failed (B1: with the fork PoC waived,
// this unconditional requirement made submission_ready permanently
// unreachable). The verification branch is byte-identical to the pre-D8
// check, so a policy without the new key gates exactly as it always did.
func (g *gate) check12() error {
	mode, err := patchClause(g.policy)
	if err != nil {
		return err
	}
	switch mode {
	case "prose":
		return g.check12Prose()
	case "none":
		g.add("immunization", "pass", "no fix requested by this program ("+
			g.programLabel()+") — poc_requirements.patch_clause is `none`", "")
		if adv := boundaryAdvisory(g.f); adv != "" {
			g.advisories = append(g.advisories, adv)
		}
		return nil
	}
	state, detail := immunizationDetailFunc(g.f)
	if state == "immunized" {
		g.add("immunization", "pass", detail, "")
		return nil
	}
	ok, err := g.waived("immunization")
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	g.add("immunization", "fail", state+": "+detail, "")
	g.blockers = append(g.blockers, "not immunized ("+state+") — the patch "+
		"must block the FORK PoC and its 3 boundary mutations")
	return nil
}

// check12Prose is the `prose` mode: the program wants a recommendation, so
// that is what the gate reads.
func (g *gate) check12Prose() error {
	rec := recommendation(g.f)
	if recommendationOK(g.f) {
		g.add("immunization", "pass", "recommendation recorded ("+
			g.programLabel()+" asks for prose, not a tested patch): "+
			headRunes(rec, 80), "")
		if adv := boundaryAdvisory(g.f); adv != "" {
			g.advisories = append(g.advisories, adv)
		}
		return nil
	}
	ok, err := g.waived("immunization")
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	g.add("immunization", "fail", "no written recommendation: "+
		g.programLabel()+" asks for the minimal fix in prose "+
		"(verification.recommendation, >= "+itoa(minRecommendationRunes)+
		" chars) and the finding does not carry one", "")
	g.blockers = append(g.blockers,
		"no written recommendation (the program's patch clause is `prose`)")
	return nil
}
