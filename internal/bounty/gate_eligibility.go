// Eligibility gate checks: security-confirmed, snapshot pin, scope,
// known-issue exclusions and the severity floor (checks 1-5).

package bounty

import (
	"websec/internal/validation"
)

// check1 is security-confirmed (deterministic, from finding status).
func (g *gate) check1() {
	if validation.ObjStr(g.f, "status") == "CONFIRMED" {
		g.add("security-confirmed", "pass", "", "")
		return
	}
	g.add("security-confirmed", "fail",
		"status is "+validation.PyStr(validation.ObjAt(g.f, "status")), "")
	g.blockers = append(g.blockers, "finding is not CONFIRMED")
}

// check2 is reachable deployment / snapshot pin.
func (g *gate) check2() error {
	active, err := g.campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return err
	}
	pin := validation.ObjAt(validation.ObjAt(g.f, "snapshot_ids"), "source")
	switch {
	case active != nil && pin.Kind == validation.Str && pin.S == *active:
		g.add("snapshot-pinned", "pass", "", "")
	case active != nil:
		g.add("snapshot-pinned", "fail", "finding pinned to "+
			validation.PyRepr(pin)+", campaign to "+validation.PyReprStr(*active), "")
		g.blockers = append(g.blockers,
			"snapshot mismatch — re-verify against active pin")
	default:
		g.add("snapshot-pinned", "unknown", "campaign has no active snapshot", "")
		g.blockers = append(g.blockers, "no active snapshot pin")
	}
	return nil
}

// check3 is scope. A finding is in scope if ANY of its candidate targets
// (name, path, and the name's structidx-resolved path — B4) matches a scope
// entry; the failure is reported against the primary target (the name, else
// the path) exactly as before.
func (g *gate) check3() error {
	targets := g.scopeTargets()
	if len(targets) == 0 {
		g.add("in-scope", "unknown", "no affected component recorded", "")
		g.blockers = append(g.blockers, "no affected component to scope-check")
		return nil
	}
	primaryWhy := ""
	for i, t := range targets {
		ok, why, err := InScope(g.policy, t)
		if err != nil {
			return err
		}
		if i == 0 {
			primaryWhy = why
		}
		if ok {
			g.add("in-scope", "pass", why, "")
			return nil
		}
	}
	g.add("in-scope", "fail", primaryWhy, "")
	g.blockers = append(g.blockers,
		"target "+validation.PyReprStr(targets[0])+" out of scope")
	return nil
}

// check4 is exclusions / known issues. A same-pattern accepted risk
// suppresses the exclusion (A1: the accepted risk is the narrower, more
// specific rule — the program already decided "we know and we accept", so the
// exclusion tripwire must not re-block it; check13 carries the record and the
// waiver path instead).
func (g *gate) check4() error {
	ex, err := ExclusionHit(g.policy, g.f)
	if err != nil {
		return err
	}
	if ex.Kind == validation.Obj {
		pattern := validation.ObjStr(ex, "pattern")
		ar, err := AcceptedRiskHit(g.policy, g.f)
		if err != nil {
			return err
		}
		if ar.Kind == validation.Obj && validation.ObjStr(ar, "pattern") == pattern {
			g.add("known-issue-check", "pass", "exclusion "+
				validation.PyReprStr(pattern)+" suppressed — an accepted risk "+
				"with the same pattern is the narrower rule (check "+
				"accepted-risk)", "")
			return nil
		}
		kind := validation.ObjAt(ex, "kind")
		g.add("known-issue-check", "fail", "matches exclusion "+
			validation.PyReprStr(pattern)+" ("+validation.PyStr(kind)+")", "")
		g.blockers = append(g.blockers,
			"excluded: "+validation.PyStr(kind)+" — "+pattern)
		return nil
	}
	g.add("known-issue-check", "pass", "no exclusion pattern matched", "")
	return nil
}

// check5 is the severity floor.
func (g *gate) check5() error {
	sev, why, err := SeverityFor(g.policy, g.f)
	if err != nil {
		return err
	}
	if sev != "" {
		g.add("severity-floor", "pass", why, "")
		return nil
	}
	g.add("severity-floor", "human-review",
		"no deterministic severity rule matched — read program terms", "")
	g.blockers = append(g.blockers, "severity not established by policy rules")
	return nil
}
