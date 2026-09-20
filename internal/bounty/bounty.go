// Package bounty ports webv2.bounty_policy: the bounty policy engine + the
// final gate.
//
// "Is this a real bug" and "is this submission-ready against THIS program's
// rules" are different questions. This package answers the second one,
// deterministically, from a machine-readable policy:
//
//	SECURITY CONFIRMED + BOUNTY ELIGIBLE + EVIDENCE SUFFICIENT = SUBMISSION READY
//
// The matching is deliberately simple (substring/keyword on class, title,
// description) so behavior is predictable and testable. `unknown` results are
// surface for human review, never treated as pass. Always read the actual
// program page before submitting — known-issue and severity-floor calls are
// the two checks most likely to need human judgment.
package bounty

import (
	"strconv"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// gate accumulates one evaluate_bounty_gate run: the ordered check rows and
// the blocking reasons.
type gate struct {
	campaign *state.Campaign
	policy   validation.Value
	f        validation.Value
	checks   []validation.Value
	blockers []string
	// advisories are non-blocking notes a check wants surfaced on the
	// finding's bounty.advisories (A2's shape, D8's boundary mutations).
	advisories []string
}

// add is the Python closure: an entry always carries its detail, and a
// non-pass result carries a remediation (the explicit one, else the catalog's).
func (g *gate) add(name, result, detail, remediation string) {
	entry := validation.VObj(
		validation.KV{K: "check", V: validation.VStr(name)},
		validation.KV{K: "result", V: validation.VStr(result)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
	)
	if (result == "fail" || result == "unknown" || result == "human-review") &&
		remediation == "" {
		cid := ""
		if g.campaign != nil {
			cid = g.campaign.CampaignID
		}
		remediation = findings.NameCampaign(BountyRemediation[name], cid)
	}
	if remediation != "" {
		entry.O = append(entry.O,
			validation.KV{K: "remediation", V: validation.VStr(remediation)})
	}
	g.checks = append(g.checks, entry)
}

// addWaived records the pass row for a check cleared by a named waiver
// (stage + subject addressed to this finding, with actor and reason on the
// waiver row). It appends *after* the fail row it answers, so the pair has to
// be read through effectiveChecks — see the note there.
func (g *gate) addWaived(check string, w *validation.Value) {
	g.add(check, "pass", "waived by "+validation.PyStr(validation.ObjAt(*w, "actor"))+
		": "+headRunes(validation.PyStr(validation.ObjAt(*w, "reason")), 80), "")
}

// effectiveChecks collapses the policy_checks rows to one row per check name:
// the last row wins, keeping the position of that last row. A waiver appends
// its pass row behind the fail row it answers, so the raw list holds two
// verdicts for one check; reading it verbatim made a waived check permanently
// un-submittable (submission_ready false) while blocking_reasons stayed empty
// — the operator was told "not submittable" with no reason and no way to see
// why. An unwaived fail, and a row with no successor, are unaffected: only a
// later row for the same check supersedes, and it is never a pass that was
// never emitted.
func effectiveChecks(rows []validation.Value) []validation.Value {
	if len(rows) == 0 {
		return rows
	}
	last := make(map[string]int, len(rows))
	for i, c := range rows {
		last[validation.ObjStr(c, "check")] = i
	}
	if len(last) == len(rows) {
		return rows
	}
	out := make([]validation.Value, 0, len(last))
	for i, c := range rows {
		if last[validation.ObjStr(c, "check")] == i {
			out = append(out, c)
		}
	}
	return out
}

// scopeTargets returns the strings the scope policy is matched against for
// this finding, deduplicated and order-preserving. A name-carrying finding is
// matched on the name (the primary target, the pre-B4 behaviour) AND (B4) the
// path the name resolves to via the structural index — so a path-based scope
// entry can match a name-carrying finding (the campaign's false "everything
// is out of scope" was the name never resolving to the path the scope named).
// A nameless finding falls back to its recorded path, exactly as before.
func (g *gate) scopeTargets() []string {
	first := validation.VObj()
	if aff := validation.ObjAt(g.f, "affected"); aff.Kind == validation.Arr && len(aff.A) > 0 {
		first = aff.A[0]
	}
	name := ""
	if c := validation.ObjAt(first, "contract"); c.Kind == validation.Str && c.S != "" {
		name = c.S
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	if name != "" {
		// The name is the primary target (the pre-B4 behaviour — the name
		// takes precedence over the recorded path). B4 adds the path the
		// name resolves to via the structural index, so a path-based scope
		// entry can match a name-carrying finding. The recorded path is NOT
		// a separate candidate: a name-carrying finding is scoped by its
		// name (and where that name lives), not by an independent path field.
		add(name)
		add(contractPathFunc(g.campaign, name))
	} else {
		// No name: fall back to the recorded path (the pre-B4 behaviour).
		add(validation.ObjStr(first, "path"))
	}
	return out
}

// waived records the pass row when a named waiver covers this check. A store
// error is returned, never swallowed: the pre-D8 check aborted the gate on it
// and this helper must not quietly turn that into a plain failure.
func (g *gate) waived(stage string) (bool, error) {
	findingID := validation.ObjStr(g.f, "finding_id")
	rows, err := waiversFunc(g.campaign, stage)
	if err != nil {
		return false, err
	}
	for _, w := range rows {
		subject := validation.ObjStr(w, "subject")
		if subject != "*" && subject != findingID {
			continue
		}
		g.add("immunization", "pass", "waived by "+validation.PyStr(validation.ObjAt(w, "actor"))+
			": "+headRunes(validation.PyStr(validation.ObjAt(w, "reason")), 80), "")
		return true, nil
	}
	return false, nil
}

// programLabel names the target program in a check detail, for the modes whose
// detail text has to be self-explaining ("the framework is not asking for
// this — your program is, or is not").
func (g *gate) programLabel() string {
	if name := validation.ObjStr(g.policy, "program"); name != "" {
		return name
	}
	return "the target program"
}

// check13 is the accepted-risk channel (IMPROVEMENTS A1). A documented,
// program-accepted risk is NOT an exclusion: the finding stays visible and
// counted, but it is not submittable as a vulnerability. On a hit the match
// is recorded on the finding (bounty.accepted_risk) and the check fails with
// a named remediation: waive it (webv2 waive <campaign> accepted-risk
// --subject <finding> --reason ...) once the operator has decided this
// particular finding IS payable. An accepted_risk.min_severity caps the
// acceptance — at that severity and above the acceptance does not apply and
// the gate demands real handling (no record, no waiver path of its own:
// the finding simply has to clear the gate on its merits).
func (g *gate) check13() error {
	ar, err := AcceptedRiskHit(g.policy, g.f)
	if err != nil {
		return err
	}
	if ar.Kind != validation.Obj {
		g.add("accepted-risk", "pass", "no accepted-risk pattern matched", "")
		return nil
	}
	pattern := validation.ObjStr(ar, "pattern")
	kind := validation.PyStr(validation.ObjAt(ar, "kind"))
	if minSev := validation.ObjStr(ar, "min_severity"); minSev != "" {
		sev, _, err := SeverityFor(g.policy, g.f)
		if err != nil {
			return err
		}
		if sev != "" && severityRank(sev) >= severityRank(minSev) {
			g.add("accepted-risk", "fail",
				"matches accepted risk "+validation.PyReprStr(pattern)+" ("+
					kind+") but severity "+sev+" reaches its "+minSev+
					" floor — the acceptance does not apply", "")
			g.blockers = append(g.blockers,
				"accepted risk "+validation.PyReprStr(pattern)+" not "+
					"honored at severity "+sev)
			return nil
		}
	}
	// Record the acceptance on the finding (visible, counted, not
	// submittable) before the waiver decision: a waived finding still
	// carries the record, so the report can show both facts. G7 hygiene
	// (Task 15): reference_url rides the same conditional copy — present
	// in the policy entry means present in the record, absent means the
	// record keeps its old bytes exactly (the fieldAt gate below).
	rec := validation.VObj(
		validation.KV{K: "pattern", V: validation.VStr(pattern)})
	for _, key := range []string{"kind", "reference", "reference_url",
		"note"} {
		if v, ok := fieldAt(ar, key); ok {
			rec.O = append(rec.O, validation.KV{K: key, V: v})
		}
	}
	bounty := validation.ObjAt(g.f, "bounty")
	if bounty.Kind != validation.Obj {
		bounty = validation.VObj()
	}
	bounty.O = validation.SetOrAppend(bounty.O, "accepted_risk", rec)
	g.f.O = validation.SetOrAppend(g.f.O, "bounty", bounty)

	findingID := validation.ObjStr(g.f, "finding_id")
	rows, err := waiversFunc(g.campaign, "accepted-risk")
	if err != nil {
		return err
	}
	for _, w := range rows {
		subject := validation.ObjStr(w, "subject")
		if subject != "*" && subject != findingID {
			continue
		}
		g.add("accepted-risk", "pass", "waived by "+validation.PyStr(validation.ObjAt(w, "actor"))+
			": "+headRunes(validation.PyStr(validation.ObjAt(w, "reason")), 80), "")
		return nil
	}
	g.add("accepted-risk", "fail",
		"matches accepted risk "+validation.PyReprStr(pattern)+" ("+kind+
			") — recorded; not submittable", "")
	g.blockers = append(g.blockers,
		"accepted risk "+validation.PyReprStr(pattern)+" — not "+
			"submittable as a vulnerability")
	return nil
}

// check14 is paid exploitability (IMPROVEMENTS A4): "who pays, and why does
// the bug make them pay?" — the difference between a bug and a bounty
// finding. A CONFIRMED/CHAIN finding claiming extractable_usd > 0 MUST have
// answered the question (exploitability present); a recorded paid=true claim
// MUST carry an argument of at least the minimum length (the setter enforces
// it on write, the gate re-validates the stored value, so a hand-edited field
// cannot sneak past). paid=false with an argument is a legitimate answer —
// it records why the finding is NOT payable. Waivable per-finding (stage
// "paid-exploitability", reason required).
func (g *gate) check14() error {
	status := validation.ObjStr(g.f, "status")
	ext := validation.ObjAt(validation.ObjAt(g.f, "economic_impact"), "extractable_usd")
	extractable := (ext.Kind == validation.Int && (ext.I > 0 || ext.Big != "")) ||
		(ext.Kind == validation.Flt && ext.F > 0)
	findingID := validation.ObjStr(g.f, "finding_id")
	var waiver *validation.Value
	rows, err := waiversFunc(g.campaign, "paid-exploitability")
	if err != nil {
		return err
	}
	for _, w := range rows {
		if subject := validation.ObjStr(w, "subject"); subject == "*" ||
			subject == findingID {
			w := w
			waiver = &w
			break
		}
	}
	exp := validation.ObjAt(g.f, "exploitability")
	if exp.Kind != validation.Obj {
		if (status == "CONFIRMED" || status == "CHAIN") && extractable {
			g.add("paid-exploitability", "fail",
				"CONFIRMED/CHAIN finding with extractable_usd > 0 has no "+
					"exploitability argument — answer: who pays, and why "+
					"does this bug make them pay?", "")
			if waiver != nil {
				g.addWaived("paid-exploitability", waiver)
			} else {
				g.blockers = append(g.blockers,
					"no paid-exploitability argument on an extractable "+
						"finding")
			}
			return nil
		}
		g.add("paid-exploitability", "pass",
			"no extractable claim to answer", "")
		return nil
	}
	paid, paidOk := fieldAt(exp, "paid")
	if !paidOk || paid.Kind != validation.Bool {
		g.add("paid-exploitability", "fail",
			"exploitability present but malformed (paid must be a boolean)",
			"")
		return nil
	}
	n := len([]rune(validation.ObjStr(exp, "argument")))
	if paid.B {
		if n < findings.ExploitabilityArgumentMin {
			g.add("paid-exploitability", "fail",
				"paid=true but the argument is missing or too short ("+
					strconv.Itoa(n)+" < "+
					strconv.Itoa(findings.ExploitabilityArgumentMin)+
					" chars) — say who pays, and why the bug makes them "+
					"pay", "")
			if waiver != nil {
				g.addWaived("paid-exploitability", waiver)
			} else {
				g.blockers = append(g.blockers,
					"paid exploitability argument missing or too short")
			}
			return nil
		}
		g.add("paid-exploitability", "pass",
			"paid — argument recorded ("+strconv.Itoa(n)+" chars)", "")
		return nil
	}
	if n > 0 {
		g.add("paid-exploitability", "pass",
			"not payable — argument records why ("+strconv.Itoa(n)+
				" chars)", "")
		return nil
	}
	g.add("paid-exploitability", "pass", "not payable", "")
	return nil
}

// check15 is the adversarial-game clause (IMPROVEMENTS B2): a liveness
// finding must answer "who profits from the freeze, and why doesn't the
// challenge path undo it?" — the incentive argument that keeps a freeze
// finding from being buried as "liveness-only, the owner can revert". The
// trigger is findings.IsLivenessFinding (class in LivenessClasses, or
// economic_impact.kind == "liveness", or a granted liveness terminal
// capability). The clause is DATA on the finding (adversarial_game, four
// fields, each >= 20 chars); the setter enforces on write and this check
// re-validates the stored value, so a hand-edited field cannot sneak past.
// Waivable per-finding (stage "adversarial-game", reason required) — a
// named, recorded decision that the incentive question was answered
// elsewhere (e.g. in the chain narrative) is legitimate.
//
// morph §7.2: the fourth field (strongest_attacker) is what stops a WRONG
// challenge_interplay from travelling — the run filed "the challenge path
// DOES undo it" and nothing forced the proof-VALID bad-state variant.
func (g *gate) check15() error {
	if !findings.IsLivenessFinding(g.f) {
		g.add("adversarial-game", "pass", "not a liveness finding", "")
		return nil
	}
	findingID := validation.ObjStr(g.f, "finding_id")
	var waiver *validation.Value
	rows, err := waiversFunc(g.campaign, "adversarial-game")
	if err != nil {
		return err
	}
	for _, w := range rows {
		if subject := validation.ObjStr(w, "subject"); subject == "*" ||
			subject == findingID {
			w := w
			waiver = &w
			break
		}
	}
	deficits := findings.AdversarialGameDeficits(g.f)
	if len(deficits) == 0 {
		g.add("adversarial-game", "pass",
			"incentive clause complete (who_profits / profit_mechanism / "+
				"challenge_interplay / strongest_attacker)", "")
		return nil
	}
	detail := "liveness finding is missing the adversarial_game clause"
	if len(deficits) == 1 && deficits[0] != "missing" {
		detail = "adversarial_game." + deficits[0] + " is missing or too " +
			"short (>= " + strconv.Itoa(findings.AdversarialGameFieldMin) +
			" chars required)"
	} else if len(deficits) > 1 {
		detail = "adversarial_game is incomplete: " +
			strings.Join(deficits, ", ") + " missing or too short (each " +
			"field >= " + strconv.Itoa(findings.AdversarialGameFieldMin) +
			" chars)"
	}
	g.add("adversarial-game", "fail", detail, "")
	if waiver != nil {
		g.addWaived("adversarial-game", waiver)
	} else {
		g.blockers = append(g.blockers,
			"liveness finding has no adversarial_game clause (who profits, "+
				"how, and why the challenge path cannot undo it)")
	}
	return nil
}

// run executes the fifteen checks (the twelve ported + accepted-risk (A1)
// + paid-exploitability (A4) + adversarial-game (B2)).
func (g *gate) run() error {
	g.check1()
	for _, check := range []func() error{g.check2, g.check3, g.check4, g.check5,
		g.check6, g.check7, g.check8, g.check9, g.check10, g.check11,
		g.check12, g.check13, g.check14, g.check15} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// EvaluateBountyGate is evaluate_bounty_gate: the full bounty gate. Produces
// bounty.eligible, bounty.submission_ready and bounty.blocking_reasons. Check
// results are pass / fail / unknown / human-review; `unknown` never becomes
// pass. Every failing check carries a remediation (K): the exact command that
// clears it.
func EvaluateBountyGate(campaign *state.Campaign, findingID string,
	policy validation.Value, save bool) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	g := &gate{campaign: campaign, policy: policy, f: f}
	if err := g.run(); err != nil {
		return validation.VNull(), err
	}
	// The checks run on a struct copy of the finding (the gate's f shares
	// the top-level KV slice but a check may re-append to it — check13
	// records the accepted risk when the finding had no bounty object yet).
	// Re-adopt the gate's copy so the record reaches the save below.
	f = g.f
	effective := effectiveChecks(g.checks)
	eligible := true
	for _, c := range effective {
		if validation.ObjStr(c, "result") != "fail" {
			continue
		}
		switch validation.ObjStr(c, "check") {
		case "security-confirmed", "in-scope", "known-issue-check":
			eligible = false
		}
	}
	submissionReady := len(g.blockers) == 0
	for _, c := range effective {
		if validation.ObjStr(c, "result") != "pass" {
			submissionReady = false
			break
		}
	}
	bounty := validation.ObjAt(f, "bounty")
	if bounty.Kind != validation.Obj {
		bounty = validation.VObj()
	}
	// A2 advisory: an in-code acknowledgement (dedup_meta.in_code_ack)
	// demotes acceptance likelihood. Advisory only — it never blocks: the
	// owner's own comment is context for the reviewer, not a gate condition.
	if ack := validation.ObjAt(validation.ObjAt(f, "dedup_meta"), "in_code_ack"); ack.Kind ==
		validation.Obj {
		bounty.O = validation.SetOrAppend(bounty.O, "advisories", strList(
			[]string{"in_code_ack present: acceptance likelihood demoted"}))
	}
	// D8: advisories raised by the checks themselves (the boundary-mutation
	// record under a prose/none patch clause). Advisory only, same channel.
	if len(g.advisories) > 0 {
		combined := []string{}
		if cur := validation.ObjAt(bounty, "advisories"); cur.Kind == validation.Arr {
			for _, v := range cur.A {
				combined = append(combined, validation.PyStr(v))
			}
		}
		combined = append(combined, g.advisories...)
		bounty.O = validation.SetOrAppend(bounty.O, "advisories", strList(combined))
	}
	// A3: the deterministic acceptance score, stored on the finding at gate
	// time (the report and `webv2 rank` recompute it live, so the stored
	// number is the gate's audit trail, not the source of truth).
	// Policy-gated (G3): acceptance_priors true carries the class prior.
	score, _ := gateAcceptance(f, g.policy)
	riskObj := validation.ObjAt(f, "risk")
	if riskObj.Kind != validation.Obj {
		riskObj = validation.VObj()
	}
	riskObj.O = validation.SetOrAppend(riskObj.O, "acceptance_score",
		validation.VFloat(validation.PythonRound(score, 2)))
	f.O = validation.SetOrAppend(f.O, "risk", riskObj)
	bounty.O = validation.SetOrAppend(bounty.O, "eligible", validation.VBool(eligible))
	bounty.O = validation.SetOrAppend(bounty.O, "submission_ready",
		validation.VBool(submissionReady))
	bounty.O = validation.SetOrAppend(bounty.O, "blocking_reasons", strList(g.blockers))
	bounty.O = validation.SetOrAppend(bounty.O, "policy_checks",
		validation.Value{Kind: validation.Arr, A: g.checks})
	f.O = validation.SetOrAppend(f.O, "bounty", bounty)
	if save {
		// r18 P2 sweep: gate stamped on the finding with no bounty.gate
		// event = a payout decision the ledger cannot replay. Unwind law.
		data := validation.VObj(
			validation.KV{K: "eligible", V: validation.VBool(eligible)},
			validation.KV{K: "submission_ready", V: validation.VBool(submissionReady)},
			validation.KV{K: "blockers", V: strList(g.blockers)},
		)
		if err := findings.SaveThenLog(campaign, &f, func() error {
			_, lerr := campaign.Log("bounty.gate", &findingID, &data)
			return lerr
		}); err != nil {
			return validation.VNull(), err
		}
	}
	return bounty, nil
}

// strList renders a []string as a JSON array value ([] when empty).
func strList(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.Value{Kind: validation.Arr, A: out}
}
