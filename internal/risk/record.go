// Risk — recording impact: economic-impact and unpriceable decisions, calibration, and E7 evidence minting (split from risk.go; pure structural move).

package risk

import (
	"fmt"

	"unicode/utf8"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// RecordEconomicImpact is record_economic_impact: record quantified impact
// numbers on a finding, then recalibrate. Each number is a validation.Value
// so Python's None (VNull) and the int-vs-float identity of the caller's
// kwarg survive: the finding stores float(v), the event keeps the literal.
//
// The quantification step is a real stage of the workflow (E7 cites it),
// but nothing before this wrote those numbers through an API — operators
// hand-edited finding JSON, which the schema only half-guarded.
//
// A priced record also REVERSES a previous unpriceable decision (the
// latest decision wins, the floors pattern): priceable flips back to true,
// the ceiling basis is dropped, and the log keeps both events. A finding
// that never carried the decision is written exactly as before — no new
// key — so old behaviour is byte-identical.
// refuseClassWeightKeys is the G2 class-weights boundary for caller-supplied
// Values: RecordEconomicImpact's USD inputs arrive from CLI flag parsing, so
// any class-weights-table key (severity_default / class_weights / classes)
// smuggled into them is refused here, naming the key. The walk is recursive
// to the capped depth below, so a key buried at any realistic nesting depth
// is still caught. Legitimate inputs are scalars or null and never carry
// these keys.
// refusalWalkMaxDepth caps the G2 refusal walk below — the same cap as the
// floors boundary (internal/floors refuseWalk). Legitimate risk inputs are
// scalars or null (depth 0), so the cap never fires on real traffic — it
// only bounds pathological nesting, fail-closed.
const refusalWalkMaxDepth = 32

// refuseWalk visits every Obj key and Arr element of v down to
// refusalWalkMaxDepth and refuses any class-weights-table key, naming it.
func refuseWalk(v validation.Value, depth int) error {
	if depth > refusalWalkMaxDepth {
		return fmt.Errorf("risk input exceeds max nesting depth %d "+
			"(refused as smuggled shape)", refusalWalkMaxDepth)
	}
	switch v.Kind {
	case validation.Obj:
		for _, kv := range v.O {
			if kv.K == "severity_default" || kv.K == "class_weights" ||
				kv.K == "classes" {
				return fmt.Errorf("risk input must not contain %q "+
					"(severity_default is display-only; class weights live "+
					"in the class-weights table, never in a risk decision)",
					kv.K)
			}
			if err := refuseWalk(kv.V, depth+1); err != nil {
				return err
			}
		}
	case validation.Arr:
		for _, e := range v.A {
			if err := refuseWalk(e, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// refuseClassWeightKeys runs the capped refuseWalk over each caller-supplied
// Value (RecordEconomicImpact's three USD inputs).
func refuseClassWeightKeys(vs ...validation.Value) error {
	for _, v := range vs {
		if err := refuseWalk(v, 0); err != nil {
			return err
		}
	}
	return nil
}

func RecordEconomicImpact(campaign *state.Campaign, findingID string,
	extractableUSD, maxLossUSD, requiredCapitalUSD validation.Value) (validation.Value, error) {
	if err := refuseClassWeightKeys(extractableUSD, maxLossUSD,
		requiredCapitalUSD); err != nil {
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ii, err := ensureObjField(&f.O, "economic_impact")
	if err != nil {
		return validation.VNull(), err
	}
	impact := &f.O[ii].V.O
	reversedUnpriceable := false
	if p := validation.ObjAt(f.O[ii].V, "priceable"); p.Kind == validation.Bool && !p.B {
		reversedUnpriceable = true
	}
	if reversedUnpriceable {
		*impact = validation.SetOrAppend(*impact, "priceable", validation.VBool(true))
		*impact = popKey(*impact, "ceiling")
	}
	if err := setFloatField(impact, "extractable_usd", extractableUSD); err != nil {
		return validation.VNull(), err
	}
	if err := setFloatField(impact, "max_loss_usd", maxLossUSD); err != nil {
		return validation.VNull(), err
	}
	if requiredCapitalUSD.Kind != validation.Null {
		ai, err := ensureObjField(&f.O, "attacker")
		if err != nil {
			return validation.VNull(), err
		}
		if err := setFloatField(&f.O[ai].V.O, "required_capital_usd",
			requiredCapitalUSD); err != nil {
			return validation.VNull(), err
		}
	}
	// r40: the finding file is the state half of the pair; Calibrate's own
	// save+log sits inside the log closure, so a refusal ANYWHERE in the
	// chain unwinds the whole verb back to its pre-write bytes (Calibrate's
	// own SaveThenLog restores its step, then this one restores the verb's).
	if err := findings.SaveThenLog(campaign, &f, func() error {
		if _, err := Calibrate(campaign, findingID); err != nil {
			return err
		}
		data := validation.VObj(
			validation.KV{K: "extractable_usd", V: extractableUSD},
			validation.KV{K: "max_loss_usd", V: maxLossUSD},
		)
		if reversedUnpriceable {
			data.O = append(data.O, validation.KV{K: "reversed_unpriceable",
				V: validation.VBool(true)})
		}
		_, lerr := campaign.Log("finding.impact_recorded", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return findings.LoadFinding(campaign, findingID)
}

// RecordUnpriceable is record_unpriceable: record the NAMED DECISION that
// this impact cannot be priced.
//
// PORT-NOTE (b22ca95): two surfaces of the same Python commit are NOT in
// this port because their Go homes do not exist yet — report.py::generate
// prints "- economically extractable: UNPRICEABLE (ceiling: ...)" where the
// figure used to print, and cli.py's `impact --unpriceable` flag surface
// (exit 2 for a missing --ceiling/--reason/--actor or a priced flag passed
// alongside) plus `gate --dry-run`'s "satisfied by NAMED DECISION (actor
// ..., reason: ...)" line belong to the CLI/report tasks. Both read the
// decision through findings.UnpriceableDecision; the API-level refusal
// messages below are the same strings those surfaces print.
//
// E7 is a quantification, and for some findings the honest quantification
// is "no defensible number exists" — the run-7 case was a value sitting in
// an address[255] test constant, where the CLI's demand for a USD figure
// produced invented precision. This is the sanctioned alternative to that
// theatre: the decision is DATA (economic_impact.priceable false + the
// ceiling basis it was made against), attributed to a named actor,
// reasoned in writing, and logged as one finding.unpriceable event — the
// same discipline as floors.set_floor_policy and completion.waive.
//
// The decision supersedes any earlier figure: an unpriceable finding must
// not keep a number that costs/bounty severity rules would still treat as
// confirmed money. The superseded numbers stay recoverable from the
// finding.impact_recorded events on the log.
//
// findings.UnpriceableDecision reads this back (state only, like
// floors.floor_override); audit cross-checks it against the log, so a
// hand-edited priceable: false is caught exactly like a hand-edited floor
// policy.
func RecordUnpriceable(campaign *state.Campaign, findingID, ceiling, reason,
	actor string) (validation.Value, error) {
	ceiling = validation.PyStrip(ceiling)
	reason = validation.PyStrip(reason)
	actor = validation.PyStrip(actor)
	if ceiling == "" {
		return validation.VNull(), fmt.Errorf("an unpriceable decision " +
			"must state the capacity basis it was made against (--ceiling)")
	}
	if utf8.RuneCountInString(reason) < 10 {
		return validation.VNull(), fmt.Errorf("an unpriceable decision " +
			"needs a written reason (>=10 chars): the point is the audit " +
			"trail, not the bypass")
	}
	if actor == "" {
		return validation.VNull(), fmt.Errorf("an unpriceable decision " +
			"must name its actor (who decided this)")
	}
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ii, err := ensureObjField(&f.O, "economic_impact")
	if err != nil {
		return validation.VNull(), err
	}
	impact := &f.O[ii].V.O
	*impact = validation.SetOrAppend(*impact, "priceable", validation.VBool(false))
	*impact = validation.SetOrAppend(*impact, "ceiling", validation.VStr(ceiling))
	*impact = popKey(*impact, "extractable_usd")
	*impact = popKey(*impact, "max_loss_usd")
	// r40: priceable:false IS the named decision and findings.UnpriceableDecision
	// reads it back state-only — a decision on disk without its event is
	// byte-for-byte the hand-edited shape audit red-lines. Unwind on
	// refusal; Calibrate nests inside the log closure (same as
	// RecordEconomicImpact).
	if err := findings.SaveThenLog(campaign, &f, func() error {
		if _, err := Calibrate(campaign, findingID); err != nil {
			return err
		}
		data := validation.VObj(
			validation.KV{K: "finding", V: validation.VStr(findingID)},
			validation.KV{K: "ceiling", V: validation.VStr(ceiling)},
			validation.KV{K: "reason", V: validation.VStr(reason)},
			validation.KV{K: "actor", V: validation.VStr(actor)},
		)
		_, lerr := campaign.Log("finding.unpriceable", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return findings.LoadFinding(campaign, findingID)
}

// Calibrate is calibrate: compute and store all three passes plus the
// advisory impact vector, then log finding.calibrated.
func Calibrate(campaign *state.Campaign, findingID string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	impact := orObj(validation.ObjAt(f, "economic_impact"))
	ri, err := ensureObjField(&f.O, "risk")
	if err != nil {
		return validation.VNull(), err
	}
	riskV := f.O[ri].V
	validated, err := ValidatedRisk(f)
	if err != nil {
		return validation.VNull(), err
	}
	riskV.O = validation.SetOrAppend(riskV.O, "validated", validated)
	econ, err := economicRisk(validation.ObjAt(impact, "max_loss_usd"),
		validation.ObjAt(impact, "extractable_usd"),
		validation.ObjAt(orObj(validation.ObjAt(f, "attacker")), "required_capital_usd"))
	if err != nil {
		return validation.VNull(), err
	}
	riskV.O = validation.SetOrAppend(riskV.O, "economic", econ)
	iv, err := ImpactVector(f)
	if err != nil {
		return validation.VNull(), err
	}
	riskV.O = validation.SetOrAppend(riskV.O, "impact_vector", iv)
	f.O[ri].V = riskV
	// r40: the risk block (band included) is gate-read state; a stored
	// calibration without its finding.calibrated event is a verdict the
	// ledger never issued. Unwind on refusal.
	data := validation.VObj(validation.KV{K: "band", V: validation.ObjAt(validated, "band")})
	if err := findings.SaveThenLog(campaign, &f, func() error {
		_, lerr := campaign.Log("finding.calibrated", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return riskV, nil
}

// MintImpactEvidence is mint_impact_evidence: mint E7 — the economic impact
// is quantified against a recorded artifact. E7 is ANALYSIS evidence (no
// execution created it), so instead of a sandbox profile it must cite an
// artifact registered in this campaign.
func MintImpactEvidence(campaign *state.Campaign, findingID, artifactID,
	description string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	impact := orObj(validation.ObjAt(f, "economic_impact"))
	if isNoneField(impact, "extractable_usd") && isNoneField(impact, "max_loss_usd") {
		return validation.VNull(), fmt.Errorf("cannot mint E7 on %s: no "+
			"economic_impact numbers recorded (set extractable_usd and/or "+
			"max_loss_usd first)", findingID)
	}
	if _, err := campaign.Artifact(artifactID); err != nil {
		return validation.VNull(), err
	}
	level, err := findings.FindingLevel(f)
	if err != nil {
		return validation.VNull(), err
	}
	item := validation.VObj(
		validation.KV{K: "evidence_id",
			V: validation.VStr("EV-" + idTail(state.NewID("x", 8)))},
		validation.KV{K: "level", V: validation.VStr("E7")},
		validation.KV{K: "type", V: validation.VStr("balance-delta")},
		validation.KV{K: "artifact_id", V: validation.VStr(artifactID)},
		validation.KV{K: "description", V: validation.VStr(description)},
		validation.KV{K: "produced_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "snapshot_id", V: snapshotSource(f)},
	)
	out, err := findings.AddEvidence(campaign, findingID, item)
	if err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "artifact_id", V: validation.VStr(artifactID)},
		validation.KV{K: "from_level", V: validation.VStr(level)},
	)
	if _, err := campaign.Log("finding.impact_quantified", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return out, nil
}

// ---- helpers -------------------------------------------------------------
