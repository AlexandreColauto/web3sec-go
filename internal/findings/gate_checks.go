// gate_checks.go: the CONFIRMED gate's per-check clause helpers — the
// gateRun methods over critic verdict, memory, reproduction, evidence
// floor, tiers, sequence coverage, snapshot compatibility, shield,
// invariants, and claim drift (webv2.findings).
package findings

import (
	"fmt"
	"strings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// gateRun carries the gate state across the per-check helpers so each stays
// well under the length limit.
type gateRun struct {
	campaign *state.Campaign
	finding  validation.Value
	out      []Clause
}

// remediation renders the catalog entry for checkID with the campaign id the
// run holds, so a printed fix line is a command the operator can copy.
func (g *gateRun) remediation(checkID string) string {
	cid := ""
	if g.campaign != nil {
		cid = g.campaign.CampaignID
	}
	return NameCampaign(GATE_REMEDIATION[checkID], cid)
}

func (g *gateRun) fail(checkID, message string, subject *string) {
	g.out = append(g.out, Clause{CheckID: checkID, OK: false, Message: message,
		Remediation: g.remediation(checkID), Subject: subject})
}

func (g *gateRun) satisfied(checkID string, subject *string) {
	g.out = append(g.out, Clause{CheckID: checkID, OK: true,
		Remediation: g.remediation(checkID), Subject: subject})
}

// failWith appends a failing clause whose remediation is computed from the
// finding at hand instead of read from the static catalog. B10(a) is the one
// check that needs it: its heal names the ROW'S OWN priority, which no static
// entry can carry — and GATE_REMEDIATION is byte-pinned to its 11 ids by
// bounty's TestGateExplainCatalogByteExact, so the catalog is not the place
// for a per-row command. The per-row heal is still a real command, pinned by
// TestProbeAnchorHealNamesRealCommand.
func (g *gateRun) failWith(checkID, message, remediation string,
	subject *string) {
	g.out = append(g.out, Clause{CheckID: checkID, OK: false, Message: message,
		Remediation: remediation, Subject: subject})
}

// probeAnchor is the B10(a) forcing function's clause: one clause per
// undispositioned high-risk surface row that cites this finding's own anchor,
// subject = the row id (the shape invariant-unverified uses for its
// per-invariant clauses). gate_probe_anchor.go carries the rule.
//
// SKIPPED ENTIRELY (no clause at all) when the campaign has no protocol
// model, no probe surface or no campaign plan: the clause set, the count the
// dry run prints and the refusal text are then exactly what they were before
// this check existed.
func (g *gateRun) probeAnchor(finding validation.Value) {
	if g.campaign == nil {
		return
	}
	spots, ran := ProbeAnchorBlindSpots(g.campaign, finding)
	if !ran {
		return
	}
	if len(spots) == 0 {
		g.satisfied(ProbeAnchorCheckID, nil)
		return
	}
	for _, spot := range spots {
		subj := spot.RowID
		g.failWith(ProbeAnchorCheckID, spot.Message(),
			spot.Heal(g.campaign.CampaignID), &subj)
	}
}

func (g *gateRun) criticVerdict(ver validation.Value) {
	v := validation.ObjAt(ver, "critic_verdict")
	if v.Kind != validation.Str || v.S != "confirmed" {
		g.fail("critic-verdict", "hostile critic verdict is "+
			validation.PyRepr(v)+", need 'confirmed'", nil)
		return
	}
	g.satisfied("critic-verdict", nil)
}

func (g *gateRun) memoryCheck(finding validation.Value) error {
	msg, err := MemoryCheckFails(g.campaign, validation.ObjStr(finding, "finding_id"))
	if err != nil {
		return err
	}
	if msg != nil {
		g.fail("memory-check", *msg, nil)
		return nil
	}
	g.satisfied("memory-check", nil)
	return nil
}

func (g *gateRun) reproduction(repro validation.Value) {
	if s := validation.ObjAt(repro, "status"); s.Kind != validation.Str ||
		s.S != "reproduced" {
		g.fail("reproduction-reproduced", "reproduction status is "+
			validation.PyRepr(s)+", need 'reproduced'", nil)
		return
	}
	g.satisfied("reproduction-reproduced", nil)
}

// evidenceFloor appends evidence-floor (and the unreachable diagnostic) and
// returns the class floor the later tier check keys on.
func (g *gateRun) evidenceFloor(finding validation.Value) (string, error) {
	classV := validation.ObjAt(asDict(validation.ObjAt(finding, "root_cause")), "class")
	bugClass := ""
	if classV.Kind == validation.Str {
		bugClass = classV.S
	}
	floor := RequiredLevelForCampaign(g.campaign, "CONFIRMED", bugClass)
	deficit := EvidenceDeficit(finding, "CONFIRMED", g.campaign)
	if deficit == nil {
		g.satisfied("evidence-floor", nil)
		return floor, nil
	}
	g.fail("evidence-floor", *deficit, nil)
	fi, err := LevelIndex(floor)
	if err != nil {
		return floor, err
	}
	e5 := levelIndexValue("E5")
	if fi < e5 {
		return floor, nil
	}
	diag, err := ReachabilityDiagnostic(g.campaign, floor, bugClassPtr(classV))
	if err != nil {
		return floor, err
	}
	if len(diag) > 0 {
		g.fail("evidence-floor-unreachable",
			"structurally unreachable in this campaign: "+
				strings.Join(diag, "; ")+" — if the target truly cannot produce "+
				"that evidence, record the decision with `webv2 floors set` "+
				"instead of editing the framework's floor table", nil)
	}
	return floor, nil
}

func (g *gateRun) reproductionTier(repro validation.Value, floor string) {
	fi, err := LevelIndex(floor)
	if err != nil {
		return
	}
	e5 := levelIndexValue("E5")
	if fi < e5 {
		return
	}
	tier := validation.ObjAt(repro, "tier_reached")
	if _, ok := fieldAt(repro, "tier_reached"); !ok {
		tier = validation.VStr("none")
	}
	if !tierBelowT3(tier, reproductionTierOrderFunc()) {
		g.satisfied("reproduction-tier", nil)
		return
	}
	g.fail("reproduction-tier", fmt.Sprintf("evidence floor %s demands a "+
		"fork-level reproduction (T3+), but tier_reached is %s — record the "+
		"fork-tier attempt (record_attempt / attempt_and_mint) before "+
		"confirming", floor, validation.PyRepr(tier)), nil)
}

func (g *gateRun) sequenceCoverage(repro validation.Value) error {
	if !onchainSequenceRequiredFunc(g.campaign, g.finding) {
		return nil
	}
	// r45b: the predicate is fail-closed on a pin the tool could not read
	// (it answers "required", never "not required"). Read the pin here as
	// well: when THAT read fails, the clause cannot be judged, so the gate
	// refuses with the path and the errno instead of reporting missing
	// sequence coverage the operator cannot act on. A genuinely absent pin
	// (ENOENT) is a fact and falls through to the normal clause.
	if _, _, err := activeForkTargetPin(g.campaign); err != nil {
		return err
	}
	execs, err := state.AllExecs(g.campaign)
	if err != nil {
		return err
	}
	byID := make(map[string]validation.Value, len(execs))
	for _, r := range execs {
		if id := validation.ObjStr(r, "exec_id"); id != "" {
			byID[id] = r
		}
	}
	attempts := validation.ObjAt(repro, "attempts")
	if attempts.Kind != validation.Arr {
		attempts = validation.VArr()
	}
	for _, a := range attempts.A {
		if a.Kind != validation.Obj {
			continue
		}
		rec, ok := byID[validation.ObjStr(a, "artifact_id")]
		if !ok {
			continue
		}
		if covered, _ := verifySequenceCoverageFunc(g.campaign, g.finding,
			rec); covered {
			g.satisfied("sequence-coverage", nil)
			return nil
		}
	}
	g.fail("sequence-coverage", "declared exploit_sequence needs a multi-tx "+
		"PoC — no recorded attempt traces to an exec with verified sequence "+
		"coverage (single-call PoCs cannot cover it)", nil)
	return nil
}

func (g *gateRun) snapshotCompatible() {
	// Python calls assert_snapshot_compatible(campaign, finding) with its
	// strict default (True) and folds the mismatch into a gate failure.
	if _, err := snapshot.AssertSnapshotCompatible(g.campaign, g.finding,
		true); err != nil {
		g.fail("snapshot-compatible", err.Error(), nil)
		return
	}
	g.satisfied("snapshot-compatible", nil)
}

func (g *gateRun) shield(ver validation.Value) error {
	iid := validation.ObjAt(asDict(validation.ObjAt(g.finding, "invariant")), "id")
	if !validation.PyTruthy(iid) || iid.Kind != validation.Str {
		return nil
	}
	claims, err := intentClaimsFunc(g.campaign)
	if err != nil {
		return err
	}
	claim, ok := claims[normalizeInvIDFunc(iid.S)]
	if !ok || !validation.PyTruthy(claim) {
		return nil
	}
	if validation.PyTruthy(validation.ObjAt(ver, "shield_adjudication")) {
		g.satisfied("shield-adjudication", nil)
		return nil
	}
	g.fail("shield-adjudication", fmt.Sprintf("invariant %s is documented as "+
		"intended (%s) — record the extraction adjudication before CONFIRMED",
		iid.S, firstRunes(validation.ObjStr(claim, "intent_line"), 100)), nil)
	return nil
}

func (g *gateRun) invariants(finding validation.Value) error {
	links, err := loadInvariantLinksFunc(g.campaign)
	if err != nil {
		return err
	}
	reg := asDict(validation.ObjAt(links, "invariants"))
	normReg := make(map[string]validation.Value, len(reg.O))
	for _, kv := range reg.O {
		if kv.V.Kind == validation.Obj {
			normReg[normalizeInvIDFunc(kv.K)] = kv.V
		}
	}
	doc, err := documentedInvariantsFunc(g.campaign)
	if err != nil {
		return err
	}
	events, err := g.campaign.Events()
	if err != nil {
		return err
	}
	for _, iid := range invariantIDs(finding) {
		subj := iid
		e, ok := normReg[iid]
		if !ok {
			g.fail("invariant-unverified", "invariant-unverified: "+iid+
				" not in registry — seed it or correct the id", &subj)
			continue
		}
		if _, isDoc := doc[iid]; isDoc || validation.ObjStr(e, "source") == "documented" {
			g.satisfied("invariant-unverified", &subj)
			continue
		}
		if !invariantVerifiedFunc(e, g.campaign, iid, events) {
			g.fail("invariant-unverified", fmt.Sprintf("invariant %s has "+
				"status %s — verify it against code before CONFIRMED", iid,
				validation.PyRepr(validation.ObjAt(e, "status"))), &subj)
			continue
		}
		g.satisfied("invariant-unverified", &subj)
	}
	return nil
}

func (g *gateRun) claimDrift(finding validation.Value) ([]Clause, error) {
	problems, err := ClaimDriftProblems(finding)
	if err != nil {
		return nil, err
	}
	for _, p := range problems {
		g.fail("claim-drift", p, nil)
	}
	if len(problems) == 0 {
		g.satisfied("claim-drift", nil)
	}
	return g.out, nil
}
