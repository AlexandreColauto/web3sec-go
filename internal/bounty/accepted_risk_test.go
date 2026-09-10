package bounty

// IMPROVEMENTS A1 — the accepted-risk channel: documented, program-accepted
// risks. A matched finding is recorded (finding.bounty.accepted_risk), stays
// visible and counted, but is not submittable as written; a same-pattern
// exclusion is suppressed (the accepted risk is the narrower rule); a named
// waiver (stage "accepted-risk") clears the block for one finding.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

// policyWithAcceptedRisk is testPolicy + an accepted_risks entry the fixture
// finding matches ("price skew" is in its title).
func policyWithAcceptedRisk() validation.Value {
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "accepted_risks", validation.VArr(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("kind", validation.VStr("known-issue")),
			kv("reference", validation.VStr(
				"program page: known-issues#price-skew"))),
	))
	return p
}

func checkRow(result validation.Value, name string) validation.Value {
	for _, ck := range objAt(result, "policy_checks").A {
		if objStr(ck, "check") == name {
			return ck
		}
	}
	return validation.VNull()
}

// TestAcceptedRiskHitBlocksAndRecords is the A1 core: the block, the
// persisted record, and the blocker text.
func TestAcceptedRiskHitBlocksAndRecords(t *testing.T) {
	c, fid := bountyFixture(t)
	result, err := EvaluateBountyGate(c, fid, policyWithAcceptedRisk(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False (accepted risk blocks)",
			validation.PyRepr(got))
	}
	if !anyContains(objAt(result, "blocking_reasons"), "accepted risk") {
		t.Errorf("no accepted-risk blocker in %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
	row := checkRow(result, "accepted-risk")
	if row.Kind == validation.Null {
		t.Fatal("no accepted-risk row in policy_checks")
	}
	if objStr(row, "result") != "fail" {
		t.Errorf("accepted-risk result = %s, want fail", objStr(row, "result"))
	}
	if !strings.Contains(objStr(row, "detail"), "not submittable") {
		t.Errorf("accepted-risk detail = %q", objStr(row, "detail"))
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ar := objAt(objAt(stored, "bounty"), "accepted_risk")
	if objStr(ar, "pattern") != "price skew" {
		t.Errorf("recorded pattern = %q", objStr(ar, "pattern"))
	}
	if objStr(ar, "kind") != "known-issue" {
		t.Errorf("recorded kind = %q", objStr(ar, "kind"))
	}
	if objStr(ar, "reference") == "" {
		t.Error("recorded reference missing")
	}
}

// TestAcceptedRiskWaiverUnblocks: a named waiver (stage accepted-risk,
// subject = the finding) clears the block; the record stays (both facts
// visible in the report). A waiver for a different subject must NOT leak.
func TestAcceptedRiskWaiverUnblocks(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("accepted-risk")),
		kv("subject", validation.VStr(fid)),
		kv("reason", validation.VStr(
			"this one extracts beyond the accepted behavior — payable")),
		kv("actor", validation.VStr("bob")))}
	installSeams(t, stub)
	result, err := EvaluateBountyGate(c, fid, policyWithAcceptedRisk(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result, "submission_ready"); got.Kind != validation.Bool || !got.B {
		t.Errorf("submission_ready = %s, want True (waiver unblocks)",
			validation.PyRepr(got))
	}
	row := checkRow(result, "accepted-risk")
	if objStr(row, "result") != "pass" {
		t.Errorf("accepted-risk result = %s, want pass (waived)",
			objStr(row, "result"))
	}
	if !strings.Contains(objStr(row, "detail"), "waived by bob") {
		t.Errorf("accepted-risk detail = %q, want 'waived by bob'",
			objStr(row, "detail"))
	}
	if anyContains(objAt(result, "blocking_reasons"), "accepted risk") {
		t.Errorf("accepted-risk blocker survived the waiver: %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(objAt(objAt(stored, "bounty"), "accepted_risk"), "pattern"); got != "price skew" {
		t.Errorf("waived finding must keep the record; pattern = %q", got)
	}

	// A waiver addressed to another finding must not leak into this one.
	c2 := fixtureCampaign(t)
	fid2 := fixtureConfirmed(t, c2)
	stub2 := submissionReadySeamsFor("PRC-abc123")
	stub2.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("accepted-risk")),
		kv("subject", validation.VStr("F-someoneelse")),
		kv("reason", validation.VStr("not for this finding")),
		kv("actor", validation.VStr("bob")))}
	installSeams(t, stub2)
	result2, err := EvaluateBountyGate(c2, fid2, policyWithAcceptedRisk(), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(result2, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False (waiver addressed elsewhere)",
			validation.PyRepr(got))
	}
}

// policyWithAcceptedRiskOverExclusion carries the SAME pattern in both
// exclusions and accepted_risks — the narrower rule must win.
func policyWithAcceptedRiskOverExclusion() validation.Value {
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "exclusions", validation.VArr(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("kind", validation.VStr("known-issue")))))
	p.O = validation.SetOrAppend(p.O, "accepted_risks", validation.VArr(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("kind", validation.VStr("accepted-risk")))))
	return p
}

// TestAcceptedRiskSuppressesSamePatternExclusion: the exclusion tripwire
// must not re-block what the program already accepted.
func TestAcceptedRiskSuppressesSamePatternExclusion(t *testing.T) {
	c, fid := bountyFixture(t)
	result, err := EvaluateBountyGate(c, fid,
		policyWithAcceptedRiskOverExclusion(), true)
	if err != nil {
		t.Fatal(err)
	}
	known := checkRow(result, "known-issue-check")
	if objStr(known, "result") != "pass" {
		t.Errorf("known-issue-check = %s, want pass (suppressed)",
			objStr(known, "result"))
	}
	if !strings.Contains(objStr(known, "detail"), "suppressed") {
		t.Errorf("known-issue-check detail = %q, want the suppression note",
			objStr(known, "detail"))
	}
	if anyContains(objAt(result, "blocking_reasons"), "excluded:") {
		t.Errorf("exclusion blocker survived the narrower rule: %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
	// The accepted-risk check still carries the block + the record.
	if objStr(checkRow(result, "accepted-risk"), "result") != "fail" {
		t.Error("accepted-risk must still fail (the record + block stand)")
	}
}

// TestAcceptedRiskMinSeverityCap: min_severity caps the acceptance. The
// fixture finding prices at "high"; a "high" floor voids the acceptance (the
// gate demands real handling, no record), a "critical" floor honors it.
func TestAcceptedRiskMinSeverityCap(t *testing.T) {
	c, fid := bountyFixture(t)
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "accepted_risks", validation.VArr(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("min_severity", validation.VStr("high")))))
	result, err := EvaluateBountyGate(c, fid, p, true)
	if err != nil {
		t.Fatal(err)
	}
	row := checkRow(result, "accepted-risk")
	if objStr(row, "result") != "fail" {
		t.Fatalf("accepted-risk result = %s, want fail (not honored)",
			objStr(row, "result"))
	}
	if !strings.Contains(objStr(row, "detail"), "does not apply") {
		t.Errorf("detail = %q, want the not-honored note", objStr(row, "detail"))
	}
	if !anyContains(objAt(result, "blocking_reasons"), "not honored") {
		t.Errorf("blocker must name the cap: %s",
			validation.CanonCompact(objAt(result, "blocking_reasons")))
	}
	// No record when the acceptance does not apply.
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, had := fieldAt(objAt(stored, "bounty"), "accepted_risk"); had {
		t.Error("a voided acceptance must not record on the finding")
	}

	// A critical floor: high < critical → honored.
	c2, fid2 := bountyFixture(t)
	p2 := testPolicy()
	p2.O = validation.SetOrAppend(p2.O, "accepted_risks", validation.VArr(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("min_severity", validation.VStr("critical")))))
	if _, err := EvaluateBountyGate(c2, fid2, p2, true); err != nil {
		t.Fatal(err)
	}
	stored2, err := findings.LoadFinding(c2, fid2)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(objAt(objAt(stored2, "bounty"), "accepted_risk"), "pattern"); got != "price skew" {
		t.Errorf("below-floor acceptance must record; pattern = %q", got)
	}
}

// TestAcceptedRiskPolicyRoundTrip: the schema accepts accepted_risks and the
// save/load round trip preserves them.
func TestAcceptedRiskPolicyRoundTrip(t *testing.T) {
	c := vectorCamp(t, "")
	policy := policyWithAcceptedRisk()
	path, err := SavePolicy(c, policy, nil)
	if err != nil {
		t.Fatalf("schema must accept accepted_risks: %v", err)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(got) != validation.CanonSpaced(policy) {
		t.Errorf("round trip\n got %s\nwant %s",
			validation.CanonSpaced(got), validation.CanonSpaced(policy))
	}
}
