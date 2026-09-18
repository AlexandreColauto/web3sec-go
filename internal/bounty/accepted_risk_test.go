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
	for _, ck := range validation.ObjAt(result, "policy_checks").A {
		if validation.ObjStr(ck, "check") == name {
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
	if got := validation.ObjAt(result, "submission_ready"); got.Kind != validation.Bool || got.B {
		t.Errorf("submission_ready = %s, want False (accepted risk blocks)",
			validation.PyRepr(got))
	}
	if !anyContains(validation.ObjAt(result, "blocking_reasons"), "accepted risk") {
		t.Errorf("no accepted-risk blocker in %s",
			validation.CanonCompact(validation.ObjAt(result, "blocking_reasons")))
	}
	row := checkRow(result, "accepted-risk")
	if row.Kind == validation.Null {
		t.Fatal("no accepted-risk row in policy_checks")
	}
	if validation.ObjStr(row, "result") != "fail" {
		t.Errorf("accepted-risk result = %s, want fail", validation.ObjStr(row, "result"))
	}
	if !strings.Contains(validation.ObjStr(row, "detail"), "not submittable") {
		t.Errorf("accepted-risk detail = %q", validation.ObjStr(row, "detail"))
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ar := validation.ObjAt(validation.ObjAt(stored, "bounty"), "accepted_risk")
	if validation.ObjStr(ar, "pattern") != "price skew" {
		t.Errorf("recorded pattern = %q", validation.ObjStr(ar, "pattern"))
	}
	if validation.ObjStr(ar, "kind") != "known-issue" {
		t.Errorf("recorded kind = %q", validation.ObjStr(ar, "kind"))
	}
	if validation.ObjStr(ar, "reference") == "" {
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
	if got := validation.ObjAt(result, "submission_ready"); got.Kind != validation.Bool || !got.B {
		t.Errorf("submission_ready = %s, want True (waiver unblocks)",
			validation.PyRepr(got))
	}
	row := checkRow(result, "accepted-risk")
	if validation.ObjStr(row, "result") != "pass" {
		t.Errorf("accepted-risk result = %s, want pass (waived)",
			validation.ObjStr(row, "result"))
	}
	if !strings.Contains(validation.ObjStr(row, "detail"), "waived by bob") {
		t.Errorf("accepted-risk detail = %q, want 'waived by bob'",
			validation.ObjStr(row, "detail"))
	}
	if anyContains(validation.ObjAt(result, "blocking_reasons"), "accepted risk") {
		t.Errorf("accepted-risk blocker survived the waiver: %s",
			validation.CanonCompact(validation.ObjAt(result, "blocking_reasons")))
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(stored, "bounty"), "accepted_risk"), "pattern"); got != "price skew" {
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
	if got := validation.ObjAt(result2, "submission_ready"); got.Kind != validation.Bool || got.B {
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
	if validation.ObjStr(known, "result") != "pass" {
		t.Errorf("known-issue-check = %s, want pass (suppressed)",
			validation.ObjStr(known, "result"))
	}
	if !strings.Contains(validation.ObjStr(known, "detail"), "suppressed") {
		t.Errorf("known-issue-check detail = %q, want the suppression note",
			validation.ObjStr(known, "detail"))
	}
	if anyContains(validation.ObjAt(result, "blocking_reasons"), "excluded:") {
		t.Errorf("exclusion blocker survived the narrower rule: %s",
			validation.CanonCompact(validation.ObjAt(result, "blocking_reasons")))
	}
	// The accepted-risk check still carries the block + the record.
	if validation.ObjStr(checkRow(result, "accepted-risk"), "result") != "fail" {
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
	if validation.ObjStr(row, "result") != "fail" {
		t.Fatalf("accepted-risk result = %s, want fail (not honored)",
			validation.ObjStr(row, "result"))
	}
	if !strings.Contains(validation.ObjStr(row, "detail"), "does not apply") {
		t.Errorf("detail = %q, want the not-honored note", validation.ObjStr(row, "detail"))
	}
	if !anyContains(validation.ObjAt(result, "blocking_reasons"), "not honored") {
		t.Errorf("blocker must name the cap: %s",
			validation.CanonCompact(validation.ObjAt(result, "blocking_reasons")))
	}
	// No record when the acceptance does not apply.
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, had := fieldAt(validation.ObjAt(stored, "bounty"), "accepted_risk"); had {
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
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(stored2, "bounty"), "accepted_risk"), "pattern"); got != "price skew" {
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

// policyWithAcceptedRiskRef is policyWithAcceptedRisk + a reference_url on
// the entry (G7 hygiene, Task 15): the program page / scope clause the
// exclusion cites.
func policyWithAcceptedRiskRef() validation.Value {
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "accepted_risks", validation.VArr(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("kind", validation.VStr("known-issue")),
			kv("reference", validation.VStr(
				"program page: known-issues#price-skew")),
			kv("reference_url", validation.VStr(
				"https://immunefi.com/acme/scope#price-skew"))),
	))
	return p
}

// TestAcceptedRiskIgnoresMitigationPresent is law half (c): AcceptedRiskHit
// — check13's matcher — on a finding carrying dedup_meta.mitigation_present
// matches byte-identically to the same finding without it, and the full
// gate's stored accepted_risk record is byte-identical too (mitigation
// NEVER influences the money check; it only demotes the acceptance score,
// which lives outside this record).
func TestAcceptedRiskIgnoresMitigationPresent(t *testing.T) {
	mitigation := validation.VStr(findings.MitigRecord("cei-order",
		"src/Escrow.sol", 23, "last write at L23 precedes call at L26"))
	withMit := func(f validation.Value) validation.Value {
		return withField(f, "dedup_meta", validation.VObj(
			kv("mitigation_present", mitigation)))
	}
	// Matcher level: the hit is the policy entry, untouched by soundness.
	p := policyWithAcceptedRisk()
	plain, err := AcceptedRiskHit(p, baseFinding())
	if err != nil {
		t.Fatal(err)
	}
	mitted, err := AcceptedRiskHit(p, withMit(baseFinding()))
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonCompact(plain) != validation.CanonCompact(mitted) {
		t.Errorf("matcher moved with mitigation:\n %s\n %s",
			validation.CanonCompact(plain),
			validation.CanonCompact(mitted))
	}
	// Gate level: the STORED record is byte-identical with/without it.
	c1, fid1 := bountyFixture(t)
	c2, fid2 := bountyFixture(t)
	stored2, err := findings.LoadFinding(c2, fid2)
	if err != nil {
		t.Fatal(err)
	}
	stored2 = withField(stored2, "dedup_meta", validation.VObj(
		kv("mitigation_present", mitigation)))
	if err := findings.SaveFinding(c2, &stored2); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateBountyGate(c1, fid1, policyWithAcceptedRisk(),
		true); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateBountyGate(c2, fid2, policyWithAcceptedRisk(),
		true); err != nil {
		t.Fatal(err)
	}
	s1, err := findings.LoadFinding(c1, fid1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := findings.LoadFinding(c2, fid2)
	if err != nil {
		t.Fatal(err)
	}
	rec1 := validation.CanonCompact(validation.ObjAt(validation.ObjAt(s1, "bounty"),
		"accepted_risk"))
	rec2 := validation.CanonCompact(validation.ObjAt(validation.ObjAt(s2, "bounty"),
		"accepted_risk"))
	if rec1 != rec2 {
		t.Errorf("stored record moved with mitigation:\n %s\n %s",
			rec1, rec2)
	}
	// The record carries no soundness key (file/line/evidence live only
	// in the mitigation JSON, never here).
	for _, banned := range []string{"file", "line", "evidence",
		"mitigation_present"} {
		if _, ok := fieldAt(validation.ObjAt(validation.ObjAt(s2, "bounty"), "accepted_risk"),
			banned); ok {
			t.Errorf("accepted_risk record carries soundness key %q",
				banned)
		}
	}
}

// TestAcceptedRiskReferenceURLRidesThrough: a reference_url on the policy
// entry lands on the stored record; an entry without one leaves the record
// at its old bytes exactly (no new key).
func TestAcceptedRiskReferenceURLRidesThrough(t *testing.T) {
	c, fid := bountyFixture(t)
	if _, err := EvaluateBountyGate(c, fid, policyWithAcceptedRiskRef(),
		true); err != nil {
		t.Fatal(err)
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	rec := validation.ObjAt(validation.ObjAt(stored, "bounty"), "accepted_risk")
	if got := validation.ObjStr(rec, "reference_url"); got !=
		"https://immunefi.com/acme/scope#price-skew" {
		t.Errorf("reference_url = %q, want the policy URL", got)
	}
	// Absent in policy => absent in record, old key set untouched.
	c2, fid2 := bountyFixture(t)
	if _, err := EvaluateBountyGate(c2, fid2, policyWithAcceptedRisk(),
		true); err != nil {
		t.Fatal(err)
	}
	stored2, err := findings.LoadFinding(c2, fid2)
	if err != nil {
		t.Fatal(err)
	}
	rec2 := validation.ObjAt(validation.ObjAt(stored2, "bounty"), "accepted_risk")
	if _, ok := fieldAt(rec2, "reference_url"); ok {
		t.Errorf("record gained reference_url unasked: %s",
			validation.CanonCompact(rec2))
	}
	var keys []string
	for _, kv := range rec2.O {
		keys = append(keys, kv.K)
	}
	if validation.CanonCompact(rec2) != validation.CanonCompact(
		validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("kind", validation.VStr("known-issue")),
			kv("reference", validation.VStr(
				"program page: known-issues#price-skew")))) {
		t.Errorf("reference-less record moved bytes: %s (%v)",
			validation.CanonCompact(rec2), keys)
	}
}

// TestAcceptedRiskReferenceURLSchema: the policy schema accepts a
// reference_url (round trip preserves it) and rejects a non-string one;
// a stub shorter than minLength 8 is rejected too.
func TestAcceptedRiskReferenceURLSchema(t *testing.T) {
	c := vectorCamp(t, "")
	policy := policyWithAcceptedRiskRef()
	path, err := SavePolicy(c, policy, nil)
	if err != nil {
		t.Fatalf("schema must accept reference_url: %v", err)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(got) != validation.CanonSpaced(policy) {
		t.Errorf("round trip\n got %s\nwant %s",
			validation.CanonSpaced(got), validation.CanonSpaced(policy))
	}
	bad := func(v validation.Value) validation.Value {
		p := testPolicy()
		return validation.Value{Kind: validation.Obj, O: append(
			append([]validation.KV(nil), p.O...),
			validation.KV{K: "accepted_risks", V: validation.VArr(
				validation.VObj(
					kv("pattern", validation.VStr("price skew")),
					kv("reference_url", v)))})}
	}
	if _, err := SavePolicy(c, bad(validation.VInt(42)), nil); err == nil {
		t.Error("non-string reference_url must fail policy validation")
	}
	if _, err := SavePolicy(c, bad(validation.VStr("short")),
		nil); err == nil {
		t.Error("reference_url below minLength 8 must fail validation")
	}
}
