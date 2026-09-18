package bounty

// D8: the patch clause follows the target program. These tests pin the three
// modes against the four finding states the design named (no record,
// prose-only, immunized, bypass), the default-when-absent guard, and the
// loud refusal of an unknown mode.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// policyWithPatchClause is testPolicy() with poc_requirements.patch_clause
// set ("" removes the key entirely — the default path).
func policyWithPatchClause(mode string) validation.Value {
	p := testPolicy()
	req := validation.ObjAt(p, "poc_requirements")
	if mode == "" {
		return p
	}
	req.O = validation.SetOrAppend(req.O, "patch_clause", validation.VStr(mode))
	p.O = validation.SetOrAppend(p.O, "poc_requirements", req)
	return p
}

// setVerification writes keys into the stored finding's verification object
// (the same path the CLI's immunize/shield writers take).
func setVerification(t *testing.T, c *state.Campaign, fid string,
	keys ...validation.KV) {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	for _, kvIn := range keys {
		ver.O = validation.SetOrAppend(ver.O, kvIn.K, kvIn.V)
	}
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
}

// immunizationRow returns the gate's immunization check row.
func immunizationRow(t *testing.T, result validation.Value) validation.Value {
	t.Helper()
	for _, ck := range validation.ObjAt(result, "policy_checks").A {
		if validation.ObjStr(ck, "check") == "immunization" {
			return ck
		}
	}
	t.Fatal("no immunization row in policy_checks")
	return validation.VNull()
}

func readyOf(result validation.Value) bool {
	return validation.ObjAt(result, "submission_ready").Kind == validation.Bool &&
		validation.ObjAt(result, "submission_ready").B
}

func blockersOf(result validation.Value) []string {
	var out []string
	if br := validation.ObjAt(result, "blocking_reasons"); br.Kind == validation.Arr {
		for _, v := range br.A {
			out = append(out, v.S)
		}
	}
	return out
}

func advisoriesOf(result validation.Value) []string {
	var out []string
	if a := validation.ObjAt(result, "advisories"); a.Kind == validation.Arr {
		for _, v := range a.A {
			out = append(out, v.S)
		}
	}
	return out
}

// TestPatchClauseAbsentMeansVerification is the compatibility guard: without
// the key, a missing patch record blocks exactly as it always did — same
// result, same blocker text, same remediation catalog entry.
func TestPatchClauseAbsentMeansVerification(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.immState = "missing"
	stub.immDetail = "no patch recorded"
	installSeams(t, stub)

	result, err := EvaluateBountyGate(c, fid, policyWithPatchClause(""), true)
	if err != nil {
		t.Fatal(err)
	}
	if readyOf(result) {
		t.Error("submission_ready = True without a patch record (default mode)")
	}
	if row := immunizationRow(t, result); validation.ObjStr(row, "result") != "fail" {
		t.Errorf("immunization = %s, want fail", validation.ObjStr(row, "result"))
	}
	if !anyContains(validation.ObjAt(result, "blocking_reasons"), "not immunized") {
		t.Errorf("blockers = %v, want the immunization blocker",
			blockersOf(result))
	}
	if got := advisoriesOf(result); len(got) != 0 {
		t.Errorf("advisories = %v, want none in verification mode", got)
	}
}

// TestPatchClauseNoneRequiresNothing: the program does not ask for a fix, so
// the clause passes and says so — in the program's name, not the framework's.
func TestPatchClauseNoneRequiresNothing(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.immState = "missing"
	stub.immDetail = "no patch recorded"
	installSeams(t, stub)

	result, err := EvaluateBountyGate(c, fid, policyWithPatchClause("none"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !readyOf(result) {
		t.Errorf("submission_ready = False under patch_clause none; blockers %v",
			blockersOf(result))
	}
	row := immunizationRow(t, result)
	if validation.ObjStr(row, "result") != "pass" {
		t.Fatalf("immunization = %s, want pass", validation.ObjStr(row, "result"))
	}
	detail := validation.ObjStr(row, "detail")
	for _, want := range []string{"no fix requested", "Acme Protocol Immunefi", "none"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail %q missing %q", detail, want)
		}
	}
}

// TestPatchClauseProseNeedsRecommendation: prose mode passes on a written
// recommendation and blocks without one (a length-floored string, not "fix it").
func TestPatchClauseProseNeedsRecommendation(t *testing.T) {
	long := "Add a nonReentrant modifier to withdraw() and zero the deposit " +
		"before the external call; see the diff in the report appendix."
	short := "add a mutex"

	for _, tc := range []struct {
		name    string
		rec     string
		wantRun bool
	}{{"long recommendation", long, true}, {"short recommendation", short, false}} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureCampaign(t)
			fid := fixtureConfirmed(t, c)
			setVerification(t, c, fid,
				kv("recommendation", validation.VStr(tc.rec)))
			stub := submissionReadySeamsFor("PRC-abc123")
			stub.immState = "missing"
			stub.immDetail = "no patch recorded"
			installSeams(t, stub)

			result, err := EvaluateBountyGate(c, fid,
				policyWithPatchClause("prose"), true)
			if err != nil {
				t.Fatal(err)
			}
			if readyOf(result) != tc.wantRun {
				t.Errorf("submission_ready = %v, want %v (blockers %v)",
					readyOf(result), tc.wantRun, blockersOf(result))
			}
			row := immunizationRow(t, result)
			if tc.wantRun {
				if validation.ObjStr(row, "result") != "pass" {
					t.Fatalf("immunization = %s, want pass", validation.ObjStr(row, "result"))
				}
				if !strings.Contains(validation.ObjStr(row, "detail"), "recommendation recorded") {
					t.Errorf("detail = %q", validation.ObjStr(row, "detail"))
				}
			} else {
				if validation.ObjStr(row, "result") != "fail" {
					t.Fatalf("immunization = %s, want fail", validation.ObjStr(row, "result"))
				}
				if !anyContains(validation.ObjAt(result, "blocking_reasons"),
					"no written recommendation") {
					t.Errorf("blockers = %v", blockersOf(result))
				}
			}
		})
	}
}

// TestPatchClauseProseBoundaryMutationsAreAdvisory: the record keeps its
// teeth as a note — a bypass under a recorded patch never blocks in prose
// mode, and never disappears either.
func TestPatchClauseProseBoundaryMutationsAreAdvisory(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	setVerification(t, c, fid,
		kv("recommendation", validation.VStr(
			"Hoist the balance write above the external call in withdraw() "+
				"and use a reentrancy guard; full diff in the report.")),
		kv("patch_verified", validation.VObj(
			kv("patch_blocks_poc", validation.VBool(true)),
			kv("boundary_mutations_tested", validation.VInt(1)),
			kv("boundary_bypass_found", validation.VBool(true)),
			kv("artifact_id", validation.VStr("EXEC-0000000002")))))
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.immState = "bypass"
	stub.immDetail = "a boundary mutation still extracts"
	installSeams(t, stub)

	result, err := EvaluateBountyGate(c, fid, policyWithPatchClause("prose"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !readyOf(result) {
		t.Errorf("submission_ready = False; blockers %v", blockersOf(result))
	}
	adv := advisoriesOf(result)
	if len(adv) != 1 || !strings.Contains(adv[0], "still extracts") {
		t.Errorf("advisories = %v, want the boundary-bypass note", adv)
	}
	if anyContains(validation.ObjAt(result, "blocking_reasons"), "immunized") {
		t.Errorf("the advisory leaked into blockers: %v", blockersOf(result))
	}
}

// TestPatchClauseUnknownValueIsAnError: a mode the framework does not
// implement is a loud refusal, never a silent fall back to the strictest bar.
func TestPatchClauseUnknownValueIsAnError(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	installSeams(t, submissionReadySeamsFor("PRC-abc123"))

	_, err := EvaluateBountyGate(c, fid, policyWithPatchClause("maybe"), true)
	if err == nil {
		t.Fatal("unknown patch_clause produced no error")
	}
	if !strings.Contains(err.Error(), "unknown poc_requirements.patch_clause") ||
		!strings.Contains(err.Error(), "maybe") {
		t.Errorf("error = %q", err.Error())
	}
}

// TestPatchClauseSchemaRefusesUnknownValue is the other half of the loud
// refusal: the policy schema's enum stops the bad value at LOAD time (scope
// --policy), before any gate runs.
func TestPatchClauseSchemaRefusesUnknownValue(t *testing.T) {
	for _, mode := range []string{"verification", "prose", "none"} {
		if err := validation.Validate(policyWithPatchClause(mode),
			"bounty_policy", 999); err != nil {
			t.Errorf("patch_clause %q rejected by the schema: %v", mode, err)
		}
	}
	err := validation.Validate(policyWithPatchClause("maybe"), "bounty_policy", 999)
	if err == nil {
		t.Fatal("the policy schema accepted patch_clause `maybe`")
	}
	if !strings.Contains(err.Error(), "patch_clause") {
		t.Errorf("schema error does not name the key: %v", err)
	}
	if err := validation.Validate(policyWithPatchClause(""), "bounty_policy", 999); err != nil {
		t.Errorf("the absent key must validate (the default path): %v", err)
	}
}

// TestPatchClauseWaiverStillWorks: B1's escape hatch survives every mode (a
// program that asks for a patch may still accept a finding without one).
func TestPatchClauseWaiverStillWorks(t *testing.T) {
	c := fixtureCampaign(t)
	fid := fixtureConfirmed(t, c)
	stub := submissionReadySeamsFor("PRC-abc123")
	stub.immState = "missing"
	stub.immDetail = "no patch recorded"
	stub.waivers = []validation.Value{validation.VObj(
		kv("stage", validation.VStr("immunization")),
		kv("subject", validation.VStr("*")),
		kv("reason", validation.VStr("the fix ships in the same PR as the disclosure")),
		kv("actor", validation.VStr("alice")),
	)}
	installSeams(t, stub)

	result, err := EvaluateBountyGate(c, fid, policyWithPatchClause("prose"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !readyOf(result) {
		t.Errorf("submission_ready = False with an immunization waiver; blockers %v",
			blockersOf(result))
	}
	if row := immunizationRow(t, result); !strings.Contains(validation.ObjStr(row, "detail"), "waived by alice") {
		t.Errorf("immunization detail = %q", validation.ObjStr(row, "detail"))
	}
}
