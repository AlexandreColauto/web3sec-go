// priors_test.go (G3 wPrior): the policy gate is conservative — absent or
// false behaves byte-for-byte as before, true/false validate, and a
// non-boolean is refused by the schema (with PriorsEnabled as the last
// line of defense). The gate-level test pins the default state: a
// policy-off campaign stores today's score and no prior keys anywhere in
// the finding.
package bounty

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/risk"
	"websec/internal/validation"
)

func TestPriorsEnabled(t *testing.T) {
	if PriorsEnabled(validation.VNull()) {
		t.Error("null policy must not enable priors")
	}
	if PriorsEnabled(testPolicy()) {
		t.Error("the default policy (no flag) must not enable priors")
	}
	off := testPolicy()
	off.O = validation.SetOrAppend(off.O, "acceptance_priors",
		validation.VBool(false))
	if PriorsEnabled(off) {
		t.Error("explicit false must not enable priors")
	}
	on := testPolicy()
	on.O = validation.SetOrAppend(on.O, "acceptance_priors",
		validation.VBool(true))
	if !PriorsEnabled(on) {
		t.Error("explicit true must enable priors")
	}
	// A hand-built non-boolean never enables (the schema refuses it at
	// load time; this is the defense in depth).
	junk := testPolicy()
	junk.O = validation.SetOrAppend(junk.O, "acceptance_priors",
		validation.VStr("yes"))
	if PriorsEnabled(junk) {
		t.Error("a string flag must not enable priors")
	}
}

func TestAcceptancePriorsSchemaGate(t *testing.T) {
	if err := validation.Validate(testPolicy(), "bounty_policy", 1); err != nil {
		t.Fatalf("default policy must validate: %v", err)
	}
	for _, b := range []bool{true, false} {
		p := testPolicy()
		p.O = validation.SetOrAppend(p.O, "acceptance_priors",
			validation.VBool(b))
		if err := validation.Validate(p, "bounty_policy", 1); err != nil {
			t.Fatalf("acceptance_priors=%v must validate: %v", b, err)
		}
	}
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "acceptance_priors",
		validation.VStr("yes"))
	if err := validation.Validate(p, "bounty_policy", 1); err == nil {
		t.Fatal("a string acceptance_priors must be rejected by the schema")
	}
}

// walkKeys asserts no object KEY anywhere under v contains "prior" — the
// policy-off byte check on the gate's stored finding (values are never
// inspected: a class named e.g. "prior-art" would be a false positive).
func walkKeys(t *testing.T, v validation.Value) {
	t.Helper()
	if v.Kind == validation.Obj {
		for _, kv := range v.O {
			if strings.Contains(kv.K, "prior") {
				t.Fatalf("policy-off finding carries key %q", kv.K)
			}
			walkKeys(t, kv.V)
		}
	}
	if v.Kind == validation.Arr {
		for _, e := range v.A {
			walkKeys(t, e)
		}
	}
}

// TestGatePolicyOffStoresNoPriorKeys is the (f) gate half: the default
// policy stores today's deterministic score and no prior keys anywhere.
func TestGatePolicyOffStoresNoPriorKeys(t *testing.T) {
	c := vectorCamp(t, "SNAP-22222222")
	ts := "2026-09-10T00:00:00+00:00"
	f := validation.VObj(
		kv("finding_id", validation.VStr("F-0a0b0c0d0e02")),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("snapshot_ids", validation.VObj(
			kv("source", validation.VStr("SNAP-22222222")),
			kv("deployment", validation.VNull()),
			kv("chain", validation.VNull()))),
		kv("title", validation.VStr("unbacked withdrawal via price skew")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("oracle-manipulation")),
			kv("description", validation.VStr(
				"spot price read lets the attacker trade against their own price")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("borrow"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("evidence", validation.VArr(validation.VObj(
			kv("evidence_id", validation.VStr("EV-1")),
			kv("level", validation.VStr("E5")),
			kv("type", validation.VStr("fork-test")),
			kv("description", validation.VStr("fork repro extracts the funds")),
			kv("sandbox_profile", validation.VStr("fork-runner"))))),
		kv("risk", validation.VObj(
			kv("validated", validation.VObj(
				kv("score", validation.VFloat(7.5)),
				kv("band", validation.VStr("high")),
				kv("rationale", validation.VStr("fixture")))),
			kv("reversibility", validation.VStr("irreversible")))),
		kv("verification", validation.VObj(
			kv("critic_verdict", validation.VStr("confirmed")))),
		kv("dedup", validation.VObj()),
		kv("dedup_meta", validation.VObj()),
		kv("history", validation.VArr(validation.VObj(
			kv("at", validation.VStr(ts)),
			kv("from", validation.VStr("NEW")),
			kv("to", validation.VStr("CONFIRMED")),
			kv("reason", validation.VStr("priors fixture")),
			kv("actor", validation.VStr("test"))))),
		kv("created_at", validation.VStr(ts)),
		kv("updated_at", validation.VStr(ts)),
	)
	writeFinding(t, c, f)
	installSeams(t, submissionReadySeams())
	if _, err := EvaluateBountyGate(c, objStr(f, "finding_id"),
		testPolicy(), true); err != nil {
		t.Fatal(err)
	}
	stored, err := validation.ReadJson(filepath.Join(c.FindingsDir,
		objStr(f, "finding_id")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	walkKeys(t, stored)
	// ... and the stored number IS today's deterministic score.
	want, _ := risk.AcceptanceScore(f)
	gotScore := objAt(objAt(stored, "risk"), "acceptance_score")
	if gotScore.F != validation.PythonRound(want, 2) {
		t.Fatalf("stored score = %v, want %v", gotScore.F,
			validation.PythonRound(want, 2))
	}
}
