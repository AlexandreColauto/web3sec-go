package bounty

// PolicyGateBindings binds every EVIDENCE-TIER boolean the policy schema
// offers to the gate check id that reads it. TestPolicyBooleansAreReferenced-
// ByTheirGate walks the embedded schema against this table, so a boolean with
// no gate — or a gate with no boolean — is a red test, not a silent no-op
// (framework-plan-v1.6 Part 7, Phase 1 exit criterion).
type PolicyGateBinding struct {
	Key   string // dotted path inside bounty_policy.schema.json
	Check string // gate check id this boolean turns on; must be in BountyRemediation
}

var PolicyGateBindings = []PolicyGateBinding{
	{Key: "poc_requirements.require_fork_repro", Check: "fork-repro"},
	{Key: "poc_requirements.require_economic_quantification", Check: "economic-quantified"},
	{Key: "poc_requirements.require_exploit_contract", Check: "exploit-contract"},
}
