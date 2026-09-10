package report

// unscoped_test.go — the policy-absent loudness (post-mortem item 1). The
// BountyGateAll refusal already existed ("bounty gate requires a policy"), but
// nothing on the REPORT said the campaign was never scoped: a policy-less
// campaign rendered a complete-looking Results section with no acceptance
// ranking, no submission budget and no accepted-risks check, which is how a
// 23-finding campaign looked finished next to a 2-finding gold. The report now
// says it in one line, and says it only when there is no policy.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestReportSaysItIsUnscoped: a campaign with no policy_path must carry the
// unscored notice in Results.
func TestReportSaysItIsUnscoped(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Unscoped Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mkBareHypothesis(t, camp, "Unscored finding")
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "NO POLICY LOADED") {
		t.Fatalf("report does not say it is unscoped:\n%s", text)
	}
	if !strings.Contains(text, "webv2 scope "+camp.CampaignID+" --policy FILE") {
		t.Errorf("the notice does not name the fix:\n%s", text)
	}
	if !strings.Contains(text, "not a submission recommendation") {
		t.Errorf("the notice does not state the consequence:\n%s", text)
	}
}

// TestReportScopedCampaignHasNoNotice: the notice is presence-gated — a scoped
// campaign's bytes do not change.
func TestReportScopedCampaignHasNoNotice(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Scoped Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mkBareHypothesis(t, camp, "Scored finding")
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"program":"Scoped Program",`+
		`"program_url":"https://x","chains":["ethereum"],`+
		`"scope":[{"target":"Vault","kind":"contract"}],"exclusions":[],`+
		`"severity_rules":[{"severity":"critical","match":{"bug_classes":`+
		`["share-price-inflation"]}}],`+
		`"poc_requirements":{"min_evidence_level":"E4","require_fork_repro":false},`+
		`"submission_budget":{"max_findings":3,"rank_by":"acceptance"},`+
		`"reporting":{"contact":"immunefi","required_fields":["PoC"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// state.InitOpts carries no policy path, so patch the state file the way
	// the report's own tests do.
	doc, err := validation.ReadJson(camp.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(policyPath))
	if err := validation.WriteJson(camp.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "NO POLICY LOADED") {
		t.Fatalf("a scoped campaign must not print the unscoped notice:\n%s",
			string(body))
	}
}
