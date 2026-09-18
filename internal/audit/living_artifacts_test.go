package audit

// Ported 1:1 from web3sec-final tests/test_living_artifacts.py (audit
// angle, P0 addendum / P1-plan Task 0): a sanctioned refresh keeps the
// audit green; a hand-edit that bypasses the API still fails it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/state"
)

const livingDefReason = "re-registered (content may have changed)"

func livingPlan(t *testing.T, c *state.Campaign, text string) string {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	b, err := json.Marshal(map[string]any{"plan": text})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func livingPlanID(t *testing.T, c *state.Campaign) string {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(a, "kind") == "plan" {
			return validation.ObjStr(a, "artifact_id")
		}
	}
	t.Fatal("no plan artifact")
	return ""
}

// test_audit_green_after_sanctioned_refresh
func TestLivingAuditGreenAfterSanctionedRefresh(t *testing.T) {
	c := initCampaign(t)
	p := livingPlan(t, c, "v1")
	if _, err := c.RegisterOrRefresh("plan", p, "", nil, livingDefReason); err != nil {
		t.Fatal(err)
	}
	livingPlan(t, c, "v2")
	aid := livingPlanID(t, c)
	if _, err := c.RefreshArtifact(aid, "plan rewritten by answer loop", "pipeline"); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(validation.ObjAt(report, "sections"), "artifacts"); !validation.ObjAt(got, "ok").B {
		t.Errorf("sanctioned refresh left artifacts section failing: %v", got)
	}
}

// test_audit_flags_hand_edit_even_after_refresh
func TestLivingAuditFlagsHandEditEvenAfterRefresh(t *testing.T) {
	c := initCampaign(t)
	p := livingPlan(t, c, "v1")
	if _, err := c.RegisterOrRefresh("plan", p, "", nil, livingDefReason); err != nil {
		t.Fatal(err)
	}
	livingPlan(t, c, "v2")
	aid := livingPlanID(t, c)
	if _, err := c.RefreshArtifact(aid, "sanctioned v2", "pipeline"); err != nil {
		t.Fatal(err)
	}
	// then someone hand-edits WITHOUT the API.
	livingPlan(t, c, "v3 FORGED")
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	sec := validation.ObjAt(validation.ObjAt(report, "sections"), "artifacts")
	if validation.ObjAt(sec, "ok").B {
		t.Fatal("hand-edit after refresh not caught")
	}
	found := false
	for _, pr := range validation.ObjAt(sec, "problems").A {
		if strings.Contains(pr.S, "hash mismatch") {
			found = true
		}
	}
	if !found {
		t.Errorf("no hash-mismatch problem: %v", validation.ObjAt(sec, "problems"))
	}
}
