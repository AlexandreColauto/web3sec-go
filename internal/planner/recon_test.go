package planner

// recon_test.go — FIX-8 unit coverage for the divergence-gate-close recon
// demand (the end-to-end real-verb coverage lives in internal/cli's
// cmd_recon_gate_test.go; this package cannot import the recon verbs —
// structidx wires the planner, an import cycle in test).

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestReconGateRefusalNamesBothCommands: neither stamp on record refuses
// with both runnable commands named.
func TestReconGateRefusalNamesBothCommands(t *testing.T) {
	c := newCampaign(t, "recon-gate-none")
	err := checkReconStamps(c)
	if err == nil {
		t.Fatal("no-stamp campaign accepted")
	}
	msg := err.Error()
	for _, want := range []string{
		"no archetype prescreen on record",
		"no `webv2 sinks` run on record",
		"webv2 prescreen " + c.CampaignID + " --src SRC",
		"webv2 sinks " + c.CampaignID + " --src SRC",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
}

// TestReconGateCorruptPrescreenIsNotAPrescreen: a corrupt artifact reads as
// never-ran — absence is exactly the state the gate refuses on.
func TestReconGateCorruptPrescreenIsNotAPrescreen(t *testing.T) {
	c := newCampaign(t, "recon-gate-corrupt")
	if err := c.StampRecon("sinks", "src"); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"archetype_prescreen.json"), validation.VArr(), ""); err != nil {
		t.Fatal(err)
	}
	err := checkReconStamps(c)
	if err == nil || !strings.Contains(err.Error(),
		"no archetype prescreen on record") {
		t.Fatalf("corrupt prescreen accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "webv2 prescreen "+c.CampaignID) ||
		strings.Contains(err.Error(), "webv2 sinks "+c.CampaignID) {
		t.Fatalf("refusal does not name exactly the missing command: %v", err)
	}
}

// TestReconGatePassesWithBothStamps: the honest exit is cheap — both stamps
// on record pass, and the sinks row carries the tree it ran over.
func TestReconGatePassesWithBothStamps(t *testing.T) {
	c := newCampaign(t, "recon-gate-ok")
	reconOnRecord(t, c)
	if err := checkReconStamps(c); err != nil {
		t.Fatalf("both stamps refused: %v", err)
	}
	sinks, err := c.ReconStamp("sinks")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(sinks, "src") != "src" || validation.ObjStr(sinks, "at") == "" {
		t.Fatalf("sinks stamp = %s", validation.CanonCompact(sinks))
	}
}
