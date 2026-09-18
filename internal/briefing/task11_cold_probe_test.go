// task11_cold_probe_test.go — plan §Task 11 (2026-09-17-trust-boundary-
// hardening.md): the cold probe surface is a persistent brief warning.
//
// Law: while the campaign phase is DISCOVERY and no `probes run --emit` is on
// record in the ledger, `brief` prints a standing warning line naming the
// exact command. It is NOT a gate: the line is advisory cockpit prose that
// clears the moment the emit is recorded.
package briefing

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// task11ColdBrief is the brief for a campaign in the given phase.
func task11ColdBrief(t *testing.T, phase string) []string {
	t.Helper()
	c := newCamp(t, "Cold Probe Program")
	if err := c.SetPhase(phase, "task 11 fixture"); err != nil {
		t.Fatalf("set phase %s: %v", phase, err)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("build brief: %v", err)
	}
	return objStringList(t, b, "next_actions")
}

// task11HasColdLine reports whether the actions carry the standing cold-probe
// warning: a `webv2 probes <cid> run --emit` line with the cold-surface reason.
func task11HasColdLine(cid string, actions []string) bool {
	for _, a := range actions {
		if strings.Contains(a, "webv2 probes "+cid+" run --emit") &&
			strings.Contains(a, "cold probe surface") {
			return true
		}
	}
	return false
}

// TestColdProbeWarningDuringDiscovery is the Task 11 witness: DISCOVERY with
// no emit on record warns; the recorded emit clears it.
func TestColdProbeWarningDuringDiscovery(t *testing.T) {
	c := newCamp(t, "Cold Probe Program")
	if err := c.SetPhase("DISCOVERY", "task 11 fixture"); err != nil {
		t.Fatalf("set phase: %v", err)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("build brief: %v", err)
	}
	actions := objStringList(t, b, "next_actions")
	if !task11HasColdLine(c.CampaignID, actions) {
		t.Fatalf("no cold probe surface warning in %v", actions)
	}
	// The warning is not a gate: the brief still reports, and the line is
	// advisory prose (command-first, no parenthesis — the Task 7 law).
	for _, a := range actions {
		if !strings.HasPrefix(a, "webv2 ") {
			t.Errorf("cold-probe campaign action %q is not command-first", a)
		}
	}
	// a recorded probe emit clears it
	data := validation.VObj(
		kv("surface_sha", validation.VStr("0000000000000000")),
		kv("created", validation.VArr()))
	if _, err := c.Log("probes.emit", nil, &data); err != nil {
		t.Fatalf("record probes.emit: %v", err)
	}
	b2, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatalf("build brief after emit: %v", err)
	}
	after := objStringList(t, b2, "next_actions")
	if task11HasColdLine(c.CampaignID, after) {
		t.Fatalf("cold probe warning survived the recorded emit: %v", after)
	}
}

// TestColdProbeWarningOnlyDuringDiscovery pins the phase gate: outside
// DISCOVERY the line is absent, emit or no emit.
func TestColdProbeWarningOnlyDuringDiscovery(t *testing.T) {
	for _, phase := range []string{"SCOPE", "CAMPAIGN_PLANNING", "COMPLETE"} {
		actions := task11ColdBrief(t, phase)
		for _, a := range actions {
			if strings.Contains(a, "cold probe surface") {
				t.Errorf("phase %s carries the DISCOVERY-only warning: %q",
					phase, a)
			}
		}
	}
}
