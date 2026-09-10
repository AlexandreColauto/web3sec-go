// Port of tests/test_campaign_complete.py's two state-level functions.
// The Python twin was retired 2026-09-09; this package is the source of truth. (The broader TestComplete in phases_test.go covers the same
// API; these keep the Python row mapping 1:1.)
package state

import "testing"

func TestCompleteSetsPhaseAndRecordsDecision(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Closure Program", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete("alice",
		"pass closed: report generated, findings filed"); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(st, "phase"); got != "COMPLETE" {
		t.Errorf("phase = %q, want COMPLETE", got)
	}
	if got := objStr(st, "completed_by"); got != "alice" {
		t.Errorf("completed_by = %q, want alice", got)
	}
	reason := objStr(st, "completed_reason")
	if len(reason) < 10 || reason[:11] != "pass closed" {
		t.Errorf("completed_reason = %q, want it to start with 'pass closed'",
			reason)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	completed := 0
	transition := false
	for _, e := range events {
		if objStr(e, "type") == "campaign.completed" {
			completed++
			if got := objStr(objAt(e, "data"), "actor"); got != "alice" {
				t.Errorf("campaign.completed actor = %q, want alice", got)
			}
		}
		if objStr(e, "type") == "phase.transition" &&
			objStr(e, "ref") == "COMPLETE" {
			transition = true
		}
	}
	if completed != 1 {
		t.Errorf("campaign.completed events = %d, want 1", completed)
	}
	if !transition {
		t.Errorf("the phase transition to COMPLETE is not on the log")
	}
}

func TestCompleteRequiresActorAndWrittenReason(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Closure Program", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Complete("", "a reason that is long enough"); err == nil {
		t.Errorf("empty actor must be rejected")
	}
	if _, err := c.Complete("alice", "short"); err == nil {
		t.Errorf("a short reason must be rejected")
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(st, "phase"); got == "COMPLETE" {
		t.Errorf("phase = COMPLETE after rejected completions")
	}
}
