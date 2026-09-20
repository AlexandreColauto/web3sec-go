package probes

// r3_audit_test.go — R3-7 (Morph r3 defect 7): after a mid-campaign
// surface rebuild, priorities citing dead rows burned the audit section
// forever — `answered ... blocked` was the only honest verb for an orphan,
// and the flag loop ignored status, so the discharge never landed. Only the
// ORPHAN arm learns to stand down for closed priorities; the never-emitted
// arm keeps seeing every priority (a closed priority still covers its row).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// r3AuditCamp seeds a campaign whose surface carries two rows; the plan
// gives Q-007 a DEAD row_id (the orphan) at `orphanStatus` and Q-008 the
// live row 81dfad6492 at `liveStatus`.
func r3AuditCamp(t *testing.T, orphanStatus, liveStatus string,
	liveRow string) *state.Campaign {
	t.Helper()
	camp, err := state.Init(t.TempDir(), "r3 audit",
		state.InitOpts{CampaignID: "C-0123456789ab"})
	if err != nil {
		t.Fatal(err)
	}
	surface := `{"campaign_id":"C-0123456789ab","index_sha":"None","rows":[` +
		`{"row_id":"81dfad6492","probe":"assertion-strength"},` +
		`{"row_id":"b6fe31cdf7","probe":"assertion-strength"}]}`
	plan := `{"campaign_id":"C-0123456789ab","priorities":[` +
		`{"id":"Q-007","status":"` + orphanStatus +
		`","question":"orphan row check","probe":{"row_id":"deadbeef01"}}` +
		`,{"id":"Q-008","status":"` + liveStatus +
		`","question":"live row check","probe":{"row_id":"` + liveRow +
		`"}}]}`
	for name, body := range map[string]string{
		"probe_surface.json": surface, "campaign_plan.json": plan} {
		if err := os.WriteFile(filepath.Join(camp.ArtifactsDir, name),
			[]byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return camp
}

func r3AuditProblems(t *testing.T, camp *state.Campaign) []string {
	t.Helper()
	sect, err := AuditSurface{}.AuditSurface(camp)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range vList(sect, "problems") {
		if p.Kind != validation.Str {
			t.Fatalf("problem not a string: %v", p)
		}
		out = append(out, p.S)
	}
	return out
}

func hasOrphanFlag(problems []string) bool {
	for _, p := range problems {
		if strings.Contains(p, "cites probe row 'deadbeef01'") &&
			strings.Contains(p, "does not carry") {
			return true
		}
	}
	return false
}

// (a) the open orphan still fires — byte-identical sentence.
func TestAuditOrphanFlagForOpenPriorityUnchanged(t *testing.T) {
	problems := r3AuditProblems(t, r3AuditCamp(t, "open", "open",
		"81dfad6492"))
	want := "plan priority Q-007 cites probe row 'deadbeef01', which the " +
		"current surface does not carry — the surface was rebuilt without " +
		"it; re-run `webv2 probes C-0123456789ab run --emit`"
	found := ""
	for _, p := range problems {
		if strings.HasPrefix(p, want) {
			found = p
		}
	}
	if found == "" {
		t.Fatalf("open orphan must flag with the pinned sentence:\n%v",
			problems)
	}
	if !hasOrphanFlag(problems) {
		t.Fatal("hasOrphanFlag disagrees with its own substring")
	}
}

// (b) a closed discharge — blocked, or answered — stands the orphan flag
// down: `webv2 answered C Q-007 blocked --reason 'row dropped by the
// surface rebuild'` IS the repair verb for an orphan.
func TestAuditClosedOrphanDischargesFlag(t *testing.T) {
	for _, status := range []string{"blocked", "answered", "not-applicable",
		"deprioritized"} {
		problems := r3AuditProblems(t, r3AuditCamp(t, status, "open",
			"81dfad6492"))
		if hasOrphanFlag(problems) {
			t.Errorf("status %q must discharge the orphan flag:\n%v",
				status, problems)
		}
	}
	// reopen keeps honesty: a closed-then-reopened orphan flags again
	problems := r3AuditProblems(t, r3AuditCamp(t, "open", "open",
		"81dfad6492"))
	if !hasOrphanFlag(problems) {
		t.Fatalf("an open orphan must flag after the closed path:\n%v",
			problems)
	}
}

// (c) the reverse arms stay honest: a live row covered only by a CLOSED
// priority is not never-emitted; an uncovered surface row still is.
func TestAuditNeverEmittedArmIgnoresStatus(t *testing.T) {
	problems := r3AuditProblems(t, r3AuditCamp(t, "open", "answered",
		"81dfad6492"))
	for _, p := range problems {
		if strings.Contains(p, "'81dfad6492'") && strings.Contains(p,
			"never emitted") {
			t.Fatalf("a closed priority still covers its live row:\n%v",
				problems)
		}
	}
	found := false
	for _, p := range problems {
		if strings.Contains(p, "'b6fe31cdf7'") && strings.Contains(p,
			"never emitted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("uncovered surface row must still flag never-emitted:\n%v",
			problems)
	}
}
