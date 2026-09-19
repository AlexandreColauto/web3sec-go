package cli

// floor_evidence_r33_test: the ONE fixture funnel for the R3-3 evidence floor.
//
// findings.Transition now refuses any move whose target status carries an
// evidence floor above the finding's own level (POSSIBLE -> E2,
// PROVISIONALLY_VALID -> E1, CHAIN -> E4), so a fixture that stamps one of
// those statuses must earn the floor first. addFloorEvidence attaches the
// manual (non-exec) item the floor demands; it is the finding's first rise
// above the E0 baseline, so it pays the campaign's discovery slot once — the
// exec-backed evidence the fixtures attach afterwards rides that same rise
// for free, keeping the campaign's slot spend unchanged.

import (
	"fmt"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// cliFloorEvidenceSeq mints unique evidence ids for the manual floor items
// the fixtures attach before a status whose evidence floor is above E0.
var cliFloorEvidenceSeq int

// addFloorEvidence attaches a manual (non-exec) evidence item at *level*: the
// reachability evidence a status floor demands before the status stamp.
func addFloorEvidence(t *testing.T, c *state.Campaign, fid, level string) {
	t.Helper()
	cliFloorEvidenceSeq++
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr(
			fmt.Sprintf("EV-floor-%04d", cliFloorEvidenceSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"manual reachability note: the path to the sink is reachable")))); err != nil {
		t.Fatalf("add floor evidence %s: %v", level, err)
	}
}
