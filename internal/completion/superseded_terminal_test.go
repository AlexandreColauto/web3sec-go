package completion

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

// Morph pass-1 review §7.6: SUPERSEDED is a bookkeeping REDIRECT, not a claim
// awaiting a memory row — the successor finding carries the knowledge and the
// predecessor has nothing to remember. The memory store's own status
// vocabulary never accepted SUPERSEDED, so demanding a row for it was a
// catch-22 that forced a waiver per retired finding. The learning proof must
// therefore ignore the superseded finding entirely: it is not named in
// missing[], and once the only other open item (the reflection entry) lands,
// the proof is DONE.
func TestLearningProofIgnoresSuperseded(t *testing.T) {
	const fid = "F-0000000000aa"
	camp := supersededCampaign(t, fid)
	// The reflection is the only other open item; land it through the same
	// call the CLI's `--reflect` path makes.
	if _, err := learning.ReflectionEntry(camp, learning.ReflectionOpts{
		Round: 1, ProcessImprovements: []string{"superseded needs no memory"},
	}); err != nil {
		t.Fatal(err)
	}
	res, err := ProofStatus(camp, "learning")
	if err != nil {
		t.Fatal(err)
	}
	if learningProofMentions(res, fid) {
		t.Fatalf("learning proof still owes a memory row to the superseded "+
			"finding: %v", validation.DumpsOrdered(res, true))
	}
	if !validation.ObjAt(res, "done").B {
		t.Fatalf("reflected campaign whose only finding is superseded must be "+
			"done: %v", validation.DumpsOrdered(res, true))
	}
}

// supersededCampaign builds a campaign whose ONLY finding is a terminal
// SUPERSEDED row.
func supersededCampaign(t *testing.T, fid string) *state.Campaign {
	t.Helper()
	camp, err := state.Init(t.TempDir(), "Superseded Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	v := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("status", validation.VStr("SUPERSEDED")),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")))
	if err := validation.WriteJson(findings.FindingPath(camp, fid), v, ""); err != nil {
		t.Fatal(err)
	}
	return camp
}
