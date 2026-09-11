package completion

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// A SUPERSEDED finding is terminal-absorbing: the learning proof tracks it
// like every other terminal status (TerminalStatuses) and demands a memory
// entry for it.
func TestLearningProofTracksSupersededAsTerminal(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Superseded Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	const fid = "F-0000000000aa"
	v := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("status", validation.VStr("SUPERSEDED")),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
	)
	if err := validation.WriteJson(findings.FindingPath(camp, fid), v, ""); err != nil {
		t.Fatal(err)
	}
	res, err := ProofStatus(camp, "learning")
	if err != nil {
		t.Fatal(err)
	}
	if !learningProofMentions(res, fid) {
		t.Fatalf("learning proof does not track the superseded finding: %v",
			validation.DumpsOrdered(res, true))
	}
}
