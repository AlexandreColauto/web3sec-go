package findings

// levels_test.go: plan §Task 3 (morph pass-2 framework fixes) — the liveness
// family's CONFIRMED floor. The class-map default (E5, fork reality) made the
// missing fork the evidence ceiling on bugs a repo's own harness can decide.
import (
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// Morph pass-1 review §6.3: the liveness family is the MOST locally provable
// class — sequential finalization, queue ordering and challenge windows run
// end-to-end on a repo's own foundry harness. E5 (fork reality) made the
// missing fork the evidence ceiling on a bug the sandbox could prove.
func TestLivenessClassesConfirmAtE4(t *testing.T) {
	for _, cls := range []string{"chain-freeze", "sequencer-halt", "liveness"} {
		if got := ClassConfirmFloor(cls); got != "E4" {
			t.Errorf("ClassConfirmFloor(%q) = %s, want E4", cls, got)
		}
		if !ReachableLocally(cls, "E4") {
			t.Errorf("%s must be locally reachable at cap E4", cls)
		}
	}
}

// posChainFreeze walks a chain-freeze finding to POSSIBLE with a recorded T2
// local reproduction — the state a repo's own lifecycle harness reaches with
// no fork at all.
func posChainFreeze(t *testing.T) (*state.Campaign, validation.Value) {
	t.Helper()
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(kv("root_cause",
		validation.VObj(
			kv("class", validation.VStr("chain-freeze")),
			kv("description", validation.VStr(
				"finalizeBatch accepts a challenge after the window closes"))))),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	eFloor(t, c, fid, "E2") // R3-3: POSSIBLE carries an E2 floor
	if _, err := Transition(c, fid, "POSSIBLE", "triage", "", "", false); err != nil {
		t.Fatal(err)
	}
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(validation.ObjAt(vf, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T2")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	return c, vf
}

// The floor table is not the only reader: gate_checks.go's reproduction-tier
// arms only when the CONFIRMED floor is >= E5, so an E4 liveness class owes no
// fork-tier (T3) demand — the local lifecycle harness is the proof. Mirrors
// TestConfirmationGateHasNoTierClauseAtE4Floor (access-control) for the class
// the morph pass-1 miss was filed under.
func TestLivenessFloorDropsTheForkTierClause(t *testing.T) {
	c, vf := posChainFreeze(t)
	detail, err := ConfirmationGateDetail(c, vf)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range detail {
		if f.CheckID == "reproduction-tier" {
			t.Fatalf("E4-floor liveness class must carry no reproduction-tier "+
				"clause (morph §7.3): %v", f)
		}
	}
}
