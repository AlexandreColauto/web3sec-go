package findings_test

// gate_probe_anchor_dispo_test.go — the disposition-status drift pin, placed
// in the EXTERNAL test package on purpose: anchorlink cannot import planner
// (planner -> findings -> anchorlink; the wave-2 gate made even a test-binary
// import a real cycle — see anchorlink/query.go's copy comment), and this
// package's external tests import planner legally.
//
// The pin is behavior-over-list, both directions:
//   - planner.ProbeRowDispositioned must still equal the literal snapshot
//     below AND anchorlink's exported behaviour must agree with that list:
//     the CONFIRMED clause stays silent for every IN-list status and fires
//     for a foreign one. A planner edit fails the snapshot first (loud,
//     names the commit pair); the behaviour case then proves the copy moved
//     with it, so no silent widening of the gate is possible.

import (
	"strings"
	"testing"

	"websec/internal/anchorlink"
	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/validation"
)

// dispositionSnapshot is planner.ProbeRowDispositioned as of 2026-09-18.
var dispositionSnapshot = []string{"answered", "not-applicable", "deprioritized"}

func TestProbeAnchorDispositionListUnchanged(t *testing.T) {
	got := append([]string{}, planner.ProbeRowDispositioned...)
	if strings.Join(got, "|") != strings.Join(dispositionSnapshot, "|") {
		t.Fatalf("planner.ProbeRowDispositioned moved: %v vs snapshot %v — "+
			"update the snapshot AND anchorlink/query.go's dispositionedStatuses "+
			"copy in the same commit", got, dispositionSnapshot)
	}
}

func TestProbeAnchorDispositionBehaviourMatchesPlanner(t *testing.T) {
	model := validation.VObj(
		validation.KV{K: "contracts", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "name", V: validation.VStr("Rollup")},
				validation.KV{K: "path", V: validation.VStr("l1/rollup/Rollup.sol")},
			))},
		validation.KV{K: "state_machines", V: validation.VArr()},
	)
	row := validation.VObj(
		validation.KV{K: "row_id", V: validation.VStr("R-1")},
		validation.KV{K: "tier", V: validation.VInt(0)},
		validation.KV{K: "contract", V: validation.VStr("Rollup")},
		validation.KV{K: "consumer", V: validation.VStr("commitBatch")},
		validation.KV{K: "consumer_line", V: validation.VInt(204)})
	prio := func(status string) validation.Value {
		return validation.VObj(
			validation.KV{K: "id", V: validation.VStr("Q-1")},
			validation.KV{K: "status", V: validation.VStr(status)},
			validation.KV{K: "probe", V: validation.VObj(
				validation.KV{K: "row_id", V: validation.VStr("R-1")})})
	}
	store, err := anchorlink.Open(model)
	if err != nil {
		t.Fatal(err)
	}
	dispo := func(status string) bool {
		m := store.Index([]validation.Value{row},
			[]validation.Value{prio(status)}, nil).Query("l1/rollup/Rollup.sol")
		return len(m.Rows) == 1 && m.Rows[0].Dispositioned
	}
	for _, s := range planner.ProbeRowDispositioned {
		if !dispo(s) {
			t.Errorf("planner status %q reads undispositioned through "+
				"anchorlink — the copy in query.go is behind planner", s)
		}
	}
	if dispo("deferred") {
		t.Error(`status "deferred" (NOT in planner.ProbeRowDispositioned) reads ` +
			"dispositioned — the copy is wider than planner, silently closing " +
			"the gate for rows the planner still counts open")
	}
	// Reference the exported clause entry so the pin cannot rot silently
	// while its signature changes.
	_ = findings.ConfirmationGateClauses
}
