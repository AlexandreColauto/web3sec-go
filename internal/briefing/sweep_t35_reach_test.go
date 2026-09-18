package briefing

// Port of tests/test_reachability.py::test_brief_surfaces_reachability_for_stuck_class.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestBriefSurfacesReachabilityForStuckClass(t *testing.T) {
	c := newCamp(t, "Acme Program")
	f := t35WorkHypo(t, c, "cross-chain replay hypothesis",
		"subset-of-users", "cross-chain-replay", nil)
	fid := validation.ObjStr(f, "finding_id")
	b := build(t, c, false)
	stuck := listAt(validation.ObjAt(b, "findings"), "structurally_unreachable")
	item := validation.VNull()
	for _, x := range stuck {
		if validation.ObjStr(x, "finding_id") == fid {
			item = x
		}
	}
	if item.Kind != validation.Obj {
		t.Fatalf("finding %s missing from structurally_unreachable: %v", fid,
			t35IDs(stuck))
	}
	if got := validation.ObjStr(item, "floor"); got != "E6" {
		t.Errorf("floor = %q, want E6", got)
	}
	hasPin := false
	for _, m := range strListOf(validation.ObjAt(item, "missing")) {
		if strings.Contains(m, "pin") {
			hasPin = true
		}
	}
	if !hasPin {
		t.Errorf("missing = %v, want a pin demand", validation.ObjAt(item, "missing"))
	}
	named := false
	for _, a := range validation.ObjAt(b, "next_actions").A {
		// Task 7 fix round 1 (I-2): the line leads with the real command
		// (`webv2 floors <C> set …`), so "floors set" is no longer a
		// contiguous substring — the command head and the stuck reason
		// are checked separately.
		if strings.Contains(a.S, fid) && strings.Contains(a.S, "floors") &&
			strings.Contains(a.S, " set ") {
			named = true
		}
	}
	if !named {
		t.Errorf("no next action names %s with the floors set command", fid)
	}
}
