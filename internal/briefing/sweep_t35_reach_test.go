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
	fid := objStr(f, "finding_id")
	b := build(t, c, false)
	stuck := listAt(objAt(b, "findings"), "structurally_unreachable")
	item := validation.VNull()
	for _, x := range stuck {
		if objStr(x, "finding_id") == fid {
			item = x
		}
	}
	if item.Kind != validation.Obj {
		t.Fatalf("finding %s missing from structurally_unreachable: %v", fid,
			t35IDs(stuck))
	}
	if got := objStr(item, "floor"); got != "E6" {
		t.Errorf("floor = %q, want E6", got)
	}
	hasPin := false
	for _, m := range strListOf(objAt(item, "missing")) {
		if strings.Contains(m, "pin") {
			hasPin = true
		}
	}
	if !hasPin {
		t.Errorf("missing = %v, want a pin demand", objAt(item, "missing"))
	}
	named := false
	for _, a := range objAt(b, "next_actions").A {
		if strings.Contains(a.S, fid) && strings.Contains(a.S, "floors set") {
			named = true
		}
	}
	if !named {
		t.Errorf("no next action names %s with `floors set`", fid)
	}
}
