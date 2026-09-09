package briefing

// T35 testmap re-triage:
// tests/test_symmetry_teeth.py::test_brief_surfaces_primitive_less_l04_family
// — the divergence block names the family whose symmetry table lacks a quoted
// primitive.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/validation"
)

func TestBriefSurfacesPrimitiveLessL04Family(t *testing.T) {
	c := newCamp(t, "Morph L2")
	l1 := validation.VObj(
		kv("name", validation.VStr("L1")),
		kv("path", validation.VStr("a.sol")),
		kv("entry_points", validation.VArr(validation.VStr("deposit"),
			validation.VStr("withdraw"))))
	l2 := validation.VObj(
		kv("name", validation.VStr("L2")),
		kv("path", validation.VStr("b.sol")),
		kv("entry_points", validation.VArr(validation.VStr("deposit"),
			validation.VStr("withdraw"), validation.VStr("drop"))))
	machine := validation.VObj(
		kv("name", validation.VStr("rollup")),
		kv("states", validation.VArr(validation.VObj(
			kv("id", validation.VStr("open"))))),
		kv("transitions", validation.VArr(validation.VObj(
			kv("from", validation.VStr("open")),
			kv("to", validation.VStr("fin")),
			kv("trigger", validation.VStr("finalize"))))))
	model := validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("n")),
		kv("contracts", validation.VArr(l1, l2)),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("state_machines", validation.VArr(machine)))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), model, ""); err != nil {
		t.Fatal(err)
	}
	plan, err := planner.DefaultPlanFromModel(c, planner.ModelOrEmpty(c))
	if err != nil {
		t.Fatal(err)
	}
	// withdraw lacks a primitive: only deposit is attested
	sym := []validation.Value{validation.VObj(
		kv("family", validation.VStr("deposit")),
		kv("primitives", validation.VArr(validation.VStr("burn"))))}
	reason := "compared the gateway primitives across siblings"
	plan, err = planner.MarkLens(c, plan, "L-04", "answered",
		planner.LensOpts{Reason: &reason, Actor: "tester", Symmetry: &sym})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	missing := listAt(asObj(objAt(b, "divergence")), "missing")
	found := false
	for _, m := range missing {
		if objStr(m, "subject") == "L-04" &&
			strings.Contains(objStr(m, "what"), "withdraw") {
			found = true
		}
	}
	if !found {
		t.Fatalf("divergence.missing does not name the primitive-less "+
			"withdraw family: %v", missing)
	}
}
