package report

// T35 testmap re-triage:
// tests/test_disproof_sibling.py::test_report_annotates_sibling_priority.
// An open sibling priority is annotated in the Answer-quality plan block.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

func siblingPlanCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	installMemorySeams(t)
	c, err := state.Init(root, "Sibling Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	model := validation.VObj(
		kv("protocol_id", validation.VStr("sib")),
		kv("name", validation.VStr("Sibling Program")),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Vault")),
			kv("path", validation.VStr("src/Vault.sol")),
			kv("entry_points", validation.VArr(validation.VStr("withdraw")))))),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("state_machines", validation.VArr()))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), model, ""); err != nil {
		t.Fatal(err)
	}
	plan, err := planner.DefaultPlanFromModel(c, planner.ModelOrEmpty(c))
	if err != nil {
		t.Fatal(err)
	}
	sib := validation.VObj(
		kv("budget_class", validation.VStr("cheap")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("components", validation.VArr()),
		kv("id", validation.VStr("Q-900")),
		kv("invariant_ids", validation.VArr()),
		kv("question", validation.VStr("Check the adjacent unchecked property: "+
			"the other root in the struct")),
		kv("recommended_stages", validation.VArr()),
		kv("required_context", validation.VArr()),
		kv("risk", validation.VFloat(0.6)),
		kv("status", validation.VStr("open")),
		kv("trajectories", validation.VArr(validation.VStr("lifecycle"))),
		kv("sibling_of", validation.VStr("F-001")))
	prios := append([]validation.Value{}, listAt(plan, "priorities")...)
	prios = append(prios, sib)
	plan = withKey(plan, "priorities", validation.VArr(prios...))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestReportAnnotatesSiblingPriority(t *testing.T) {
	c := siblingPlanCampaign(t)
	path, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	if !strings.Contains(text, "sibling of f-001") {
		t.Fatalf("report does not annotate the sibling priority:\n%s",
			tailLines(string(raw), 40))
	}
}

// withKey replaces (or appends) one top-level plan key.
func withKey(plan validation.Value, key string,
	v validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(plan.O)+1)
	replaced := false
	for _, kv := range plan.O {
		if kv.K == key {
			out = append(out, validation.KV{K: key, V: v})
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: v})
	}
	return validation.VObj(out...)
}

// tailLines returns the last n lines of s (failure diagnostics only).
func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// TestReportRendersSymmetryPrimitives ports
// test_symmetry_teeth.py::test_report_renders_symmetry_primitives: the
// hypothesis-lens block renders each family's quoted primitives.
func TestReportRendersSymmetryPrimitives(t *testing.T) {
	c := siblingPlanCampaign(t)
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	sym := []validation.Value{
		validation.VObj(
			kv("family", validation.VStr("deposit")),
			kv("primitives", validation.VArr(validation.VStr("burn")))),
		validation.VObj(
			kv("family", validation.VStr("withdraw")),
			kv("primitives", validation.VArr(validation.VStr("mint"),
				validation.VStr("safeTransfer")))),
	}
	reason := "compared the gateway primitives across siblings"
	plan, err = planner.MarkLens(c, plan, "L-04", "answered",
		planner.LensOpts{Reason: &reason, Actor: "tester", Symmetry: &sym})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	path, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"safeTransfer", "deposit", "withdraw"} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not render %q:\n%s", want,
				tailLines(text, 30))
		}
	}
}
