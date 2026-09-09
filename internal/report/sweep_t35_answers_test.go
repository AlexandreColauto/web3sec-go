package report

// Port of the report-rendering rows deferred as P3: lens families, reopened
// lenses, and the answer-quality red flag.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35PlanCampaign is the lens/answer fixture: a campaign with one saved plan.
func t35PlanCampaign(t *testing.T, lenses []validation.Value,
	priorities []validation.Value) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Lens Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-09-07T00:00:00Z")),
		kv("lenses", validation.VArr(lenses...)),
		kv("priorities", validation.VArr(priorities...)))
	if _, err := planner.SavePlan(c, plan); err != nil {
		t.Fatal(err)
	}
	return c
}

func t35Priority(id, question, status string, extra ...validation.KV) validation.Value {
	o := []validation.KV{
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr(question)),
		kv("risk", validation.VFloat(0.5)),
		kv("status", validation.VStr(status)),
		kv("trajectories", validation.VArr(validation.VStr("code")))}
	o = append(o, extra...)
	return validation.VObj(o...)
}

func t35Lens(id, status string, extra ...validation.KV) validation.Value {
	o := []validation.KV{
		kv("id", validation.VStr(id)),
		kv("lens", validation.VStr("primitive-symmetry")),
		kv("surface", validation.VStr("protocol")),
		kv("question", validation.VStr(strings.Repeat("q", 20))),
		kv("status", validation.VStr(status))}
	o = append(o, extra...)
	return validation.VObj(o...)
}

// Port of tests/test_lens_exhaustive.py::test_report_lists_lens_families.
func TestReportListsLensFamilies(t *testing.T) {
	c := t35PlanCampaign(t,
		[]validation.Value{t35Lens("L-04", "answered",
			kv("families", validation.VArr(validation.VStr("withdraw"),
				validation.VStr("mint"))),
			kv("families_checked", validation.VArr(
				validation.VStr("withdraw"), validation.VStr("mint"))),
			kv("closed_reason", validation.VStr("compared both")),
			kv("closed_by", validation.VStr("t")))},
		[]validation.Value{t35Priority("Q-001", strings.Repeat("q", 20),
			"open")})
	text := t35Generate(t, c)
	if !strings.Contains(text, "withdraw") || !strings.Contains(text, "mint") {
		t.Error("report omits the lens families")
	}
	if !strings.Contains(text,
		"[families: withdraw, mint; attested: withdraw, mint]") {
		t.Errorf("report lacks the families/attested line:\n%s",
			tailLines(text, 40))
	}
}

// Port of tests/test_lens_exhaustive.py::test_report_marks_reopened_lens.
func TestReportMarksReopenedLens(t *testing.T) {
	c := t35PlanCampaign(t,
		[]validation.Value{t35Lens("L-04", "open",
			kv("families", validation.VArr(validation.VStr("withdraw"),
				validation.VStr("mint"))),
			kv("reopen_reason", validation.VStr(
				"CONFIRMED F-001 in family withdraw")),
			kv("reopened_at", validation.VStr("2026-09-07T00:00:00Z")))},
		[]validation.Value{t35Priority("Q-001", strings.Repeat("q", 20),
			"open")})
	text := t35Generate(t, c)
	if !strings.Contains(text, "REOPENED") {
		t.Errorf("report does not mark the reopened lens:\n%s",
			tailLines(text, 40))
	}
	if !strings.Contains(text, "CONFIRMED F-001 in family withdraw") {
		t.Error("report omits the reopen reason")
	}
}

// Port of tests/test_answered.py::test_report_flags_unreferenced_answers.
func TestReportFlagsUnreferencedAnswers(t *testing.T) {
	c := t35PlanCampaign(t, nil, []validation.Value{
		t35Priority("Q-000", "probe question one here", "answered",
			kv("closed_reason", validation.VStr("probe ran; no effect")),
			kv("closed_ref", validation.VStr("EXEC-abc123"))),
		t35Priority("Q-001", "probe question two here", "answered",
			kv("closed_reason", validation.VStr(
				"not applicable to an off-chain target")))})
	text := t35Generate(t, c)
	if !strings.Contains(text, "## Answer quality") {
		t.Fatalf("report lacks the answer-quality section:\n%s",
			tailLines(text, 40))
	}
	if !strings.Contains(text, "**Q-001** (answered, no evidence ref)") {
		t.Error("a sentence-only answer must be the report's red flag")
	}
	if strings.Contains(text, "**Q-000** (answered, no evidence ref)") {
		t.Error("a referenced answer must not be flagged")
	}
}

// t35Generate writes the report and returns its text.
func t35Generate(t *testing.T, c *state.Campaign) string {
	t.Helper()
	path, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
