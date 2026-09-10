package report

// D8/A2: bounty advisories are non-blocking notes that must reach the reader.
// They render next to the gate verdict — and only when present, so a finding
// without them stays byte-identical.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func advisoryFinding(advisories []string) validation.Value {
	bounty := validation.VObj(
		kv("eligible", validation.VBool(true)),
		kv("submission_ready", validation.VBool(true)),
		kv("blocking_reasons", validation.VArr()))
	if advisories != nil {
		items := make([]validation.Value, 0, len(advisories))
		for _, a := range advisories {
			items = append(items, validation.VStr(a))
		}
		bounty.O = validation.SetOrAppend(bounty.O, "advisories",
			validation.Value{Kind: validation.Arr, A: items})
	}
	return validation.VObj(
		kv("finding_id", validation.VStr("F-abc123")),
		kv("title", validation.VStr("Reentrancy in withdraw")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")),
		kv("bounty", bounty))
}

func renderAdvisorySection(t *testing.T, advisories []string) string {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Advisory Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	lines, err := findingSection(c, advisoryFinding(advisories), "CONFIRMED", nil)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func TestReportRendersBountyAdvisories(t *testing.T) {
	const note = "boundary mutation still extracts under the recorded patch — " +
		"re-check the root cause before submitting"
	got := renderAdvisorySection(t, []string{note})
	if !strings.Contains(got, "- advisory: "+note) {
		t.Errorf("advisory missing from the section:\n%s", got)
	}
	if !strings.Contains(got, "- bounty gate:") {
		t.Errorf("gate line missing:\n%s", got)
	}
}

func TestReportOmitsAdvisoryLineWhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		adv  []string
	}{{"nil", nil}, {"empty", []string{}}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderAdvisorySection(t, tc.adv); strings.Contains(got, "advisory:") {
				t.Errorf("unexpected advisory line:\n%s", got)
			}
		})
	}
}
