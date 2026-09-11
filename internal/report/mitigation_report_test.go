package report

// G5: the soundness-layer bullet is the in-code-ack bullet's sibling in
// the correctness group — score-only, never a dismissal — and the POLICY
// layer (accepted risk) never gains it. Presence-gated: a finding without
// a parseable mitigation_present renders byte-for-byte as before.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

func mitigationFinding(extra ...validation.KV) validation.Value {
	dm := validation.VObj(kv("mitigation_present", validation.VStr(
		findings.MitigRecord("cei-order", "src/Escrow.sol", 23,
			"last write at L23 precedes call at L26"))))
	o := []validation.KV{
		kv("finding_id", validation.VStr("F-mit1")),
		kv("title", validation.VStr("Reentrancy in withdraw")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")),
		kv("dedup_meta", dm),
	}
	return validation.VObj(append(o, extra...)...)
}

func renderMitigationSection(t *testing.T, f validation.Value) string {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Mitigation Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	lines, err := findingSection(c, f, "CONFIRMED", nil)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func TestReportRendersSoundnessDemotionBullet(t *testing.T) {
	got := renderMitigationSection(t, mitigationFinding())
	if !strings.Contains(got,
		"- soundness layer demotes: cei-order (src/Escrow.sol:23)") {
		t.Errorf("soundness bullet missing from the section:\n%s", got)
	}
}

func TestReportOmitsSoundnessBulletWhenAbsent(t *testing.T) {
	bare := validation.VObj(
		kv("finding_id", validation.VStr("F-mit0")),
		kv("title", validation.VStr("Reentrancy in withdraw")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")))
	if got := renderMitigationSection(t, bare); strings.Contains(got,
		"soundness layer") {
		t.Errorf("unexpected soundness line:\n%s", got)
	}
	// garbage shapes render nothing either.
	junk := mitigationFinding()
	junk.O = validation.SetOrAppend(junk.O, "dedup_meta", validation.VObj(
		kv("mitigation_present", validation.VStr("not json"))))
	if got := renderMitigationSection(t, junk); strings.Contains(got,
		"soundness layer") {
		t.Errorf("garbage mitigation_present must not render:\n%s", got)
	}
}

func TestReportAcceptedRiskBulletIgnoresMitigation(t *testing.T) {
	// Both layers present: the policy bullet renders its own record and
	// carries no soundness content.
	f := mitigationFinding(kv("bounty", validation.VObj(
		kv("accepted_risk", validation.VObj(
			kv("pattern", validation.VStr("reentrancy")),
			kv("kind", validation.VStr("accepted-risk")),
		)))))
	got := renderMitigationSection(t, f)
	want := "- accepted risk: **reentrancy** (accepted-risk)"
	if !strings.Contains(got, want) {
		t.Errorf("policy bullet changed:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "- accepted risk:") &&
			strings.Contains(line, "cei-order") {
			t.Errorf("policy bullet leaked the soundness layer:\n%s", line)
		}
	}
}

func TestScoreCellMitigationMarker(t *testing.T) {
	mk := func(demoted bool) string {
		return scoreCell(risk.AcceptanceEntry{Score: 3.0,
			MitigationDemoted: demoted})
	}
	if got := mk(false); got != "3.00" {
		t.Fatalf("unmarked = %q, want 3.00", got)
	}
	if got := mk(true); got != "3.00 -mitigation" {
		t.Fatalf("marked = %q, want %q", got, "3.00 -mitigation")
	}
}
