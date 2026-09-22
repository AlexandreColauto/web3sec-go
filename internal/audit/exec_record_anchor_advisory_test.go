package audit

// v1.6 — the audit's non-problem advisory channel.
//
// The exec_record_anchor section reports UNANCHORED exec records as coverage,
// never as problems: the committed Python-era fixture carries two unanchored
// sandbox.exec events and scripts/verify-full.sh step 9 asserts audit PASS
// over it. A count visible only in `audit --json` is invisible to an operator
// who runs `webv2 audit` and reads PASS, so AuditAdvisories surfaces it — on
// a channel that cannot move `ok` or the exit code.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// auditAnchorExec writes a minimal schema-valid exec record and returns the
// exec id (deterministic: a literal timestamp, never the clock).
func auditAnchorExec(t *testing.T, c *state.Campaign) string {
	t.Helper()
	execID := "EXEC-0000000001"
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr("docker-networkless")},
		validation.KV{K: "command", V: validation.VStr("forge test")},
		validation.KV{K: "policy_verdict", V: validation.VObj(
			validation.KV{K: "allowed", V: validation.VBool(true)})},
		validation.KV{K: "started_at",
			V: validation.VStr("2026-01-01T00:00:00.000000+00:00")},
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	return execID
}

// logLegacyExec appends the pre-anchor sandbox.exec event shape: profile and
// exit only, no anchor key.
func logLegacyExec(t *testing.T, c *state.Campaign, execID string) {
	t.Helper()
	ref := execID
	data := validation.VObj(validation.KV{K: "exit", V: validation.VInt(0)})
	if _, err := c.Log("sandbox.exec", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

func TestAuditAdvisoriesSurfaceUnanchoredCoverage(t *testing.T) {
	c := initCampaign(t)
	logLegacyExec(t, c, auditAnchorExec(t, c))
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	// The unanchored event is a coverage fact: the report is CLEAN (this is
	// the step-9 property, at the report level).
	if !reportOK(report) {
		t.Fatalf("an unanchored exec record made the audit dirty: %v",
			sectionOKFlags(report))
	}
	adv := AuditAdvisories(report)
	if len(adv) != 1 {
		t.Fatalf("advisories = %v, want exactly the unanchored coverage line",
			adv)
	}
	if !strings.Contains(adv[0], "1 unanchored exec record(s)") {
		t.Fatalf("the advisory must carry the count: %q", adv[0])
	}
	if strings.Contains(AuditSummaryLine(report), "unanchored") {
		t.Fatalf("the advisory leaked into the summary line: %q",
			AuditSummaryLine(report))
	}
}

func TestAuditAdvisoriesAreEmptyWithoutTheAnchorSection(t *testing.T) {
	report, err := AuditCampaign(initCampaign(t))
	if err != nil {
		t.Fatal(err)
	}
	if adv := AuditAdvisories(report); len(adv) != 0 {
		t.Fatalf("a campaign with no exec events must produce no advisory: %v",
			adv)
	}
}
