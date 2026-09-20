package cli

// r3_help_test.go — R3-9e + R3-9d: refusal/help pointers. The audit --deep
// refusal must name the verb that holds the deep sweep, and the schema help
// must say where bug classes live (taxonomy data — not a schema, by design).

import (
	"strings"
	"testing"
)

// R3-9e: `audit --deep` must point at the verb that actually holds the
// deep sweep, not just shrug the generic refusal (house law: every refusal
// names the next command).
func TestAuditDeepRefusalNamesTheWorkingCommand(t *testing.T) {
	c, root := t15Campaign(t, "auditdeep")
	code, _, errS := run(t, "--root", root, "audit", c.CampaignID, "--deep")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "unrecognized arguments: --deep") {
		t.Fatalf("lost the argparse shape: %q", errS)
	}
	if !strings.Contains(errS, "webv2 brief "+c.CampaignID+" --deep") {
		t.Fatalf("refusal must name the working command: %q", errS)
	}
	// pre-positional form keeps the generic pointer, still exit 2
	code, _, errS = run(t, "--root", root, "audit", "--deep")
	if code != 2 || !strings.Contains(errS, "webv2 brief <campaign> --deep") {
		t.Fatalf("no-campaign form: exit %d %q", code, errS)
	}
}

// R3-9d: the schema help cannot list the taxonomy (by design — classes are
// data), but it must SAY where they live.
func TestSchemaHelpPointsAtTheTaxonomy(t *testing.T) {
	code, out, errS := run(t, "--root", mkroot(t), "schema", "-h")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "assets/taxonomy") {
		t.Fatalf("schema help must name the taxonomy home:\n%s", out)
	}
}
