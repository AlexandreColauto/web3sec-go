package cli

// P1b CLI tests — `prioritize` and `repro-queue` (ord 6/7).
//
// Ports: tests/test_orchestrator.py's triage/queue row shape through the
// CLI's own rendering (cli.py cmd_prioritize / cmd_repro_queue).

import (
	"regexp"
	"strings"
	"testing"
)

var triageLine = regexp.MustCompile(`^\[\S+\] prior=\d+\.\d{2} cost=\S+\s+F-[0-9a-f]{12}$`)

func TestPrioritizePrintsTriageRows(t *testing.T) {
	c, root := t15Campaign(t, "prioritize")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	code, out, errS := run(t, "--root", root, "prioritize", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines %q", lines)
	}
	if !triageLine.MatchString(lines[0]) {
		t.Fatalf("row %q does not match the triage shape", lines[0])
	}
	if !strings.HasSuffix(lines[0], objStr(f, "finding_id")) {
		t.Fatalf("row %q must name the finding", lines[0])
	}
}

func TestPrioritizeMissingCampaignArgIsArgparse(t *testing.T) {
	code, _, errS := run(t, "prioritize")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := "usage: webv2 prioritize [-h] campaign\n" +
		"webv2 prioritize: error: the following arguments are required: campaign\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
