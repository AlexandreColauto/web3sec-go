package cli

// P1b CLI tests — `repro-queue` (ord 7).
//
// Ports: tests/test_orchestrator.py's reproduction-queue row shape through
// the CLI's own rendering (cli.py cmd_repro_queue).

import (
	"regexp"
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/findings"
)

func TestReproQueuePrintsOrderedCandidates(t *testing.T) {
	c, root := t15Campaign(t, "repro-queue")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	if _, err := findings.Transition(c, validation.ObjStr(f, "finding_id"), "POSSIBLE",
		"triage: reachable path", "", "", false); err != nil {
		t.Fatalf("transition: %v", err)
	}
	code, out, errS := run(t, "--root", root, "repro-queue", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	row := strings.TrimRight(out, "\n")
	if !regexp.MustCompile(`^prior=\d+\.\d{2} next=T\d attempts=\d+  F-[0-9a-f]{12}$`).
		MatchString(row) {
		t.Fatalf("row %q does not match the queue shape", row)
	}
	if !strings.HasSuffix(row, validation.ObjStr(f, "finding_id")) {
		t.Fatalf("row %q must name the finding", row)
	}
}

func TestReproQueueMissingCampaignArgIsArgparse(t *testing.T) {
	code, _, errS := run(t, "repro-queue")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := "usage: webv2 repro-queue [-h] campaign\n" +
		"webv2 repro-queue: error: the following arguments are required: campaign\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
