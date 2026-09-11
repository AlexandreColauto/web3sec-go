package cli

// cmd_answered_batch_test.go — G14b: the batch `answered` verb. One status
// applies to every row (a mixed-status batch is not supported); every row's
// gates run before any mutation lands, and the first failure names its row.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// batchPlanBytes reads the campaign's plan file bytes for the
// byte-identical refusal check.
func batchPlanBytes(t *testing.T, root, cid string) string {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestAnsweredSinglePriorityUnchanged pins the old invocation
// byte-for-byte: one priority, one status, --reason.
func TestAnsweredSinglePriorityUnchanged(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason", "the vault is empty on first deposit",
		"--ref", "src/ShareVault.sol#L42", "--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "Q-001: status -> answered (ref: src/ShareVault.sol#L42)\n" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestAnsweredBatchClosesSeveral pins the batch happy path: one status for
// three rows, --reason-all riding each row, one status line per row.
func TestAnsweredBatchClosesSeveral(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid,
		"Q-001", "Q-002", "Q-003", "answered",
		"--reason-all", "batch review of the queue", "--actor", "op")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "Q-001: status -> answered\n" +
		"Q-002: status -> answered\n" +
		"Q-003: status -> answered\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	// --reason-all rode each row.
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"Q-001", "Q-002", "Q-003"} {
		p, ok := t14FindByID(t14List(plan, "priorities"), pid)
		if !ok {
			t.Fatalf("priority %s gone from the plan", pid)
		}
		if got := objStr(p, "closed_reason"); got !=
			"batch review of the queue" {
			t.Errorf("%s closed_reason = %q", pid, got)
		}
	}
	evts := dgEventsOfType(t, root, cid, "plan.priority_status")
	if len(evts) != 3 {
		t.Fatalf("plan.priority_status events = %d, want 3", len(evts))
	}
}

// TestAnsweredBatchRefusalNamesRow pins the all-or-nothing law through the
// CLI: the mid-batch failure names the first bad row, the plan file stays
// byte-identical, and zero events land.
func TestAnsweredBatchRefusalNamesRow(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	before := batchPlanBytes(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid,
		"Q-001", "Q-999", "Q-002", "answered",
		"--reason-all", "batch review of the queue")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasPrefix(errS, "answered: row 2 (Q-999):") ||
		!strings.Contains(errS, "no priority 'Q-999'") {
		t.Fatalf("stderr must name the first bad row: %q", errS)
	}
	if got := batchPlanBytes(t, root, cid); got != before {
		t.Fatal("refused batch mutated the plan file")
	}
	if evts := dgEventsOfType(t, root, cid,
		"plan.priority_status"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d events", len(evts))
	}
}

// TestAnsweredBatchEmptyPriorities pins the empty batch refusal: a campaign
// plus a status names no row.
func TestAnsweredBatchEmptyPriorities(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, _, errS := run(t, "--root", root, "answered", cid, "answered",
		"--reason-all", "batch review of the queue")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "priority") {
		t.Fatalf("stderr must complain about the missing priority: %q",
			errS)
	}
}

// TestAnsweredBatchReasonNeedsReasonAll pins the reason spelling: several
// priorities closed with --reason (not --reason-all) are refused with a
// pointer at the batch flag.
func TestAnsweredBatchReasonNeedsReasonAll(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, _, errS := run(t, "--root", root, "answered", cid,
		"Q-001", "Q-002", "answered",
		"--reason", "batch review of the queue")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "--reason-all") {
		t.Fatalf("stderr must point at --reason-all: %q", errS)
	}
}

// TestAnsweredBatchRejectsLenses pins the batch scope: lenses close one at
// a time, never in a batch.
func TestAnsweredBatchRejectsLenses(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, _, errS := run(t, "--root", root, "answered", cid,
		"Q-001", "L-01", "answered",
		"--reason-all", "batch review of the queue")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "Q-*") {
		t.Fatalf("stderr must name the Q-* scope: %q", errS)
	}
}

// TestAnsweredBatchClosingNeedsReason pins the reason enforcement for the
// batch spelling: closing without any reason is refused.
func TestAnsweredBatchClosingNeedsReason(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, _, errS := run(t, "--root", root, "answered", cid,
		"Q-001", "Q-002", "answered")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "--reason-all") {
		t.Fatalf("stderr must demand --reason-all: %q", errS)
	}
}
