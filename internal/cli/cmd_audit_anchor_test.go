package cli

// v1.6 — the unanchored advisory at the CLI.
//
// `webv2 audit` prints only problems, so before this the anchor's coverage
// count was visible only in `audit --json`. It is surfaced now as a `note:`
// line on stderr — the house advisory idiom (cmd_floors.go's unknown-class
// note) — and it can never move the verdict: the campaign below audits PASS
// with exit 0.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// cliAnchorExec writes a minimal schema-valid exec record plus a
// pre-anchor-shaped sandbox.exec event, and returns the campaign.
func cliAnchorExec(t *testing.T, root, cid string) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	execID := "EXEC-0000000001"
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)},
		validation.KV{K: "campaign_id", V: validation.VStr(cid)},
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
	ref := execID
	data := validation.VObj(validation.KV{K: "exit", V: validation.VInt(0)})
	if _, err := c.Log("sandbox.exec", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

func TestAuditPrintsTheUnanchoredAdvisoryWithoutFailing(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	cliAnchorExec(t, root, cid)

	code, out, errS := run(t, "--root", root, "audit", cid)
	if code != 0 {
		t.Fatalf("audit exit %d (out %q err %q); an unanchored exec record "+
			"must not fail the audit", code, out, errS)
	}
	if !strings.HasPrefix(out, "audit PASS") {
		t.Fatalf("missing PASS summary: %q", out)
	}
	const want = "note: exec_record_anchor: 1 unanchored exec record(s) — " +
		"their sandbox.exec events carry no record digest, so their " +
		"declared exit/expectation is not anchored to the ledger " +
		"(coverage only: not a problem)"
	if !strings.Contains(errS, want) {
		t.Fatalf("stderr %q lacks the advisory line %q", errS, want)
	}
	// The advisory is a note, not a problem row: stdout carries no such line.
	if strings.Contains(out, "unanchored") {
		t.Fatalf("the advisory leaked into stdout: %q", out)
	}
}

func TestAuditPrintsNoAdvisoryWithoutExecEvents(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "audit", cid)
	if code != 0 {
		t.Fatalf("audit exit %d: %q", code, errS)
	}
	if strings.Contains(errS, "exec_record_anchor") {
		t.Fatalf("a campaign with no exec events produced an advisory: %q", errS)
	}
}
