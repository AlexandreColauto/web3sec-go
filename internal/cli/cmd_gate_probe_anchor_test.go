package cli

// cmd_gate_probe_anchor_test.go: the B10(a) end-to-end evidence for
// `webv2 gate <campaign> <finding>` — the check appears in the dry run's
// diagnose-as-command style (the failing clause line plus its `fix:` line,
// naming the row's own Q-* priority), and the presence gate holds at the byte
// level: a campaign without the model/surface/plan prints EXACTLY the bytes it
// printed before this check existed.
//
// The rule itself (and the enforcing `move … CONFIRMED` half) is tested in
// internal/findings/gate_probe_anchor_test.go; this file is only the CLI
// rendering of the same clause set.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// probeAnchorCLIRowID is the firing row's id (the §5 replay's G-01 row).
const probeAnchorCLIRowID = "34589e8588"

// writeProbeAnchorCLIArtifacts writes the three artifacts the check is gated
// on: a model that maps the finding's affected file (t15Finding's "src/V.sol")
// onto the surface row's contract.
func writeProbeAnchorCLIArtifacts(t *testing.T, root, cid string) {
	t.Helper()
	dir := filepath.Join(root, "campaigns", cid, "artifacts")
	write := func(name string, v validation.Value) {
		t.Helper()
		if err := validation.WriteJson(filepath.Join(dir, name), v, ""); err != nil {
			t.Fatal(err)
		}
	}
	write("protocol_model.json", validation.VObj(
		kvT("contracts", validation.VArr(validation.VObj(
			kvT("name", validation.VStr("V")),
			kvT("path", validation.VStr("src/V.sol"))))),
		kvT("state_machines", validation.VArr())))
	write("probe_surface.json", validation.VObj(
		kvT("rows", validation.VArr(validation.VObj(
			kvT("row_id", validation.VStr(probeAnchorCLIRowID)),
			kvT("axis", validation.VStr("enforcement-timing")),
			kvT("contract", validation.VStr("V")),
			kvT("consumer", validation.VStr("f")),
			kvT("consumer_line", validation.VInt(12)),
			kvT("tier", validation.VInt(0)),
			kvT("assertion_gap", validation.VInt(0)))))))
	write("campaign_plan.json", validation.VObj(
		kvT("priorities", validation.VArr(validation.VObj(
			kvT("id", validation.VStr("Q-008")),
			kvT("status", validation.VStr("open")),
			kvT("probe", validation.VObj(
				kvT("row_id", validation.VStr(probeAnchorCLIRowID)),
				kvT("probe_id", validation.VStr("p")))))))))
}

// dropProbeAnchorCLIArtifacts removes them again.
func dropProbeAnchorCLIArtifacts(t *testing.T, root, cid string) {
	t.Helper()
	dir := filepath.Join(root, "campaigns", cid, "artifacts")
	for _, name := range []string{"protocol_model.json",
		"probe_surface.json", "campaign_plan.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestGateDryRunRendersProbeAnchorCheck is the headline evidence: the check
// lands in the dry run's clause list with its exact heal, and the campaign
// without the artifacts prints the baseline bytes unchanged.
func TestGateDryRunRendersProbeAnchorCheck(t *testing.T) {
	c, root := t15Campaign(t, "probe-anchor-gate")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	fid := validation.ObjStr(f, "finding_id")

	code0, out0, _ := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code0 != 1 {
		t.Fatalf("baseline exit %d, want 1: %q", code0, out0)
	}
	if strings.Contains(out0, "probe-surface-undispositioned") {
		t.Fatalf("no artifacts: the check must not render:\n%s", out0)
	}

	writeProbeAnchorCLIArtifacts(t, root, c.CampaignID)
	code1, out1, _ := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code1 != 1 {
		t.Fatalf("exit %d, want 1: %q", code1, out1)
	}
	subject := "probe-surface-undispositioned[" + probeAnchorCLIRowID + "]"
	clause := "  \u2717 " + subject + ": undispositioned probe-surface row " +
		probeAnchorCLIRowID + " (tier 0, assertion_gap 0) cites this " +
		"finding's own anchor src/V.sol"
	if !strings.Contains(out1, clause) {
		t.Fatalf("dry run missing the failing clause:\n%s", out1)
	}
	fix := "    fix: webv2 answered " + c.CampaignID + " Q-008 answered " +
		"--reason '<why row " + probeAnchorCLIRowID + " is safe \u2014 cite " +
		"the row's own code>' --anchor <field>"
	if !strings.Contains(out1, fix) {
		t.Fatalf("dry run missing the exact heal line %q:\n%s", fix, out1)
	}

	// The presence gate, at the byte level: the same campaign with the
	// artifacts removed prints exactly the baseline bytes again.
	dropProbeAnchorCLIArtifacts(t, root, c.CampaignID)
	code2, out2, _ := run(t, "--root", root, "gate", c.CampaignID, fid)
	if code2 != code0 {
		t.Fatalf("exit %d, want %d", code2, code0)
	}
	if out2 != out0 {
		t.Fatalf("clause set moved without the artifacts:\n got %q\nwant %q",
			out2, out0)
	}
}

// TestGateDryRunProbeAnchorHealIsCopyableFromTheShell: the printed heal is a
// command the operator can paste — the campaign id is real, the priority id
// is the row's own, and every flag it names is accepted by `answered`.
func TestGateDryRunProbeAnchorHealIsCopyableFromTheShell(t *testing.T) {
	c, root := t15Campaign(t, "probe-anchor-heal")
	f := t15Finding(t, c, "an inflation hypothesis",
		"first-depositor-inflation")
	fid := validation.ObjStr(f, "finding_id")
	writeProbeAnchorCLIArtifacts(t, root, c.CampaignID)
	_, out, _ := run(t, "--root", root, "gate", c.CampaignID, fid)
	var fix string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "    fix: webv2 answered ") {
			fix = strings.TrimPrefix(ln, "    fix: ")
			break
		}
	}
	if fix == "" {
		t.Fatalf("no fix line in:\n%s", out)
	}
	if !strings.Contains(fix, " "+c.CampaignID+" Q-008 ") {
		t.Fatalf("fix %q must name the campaign and the row's priority", fix)
	}
	// It really runs: `answered` accepts the shape (the campaign has no probe
	// registry wired here, so the closure itself is refused for the anchor,
	// not for the flags — which is the claim being pinned).
	code, _, errS := run(t, "--root", root, "answered", c.CampaignID, "Q-008",
		"answered", "--reason", "row is safe: the sentinel check is the "+
			"guard", "--anchor", "consumer")
	if code == 0 {
		t.Fatalf("expected a refusal from a bare fixture, got exit 0")
	}
	if strings.Contains(errS, "unrecognized arguments") {
		t.Fatalf("the printed flags are not accepted by answered: %q", errS)
	}
}
