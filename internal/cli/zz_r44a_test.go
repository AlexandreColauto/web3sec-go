package cli

// R44A (P1) end to end, through the real verbs — the critic's repro:
//
//	init + ingest one finding; chmod 000 <c>/execs/ (or replace execs/ with a
//	regular file) -> audit used to print PASS with execs=0 problem(s) exit 0.
//
// The audit's exec section read state.AllExecs, the unfixed twin of
// sandbox.AllExecs (r43a), so the same campaign refused for findings/ and
// chains/ and certified for execs/. The other migrated consumers must not
// answer "no execs" either: scorecard, invariant-verify and verify
// --harness-result each render a 2 "no exec ... ledger" refusal on a readable
// store and must refuse with the store named when it is unreadable. And
// artifact-prune, whose campaign scan came from state.ListCampaigns, must not
// render "unknown artifact" (exit 2) for an artifact an unreadable
// campaigns/ store may well hold.
//
// The honest shapes stay green: a fresh campaign with no execs/ directory, a
// genuinely empty one, and a real artifact prune.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/state"
)

// r44aIngestOneFinding is init + one ingested finding: the critic's campaign.
func r44aIngestOneFinding(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c, root := r43aCampaign(t)
	code, payload, errS := run(t, "--root", root, "ingest", "--example")
	if code != 0 {
		t.Fatalf("ingest --example exit %d: %q", code, errS)
	}
	p := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(p, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "ingest", c.CampaignID,
		"--json-file", p)
	if code != 0 {
		t.Fatalf("ingest exit %d: out=%q err=%q", code, out, errS)
	}
	return c, root
}

// r44aExecsAsFile replaces execs/ with a regular file (ENOTDIR).
func r44aExecsAsFile(t *testing.T, c *state.Campaign) {
	t.Helper()
	if err := os.RemoveAll(c.ExecsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ExecsDir, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestR44aAuditRefusesUnreadableExecStore(t *testing.T) {
	c, root := r44aIngestOneFinding(t)
	if err := os.MkdirAll(c.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code != 0 || !strings.Contains(out, "audit PASS") {
		t.Fatalf("readable empty exec store: exit %d out %q err %q",
			code, out, errS)
	}

	r43aChmod(t, c.ExecsDir)
	code, out, errS = run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 {
		t.Fatalf("audit exit %d (out %q err %q); want 1", code, out, errS)
	}
	if strings.Contains(out, "PASS") || strings.Contains(out, "execs=0") {
		t.Fatalf("audit certified an unreadable exec store: %q", out)
	}
	if !strings.Contains(errS, c.ExecsDir) ||
		!strings.Contains(errS, "cannot be listed") ||
		!strings.Contains(errS, "permission denied") {
		t.Fatalf("audit must name the store and the errno: %q", errS)
	}
	if err := os.Chmod(c.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	r44aExecsAsFile(t, c)
	code, out, errS = run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 || strings.Contains(out, "PASS") {
		t.Fatalf("ENOTDIR exec store: exit %d out %q err %q", code, out, errS)
	}
	if !strings.Contains(errS, "not a directory") ||
		!strings.Contains(errS, c.ExecsDir) {
		t.Fatalf("audit must name the store and the errno: %q", errS)
	}
}

func TestR44aScorecardRefusesUnreadableExecStore(t *testing.T) {
	c, root := r43aCampaign(t)
	if err := os.MkdirAll(c.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "scorecard", c.CampaignID)
	if code != 0 || !strings.Contains(out, "exec records: 0") {
		t.Fatalf("readable empty exec store: exit %d out %q err %q",
			code, out, errS)
	}

	r43aChmod(t, c.ExecsDir)
	code, out, errS = run(t, "--root", root, "scorecard", c.CampaignID)
	if code != 1 {
		t.Fatalf("scorecard exit %d (out %q err %q); want 1", code, out, errS)
	}
	if strings.Contains(out, "exec records: 0") {
		t.Fatalf("scorecard counted an unreadable exec store as zero: %q", out)
	}
	if !strings.Contains(errS, "cannot be listed") ||
		!strings.Contains(errS, c.ExecsDir) {
		t.Fatalf("scorecard must name the unreadable store: %q", errS)
	}
}

// r44aLinks writes the registry row `invariant-verify` and `verify
// --harness-result` both need to reach their exec lookup.
func r44aLinks(t *testing.T, c *state.Campaign) {
	t.Helper()
	if err := os.MkdirAll(c.ArtifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir, "invariant_links.json"),
		[]byte(`{"invariants":{"INV-1":{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestR44aInvariantVerifyRefusesUnreadableExecStore(t *testing.T) {
	c, root := r43aCampaign(t)
	r44aLinks(t, c)

	code, _, errS := run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--exec", "EXEC-1")
	if code != 2 || !strings.Contains(errS, "no exec 'EXEC-1'") {
		t.Fatalf("readable store: exit %d err %q; want the exit-2 no-exec",
			code, errS)
	}

	r43aChmod(t, c.ExecsDir)
	code, _, errS = run(t, "--root", root, "invariant-verify", c.CampaignID,
		"INV-1", "--exec", "EXEC-1")
	if code != 1 {
		t.Fatalf("invariant-verify exit %d (err %q); want 1", code, errS)
	}
	if strings.Contains(errS, "no exec") {
		t.Fatalf("invariant-verify answered 'no exec' for a store it could "+
			"not read: %q", errS)
	}
	if !strings.Contains(errS, "cannot be listed") ||
		!strings.Contains(errS, c.ExecsDir) {
		t.Fatalf("invariant-verify must name the unreadable store: %q", errS)
	}
}

func TestR44aVerifyHarnessRefusesUnreadableExecStore(t *testing.T) {
	c, root := r43aCampaign(t)
	r44aLinks(t, c)

	args := []string{"--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-1",
		"--kind", "minicertora"}
	code, _, errS := run(t, args...)
	if code != 2 || !strings.Contains(errS, "no exec 'EXEC-1'") {
		t.Fatalf("readable store: exit %d err %q; want the exit-2 no-exec",
			code, errS)
	}

	r43aChmod(t, c.ExecsDir)
	code, _, errS = run(t, args...)
	if code != 1 {
		t.Fatalf("verify exit %d (err %q); want 1", code, errS)
	}
	if strings.Contains(errS, "no exec") {
		t.Fatalf("verify answered 'no exec' for a store it could not read: %q",
			errS)
	}
	if !strings.Contains(errS, "cannot be listed") ||
		!strings.Contains(errS, c.ExecsDir) {
		t.Fatalf("verify must name the unreadable store: %q", errS)
	}
}

func TestR44aArtifactPruneRefusesUnreadableCampaignStore(t *testing.T) {
	c, root := r43aCampaign(t)

	code, _, errS := run(t, "--root", root, "artifact-prune", "OTH-nope",
		"--reason", "r44a")
	if code != 2 || !strings.Contains(errS, "unknown artifact") {
		t.Fatalf("readable store: exit %d err %q; want the exit-2 unknown "+
			"artifact", code, errS)
	}

	cdir := filepath.Join(root, "campaigns")
	r43aChmod(t, cdir)
	code, _, errS = run(t, "--root", root, "artifact-prune", "OTH-nope",
		"--reason", "r44a")
	if code != 1 {
		t.Fatalf("artifact-prune exit %d (err %q); want 1 — never the "+
			"exit-2 unknown-artifact for an unreadable store", code, errS)
	}
	if strings.Contains(errS, "unknown artifact") {
		t.Fatalf("artifact-prune declared an artifact unknown from a store "+
			"it could not read: %q", errS)
	}
	if !strings.Contains(errS, "the campaign store") ||
		!strings.Contains(errS, cdir) ||
		!strings.Contains(errS, "permission denied") {
		t.Fatalf("refusal must name the campaign store and the errno: %q", errS)
	}
	if err := os.Chmod(cdir, 0o755); err != nil {
		t.Fatal(err)
	}

	// The file-in-place-of-a-directory shape.
	if err := os.Rename(cdir, cdir+".bak"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cdir, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "--root", root, "artifact-prune", "OTH-nope",
		"--reason", "r44a")
	if code != 1 || !strings.Contains(errS, "not a directory") {
		t.Fatalf("ENOTDIR campaign store: exit %d err %q; want a refusal "+
			"naming the errno", code, errS)
	}
	if err := os.Remove(cdir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cdir+".bak", cdir); err != nil {
		t.Fatal(err)
	}

	// Honest: no campaigns/ directory at all, and a genuinely empty one, are
	// "no campaign holds the id" — the exit-2 unknown-artifact answer.
	code, _, errS = run(t, "--root", t.TempDir(), "artifact-prune", "OTH-nope",
		"--reason", "r44a")
	if code != 2 || !strings.Contains(errS, "unknown artifact") {
		t.Fatalf("absent campaign store: exit %d err %q; want the exit-2 "+
			"unknown artifact", code, errS)
	}

	// Honest: a real registered artifact still prunes (rc 0), so the refusal
	// did not cost the verb its working path.
	p := filepath.Join(t.TempDir(), "art.txt")
	if err := os.WriteFile(p, []byte("contract src\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, p)
	if code != 0 {
		t.Fatalf("artifact-register exit %d: out=%q err=%q", code, out, errS)
	}
	m := regexp.MustCompile(`(?m)^([A-Z]+-[0-9a-f]+):`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no artifact id in register output: %q", out)
	}
	code, out, errS = run(t, "--root", root, "artifact-prune", m[1],
		"--reason", "r44a honest prune")
	if code != 0 {
		t.Fatalf("honest prune exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, m[1]+": kind=") {
		t.Fatalf("honest prune did not print the retired row: %q", out)
	}
}

// TestR44aHonestExecsShapesStayGreen: the distinction the fix must preserve —
// a campaign that has NOT produced execs/ yet audits green, and so does one
// whose execs/ directory is genuinely empty.
func TestR44aHonestExecsShapesStayGreen(t *testing.T) {
	absent, root := r43aCampaign(t)
	if err := os.RemoveAll(absent.ExecsDir); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "audit", absent.CampaignID)
	if code != 0 || !strings.Contains(out, "audit PASS") {
		t.Fatalf("absent exec store: exit %d out %q err %q", code, out, errS)
	}

	empty, root2 := r43aCampaign(t)
	if err := os.MkdirAll(empty.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root2, "audit", empty.CampaignID)
	if code != 0 || !strings.Contains(out, "audit PASS") {
		t.Fatalf("empty exec store: exit %d out %q err %q", code, out, errS)
	}

	code, out, errS = run(t, "--root", root2, "scorecard", empty.CampaignID)
	if code != 0 || !strings.Contains(out, "exec records: 0") {
		t.Fatalf("empty exec store scorecard: exit %d out %q err %q",
			code, out, errS)
	}
}
