package audit

// d3_supersession_test.go — D3: the audit's artifacts section re-hashes EVERY
// registered row, so a stale row at a live path keeps the whole audit red.
// These tests reproduce the morph campaign's four-row shape, then prove the
// section goes green once RegisterOrRefresh reconciles instead of minting, and
// that a rewrite made by something other than the tool is fixable with the
// reconcile sweep.

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// artifactProblems is the artifact section's problems list as strings
// (sectionProblems in this package takes a section name).
func artifactProblems(t *testing.T, report validation.Value) []string {
	t.Helper()
	sec := validation.ObjAt(validation.ObjAt(report, "sections"), "artifacts")
	var out []string
	for _, p := range validation.ObjAt(sec, "problems").A {
		out = append(out, p.S)
	}
	return out
}

// TestAuditArtifactsGreenAfterReRegister is the D3 reproduction:
//   - a report.md registered by hand (kind "other"), then generated (kind
//     "report") and rewritten twice, leaves rows whose hashes are stale;
//   - the artifacts section reports a content-hash mismatch for each stale row;
//   - after the Go reconcile (one row per path, re-hashed), it is green.
func TestAuditArtifactsGreenAfterReRegister(t *testing.T) {
	c := initCampaign(t)
	p := filepath.Join(c.Dir, "report.md")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("report v1")
	if _, err := c.RegisterArtifact("other", p, "", nil); err != nil {
		t.Fatal(err)
	}
	// A second row at the same path, the way the pre-fix report.generate did.
	if _, err := c.RegisterArtifact("report", p, "", nil); err != nil {
		t.Fatal(err)
	}
	// The file is rewritten after registration: both rows are stale now.
	write("report v2")
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(artifactProblems(t, report)); got != 2 {
		t.Fatalf("pre-reconcile problems: %d want 2 (%v)", got,
			artifactProblems(t, report))
	}
	// The fix path: re-registering the same path reconciles the registry.
	if _, err := c.RegisterOrRefresh("report", p, "", nil,
		"re-registered (content may have changed)"); err != nil {
		t.Fatal(err)
	}
	report, err = AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := artifactProblems(t, report); len(got) != 0 {
		t.Fatalf("post-reconcile artifacts section: %v", got)
	}
	if !reportOK(report) {
		t.Fatalf("audit not ok after reconcile: %v", sectionOKFlags(report))
	}
}

// TestAuditArtifactsReconcileSweepCoversExternalRewrite: the escape hatch —
// something rewrote a registered file after the fact, and the operator's
// `artifacts reconcile` clears the audit without touching the file.
func TestAuditArtifactsReconcileSweepCoversExternalRewrite(t *testing.T) {
	c := initCampaign(t)
	p := filepath.Join(c.Dir, "notes.md")
	if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("other", p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("v2 by someone else"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := artifactProblems(t, report); len(got) != 1 {
		t.Fatalf("problems: %v", got)
	}
	// dry run: reports but changes nothing, so the audit stays red.
	res, err := c.ReconcileArtifacts(true)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(validation.ObjAt(res, "refreshed").A); got != 1 {
		t.Fatalf("dry refreshed: %d", got)
	}
	report, err = AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := artifactProblems(t, report); len(got) != 1 {
		t.Fatalf("dry run changed the registry: %v", got)
	}
	// live run: refreshed, green.
	if _, err := c.ReconcileArtifacts(false); err != nil {
		t.Fatal(err)
	}
	a, err := c.Artifact(id)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(a, "sha256"); got != validation.Sha256Hex([]byte("v2 by someone else")) {
		t.Errorf("sha256 after reconcile: %q", got)
	}
	report, err = AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := artifactProblems(t, report); len(got) != 0 {
		t.Fatalf("problems after live reconcile: %v", got)
	}
}
