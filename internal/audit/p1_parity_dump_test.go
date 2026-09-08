// Live cross-twin parity harness, Go half (t15). It is inert unless the
// driver (.scratch/t15/parity_check.py) sets T15_OUT: that script builds the
// same P1-shaped campaign in the LIVE Python twin, audits it, and diffs the
// two full reports after id/hash normalization. Building the campaign here
// with the ported Go API (not by copying Python's files) is what makes this
// an independent cross-twin check.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/audit/sections"
	"websec/internal/floors"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	t15CampaignID = "C-parityp001"
	t15Evidence   = "checked against code\n"
)

func TestT15GoParityDump(t *testing.T) {
	out := os.Getenv("T15_OUT")
	if out == "" {
		t.Skip("T15_OUT unset: live parity dump is driven by .scratch/t15/parity_check.py")
	}
	Setup()
	root := os.Getenv("T15_ROOT")
	if root == "" {
		root = t.TempDir()
	}
	c, err := state.Init(root, "Acme", state.InitOpts{CampaignID: t15CampaignID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := floors.SetFloorPolicy(c, "access-control", "E2", "auditor",
		"reviewed the access control table"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetStage("dedup", "done", validation.VNull(), nil); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(c.ArtifactsDir, "evidence.md")
	if err := os.WriteFile(evidence, []byte(t15Evidence), 0o644); err != nil {
		t.Fatal(err)
	}
	artID, err := c.RegisterArtifact("other", evidence, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := validation.VObj(
		kv("test_status", validation.VStr("untested")),
		kv("status", validation.VStr("UNVERIFIED")),
	)
	links := validation.VObj(kv("invariants", validation.VObj(kv("INV-1", entry))))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"invariant_links.json"), links, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-1", artID); err != nil {
		t.Fatal(err)
	}
	useT15Baselines(t)
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(validation.DumpIndented(report)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(SectionNames()) != 13 {
		t.Fatalf("dump wrote %d sections, want 13", len(SectionNames()))
	}
}

// useT15Baselines wires the forkdiff seam to the driver's shared fixture
// (fingerprints recorded from the LIVE Python T0 parser).
func useT15Baselines(t *testing.T) {
	t.Helper()
	dir := os.Getenv("T15_BASELINES")
	if dir == "" {
		return
	}
	fps := map[string]validation.Value{}
	raw, err := os.ReadFile(os.Getenv("T15_FINGERPRINTS"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for name, body := range doc {
		fp, err := validation.ParseOrdered(body)
		if err != nil {
			t.Fatal(err)
		}
		fps[name] = fp
	}
	sections.SetForkdiff(fixtureForkdiff{dir: dir, fps: fps})
	t.Cleanup(func() { sections.SetForkdiff(nil) })
	if len(fps) == 0 {
		t.Fatal("no fingerprints loaded for the shared baselines fixture")
	}
}
