// e2e_test.go: 1:1 port of tests/test_corpus_surface_e2e_sharevault.py — the
// sweep must surface sharevault's donation bug deterministically, and the
// whole build_report path must never pull in a model layer. Skipped when the
// sharevault fixture repo is absent (it lives beside this repository).
package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// sharevaultSrc is <repo>/../sharevault/src, the fixture's real location
// (Python: Path(__file__).parents[2] / "sharevault").
func sharevaultSrc(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wd, "..", "..", "..", "sharevault", "src")
	if !isDir(p) {
		t.Skip("sharevault fixture repo absent")
	}
	return p
}

// copyTree mirrors shutil.copytree for the fixture (non-git copy ->
// deterministic content pin).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// sharevaultCampaign pins the fixture and returns the campaign.
func sharevaultCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	base := t.TempDir()
	snap := filepath.Join(base, "snap")
	copyTree(t, sharevaultSrc(t), snap)
	c, err := state.Init(filepath.Join(base, "root"), "sharevault-e2e",
		state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, snap, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSweepFlagsSharePriceInflation(t *testing.T) {
	c := sharevaultCampaign(t)
	report, err := BuildReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var spi validation.Value
	for _, r := range listAt(report, "class_exposure") {
		if validation.ObjStr(r, "bug_class") == "share-price-inflation" {
			spi = r
		}
	}
	if spi.Kind != validation.Obj {
		t.Fatal("share-price-inflation must be probed")
	}
	if !validation.ObjAt(spi, "exposed").B {
		t.Fatalf("delegated ratio site (_previewDeposit) not detected: %v",
			listAt(spi, "hits"))
	}
	// the hit must point at the ratio site or its entry caller
	var ids []string
	for _, h := range listAt(spi, "hits") {
		ids = append(ids, validation.ObjStr(h, "node_id"))
	}
	joined := strings.Join(ids, " ")
	if !strings.Contains(joined, "_previewDeposit") && !strings.Contains(joined, "deposit") {
		t.Fatalf("hits = %v, want _previewDeposit or deposit", ids)
	}
}

func TestNoModelCallsAnywhereInSweep(t *testing.T) {
	// The whole build_report path must never pull in the model layer: the
	// Go port of Python's "no new webv2 model/provider/llm module" check is
	// the corpus package's transitive import set.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(wd, "..", "..")
	cmd := exec.Command("go", "list", "-deps", "./internal/corpus")
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	var bad []string
	for _, dep := range strings.Fields(string(out)) {
		for _, marker := range []string{"model", "provider", "llm"} {
			if strings.Contains(dep, marker) {
				bad = append(bad, dep)
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("model layer imported by the sweep: %v", bad)
	}
	c := sharevaultCampaign(t)
	report, err := BuildReport(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(report, "campaign_id") != c.CampaignID {
		t.Fatalf("campaign_id = %q, want %q", validation.ObjStr(report, "campaign_id"),
			c.CampaignID)
	}
}
