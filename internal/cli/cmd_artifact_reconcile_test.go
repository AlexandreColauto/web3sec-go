package cli

// D3 CLI tests — `artifact-reconcile` (ord 75): re-hash the registry against
// the files, refresh what changed, report what is gone, and stay read-only
// under --dry.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestArtifactReconcileHelpAndArgparse(t *testing.T) {
	code, out, errS := run(t, "artifact-reconcile", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, artifactReconcileUsage) {
		t.Fatalf("help does not start with the usage block: %q", out)
	}
	code, out, errS = run(t, "artifact-reconcile")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if errS != artifactReconcileUsage+"webv2 artifact-reconcile: error: the "+
		"following arguments are required: campaign\n" {
		t.Fatalf("stderr = %q", errS)
	}
	code, out, errS = run(t, "artifact-reconcile", "C-aaaaaaaaaa", "--bogus")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if errS != t14TopUsage+"webv2: error: unrecognized arguments: --bogus\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestArtifactReconcileRefreshesAndReportsMissing: one rewritten file is
// refreshed, one deleted file is reported, one untouched file is left alone.
func TestArtifactReconcileRefreshesAndReportsMissing(t *testing.T) {
	c, root := t15Campaign(t, "reconcile")
	changed := t15Register(t, c, "report.md", "report", "")
	stable := t15Register(t, c, "plan.md", "plan", "")
	gone := t15Register(t, c, "poc.sol", "poc", "")
	if err := os.WriteFile(filepath.Join(c.Root, "report.md"),
		[]byte("rewritten by someone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(c.Root, "poc.sol")); err != nil {
		t.Fatal(err)
	}
	// dry first: the output must promise the refresh without performing it.
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		c.CampaignID, "--dry")
	if code != 0 || errS != "" {
		t.Fatalf("dry exit %d err %q", code, errS)
	}
	for _, want := range []string{
		"artifact reconcile: 3 checked, 1 would refresh, 1 unchanged, 1 missing",
		"  " + changed + "\n",
		"  missing " + gone + "  " + filepath.Join(c.Root, "poc.sol") + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry output missing %q\n%s", want, out)
		}
	}
	if row, err := c.Artifact(changed); err != nil {
		t.Fatal(err)
	} else if v := objAt(row, "refresh_count"); v.Kind == validation.Int {
		t.Errorf("--dry refreshed the row (refresh_count=%d)", v.I)
	}
	// live: the changed row is refreshed and the summary counts it.
	code, out, errS = run(t, "--root", root, "artifact-reconcile", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out,
		"artifact reconcile: 3 checked, 1 refreshed, 1 unchanged, 1 missing\n") {
		t.Errorf("live output:\n%s", out)
	}
	row, err := c.Artifact(changed)
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(row, "refresh_count"); v.Kind != validation.Int || v.I != 1 {
		t.Errorf("refresh_count after live run: %+v", v)
	}
	// idempotent: nothing left to refresh.
	code, out, errS = run(t, "--root", root, "artifact-reconcile", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out,
		"artifact reconcile: 3 checked, 0 refreshed, 2 unchanged, 1 missing\n") {
		t.Errorf("second run:\n%s", out)
	}
	_ = stable
}

func TestArtifactReconcileUnknownCampaign(t *testing.T) {
	_, root := t15Campaign(t, "reconcile-unknown")
	code, out, errS := run(t, "--root", root, "artifact-reconcile",
		"C-0000000000")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("stderr = %q", errS)
	}
}
