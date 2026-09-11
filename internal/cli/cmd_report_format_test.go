// cmd_report_format_test.go — Task 25 (G18): `report --format`. The md
// default routes to Generate exactly as before (same path out, no
// immunefi files); immunefi prints one path per submission-ready finding,
// sorted; zero ready findings is the honest advisory line with exit 0;
// an unknown format is exit 2 listing {md,immunefi}.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// reportFormatFinding ingests a minimal hypothesis and hand-stamps the
// stored gate output (no policy file: the export reads the flags as-is).
func reportFormatFinding(t *testing.T, c *state.Campaign, title string,
	ready bool) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kvT("title", validation.VStr(title)),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("unclassified")),
			kvT("description", validation.VStr(
				"sparse fixture with no exportable detail")))),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("src/V.sol"))))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := ""
	for _, pair := range f.O {
		if pair.K == "finding_id" {
			fid = pair.V.S
		}
	}
	loaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	loaded.O = validation.SetOrAppend(loaded.O, "bounty", validation.VObj(
		kvT("eligible", validation.VBool(ready)),
		kvT("submission_ready", validation.VBool(ready)),
		kvT("blocking_reasons", validation.VArr())))
	if err := findings.SaveFinding(c, &loaded); err != nil {
		t.Fatal(err)
	}
	return fid
}

func TestReportImmunefiListsReadyFiles(t *testing.T) {
	c, root := t15Campaign(t, "CLI Test")
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	fid := reportFormatFinding(t, c, "Sparse ready bug", true)
	code, out, errS := run(t, "--root", root, "report", "--format", "immunefi",
		c.CampaignID)
	if code != 0 {
		t.Fatalf("exit = %d (out=%q err=%q)", code, out, errS)
	}
	want := filepath.Join(c.Dir, "report-immunefi-"+fid+".md")
	if out != want+"\n" {
		t.Errorf("stdout = %q, want %q", out, want+"\n")
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("export file missing: %v", err)
	}
}

func TestReportImmunefiNoReadyIsAdvisory(t *testing.T) {
	c, root := t15Campaign(t, "CLI Test")
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	reportFormatFinding(t, c, "Sparse unready bug", false)
	code, out, errS := run(t, "--root", root, "report", "--format", "immunefi",
		c.CampaignID)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (out=%q err=%q)", code, out, errS)
	}
	if out != "no submission-ready findings\n" {
		t.Errorf("stdout = %q, want the honest advisory line", out)
	}
	matches, err := filepath.Glob(filepath.Join(c.Dir,
		"report-immunefi-*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("wrote files with zero ready findings: %v", matches)
	}
	_ = errS
}

func TestReportDefaultAndMdRoutesMatch(t *testing.T) {
	c, root := t15Campaign(t, "CLI Test")
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(root, "global-memory"))
	reportFormatFinding(t, c, "Sparse ready bug", true)
	code1, out1, errS1 := run(t, "--root", root, "report", c.CampaignID)
	if code1 != 0 {
		t.Fatalf("default exit = %d (out=%q err=%q)", code1, out1, errS1)
	}
	code2, out2, errS2 := run(t, "--root", root, "report", "--format", "md",
		c.CampaignID)
	if code2 != 0 {
		t.Fatalf("md exit = %d (out=%q err=%q)", code2, out2, errS2)
	}
	if out1 != out2 {
		t.Errorf("default and --format md differ: %q vs %q", out1, out2)
	}
	if strings.TrimSpace(out1) != filepath.Join(c.Dir, "report.md") {
		t.Errorf("default must print the report.md path, got %q", out1)
	}
	matches, err := filepath.Glob(filepath.Join(c.Dir,
		"report-immunefi-*.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("md routes must not write immunefi files: %v", matches)
	}
}

func TestReportFormatUnknownIsExit2(t *testing.T) {
	c, root := t15Campaign(t, "CLI Test")
	code, _, errS := run(t, "--root", root, "report", "--format", "yaml",
		c.CampaignID)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (err=%q)", code, errS)
	}
	if !strings.Contains(errS, "invalid choice: 'yaml'") {
		t.Errorf("stderr must name the bad value: %q", errS)
	}
	if !strings.Contains(errS, "(choose from 'md', 'immunefi')") {
		t.Errorf("stderr must list {md,immunefi}: %q", errS)
	}
}
