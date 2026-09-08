package cli

// P1b CLI tests — `artifact-list` (ord 24).
//
// Ports: tests/test_role_isolation.py's artifact listing through the CLI
// plus the empty/kind-filter shapes (cli.py cmd_artifact_list prints
// `{id}  {kind}  {path}` and the 60-char note).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
)

func t15Register(t *testing.T, c *state.Campaign, name, kind, note string) string {
	t.Helper()
	path := filepath.Join(c.Root, name)
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact(kind, path, note, snap)
	if err != nil {
		t.Fatal(err)
	}
	return aid
}

func TestArtifactListPrintsRows(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	aid := t15Register(t, c, "poc.sol", "poc", "a working proof")
	code, out, errS := run(t, "--root", root, "artifact-list", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := aid + "  poc  poc.sol  a working proof\n"
	if out != want {
		t.Fatalf("output\n%q\nwant\n%q", out, want)
	}
}

func TestArtifactListTruncatesNoteAt60(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	note := strings.Repeat("n", 70)
	t15Register(t, c, "poc.sol", "poc", note)
	code, out, errS := run(t, "--root", root, "artifact-list", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(out, "  "+strings.Repeat("n", 60)+"\n") {
		t.Fatalf("note must be cut at 60 chars: %q", out)
	}
}

func TestArtifactListKindFilter(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	poc := t15Register(t, c, "poc.sol", "poc", "")
	t15Register(t, c, "notes.md", "other", "")
	code, out, errS := run(t, "--root", root, "artifact-list", c.CampaignID,
		"--kind", "poc")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, poc+"  poc  ") ||
		strings.Contains(out, "notes.md") {
		t.Fatalf("filtered output %q", out)
	}
}

func TestArtifactListEmpty(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	code, out, errS := run(t, "--root", root, "artifact-list", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "no artifacts\n" {
		t.Fatalf("output %q", out)
	}
}

func TestArtifactListEmptyKind(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	code, out, errS := run(t, "--root", root, "artifact-list", c.CampaignID,
		"--kind", "poc")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "no artifacts of kind poc\n" {
		t.Fatalf("output %q", out)
	}
}

func TestArtifactListMissingCampaignIsArgparse(t *testing.T) {
	code, _, errS := run(t, "artifact-list")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["artifact-list"] +
		"webv2 artifact-list: error: the following arguments are required: " +
		"campaign\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
