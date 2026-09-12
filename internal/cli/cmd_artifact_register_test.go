package cli

// P1b CLI tests — `artifact-register` (ord 23).
//
// Ports: tests/test_role_isolation.py's artifact/register path through the
// CLI plus the register-by-path failure shape (cli.py cmd_artifact_register:
// a missing file is a one-line exit-2 error, never a traceback).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactRegister(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	path := filepath.Join(root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		path, "--kind", "other", "--note", "the invariant check")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "OTH-") ||
		!strings.Contains(out, ": kind=other path="+path) {
		t.Fatalf("output %q", out)
	}
}

func TestArtifactRegisterDefaultsToKindOther(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	path := filepath.Join(root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		path)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, ": kind=other path=") {
		t.Fatalf("output %q", out)
	}
}

func TestArtifactRegisterMissingFileExits2(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	missing := filepath.Join(root, "nope.md")
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		missing)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if errS != "artifact register failed: no such file: "+missing+"\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestArtifactRegisterMissingArgsIsArgparse(t *testing.T) {
	code, _, errS := run(t, "artifact-register")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["artifact-register"] +
		"webv2 artifact-register: error: the following arguments are required: " +
		"campaign, path\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// Task 7d: a successful register says what "register" means. The artifact id
// is immutable, so the operator who wants to revise it must register the
// revision as a NEW artifact — the sharp edge was an operator overwriting the
// file at the registered path and assuming the store followed.
func TestArtifactRegisterPrintsTheImmutabilityNotice(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	path := filepath.Join(root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		path)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("the notice must ride stdout, not stderr: %q", errS)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout\n%q\nwant the success line plus one notice", out)
	}
	if !strings.HasPrefix(lines[0], "OTH-") {
		t.Fatalf("first line = %q, want the success line", lines[0])
	}
	want := "note: registered artifacts are immutable — to revise, register " +
		"a new artifact (the old one stays for provenance)"
	if lines[1] != want {
		t.Fatalf("notice\n%q\nwant\n%q", lines[1], want)
	}
}
