// T26 cmd_recency tests: the text and --json surfaces, the argparse
// requirements, and the missing-source-tree failure. The scoring itself is
// covered in internal/histmining (ported from tests/test_recency.py).
package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// recencyTarget is a real one-commit git repo with a Solidity tree.
func recencyTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" +
		"contract Vault {\n    uint256 public totalAssets;\n" +
		"    function deposit() external { totalAssets += 1; }\n" +
		"    function sweep(address to) external { totalAssets = 0; }\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "src", "Vault.sol"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_AUTHOR_DATE=2026-09-01T12:00:00+00:00",
		"GIT_COMMITTER_DATE=2026-09-01T12:00:00+00:00",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"},
		{"commit", "-qm", "fix: guard sweep"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestRecencyJSONAndText(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	target := recencyTarget(t)
	code, out, errS := run(t, "--root", root, "recency", cid, "--target",
		target, "--src", target, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if _, ok := rep["stats"]; !ok {
		t.Fatalf("json has no stats: %s", out)
	}
	if _, ok := rep["hot_files"]; !ok {
		t.Fatalf("json has no hot_files: %s", out)
	}

	code, out, errS = run(t, "--root", root, "recency", cid, "--target",
		target, "--src", target)
	if code != 0 {
		t.Fatalf("text exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "recency: ") {
		t.Fatalf("text stdout = %q", out)
	}
	if !strings.Contains(out, "Vault.sol") {
		t.Fatalf("text stdout does not name the scored file: %q", out)
	}
}

func TestRecencyArgparse(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	target := recencyTarget(t)
	code, out, errS := run(t, "--root", root, "recency", cid, "--src", target)
	if code != 2 || out != "" {
		t.Fatalf("missing target: exit %d out=%q err=%q", code, out, errS)
	}
	want := t26RecencyUsage + "webv2 recency: error: the following " +
		"arguments are required: --target\n"
	if errS != want {
		t.Fatalf("missing target stderr = %q, want %q", errS, want)
	}
	code, _, errS = run(t, "--root", root, "recency", cid, "--target", target)
	if code != 2 {
		t.Fatalf("missing src exit %d", code)
	}
	if !strings.HasSuffix(errS,
		"error: the following arguments are required: --src\n") {
		t.Fatalf("missing src stderr = %q", errS)
	}
}

func TestRecencyMissingSourceTree(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	target := recencyTarget(t)
	missing := filepath.Join(root, "nope")
	code, out, errS := run(t, "--root", root, "recency", cid, "--target",
		target, "--src", missing)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if errS != "source tree not found: "+missing+"\n" {
		t.Fatalf("stderr = %q", errS)
	}
}
