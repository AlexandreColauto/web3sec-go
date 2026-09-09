package cli

// cmd_prescreen_test: the prescreen CLI surface (cli.py cmd_prescreen).
// Python's suite exercises AT.prescreen directly
// (tests/test_tier1_minor_sweep.py::test_s5_*); these tests pin the CLI
// contract around it: help, argparse errors, the src-tree check order, the
// text/JSON rendering, the repeatable --force override and its unknown-id
// failure.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const treeSol = "contract Module {\n" +
	"    bool public initialized;\n" +
	"    address public owner_;\n" +
	"    function initialize(address o) external { initialized = true; owner_ = o; }\n" +
	"}\n"

// prescreenFixture is _tree_campaign: a campaign with a pinned tree that
// matches unguarded-initialize.
func prescreenFixture(t *testing.T) (root, cid, src string) {
	t.Helper()
	root = t.TempDir()
	cid = initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	src = filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "Tree.sol"), []byte(treeSol), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	return root, cid, src
}

func TestPrescreenHelp(t *testing.T) {
	code, out, errS := run(t, "prescreen", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%q)", code, errS)
	}
	if out != prescreenHelp {
		t.Fatalf("help text mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, prescreenHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
}

func TestPrescreenArgErrors(t *testing.T) {
	code, _, errS := run(t, "prescreen")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "the following arguments are required: campaign, --src") {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "prescreen", "c", "--src")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "argument --src: expected one argument") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPrescreenSourceTreeNotFound(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	missing := filepath.Join(root, "nope")
	code, out, errS := run(t, "--root", root, "prescreen", cid,
		"--src", missing)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (out=%q err=%q)", code, out, errS)
	}
	if errS != "source tree not found: "+missing+"\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPrescreenTextRendering(t *testing.T) {
	root, cid, src := prescreenFixture(t)
	code, out, errS := run(t, "--root", root, "prescreen", cid, "--src", src)
	if code != 0 {
		t.Fatalf("exit = %d: %q", code, errS)
	}
	if !strings.Contains(out, "  [MATCH] unguarded-initialize (critical)\n") {
		t.Fatalf("output = %q", out)
	}
	if strings.Contains(out, "NOTE:") {
		t.Fatalf("a fresh report must not be flagged stale: %q", out)
	}
}

func TestPrescreenForceAppendsAndPersists(t *testing.T) {
	root, cid, src := prescreenFixture(t)
	code, out, errS := run(t, "--root", root, "prescreen", cid, "--src", src,
		"--force", "uninitialized-proxy")
	if code != 0 {
		t.Fatalf("exit = %d: %q", code, errS)
	}
	if !strings.Contains(out, "  [forced] uninitialized-proxy (critical)\n") {
		t.Fatalf("output = %q", out)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"archetype_overrides.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.A) != 1 || objStr(doc.A[0], "archetype_id") != "uninitialized-proxy" {
		t.Fatalf("overrides = %v", doc)
	}
	// repeatable: a second --force appends rather than replacing
	code, out, errS = run(t, "--root", root, "prescreen", cid, "--src", src,
		"--force", "uninitialized-proxy", "--force", "vault-share-pricing-surface")
	if code != 0 {
		t.Fatalf("exit = %d: %q", code, errS)
	}
	if !strings.Contains(out, "[forced] vault-share-pricing-surface") {
		t.Fatalf("output = %q", out)
	}
}

func TestPrescreenUnknownForceFailsLoud(t *testing.T) {
	root, cid, src := prescreenFixture(t)
	code, _, errS := run(t, "--root", root, "prescreen", cid, "--src", src,
		"--force", "nope")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if errS != "error: unknown archetype 'nope'\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPrescreenJSON(t *testing.T) {
	root, cid, src := prescreenFixture(t)
	code, out, errS := run(t, "--root", root, "prescreen", cid, "--src", src,
		"--json")
	if code != 0 {
		t.Fatalf("exit = %d: %q", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if objStr(rep, "snapshot_id") == "" {
		t.Fatal("snapshot_id missing")
	}
	matched := strListAtCLI(rep, "matched_ids")
	if len(matched) == 0 || matched[0] != "unguarded-initialize" {
		t.Fatalf("matched_ids = %v, want unguarded-initialize", matched)
	}
	found := false
	for _, row := range listAtCLI(rep, "results") {
		if objStr(row, "id") == "unguarded-initialize" {
			found = boolAtCLI(row, "match")
		}
	}
	if !found {
		t.Fatalf("unguarded-initialize not matched in %s", out)
	}
}
