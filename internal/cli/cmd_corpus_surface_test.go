package cli

// cmd_corpus_surface_test: the corpus-surface CLI contract
// (cli.py cmd_corpus_surface + tests/test_corpus_surface_report.py::
// test_cli_writes_and_registers_artifact).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const vaultSol = "contract V { uint256 public x; }\n"

// corpusFixture pins a one-file tree so build_report has a target surface.
func corpusFixture(t *testing.T) (root, cid string) {
	t.Helper()
	root = t.TempDir()
	cid = initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "V.sol"), []byte(vaultSol), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	return root, cid
}

func TestCorpusSurfaceHelp(t *testing.T) {
	code, out, errS := run(t, "corpus-surface", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (err=%q)", code, errS)
	}
	if out != corpusSurfaceHelp {
		t.Fatalf("help text mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			out, corpusSurfaceHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q, want empty", errS)
	}
}

func TestCorpusSurfaceArgErrors(t *testing.T) {
	code, _, errS := run(t, "corpus-surface")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "the following arguments are required: campaign") {
		t.Fatalf("stderr = %q", errS)
	}
	code, _, errS = run(t, "corpus-surface", "c", "extra")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errS, "unrecognized arguments: extra") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestCorpusSurfaceNoActiveSnapshot(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "corpus-surface", cid)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	want := "error: campaign " + cid + " has no active snapshot — pin one " +
		"(webv2 snap) before running the corpus sweep\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestCorpusSurfaceWritesAndRegisters(t *testing.T) {
	root, cid := corpusFixture(t)
	code, out, errS := run(t, "--root", root, "corpus-surface", cid)
	if code != 0 {
		t.Fatalf("exit = %d: %q", code, errS)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(c.ArtifactsDir, "corpus_surface.json")
	doc, err := validation.ReadJson(art)
	if err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
	if objStr(doc, "campaign_id") != cid {
		t.Fatalf("campaign_id = %q, want %q", objStr(doc, "campaign_id"), cid)
	}
	if len(listAtCLI(doc, "class_exposure")) == 0 {
		t.Fatal("artifact carries no class exposure")
	}
	if !strings.Contains(strings.ToLower(out), "exposure") {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(out, "class exposure (top 10):\n") {
		t.Fatalf("stdout = %q", out)
	}
	registered := false
	for _, row := range listAtCLI(mustState(t, c), "artifacts") {
		if objStr(row, "kind") == "corpus-surface" {
			registered = true
		}
	}
	if !registered {
		t.Fatal("the sweep artifact was not registered")
	}
}

func mustState(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCorpusSurfaceDeterministicArtifact(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T00:00:00.000000+00:00")
	root, cid := corpusFixture(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(c.ArtifactsDir, "corpus_surface.json")
	if code, _, errS := run(t, "--root", root, "corpus-surface", cid); code != 0 {
		t.Fatalf("first run exit %d: %q", code, errS)
	}
	first, err := os.ReadFile(art)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errS := run(t, "--root", root, "corpus-surface", cid); code != 0 {
		t.Fatalf("second run exit %d: %q", code, errS)
	}
	second, err := os.ReadFile(art)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("a pinned clock must make the artifact byte-identical")
	}
	if !strings.Contains(string(first), "2026-09-09T00:00:00.000000+00:00") {
		t.Fatal("generated_at did not honor WEBV2_NOW")
	}
}
