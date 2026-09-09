package cli

// T25 CLI tests: index (ord 15), sinks (ord 16), forkdiff (ord 18) and
// baseline (ord 20). Ports the CLI halves of tests/test_structural_index.py,
// test_structural_index_v2.py and test_forkdiff.py through the Runner.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/forkdiff"
	"websec/internal/validation"
)

// t25Tree copies a structidx fixture tree into a temp dir and returns it.
func t25Tree(t *testing.T, fixture string) string {
	t.Helper()
	src := filepath.Join("..", "structidx", "testdata", fixture)
	dst := filepath.Join(t.TempDir(), fixture)
	if err := copyTreeForTest(src, dst); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return dst
}

func copyTreeForTest(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

func TestIndexCommandWritesArtifact(t *testing.T) {
	c, root := t15Campaign(t, "index")
	tree := t25Tree(t, "structural")
	code, out, errS := run(t, "--root", root, "index", c.CampaignID, "--src", tree)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "index: ") ||
		!strings.HasSuffix(out, "(snapshot unpinned)\n") {
		t.Fatalf("output %q", out)
	}
	p := filepath.Join(c.ArtifactsDir, "structural_index.json")
	idx, err := validation.ReadJson(p)
	if err != nil {
		t.Fatalf("index artifact: %v", err)
	}
	if got := objStr(idx, "parse_version"); got != "3" {
		t.Fatalf("parse_version %q", got)
	}
	if objStr(idx, "campaign_id") != c.CampaignID {
		t.Fatalf("campaign_id %q", objStr(idx, "campaign_id"))
	}
	if err := validation.Validate(idx, "structural_index", 1); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

func TestIndexCommandJSONShape(t *testing.T) {
	c, root := t15Campaign(t, "index")
	tree := t25Tree(t, "structural")
	code, out, errS := run(t, "--root", root, "index", c.CampaignID,
		"--src", tree, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v (%q)", err, out)
	}
	if len(doc) != 3 {
		t.Fatalf("keys %v", doc)
	}
	for _, k := range []string{"snapshot_id", "entry_count", "stats"} {
		if _, ok := doc[k]; !ok {
			t.Fatalf("missing key %q in %v", k, doc)
		}
	}
	if doc["snapshot_id"] != "unpinned" {
		t.Fatalf("snapshot_id %v", doc["snapshot_id"])
	}
}

func TestIndexCommandArgparseErrors(t *testing.T) {
	c, root := t15Campaign(t, "index")
	code, _, errS := run(t, "--root", root, "index")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := "usage: webv2 index [-h] --src SRC [--json] campaign\n" +
		"webv2 index: error: the following arguments are required: campaign, --src\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
	code, _, errS = run(t, "--root", root, "index", c.CampaignID)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want = "usage: webv2 index [-h] --src SRC [--json] campaign\n" +
		"webv2 index: error: the following arguments are required: --src\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestIndexCommandSourceTreeMissing(t *testing.T) {
	c, root := t15Campaign(t, "index")
	missing := filepath.Join(t.TempDir(), "nope")
	code, _, errS := run(t, "--root", root, "index", c.CampaignID, "--src", missing)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if errS != "source tree not found: "+missing+"\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestSinksCommandWritesValueFlow(t *testing.T) {
	c, root := t15Campaign(t, "sinks")
	tree := t25Tree(t, "sink")
	code, out, errS := run(t, "--root", root, "sinks", c.CampaignID, "--src", tree)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "sinks: ") || !strings.Contains(out, "unguarded paths: ") {
		t.Fatalf("output %q", out)
	}
	if !strings.Contains(out, "<- token.transferFrom") {
		t.Fatalf("output %q must name a sink call", out)
	}
	rep, err := validation.ReadJson(filepath.Join(c.ArtifactsDir, "value_flow.json"))
	if err != nil {
		t.Fatalf("value_flow artifact: %v", err)
	}
	if objStr(rep, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", objStr(rep, "snapshot_id"))
	}
}

func TestForkdiffNoBaselines(t *testing.T) {
	c, root := t15Campaign(t, "forkdiff")
	dir := t.TempDir()
	old := forkdiff.BaselinesDir
	forkdiff.SetBaselinesDir(dir)
	defer forkdiff.SetBaselinesDir(old)
	tree := t25Tree(t, "v1")
	code, out, errS := run(t, "--root", root, "forkdiff", c.CampaignID, "--src", tree)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "fork-diff: no baselines registered\n" {
		t.Fatalf("output %q", out)
	}
	rep, err := validation.ReadJson(filepath.Join(c.ArtifactsDir, "fork_diff.json"))
	if err != nil {
		t.Fatalf("fork_diff artifact: %v", err)
	}
	if objAt(rep, "matched_baseline").Kind != validation.Null {
		t.Fatalf("matched_baseline must be null")
	}
}

func TestBaselineAddListRemove(t *testing.T) {
	dir := t.TempDir()
	old := forkdiff.BaselinesDir
	forkdiff.SetBaselinesDir(dir)
	defer forkdiff.SetBaselinesDir(old)
	tree := t25Tree(t, "v1")

	code, out, errS := run(t, "baseline", "add", "known-good", "--path", tree,
		"--source-url", "https://example.invalid/repo", "--license", "MIT")
	if code != 0 {
		t.Fatalf("add exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "baseline known-good: sha256 ") ||
		!strings.HasSuffix(out, "...\n") {
		t.Fatalf("add output %q", out)
	}
	meta, err := validation.ReadJson(filepath.Join(dir, "known-good", "baseline.json"))
	if err != nil {
		t.Fatalf("baseline.json: %v", err)
	}
	if objStr(meta, "license") != "MIT" {
		t.Fatalf("license %q", objStr(meta, "license"))
	}
	if len(objStr(meta, "fingerprint_sha256")) != 64 {
		t.Fatalf("sha256 %q", objStr(meta, "fingerprint_sha256"))
	}

	code, out, errS = run(t, "baseline", "list")
	if code != 0 {
		t.Fatalf("list exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "known-good: sha256 ") ||
		!strings.Contains(out, "  https://example.invalid/repo\n") {
		t.Fatalf("list output %q", out)
	}

	code, out, errS = run(t, "baseline", "remove", "known-good")
	if code != 0 {
		t.Fatalf("remove exit %d: %q", code, errS)
	}
	if out != "baseline known-good removed\n" {
		t.Fatalf("remove output %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "known-good")); !os.IsNotExist(err) {
		t.Fatalf("baseline dir still present")
	}
}

func TestBaselineArgparseErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"baseline"}, "usage: webv2 baseline [-h] {add,list,remove} ...\n" +
			"webv2 baseline: error: the following arguments are required: baseline_cmd\n"},
		{[]string{"baseline", "bogus"}, "usage: webv2 baseline [-h] {add,list,remove} ...\n" +
			"webv2 baseline: error: argument baseline_cmd: invalid choice: 'bogus' " +
			"(choose from 'add', 'list', 'remove')\n"},
		{[]string{"baseline", "add"}, baselineAddUsage +
			"webv2 baseline add: error: the following arguments are required: name, --path\n"},
		{[]string{"baseline", "add", "x"}, baselineAddUsage +
			"webv2 baseline add: error: the following arguments are required: --path\n"},
		{[]string{"baseline", "remove"}, baselineRemoveUsage +
			"webv2 baseline remove: error: the following arguments are required: name\n"},
	}
	for _, tc := range cases {
		code, _, errS := run(t, tc.args...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", tc.args, code)
		}
		if errS != tc.want {
			t.Errorf("%v:\n got %q\nwant %q", tc.args, errS, tc.want)
		}
	}
}
