package cli

// M2/M5 CLI tests: --dry-run previews without recording; a real pin
// warns on untracked files inside the target.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// snapDryRunJSONDoc mirrors the `snap --dry-run --json` object. The keys
// are the schema-stable contract (the --json branch of snapDryRun in
// cmd_snap.go).
type snapDryRunJSONDoc struct {
	DryRun          bool     `json:"dry_run"`
	Target          string   `json:"target"`
	Ladder          string   `json:"ladder"`
	SnapshotID      string   `json:"snapshot_id"`
	FileCount       int      `json:"file_count"`
	ContentHash     string   `json:"content_hash"`
	PruneNames      []string `json:"prune_names"`
	PrunedPaths     []string `json:"pruned_paths"`
	Untracked       []string `json:"untracked"`
	UntrackedMore   int      `json:"untracked_more"`
	SkippedAttaches []string `json:"skipped_attaches"`
}

// pruneOverflowDirs builds a target whose `build` prune matches run past
// consoleRowCap: want nested dNN/build dirs = want pruned paths.
func pruneOverflowDirs(t *testing.T, tgt string, want int) {
	t.Helper()
	for i := 1; i <= want; i++ {
		dir := filepath.Join(tgt, fmt.Sprintf("d%02d", i), "build")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSnapDryRunCapsPrunedPaths (Task 7a): the pruned-path dump is the snap
// verb's path dump. A target whose prune matches run past consoleRowCap must
// not fold every path into one unreadable line: the console prints the first
// consoleRowCap paths and exactly one pointer line.
func TestSnapDryRunCapsPrunedPaths(t *testing.T) {
	const want = 45
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	// `build` is a bulk prune default; 45 nested matches = 45 pruned paths.
	for i := 1; i <= want; i++ {
		dir := filepath.Join(tgt, fmt.Sprintf("d%02d", i), "build")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	if code != 0 {
		t.Fatalf("dry-run exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "  pruned paths (45):") {
		t.Fatalf("missing the pruned-path header:\n%s", out)
	}
	if got := strings.Count(out, "/build"); got != consoleRowCap {
		t.Fatalf("console path lines = %d, want %d:\n%s", got, consoleRowCap,
			out)
	}
	if !strings.Contains(out,
		"  … +5 more rows — use --json for the full table\n") {
		t.Fatalf("missing the overflow pointer:\n%s", out)
	}
}

// gitInit makes dir a git-clean repo, skipping when git is absent.
func gitInit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{
		{"-c", "init.defaultBranch=main", "init", "-q"},
		{"add", "-A"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestSnapDryRunPreviewsAndRecordsNothing(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"dry-run:", "nothing recorded",
		"ladder:", "would-be snapshot:", "prune names", "node_modules",
		"untracked: none"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry-run output lacks %q:\n%s", want, out)
		}
	}
	// Nothing recorded: no snapshot store, no new events.
	if _, err := os.Stat(filepath.Join(root, "campaigns", cid,
		"snapshots")); !os.IsNotExist(err) {
		t.Fatal("dry-run created the snapshot store")
	}
	raw, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "\n") != 1 ||
		!strings.Contains(string(raw), "campaign.created") {
		t.Fatalf("dry-run logged events: %q", raw)
	}
}

func TestSnapDryRunIDMatchesPin(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	_, out, _ := run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	id := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "would-be snapshot:") {
			rest := strings.TrimSpace(
				strings.SplitN(ln, "would-be snapshot:", 2)[1])
			id = strings.SplitN(rest, " ", 2)[0]
		}
	}
	if id == "" {
		t.Fatalf("no would-be id in:\n%s", out)
	}
	code, pinOut, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("pin exit %d: %q", code, errS)
	}
	if !strings.Contains(pinOut, "pinned "+id+" ") {
		t.Fatalf("pin id differs from dry-run %s:\n%s", id, pinOut)
	}
}

func TestSnapWarnsOnUntrackedFiles(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	gitInit(t, tgt)
	if err := os.WriteFile(filepath.Join(tgt, "PoC_litter.t.sol"),
		[]byte("// litter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("pin exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "WARNING") ||
		!strings.Contains(out, "PoC_litter.t.sol") {
		t.Fatalf("pin does not warn on the untracked file:\n%s", out)
	}
	// The dry run warns too, naming the same file.
	code, out, errS = run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	if code != 0 {
		t.Fatalf("dry-run exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "PoC_litter.t.sol") {
		t.Fatalf("dry-run does not name the untracked file:\n%s", out)
	}
}

func TestSnapSilentOnCleanTree(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("pin exit %d: %q", code, errS)
	}
	if strings.Contains(out, "WARNING") || strings.Contains(out, "untracked") {
		t.Fatalf("clean-tree pin warns:\n%s", out)
	}
}

// TestSnapDryRunJSONIsTheFullPrunedTable: `snap --dry-run --json` emits one
// pure-JSON preview object whose pruned_paths is the COMPLETE table — no
// consoleRowCap, no banner text mixed in.
func TestSnapDryRunJSONIsTheFullPrunedTable(t *testing.T) {
	const want = 45
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	pruneOverflowDirs(t, tgt, want)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt,
		"--dry-run", "--json")
	if code != 0 {
		t.Fatalf("dry-run --json exit %d: %q", code, errS)
	}
	if trimmed := strings.TrimSpace(out); !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("--json output is not pure JSON:\n%s", out)
	}
	if strings.Contains(out, "dry-run:") ||
		strings.Contains(out, "more rows") {
		t.Fatalf("--json output mixes in console text:\n%s", out)
	}
	var doc snapDryRunJSONDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("--json does not parse: %v\n%s", err, out)
	}
	if !doc.DryRun || doc.Ladder == "" || doc.SnapshotID == "" ||
		doc.FileCount <= 0 || doc.ContentHash == "" {
		t.Fatalf("preview object incomplete: %+v", doc)
	}
	if len(doc.PrunedPaths) != want {
		t.Fatalf("--json pruned_paths = %d, want %d (no cap on the JSON)",
			len(doc.PrunedPaths), want)
	}
	for _, p := range doc.PrunedPaths {
		if !strings.Contains(p, "/build") {
			t.Fatalf("pruned_paths carries a non-match: %q", p)
		}
	}
	var hasBuild bool
	for _, n := range doc.PruneNames {
		if n == "build" {
			hasBuild = true
		}
	}
	if !hasBuild {
		t.Fatalf("prune_names lack build: %v", doc.PruneNames)
	}
	if len(doc.SkippedAttaches) != 0 {
		t.Fatalf("no attach flags given, skipped_attaches = %v",
			doc.SkippedAttaches)
	}
}

// TestSnapDryRunJSONFollowsTheOverflowPointer: the text run's pointer line
// claims a concrete N of hidden rows; --json must deliver exactly the
// consoleRowCap rows shown plus that N.
func TestSnapDryRunJSONFollowsTheOverflowPointer(t *testing.T) {
	const want = 45
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	pruneOverflowDirs(t, tgt, want)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--dry-run")
	if code != 0 {
		t.Fatalf("dry-run exit %d: %q", code, errS)
	}
	const marker = "more rows — use --json for the full table"
	line := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, marker) {
			line = ln
		}
	}
	if line == "" {
		t.Fatalf("no overflow pointer in the text run:\n%s", out)
	}
	rest := strings.SplitN(line, "… +", 2)
	if len(rest) != 2 {
		t.Fatalf("pointer line has no +N:\n%s", line)
	}
	nStr := strings.SplitN(rest[1], " more rows", 2)[0]
	var claimed int
	if _, err := fmt.Sscanf(nStr, "%d", &claimed); err != nil {
		t.Fatalf("pointer line does not carry a count: %q", line)
	}
	code, out, errS = run(t, "--root", root, "snap", cid, tgt,
		"--dry-run", "--json")
	if code != 0 {
		t.Fatalf("--json exit %d: %q", code, errS)
	}
	var doc snapDryRunJSONDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("--json does not parse: %v\n%s", err, out)
	}
	if got := len(doc.PrunedPaths); got != consoleRowCap+claimed {
		t.Fatalf("--json rows = %d, want %d shown + %d claimed",
			got, consoleRowCap, claimed)
	}
	if got := len(doc.PrunedPaths); got != want {
		t.Fatalf("--json rows = %d, want the true %d", got, want)
	}
}

// TestSnapDryRunJSONSkipsAttachesNamed: --deployment/--chain are post-pin
// attaches the dry run skips; the JSON object names them like the text.
func TestSnapDryRunJSONSkipsAttachesNamed(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--dry-run",
		"--json", "--deployment", "d.json", "--chain", "c.json")
	if code != 0 {
		t.Fatalf("dry-run --json exit %d: %q", code, errS)
	}
	var doc snapDryRunJSONDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("--json does not parse: %v\n%s", err, out)
	}
	want := []string{"--deployment", "--chain"}
	if len(doc.SkippedAttaches) != len(want) {
		t.Fatalf("skipped_attaches = %v, want %v", doc.SkippedAttaches, want)
	}
	for i, w := range want {
		if doc.SkippedAttaches[i] != w {
			t.Fatalf("skipped_attaches = %v, want %v",
				doc.SkippedAttaches, want)
		}
	}
}

// TestSnapJSONRefusesWithoutDryRun (negative control): --json is the
// dry-run table; a mutating pin keeps its human summary, so bare
// `snap --json` refuses with the argparse exit 2 instead of ignoring
// the flag.
func TestSnapJSONRefusesWithoutDryRun(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, out, errS := run(t, "--root", root, "snap", cid, tgt, "--json")
	if code != 2 {
		t.Fatalf("snap --json exit %d, want 2 (out %q err %q)", code, out, errS)
	}
	if !strings.Contains(errS, "--json applies to snap --dry-run only") {
		t.Fatalf("refusal does not name the constraint:\n%s", errS)
	}
	if _, err := os.Stat(filepath.Join(root, "campaigns", cid,
		"snapshots")); !os.IsNotExist(err) {
		t.Fatal("refused pin created the snapshot store")
	}
}
