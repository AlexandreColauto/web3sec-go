package cli

// Task 8: the re-pin exclusion report is a SUMMARY, not a dump.
//
// Law: exclusion lists (the pruned paths of a snapshot re-pin) render as
// "N paths excluded (first 10): …" with N exact, and the FULL list stays
// available in the record object — never as unbounded stdout. A prune set
// at or under the inline cap keeps every path inline (no truncation, no
// pointer to a hidden remainder).
//
// These tests own the render in cmd_snap.go (the `snap` verb, whose re-run
// is the re-pin); the record half is asserted against the pinned
// snapshot.json and the snapshot.excluded event the pin writes.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// snapExcludedFromRecord reads source.excluded out of the pinned snapshot
// record — the complete prune list the console summary must not be the
// only home of.
func snapExcludedFromRecord(t *testing.T, root, cid string) []string {
	t.Helper()
	camp := filepath.Join(root, "campaigns", cid)
	dirs, err := os.ReadDir(filepath.Join(camp, "snapshots"))
	if err != nil || len(dirs) != 1 {
		t.Fatalf("snapshots = %v (%v)", dirs, err)
	}
	snap, err := validation.ReadJson(filepath.Join(camp, "snapshots",
		dirs[0].Name(), "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v := range objAt(objAt(snap, "source"), "excluded").A {
		if v.Kind == validation.Str {
			out = append(out, v.S)
		}
	}
	return out
}

// snapExcludedEventNames reads the names the LAST snapshot.excluded event
// carries — the record trail's copy of the full prune list (every pin,
// including a noop re-pin, logs its own scope event).
func snapExcludedEventNames(t *testing.T, root, cid string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var ev struct {
			Type string `json:"type"`
			Data struct {
				Names []string `json:"names"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type == "snapshot.excluded" {
			out = ev.Data.Names
		}
	}
	return out
}

// TestSnapRepinSummarizesExclusionsOverCap: 25 pruned paths — the console
// line is bounded (N exact, at most 10 paths inline, one line), while the
// record object and the --json preview each keep the complete list.
func TestSnapRepinSummarizesExclusionsOverCap(t *testing.T) {
	const want = 25
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	pruneOverflowDirs(t, tgt, want)

	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	if !strings.Contains(out, fmt.Sprintf("%d paths excluded (first 10):", want)) {
		t.Fatalf("missing the bounded exclusion summary (want N=%d exact):\n%s",
			want, out)
	}
	// At most 10 paths inline — and exactly the first 10, sorted.
	if got := strings.Count(out, "/build"); got != 10 {
		t.Fatalf("inline pruned paths = %d, want 10:\n%s", got, out)
	}
	for i := 1; i <= 10; i++ {
		if w := fmt.Sprintf("d%02d/build", i); !strings.Contains(out, w) {
			t.Fatalf("inline head misses %s:\n%s", w, out)
		}
	}
	if strings.Contains(out, "d25/build") {
		t.Fatalf("stdout still carries the list's tail (d25/build):\n%s", out)
	}
	// The hidden remainder is exact too: 25 pruned, 10 named, 15 left to
	// the record.
	if !strings.Contains(out, "(+15 more") {
		t.Fatalf("summary does not name the exact remainder (+15 more):\n%s", out)
	}
	// Bounded in LINES too: one summary row, not a row per path.
	rows := 0
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "/build") {
			rows++
		}
	}
	if rows != 1 {
		t.Fatalf("exclusion paths span %d stdout lines, want 1:\n%s", rows, out)
	}

	// A RE-pin (same id, noop) keeps the same bounded summary — the line is
	// a property of the prune set, not of the first pin only.
	code, out2, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("re-pin exit %d: %q", code, errS)
	}
	if !strings.Contains(out2, fmt.Sprintf("%d paths excluded (first 10):", want)) ||
		!strings.Contains(out2, "(+15 more") ||
		strings.Count(out2, "/build") != 10 {
		t.Fatalf("re-pin exclusion summary is not bounded:\n%s", out2)
	}
	if strings.Contains(out2, "d25/build") {
		t.Fatalf("re-pin stdout carries the list's tail:\n%s", out2)
	}

	// The full list stays in the record object…
	wantPaths := make([]string, 0, want)
	for i := 1; i <= want; i++ {
		wantPaths = append(wantPaths, fmt.Sprintf("d%02d/build", i))
	}
	wantJoined := strings.Join(wantPaths, ",")
	if got := snapExcludedFromRecord(t, root, cid); strings.Join(got, ",") != wantJoined {
		t.Fatalf("record source.excluded = %d paths (%v), want %d (%v)",
			len(got), got, want, wantPaths)
	}
	// …and in the event trail.
	if got := snapExcludedEventNames(t, root, cid); strings.Join(got, ",") != wantJoined {
		t.Fatalf("snapshot.excluded event = %d names, want %d",
			len(got), want)
	}

	// …and in the machine-readable preview (the full table, no cap).
	code, jout, errS := run(t, "--root", root, "snap", cid, tgt,
		"--dry-run", "--json")
	if code != 0 {
		t.Fatalf("dry-run --json exit %d: %q", code, errS)
	}
	var doc snapDryRunJSONDoc
	if err := json.Unmarshal([]byte(jout), &doc); err != nil {
		t.Fatalf("--json does not parse: %v\n%s", err, jout)
	}
	if strings.Join(doc.PrunedPaths, ",") != wantJoined {
		t.Fatalf("--json pruned_paths = %d paths, want the full %d",
			len(doc.PrunedPaths), want)
	}
}

// TestSnapRepinKeepsSmallExclusionListsInline: at or under the cap nothing
// is hidden — every pruned path is named on the console and no summary
// pointer appears.
func TestSnapRepinKeepsSmallExclusionListsInline(t *testing.T) {
	const want = 4
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	pruneOverflowDirs(t, tgt, want)

	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "EXCLUDED from the pin") {
		t.Fatalf("missing the exclusion report:\n%s", out)
	}
	if strings.Contains(out, "paths excluded (first") {
		t.Fatalf("small list truncated instead of inline:\n%s", out)
	}
	for i := 1; i <= want; i++ {
		if w := fmt.Sprintf("d%02d/build", i); !strings.Contains(out, w) {
			t.Fatalf("small exclusion list hides %s:\n%s", w, out)
		}
	}
	if got := strings.Count(out, "/build"); got != want {
		t.Fatalf("inline pruned paths = %d, want all %d:\n%s", got, want, out)
	}
	wantPaths := make([]string, 0, want)
	for i := 1; i <= want; i++ {
		wantPaths = append(wantPaths, fmt.Sprintf("d%02d/build", i))
	}
	if got := snapExcludedFromRecord(t, root, cid); strings.Join(got, ",") != strings.Join(wantPaths, ",") {
		t.Fatalf("record source.excluded = %v, want %v", got, wantPaths)
	}
}

// TestSnapRepinKeepsExclusionCapBoundaryInline: EXACTLY 10 pruned paths is
// still the inline form — the cap is a strict upper bound on hiding, so a
// `>=` regression (which would print "10 paths excluded (first 10): … (+0
// more)") must fail here.
func TestSnapRepinKeepsExclusionCapBoundaryInline(t *testing.T) {
	const want = 10
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	pruneOverflowDirs(t, tgt, want)

	code, out, errS := run(t, "--root", root, "snap", cid, tgt)
	if code != 0 {
		t.Fatalf("snap exit %d: %q", code, errS)
	}
	if strings.Contains(out, "paths excluded (first") ||
		strings.Contains(out, "more —") {
		t.Fatalf("exactly %d paths must stay inline, not summarized:\n%s",
			want, out)
	}
	if got := strings.Count(out, "/build"); got != want {
		t.Fatalf("inline pruned paths = %d, want all %d:\n%s", got, want, out)
	}
	for i := 1; i <= want; i++ {
		if w := fmt.Sprintf("d%02d/build", i); !strings.Contains(out, w) {
			t.Fatalf("boundary list hides %s:\n%s", w, out)
		}
	}
}
