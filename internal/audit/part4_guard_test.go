package audit

// part4_guard_test.go: framework-plan-v1.6 Part 4 cuts the statistical-eval
// surface. The three packages below are still in the tree — deleting them is a
// refactor, not a cleanup, because they have seventeen live importers between
// them and one of them is wired to a documented CLI verb — so this test is
// what stops new code being built on them in the meantime.
//
// A comment saying "do not build on this" is not enforcement. This is: the
// allowlist below IS today's importer list, and it is asserted equal to it, so
// grandfathering one more file is a visible diff in review rather than a
// free-text edit nobody notices.
//
// The guard lives in the audit package because it is a structural trust claim
// about the tree, which is what this package is for. It scans SOURCE imports,
// so it is unaffected by what the audit package itself links.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// part4Allow lists, per cut package, the files permitted to import it today.
// Every entry is a real importer (verified 2026-09-21); the test fails if the
// list and the tree disagree in EITHER direction, so this shrinks honestly as
// the callers are cut and cannot grow without a deliberate edit here.
var part4Allow = map[string][]string{
	"websec/internal/wilson": {
		"internal/backtest/backtest.go",
		"internal/backtest/baseline.go",
		"internal/briefing/briefing_nextactions_queue.go",
		"internal/cli/cmd_selftest_evalsuite.go",
		"internal/evalscore/adjudicate_test.go",
		"internal/evalscore/bands.go",
		"internal/evalscore/classes.go",
		"internal/evalscore/evalscore.go",
		"internal/planner/autotune.go",
		"internal/planner/autotune_test.go",
		"internal/risk/calibration.go",
		"internal/risk/calibration_test.go",
	},
	"websec/internal/backtest": {
		"internal/cli/cmd_corpus_surface.go",
	},
	"websec/internal/classweights": {
		"internal/briefing/briefing_lens.go",
		"internal/corpus/corpus.go",
		"internal/report/report_dismissed.go",
		"internal/report/report_results.go",
	},
}

// importLine matches an import statement whose last token is a quoted path:
// `import "x"`, `import _ "x"`, `import . "x"`, and the aliased forms inside a
// parenthesised block (`v6 "x"`, `_ "x"`).
var importLine = regexp.MustCompile(`(?m)^\s*(?:import\s+)?(?:[A-Za-z_.][\w.]*\s+|_\s+)?"([^"]+)"\s*$`)

// TestPart4CutsAreQuarantined is the Part 4 guard.
func TestPart4CutsAreQuarantined(t *testing.T) {
	actual, err := part4Importers()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for pkg, allowed := range part4Allow {
		assertSameImporters(t, pkg, actual[pkg], allowed)
	}
}

// part4Importers scans the tree for direct imports of any cut package.
func part4Importers() (map[string][]string, error) {
	actual := map[string][]string{}
	for pkg := range part4Allow {
		actual[pkg] = nil
	}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipDir(d)
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		return scanImports(path, root, actual)
	})
	return actual, err
}

// skipDir keeps the walk on real source: build output and fixtures are not.
func skipDir(d fs.DirEntry) error {
	switch d.Name() {
	case ".git", ".scratch", "testdata":
		return fs.SkipDir
	}
	return nil
}

// scanImports adds rel to actual[imported] for every cut package path imported
// by the file at path.
func scanImports(path, root string, actual map[string][]string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
	for _, m := range importLine.FindAllStringSubmatch(string(raw), -1) {
		if _, cut := part4Allow[m[1]]; cut {
			actual[m[1]] = append(actual[m[1]], rel)
		}
	}
	return nil
}

// assertSameImporters fails when the allowlist and the tree disagree, in
// either direction.
func assertSameImporters(t *testing.T, pkg string, got, allowed []string) {
	t.Helper()
	sort.Strings(got)
	want := append([]string(nil), allowed...)
	sort.Strings(want)
	if strings.Join(got, "\n") == strings.Join(want, "\n") {
		return
	}
	t.Errorf("Part 4 quarantine for %s is out of date.\n"+
		"importers now:  %v\nallowlist says: %v\n"+
		"A NEW importer means someone is building on a package Part 4 cut — "+
		"do not add it to part4Allow; cut the dependency instead. A MISSING "+
		"importer means a caller was cut, so remove its entry here.",
		pkg, got, want)
}
