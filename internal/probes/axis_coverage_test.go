package probes

// axis_coverage_test.go closes the C2/F6 blind spot from the Go side.
//
// The detectors are already pinned byte-for-byte (testdata/golden holds
// raw_<tree>_<probe>.json for 15 fixture trees x 6 probes), so a regression
// INSIDE a probe fails the default suite. What nothing pinned was the
// end-to-end path: fixture present -> index -> surface assembly -> quota ->
// rows. The golden recipe shipped only the blind/clean variants of the
// accumulator and assertion fixtures, so `accumulator-skew` and
// `enforcement-timing` reported 0 rows in the one run the gate validates —
// a regression in the wiring around those probes moved no expectation.
//
// Two guards, one per side of the contract:
//
//  1. TestRegisteredAxesMatchGoldenChecker — the axis list
//     scripts/check-golden.py enforces is the registry, so a new probe
//     cannot land without widening the gate.
//  2. TestEveryRegisteredAxisEmitsRowsEndToEnd — one real corpus (the buggy
//     fixture families + the model that carries the invariants) driven
//     through BuildSurfaceOpts with production enrichments: every
//     registered axis must emit at least one row, and the clean fixtures
//     must stay silent on theirs.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// goldenCheckerAxes parses the EXPECTED_PROBE_AXES table out of
// scripts/check-golden.py (the gate's list — the names it enforces and the
// state each must reach).
func goldenCheckerAxes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "check-golden.py"))
	if err != nil {
		t.Fatalf("read check-golden.py: %v", err)
	}
	m := regexp.MustCompile(`(?s)EXPECTED_PROBE_AXES: dict\[str, str\] = \{(.*?)\}`).
		FindSubmatch(raw)
	if m == nil {
		t.Fatal("check-golden.py has no EXPECTED_PROBE_AXES table")
	}
	out := []string{}
	for _, q := range regexp.MustCompile(`"([^"]+)":`).FindAllStringSubmatch(
		string(m[1]), -1) {
		out = append(out, q[1])
	}
	if len(out) == 0 {
		t.Fatal("EXPECTED_PROBE_AXES parsed empty — the checker's table has " +
			"a shape this test no longer understands")
	}
	sort.Strings(out)
	return out
}

// TestRegisteredAxesMatchGoldenChecker: the gate's axis list == the registry.
func TestRegisteredAxesMatchGoldenChecker(t *testing.T) {
	want := []string{}
	for axis := range RegisteredAxes() {
		want = append(want, axis)
	}
	sort.Strings(want)
	got := goldenCheckerAxes(t)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("check-golden.py enforces %v, the registry registers %v — a "+
			"probe landed without widening the gate (or one was removed and "+
			"the gate kept waiting for it)", got, want)
	}
}

// axisCorpusRoot materializes the fixture families one real probe run needs:
// the buggy variant of every Solidity-backed axis. The blind/clean variants
// stay in the golden recipe (they prove the BLIND-key path and the silence on
// clean code); this corpus only has to make the six detectors speak.
func axisCorpusRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	families := []string{"accumulator/buggy", "assertion_strength/buggy",
		"cursor/buggy", "custody/buggy", "short_circuit/buggy"}
	for _, fam := range families {
		dest := filepath.Join(root, strings.ReplaceAll(fam, "/", "_"))
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(t29ProbesDir, fam))
		if err != nil {
			t.Fatalf("fixture family %s: %v", fam, err)
		}
		for _, e := range entries {
			data, err := os.ReadFile(filepath.Join(t29ProbesDir, fam, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dest, e.Name()), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// TestEveryRegisteredAxisEmitsRowsEndToEnd is the coverage floor: one real
// index, production probe options, and a row on every registered axis.
func TestEveryRegisteredAxisEmitsRowsEndToEnd(t *testing.T) {
	index := t29Index(t, axisCorpusRoot(t))
	model := t29Model(t, "buggy_model.json")
	surface, err := BuildSurfaceOpts(index, model, 12, 40, 3,
		"2026-01-01T00:00:00Z", ProdProbeOpts())
	if err != nil {
		t.Fatalf("BuildSurfaceOpts: %v", err)
	}
	seen := map[string]int{}
	for _, a := range vObjList(surface, "axes") {
		seen[vStr(a, "axis")] = vInt(a, "rows")
	}
	for axis := range RegisteredAxes() {
		rows, ok := seen[axis]
		if !ok {
			t.Errorf("axis %s is registered but absent from the assembled "+
				"surface", axis)
			continue
		}
		if rows < 1 {
			t.Errorf("axis %s emitted %d rows on the buggy corpus — the "+
				"end-to-end path (fixture, index, assembly, quota) stopped "+
				"producing rows for it, which is invisible to every other "+
				"gate", axis, rows)
		}
	}
	if len(seen) != len(RegisteredAxes()) {
		t.Errorf("surface carries %d axes, registry has %d", len(seen),
			len(RegisteredAxes()))
	}
}

// TestCleanFixturesStaySilentOnTheirAxis is the specificity floor: making the
// axes speak must not come from a detector that matches anything. The clean
// siblings of both previously-empty axes produce no rows.
func TestCleanFixturesStaySilentOnTheirAxis(t *testing.T) {
	for _, tc := range []struct {
		family string
		probe  string
	}{
		{"assertion_strength/clean", "assertion-strength"},
		{"accumulator/clean", "accumulator-basis-skew"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			index := t29Index(t, filepath.Join(t29ProbesDir, tc.family))
			model := t29Model(t, "buggy_model.json")
			out := t29Raw(t, index, model, tc.probe)
			if rows := len(vObjList(out, "rows")); rows != 0 {
				t.Errorf("%s on %s emitted %d rows, want 0 (a detector that "+
					"fires on clean code makes the axis floor meaningless)",
					tc.probe, tc.family, rows)
			}
		})
	}
}
