package reproduction

// Task 9 (G11 scope) tests — ScopeDiff (changed-surface file-set math over
// a snapshot pair), AppendScopeDetail (the newline-joined detail convention)
// and PlantCheck (archetype evaluators over the changed files only,
// hint-only rows).
//
// Failing-first: ScopeDiff, PlantCheck, AppendScopeDetail and SetScopePlantAPI
// do not exist yet.
//
// PlantCheck consumes its index/archetype surface through the ScopePlantAPI
// seam (structidx→reproduction is a real import edge — structidx/wire.go —
// so this package cannot import structidx or archetypes directly; the
// codebase's own answer is the seam, cf. StructuralIndexAPI in
// reachability.go). These tests drive the seam with stubs over a hand-built
// index; the real wiring (real structidx + real EvaluatePrecondition) is
// covered by the CLI test beside cmd_verify_postpatch_test.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// scopeTree writes rel→content files under a fresh temp dir and returns it.
func scopeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestScopeDiffRows(t *testing.T) {
	oldDir := scopeTree(t, map[string]string{
		"A.sol": "contract A { uint256 public x; }\n",
		"B.sol": "contract B { uint256 public y; }\n",
		"C.sol": "contract C { uint256 public z; }\n",
	})
	newDir := scopeTree(t, map[string]string{
		"A.sol": "contract A { uint256 public x; }\n// patched\n",
		"B.sol": "contract B { uint256 public y; }\n",
		"D.sol": "contract D { uint256 public w; }\n",
	})
	rows, err := ScopeDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("ScopeDiff: %v", err)
	}
	want := []string{"+ D.sol", "- C.sol", "~ A.sol"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("rows = %q, want %q", rows, want)
	}
	if !sort.StringsAreSorted(rows) {
		t.Fatalf("rows not sorted: %q", rows)
	}
}

func TestScopeDiffIdenticalTreesEmpty(t *testing.T) {
	files := map[string]string{"A.sol": "contract A {}\n"}
	rows, err := ScopeDiff(scopeTree(t, files), scopeTree(t, files))
	if err != nil {
		t.Fatalf("ScopeDiff: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("identical trees: rows = %q, want empty", rows)
	}
}

func TestScopeDiffCap(t *testing.T) {
	oldDir := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 51; i++ {
		files[fmt.Sprintf("f%02d.sol", i)] = fmt.Sprintf(
			"contract F%d {}\n", i)
	}
	newDir := scopeTree(t, files)
	rows, err := ScopeDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("ScopeDiff: %v", err)
	}
	if len(rows) != 51 {
		t.Fatalf("len(rows) = %d, want 51 (50 + overflow)", len(rows))
	}
	if !sort.StringsAreSorted(rows[:50]) {
		t.Fatalf("first 50 rows not sorted: %q", rows[:50])
	}
	if rows[50] != "… and 1 more" {
		t.Fatalf("overflow row = %q, want %q", rows[50], "… and 1 more")
	}
}

func TestScopeDiffGarbageDirErrors(t *testing.T) {
	ghost := filepath.Join(t.TempDir(), "no-such-dir")
	if _, err := ScopeDiff(ghost, t.TempDir()); err == nil {
		t.Fatal("ScopeDiff(garbage, _) must return an error, got nil")
	}
	if _, err := ScopeDiff(t.TempDir(), ghost); err == nil {
		t.Fatal("ScopeDiff(_, garbage) must return an error, got nil")
	}
}

// TestScopeSolFilesFileCap (H2): the snapshot walk is bounded — a tree with
// more .sol files than the cap yields the capped prefix and the truncated
// flag, never an unbounded path set.
func TestScopeSolFilesFileCap(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 5; i++ {
		files[fmt.Sprintf("f%d.sol", i)] = "contract F {}\n"
	}
	dir := scopeTree(t, files)
	got, truncated, err := scopeSolFiles(dir, 3)
	if err != nil {
		t.Fatalf("scopeSolFiles: %v", err)
	}
	if !truncated {
		t.Fatalf("truncated = false, want true (5 .sol files, cap 3)")
	}
	if len(got) != 3 {
		t.Fatalf("files = %q, want 3 (the capped prefix)", got)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("files not sorted: %q", got)
	}
	// Under the cap: everything, no truncation.
	all, truncated, err := scopeSolFiles(dir, 10)
	if err != nil {
		t.Fatalf("scopeSolFiles: %v", err)
	}
	if truncated || len(all) != 5 {
		t.Fatalf("under cap: %d files truncated=%v, want 5 files, false",
			len(all), truncated)
	}
}

// TestScopeDiffFileCapOmitsDiff (H2): once either walk truncates, the diff
// is not trustworthy (a prefix drops tail files, which would misreport
// removals) — the rows say so instead of emitting a wrong diff.
func TestScopeDiffFileCapOmitsDiff(t *testing.T) {
	files := map[string]string{
		"A.sol": "contract A {}\n",
		"B.sol": "contract B {}\n",
		"C.sol": "contract C {}\n",
	}
	rows, err := scopeDiffCapped(scopeTree(t, files), scopeTree(t, files),
		2, 1<<20)
	if err != nil {
		t.Fatalf("scopeDiffCapped: %v", err)
	}
	want := []string{"! scope walk truncated at 2 .sol files — diff omitted " +
		"(snapshot too large to compare reliably)"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("rows = %q, want %q", rows, want)
	}
}

// TestScopeDiffByteBudgetOverReports (H2): a spent byte budget never claims
// "unchanged" for bytes it did not read — remaining common files read as
// modified (the conservative direction for a changed-surface advisory).
func TestScopeDiffByteBudgetOverReports(t *testing.T) {
	files := map[string]string{
		"A.sol": "contract A { uint256 public x; }\n",
		"B.sol": "contract B { uint256 public y; }\n",
	}
	rows, err := scopeDiffCapped(scopeTree(t, files), scopeTree(t, files),
		100, 1)
	if err != nil {
		t.Fatalf("scopeDiffCapped: %v", err)
	}
	want := []string{"~ A.sol", "~ B.sol"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("rows = %q, want %q (identical trees, no byte budget left)",
			rows, want)
	}
	// A budget large enough for both files: identical trees diff empty.
	rows, err = scopeDiffCapped(scopeTree(t, files), scopeTree(t, files),
		100, 1<<20)
	if err != nil {
		t.Fatalf("scopeDiffCapped: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %q, want empty", rows)
	}
}

// scopeNode is one hand-built index node for the PlantCheck stub seam.
func scopeNode(kind, id, name, path string, line int64) validation.Value {
	return validation.VObj(
		validation.KV{K: "kind", V: validation.VStr(kind)},
		validation.KV{K: "id", V: validation.VStr(id)},
		validation.KV{K: "name", V: validation.VStr(name)},
		validation.KV{K: "path", V: validation.VStr(path)},
		validation.KV{K: "line", V: validation.VInt(line)},
	)
}

// stubScopePlant installs a stub ScopePlantAPI: the index carries an
// initialize function at P.sol:5 plus a helper at Q.sol:2, and every
// evaluation answers from the verdict map (result + detail by check type).
func stubScopePlant(t *testing.T, verdict map[string][2]string) {
	t.Helper()
	idx := validation.VObj(
		validation.KV{K: "nodes", V: validation.VArr(
			scopeNode("contract", "P.sol#V", "V", "P.sol", 3),
			scopeNode("function", "P.sol#V.initialize", "initialize",
				"P.sol", 5),
			scopeNode("function", "Q.sol#Q.helper", "helper", "Q.sol", 2),
		)},
		validation.KV{K: "edges", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "from", V: validation.VStr("P.sol#V.initialize")},
				validation.KV{K: "rel", V: validation.VStr("delegatecalls")},
				validation.KV{K: "to", V: validation.VStr("*#low-level.delegatecall")},
			),
		)},
	)
	SetScopePlantAPI(ScopePlantAPI{
		BuildIndex: func(*state.Campaign, string) (validation.Value, error) {
			return idx, nil
		},
		ArchetypeIDs: func() ([]string, error) {
			// Deliberately unsorted: PlantCheck must sort for determinism.
			return []string{"unguarded-initialize", "delegatecall-stub"}, nil
		},
		LoadArchetype: func(id string) (validation.Value, error) {
			typ := "unguarded_function_exists"
			if id == "delegatecall-stub" {
				typ = "delegatecall_present"
			}
			return validation.VObj(validation.KV{K: "checks",
				V: validation.VArr(validation.VObj(validation.KV{K: "type",
					V: validation.VStr(typ)}))}), nil
		},
		EvalCheck: func(check, _ validation.Value) (string, string, error) {
			got := verdict[validation.ObjStr(check, "type")]
			return got[0], got[1], nil
		},
	})
	t.Cleanup(func() { SetScopePlantAPI(ScopePlantAPI{}) })
}

func TestPlantCheckUnwiredErrors(t *testing.T) {
	SetScopePlantAPI(ScopePlantAPI{})
	c := newCampaign(t, "Acme Program")
	if _, err := PlantCheck(c, t.TempDir(), []string{"P.sol"}); err == nil {
		t.Fatal("unwired PlantCheck must return an error, got nil")
	}
}

func TestPlantCheckHitRow(t *testing.T) {
	stubScopePlant(t, map[string][2]string{
		"unguarded_function_exists": {"present", "unguarded: initialize"},
		"delegatecall_present":      {"absent", "no delegatecall edge"},
	})
	c := newCampaign(t, "Acme Program")
	rows, err := PlantCheck(c, t.TempDir(), []string{"P.sol", "Q.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	want := "patch plants risk: unguarded-initialize P.sol:5 " +
		"(hint-only — triage decides)"
	found := false
	for _, r := range rows {
		if r == want {
			found = true
		}
		if strings.HasPrefix(r, "patch plants risk:") &&
			!strings.HasSuffix(r, "(hint-only — triage decides)") {
			t.Fatalf("risk row %q missing hint-only suffix", r)
		}
	}
	if !found {
		t.Fatalf("rows %q lack exact hit row %q", rows, want)
	}
}

func TestPlantCheckDelegatecallEdgeFallback(t *testing.T) {
	// delegatecall_present details name no identifiers ("N delegatecall
	// edge(s)") — locations resolve from the delegatecalls edges instead.
	stubScopePlant(t, map[string][2]string{
		"unguarded_function_exists": {"absent", "no unguarded function"},
		"delegatecall_present":      {"present", "1 delegatecall edge(s)"},
	})
	c := newCampaign(t, "Acme Program")
	rows, err := PlantCheck(c, t.TempDir(), []string{"P.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	want := "patch plants risk: delegatecall-stub P.sol:5 " +
		"(hint-only — triage decides)"
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", []string{want}) {
		t.Fatalf("rows = %q, want %q", rows, want)
	}
}

func TestPlantCheckChangedFilter(t *testing.T) {
	stubScopePlant(t, map[string][2]string{
		"unguarded_function_exists": {"present", "unguarded: initialize"},
		"delegatecall_present":      {"absent", "no delegatecall edge"},
	})
	c := newCampaign(t, "Acme Program")
	// The hit lives in P.sol; only Q.sol changed ⇒ nothing new.
	rows, err := PlantCheck(c, t.TempDir(), []string{"Q.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	want := []string{"patch plants nothing new (1 files checked)"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("filtered rows = %q, want %q", rows, want)
	}
}

func TestPlantCheckClean(t *testing.T) {
	stubScopePlant(t, map[string][2]string{
		"unguarded_function_exists": {"absent", "no unguarded function"},
		"delegatecall_present":      {"absent", "no delegatecall edge"},
	})
	c := newCampaign(t, "Acme Program")
	rows, err := PlantCheck(c, t.TempDir(), []string{"P.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	want := []string{"patch plants nothing new (1 files checked)"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("rows = %q, want %q", rows, want)
	}
}

func TestPlantCheckRowsSorted(t *testing.T) {
	stubScopePlant(t, map[string][2]string{
		"unguarded_function_exists": {"present", "unguarded: initialize"},
		"delegatecall_present":      {"present", "1 delegatecall edge(s)"},
	})
	c := newCampaign(t, "Acme Program")
	rows, err := PlantCheck(c, t.TempDir(), []string{"P.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	if !sort.StringsAreSorted(rows) {
		t.Fatalf("rows not sorted: %q", rows)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %q, want both stub archetypes", rows)
	}
}

// TestPlantCheckOverflowCap (H3): the plant rows carry the same overflow
// convention as the scope rows — postPatchScopeCap rows plus one
// "… and N more" line, never an unbounded detail join.
func TestPlantCheckOverflowCap(t *testing.T) {
	const hits = 60
	nodes, toks := []validation.Value{}, []string{}
	for i := 0; i < hits; i++ {
		name := fmt.Sprintf("f%02d", i)
		nodes = append(nodes, scopeNode("function", "P.sol#V."+name, name,
			"P.sol", int64(i+1)))
		toks = append(toks, name)
	}
	idx := validation.VObj(validation.KV{K: "nodes",
		V: validation.VArr(nodes...)})
	SetScopePlantAPI(ScopePlantAPI{
		BuildIndex: func(*state.Campaign, string) (validation.Value,
			error) {
			return idx, nil
		},
		ArchetypeIDs: func() ([]string, error) {
			return []string{"chatty"}, nil
		},
		LoadArchetype: func(string) (validation.Value, error) {
			return validation.VObj(validation.KV{K: "checks",
				V: validation.VArr(validation.VObj(validation.KV{
					K: "type", V: validation.VStr(
						"unguarded_function_exists")}))}), nil
		},
		EvalCheck: func(_, _ validation.Value) (string, string, error) {
			return "present", "unguarded: " + strings.Join(toks, ", "), nil
		},
	})
	t.Cleanup(func() { SetScopePlantAPI(ScopePlantAPI{}) })
	c := newCampaign(t, "Acme Program")
	rows, err := PlantCheck(c, t.TempDir(), []string{"P.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	if len(rows) != postPatchScopeCap+1 {
		t.Fatalf("rows = %d, want %d (cap + overflow)",
			len(rows), postPatchScopeCap+1)
	}
	if !sort.StringsAreSorted(rows[:postPatchScopeCap]) {
		t.Fatalf("first %d rows not sorted: %q", postPatchScopeCap,
			rows[:postPatchScopeCap])
	}
	wantOverflow := fmt.Sprintf("… and %d more", hits-postPatchScopeCap)
	if rows[postPatchScopeCap] != wantOverflow {
		t.Fatalf("overflow row = %q, want %q", rows[postPatchScopeCap],
			wantOverflow)
	}
}

func TestAppendScopeDetail(t *testing.T) {
	got := AppendScopeDetail("base detail",
		[]string{"~ A.sol", "patch plants nothing new (1 files checked)"})
	want := "base detail\n~ A.sol\npatch plants nothing new (1 files checked)"
	if got != want {
		t.Fatalf("AppendScopeDetail = %q, want %q", got, want)
	}
	if AppendScopeDetail("base detail", nil) != "base detail" {
		t.Fatal("empty rows must leave detail unchanged")
	}
	if AppendScopeDetail("", []string{"+ D.sol"}) != "+ D.sol" {
		t.Fatal("empty detail must become the joined rows")
	}
}
