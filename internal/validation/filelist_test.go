package validation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestListPrefixedSelectsPrefixSuffix: the reader must list F-*.json and
// nothing else, in the same sorted order filepath.Glob produced.
func TestListPrefixedSelectsPrefixSuffix(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"F-b.json", "F-a.json", "F-c.txt", "note.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "F-dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := ListPrefixed(dir, "F-", ".json")
	want := []string{
		filepath.Join(dir, "F-a.json"), filepath.Join(dir, "F-b.json")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestListPrefixedSurvivesGlobMetacharacters is the regression the helper
// exists for: a campaign rooted under a directory whose name contains a glob
// metacharacter. filepath.Glob matches nothing there — the campaign reads as
// empty — while the helper lists the rows.
func TestListPrefixedSurvivesGlobMetacharacters(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "audit [2026]")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "F-a.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(root, "F-*.json")); len(m) != 0 {
		t.Fatalf("precondition: Glob unexpectedly matched %v", m)
	}
	if got := ListPrefixed(root, "F-", ".json"); len(got) != 1 {
		t.Errorf("ListPrefixed = %v, want the single F- row", got)
	}
}

func TestListPrefixedMissingDirIsEmpty(t *testing.T) {
	if got := ListPrefixed(filepath.Join(t.TempDir(), "nope"), "F-", ".json"); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

// TestListSubPrefixedIsTheExecLayout: EXEC-*/exec_record.json, sorted, with
// rows lacking the leaf skipped.
func TestListSubPrefixedIsTheExecLayout(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"EXEC-b", "EXEC-a", "OTHER-c"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n, "exec_record.json"),
			[]byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "EXEC-d"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := ListSubPrefixed(dir, "EXEC-", "exec_record.json")
	want := []string{
		filepath.Join(dir, "EXEC-a", "exec_record.json"),
		filepath.Join(dir, "EXEC-b", "exec_record.json")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
