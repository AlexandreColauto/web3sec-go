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
	got, err := ListPrefixed(dir, "F-", ".json")
	if err != nil {
		t.Fatalf("ListPrefixed: %v", err)
	}
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
	got, err := ListPrefixed(root, "F-", ".json")
	if err != nil {
		t.Fatalf("ListPrefixed: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("ListPrefixed = %v, want the single F- row", got)
	}
}

// TestListPrefixedMissingDirIsEmpty pins the missing-directory half of the
// contract after r43a split it from the unreadable half: the primitive hands
// the os.ReadDir error back (IsNotExist, because absence is a fact the caller
// may interpret), and the Optional form — the one every optional campaign
// subdirectory reader uses — is empty without error.
func TestListPrefixedMissingDirIsEmpty(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	got, err := ListPrefixed(missing, "F-", ".json")
	if len(got) != 0 {
		t.Errorf("ListPrefixed = %v, want empty", got)
	}
	if !os.IsNotExist(err) {
		t.Errorf("ListPrefixed error = %v, want IsNotExist", err)
	}
	opt, err := ListPrefixedOptional(missing, "F-", ".json")
	if err != nil || len(opt) != 0 {
		t.Errorf("ListPrefixedOptional = %v, %v; want empty, nil", opt, err)
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
	got, err := ListSubPrefixed(dir, "EXEC-", "exec_record.json")
	if err != nil {
		t.Fatalf("ListSubPrefixed: %v", err)
	}
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
