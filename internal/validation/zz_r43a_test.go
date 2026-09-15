package validation

// R43A (P1): a reader that could not read the directory has no evidence about
// it, so it says so and judges nothing else. These tests pin the three cases
// the file-list readers must keep apart:
//
//   - DOES NOT EXIST: the raw listing hands back IsNotExist, and the Optional
//     form (the one the optional campaign subdirectories use) is empty with no
//     error — a campaign that has not produced findings yet stays green.
//   - READABLE: the sorted list, unchanged from before.
//   - READ FAILED (EACCES): an error the caller can surface. Folding it into
//     an empty list is what let an unreadable evidence store audit clean.

import (
	"os"
	"path/filepath"
	"testing"
)

// r43aChmod makes dir unreadable for the rest of the test and restores the
// mode in cleanup: t.TempDir's RemoveAll cannot descend into a mode-000
// directory, and cleanups run newest-first, so this restore runs before it.
// A host where the mode does not actually deny (root, exotic fs) skips rather
// than asserting a condition it could not create.
func r43aChmod(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skipf("cannot create an unreadable directory here (%s stayed readable)", dir)
	}
}

func TestR43aListPrefixedUnreadableIsNotAnEmptyList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "F-a.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	r43aChmod(t, dir)

	got, err := ListPrefixed(dir, "F-", ".json")
	if err == nil {
		t.Fatalf("ListPrefixed on an unreadable dir returned %v with no error", got)
	}
	if os.IsNotExist(err) {
		t.Fatalf("a read failure was reported as IsNotExist: %v", err)
	}
	// The Optional form folds ONLY absence into emptiness; swallowing this
	// error is the bug r43a exists to kill.
	opt, oerr := ListPrefixedOptional(dir, "F-", ".json")
	if oerr == nil {
		t.Fatalf("ListPrefixedOptional swallowed the read failure: %v", opt)
	}
	if len(opt) != 0 {
		t.Fatalf("ListPrefixedOptional invented rows: %v", opt)
	}
}

func TestR43aListPrefixedOptionalMissingIsEmpty(t *testing.T) {
	got, err := ListPrefixedOptional(filepath.Join(t.TempDir(), "gone"),
		"F-", ".json")
	if err != nil {
		t.Fatalf("ListPrefixedOptional on a missing dir: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

func TestR43aListPrefixedReadableIsTheList(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"F-b.json", "F-a.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListPrefixedOptional(dir, "F-", ".json")
	if err != nil {
		t.Fatalf("readable dir: %v", err)
	}
	if len(got) != 2 || got[0] != filepath.Join(dir, "F-a.json") {
		t.Fatalf("got %v, want the two rows sorted", got)
	}
}

func TestR43aListSubPrefixedUnreadableDirIsNotAnEmptyList(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "EXEC-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "EXEC-a", "exec_record.json"),
		[]byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	r43aChmod(t, dir)

	if got, err := ListSubPrefixed(dir, "EXEC-", "exec_record.json"); err == nil {
		t.Fatalf("ListSubPrefixed on an unreadable dir returned %v with no error", got)
	}
	if _, err := ListSubPrefixedOptional(dir, "EXEC-", "exec_record.json"); err == nil {
		t.Fatal("ListSubPrefixedOptional swallowed the read failure")
	}
}

// TestR43aListSubPrefixedUnsearchableRecordIsRefused covers the inner os.Stat:
// one EXEC-* directory is mode 000, so whether its record exists CANNOT be
// decided. The reader must refuse instead of silently dropping the row (the
// old code kept only the rows whose Stat happened to succeed).
func TestR43aListSubPrefixedUnsearchableRecordIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"EXEC-a", "EXEC-bad"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n, "exec_record.json"),
			[]byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r43aChmod(t, filepath.Join(dir, "EXEC-bad"))

	got, err := ListSubPrefixed(dir, "EXEC-", "exec_record.json")
	if err == nil {
		t.Fatalf("an undecidable record was skipped silently: %v", got)
	}
	if os.IsNotExist(err) {
		t.Fatalf("an unsearchable directory was reported as IsNotExist: %v", err)
	}
}

// TestR43aListSubPrefixedMissingLeafIsSkipped keeps the documented layout
// filter: an EXEC-* directory without the leaf is not evidence of a record,
// and it is not a read failure either.
func TestR43aListSubPrefixedMissingLeafIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "EXEC-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ListSubPrefixed(dir, "EXEC-", "exec_record.json")
	if err != nil {
		t.Fatalf("a dir without the leaf is the layout filter, not an error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
