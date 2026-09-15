package state

import (
	"os"
	"path/filepath"
	"testing"
)

// A campaign root containing a glob metacharacter ([ ] ?) must still be
// scanned. The pre-fix filepath.Glob treated the whole path as a pattern, so
// a '[' in the root made every EXEC-* record invisible.
func TestAllExecsHandlesGlobMetacharacters(t *testing.T) {
	root := filepath.Join(t.TempDir(), "prog[1]")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := Init(root, "Meta Program", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	execDir := filepath.Join(c.ExecsDir, "EXEC-abc123")
	if err := os.MkdirAll(execDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(execDir, "exec_record.json"),
		[]byte(`{"exec_id":"EXEC-abc123"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := AllExecs(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("AllExecs = %d records, want 1 (root with '[' in path)", len(got))
	}
}

// A campaign reachable only through a symlink must be listed. The pre-fix
// entry.IsDir() reports the link itself (not its target), so a symlinked
// campaign dir was skipped.
func TestListCampaignsIncludesSymlinkedDirs(t *testing.T) {
	root := t.TempDir()
	cdir := filepath.Join(root, "campaigns")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(cdir, "C-real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "campaign_state.json"),
		[]byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink to a real campaign dir (its own state file, distinct name).
	link := filepath.Join(cdir, "C-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	got, err := ListCampaigns(root)
	if err != nil {
		t.Fatalf("ListCampaigns: %v", err)
	}
	found := map[string]bool{}
	for _, n := range got {
		found[n] = true
	}
	if !found["C-real"] {
		t.Errorf("C-real not listed: %v", got)
	}
	if !found["C-link"] {
		t.Errorf("C-link (symlinked campaign dir) not listed: %v", got)
	}
}
