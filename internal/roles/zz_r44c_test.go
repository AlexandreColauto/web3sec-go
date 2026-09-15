package roles

// R44C at the roles package: _known_non_issues' memory listing was a SECOND
// implementation of the store read (loadMemoryRows re-listed memory/ with its
// own os.ReadDir, folded every listing error into "no local rows", and
// SKIPPED a row whose JSON did not parse) and the shared-store half swallowed
// its error too. learning.AllMemory is the one implementation of that listing
// (validation.ListPrefixedOptional, the r43 helper) and sharedmem.LoadSharedMemory
// is the one shared-store reader; both refusals now propagate, so a
// proposer-context block can no longer tell the model "no priors" from a store
// it never read. Absence and a clean store keep today's answer.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

func r44cCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r44c", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// r44cChmod makes path unreadable and PROVES it (ReadDir for a directory,
// ReadFile for a file); under a uid that ignores mode bits the test skips.
func r44cChmod(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	mode := os.FileMode(0o600)
	if fi.IsDir() {
		mode = 0o755
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, mode) })
	if fi.IsDir() {
		if _, err := os.ReadDir(path); err == nil {
			t.Skipf("cannot create an unreadable directory here (%s stayed readable)", path)
		}
		return
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Skipf("cannot create an unreadable file here (%s stayed readable)", path)
	}
}

// r44cQueueNegative queues one negative-memory row (a real store write, so
// the fixture cannot drift from the schema) and returns it.
func r44cQueueNegative(t *testing.T, c *state.Campaign, pattern string) validation.Value {
	t.Helper()
	cls := "reentrancy"
	row, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:     "disproved",
		Status:   "DISPROVED",
		Pattern:  pattern,
		BugClass: &cls})
	if err != nil {
		t.Fatalf("queue memory: %v", err)
	}
	return row
}

func r44cKnownIDs(t *testing.T, block validation.Value) []string {
	t.Helper()
	out := []string{}
	for _, r := range objAt(block, "known_non_issues").A {
		out = append(out, objStr(r, "memory_id"))
	}
	return out
}

// TestR44cKnownNonIssuesRefusesUnreadableMemoryStore: `chmod 000 <c>/memory/`
// must refuse, naming the store — before r44c the block rendered as if the
// campaign had no priors.
func TestR44cKnownNonIssuesRefusesUnreadableMemoryStore(t *testing.T) {
	c := r44cCampaign(t, "C-r44cmemr1")
	r44cQueueNegative(t, c, "a prior observation of the reentrancy guard")
	r44cChmod(t, c.MemoryDir)

	block, err := KnownNonIssues(c, nil, 12)
	if err == nil {
		t.Fatalf("known_non_issues built from an unreadable store: %s",
			validation.CanonCompact(block))
	}
	if !strings.Contains(err.Error(), c.MemoryDir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the memory store and the errno: %v", err)
	}
}

// TestR44cKnownNonIssuesRefusesUnreadableRow: one MEM-*.json that cannot be
// read is a read failure, not "that prior does not exist" — the old local
// listing `continue`d past it and rendered the remaining rows as if the store
// had been read whole.
func TestR44cKnownNonIssuesRefusesUnreadableRow(t *testing.T) {
	c := r44cCampaign(t, "C-r44cmemr2")
	row := r44cQueueNegative(t, c, "a prior observation whose row file cannot be read")
	path := filepath.Join(c.MemoryDir, objStr(row, "memory_id")+".json")
	r44cChmod(t, path)

	block, err := KnownNonIssues(c, nil, 12)
	if err == nil {
		t.Fatalf("known_non_issues skipped an unreadable row: %s",
			validation.CanonCompact(block))
	}
	if !strings.Contains(err.Error(), objStr(row, "memory_id")) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the unreadable row and the errno: %v", err)
	}
}

// TestR44cKnownNonIssuesRefusesUnreadableSharedStore: the shared tier is the
// second half of the same listing; its refusal propagates too (the old code
// ignored the error and rendered the local rows only).
func TestR44cKnownNonIssuesRefusesUnreadableSharedStore(t *testing.T) {
	c := r44cCampaign(t, "C-r44cmemr3")
	gdir := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", gdir)
	if err := os.WriteFile(filepath.Join(gdir, "memory.json"),
		[]byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r44cChmod(t, gdir)

	block, err := KnownNonIssues(c, nil, 12)
	if err == nil {
		t.Fatalf("known_non_issues ignored an unreadable shared store: %s",
			validation.CanonCompact(block))
	}
	if !strings.Contains(err.Error(), gdir) {
		t.Fatalf("refusal must name the shared store: %v", err)
	}
}

// TestR44cKnownNonIssuesHonestShapesStayGreen: an ABSENT memory store is an
// empty campaign, an EMPTY one lists nothing, and a clean store still yields
// its rows in the pinned retrieval shape (including the shared tier's wrapped
// {scope, program_key, row} entries, unwrapped as before).
func TestR44cKnownNonIssuesHonestShapesStayGreen(t *testing.T) {
	c := r44cCampaign(t, "C-r44cmemg1")
	row := r44cQueueNegative(t, c, "a prior observation that is readable")
	gdir := t.TempDir()
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", gdir)
	shared := validation.VObj(
		kv("scope", validation.VStr("shared")),
		kv("program_key", validation.VStr("r44c")),
		kv("row", validation.VObj(
			kv("memory_id", validation.VStr("MEM-shared0001")),
			kv("status", validation.VStr("DISPROVED")),
			kv("pattern", validation.VStr("a shared prior observation")),
			kv("bug_class", validation.VStr("reentrancy")))))
	if err := validation.WriteJson(filepath.Join(gdir, "memory.json"),
		validation.VArr(shared), ""); err != nil {
		t.Fatal(err)
	}

	block, err := KnownNonIssues(c, nil, 12)
	if err != nil {
		t.Fatalf("clean store refused: %v", err)
	}
	if got := r44cKnownIDs(t, block); len(got) != 2 {
		t.Fatalf("known_non_issues = %v, want the local row %s and the "+
			"unwrapped shared row", got, objStr(row, "memory_id"))
	}

	// Absent store: still green (absence is a fact — the fold belongs to the
	// reader, not to this call site).
	if err := os.RemoveAll(c.MemoryDir); err != nil {
		t.Fatal(err)
	}
	block, err = KnownNonIssues(c, nil, 12)
	if err != nil {
		t.Fatalf("absent memory store refused: %v", err)
	}
	if got := r44cKnownIDs(t, block); len(got) != 1 || got[0] != "MEM-shared0001" {
		t.Fatalf("absent local store: %v, want only the shared row", got)
	}

	// Empty local store: same answer.
	if err := os.MkdirAll(c.MemoryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	block, err = KnownNonIssues(c, nil, 12)
	if err != nil {
		t.Fatalf("empty memory store refused: %v", err)
	}
	if got := r44cKnownIDs(t, block); len(got) != 1 || got[0] != "MEM-shared0001" {
		t.Fatalf("empty local store: %v, want only the shared row", got)
	}
}
