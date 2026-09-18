package state

// Task 6 unit pin for the shared helper the index rebuild uses:
// RegisterOrRefreshIfChanged must touch the registry ONLY when the row it
// would refresh is not already pinning the bytes on disk. The CLI test
// (internal/cli/cmd_index_refresh_test.go) pins the command-level law; this
// pins the helper's own contract, including the shapes the CLI cannot easily
// reach (a missing row, a kind migration, a path spelled a second way).

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

func refreshIfChangedCamp(t *testing.T) (*Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c, root
}

func refreshEvents(t *testing.T, c *Campaign, kind string) []validation.Value {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var out []validation.Value
	for _, e := range evs {
		if objStr(e, "type") == kind {
			out = append(out, e)
		}
	}
	return out
}

// TestRegisterOrRefreshIfChangedRegistersThenStaysSilent: the first call mints
// the row; every later call over identical bytes is a no-op with no event.
func TestRegisterOrRefreshIfChangedRegistersThenStaysSilent(t *testing.T) {
	c, root := refreshIfChangedCamp(t)
	p := filepath.Join(root, "index.json")
	if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, refreshed, err := c.RegisterOrRefreshIfChanged("structural-index", p, "",
		nil, "rebuilt")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || !refreshed {
		t.Fatalf("first call: id=%q refreshed=%v want a new row", id, refreshed)
	}
	if n := len(refreshEvents(t, c, "artifact.registered")); n != 1 {
		t.Fatalf("artifact.registered events: %d want 1", n)
	}
	got, refreshed, err := c.RegisterOrRefreshIfChanged("structural-index", p,
		"", nil, "rebuilt")
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("second call minted %q, want the same row %q", got, id)
	}
	if refreshed {
		t.Fatal("an unchanged artifact reported a registry change")
	}
	if n := len(refreshEvents(t, c, "artifact.refreshed")); n != 0 {
		t.Fatalf("artifact.refreshed events: %d want 0", n)
	}
	row := mustArtifact(t, c, id)
	// RegisterArtifact never sets refresh_count: a row nobody refreshed has
	// no refresh marker at all (a positive count would be a lie).
	if rc := objAt(row, "refresh_count"); rc.Kind == validation.Int && rc.I != 0 {
		t.Fatalf("refresh_count %d want absent/0", rc.I)
	}
	// The same file spelled a second way is the SAME artifact (resolved-path
	// law): still no event, still one row.
	other := filepath.Join(root, ".", "index.json")
	if _, refreshed, err := c.RegisterOrRefreshIfChanged("structural-index",
		other, "", nil, "rebuilt"); err != nil {
		t.Fatal(err)
	} else if refreshed {
		t.Fatal("a second spelling of one path reported a registry change")
	}
	if st := mustState(t, c); len(objAt(st, "artifacts").A) != 1 {
		t.Fatalf("rows: %d want 1", len(objAt(st, "artifacts").A))
	}
}

// TestRegisterOrRefreshIfChangedRefreshesMovedBytes: changed bytes refresh the
// row with the r16 unwind discipline's event shape (old/new sha + count).
func TestRegisterOrRefreshIfChangedRefreshesMovedBytes(t *testing.T) {
	c, root := refreshIfChangedCamp(t)
	p := filepath.Join(root, "index.json")
	if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, _, err := c.RegisterOrRefreshIfChanged("structural-index", p, "", nil,
		"rebuilt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, refreshed, err := c.RegisterOrRefreshIfChanged("structural-index", p,
		"", nil, "rebuilt")
	if err != nil {
		t.Fatal(err)
	}
	if got != id || !refreshed {
		t.Fatalf("got id=%q refreshed=%v want the same row refreshed", got,
			refreshed)
	}
	evs := refreshEvents(t, c, "artifact.refreshed")
	if len(evs) != 1 {
		t.Fatalf("artifact.refreshed events: %d want 1", len(evs))
	}
	d := objAt(evs[0], "data")
	if objStr(d, "old_sha256") != validation.Sha256Hex([]byte("v1")) ||
		objStr(d, "new_sha256") != validation.Sha256Hex([]byte("v2")) {
		t.Fatalf("refresh hashes: %s", validation.DumpIndented(d))
	}
	row := mustArtifact(t, c, id)
	if objStr(row, "sha256") != validation.Sha256Hex([]byte("v2")) {
		t.Fatalf("row sha256: %q", objStr(row, "sha256"))
	}
	if intAt(row, "refresh_count") != 1 {
		t.Fatalf("refresh_count: %d", intAt(row, "refresh_count"))
	}
}

// TestRegisterOrRefreshIfChangedMigratesKind: a differing kind is a real
// change (D3), so the row migrates and the event lands even when the bytes did
// not move.
func TestRegisterOrRefreshIfChangedMigratesKind(t *testing.T) {
	c, root := refreshIfChangedCamp(t)
	p := filepath.Join(root, "index.json")
	if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, _, err := c.RegisterOrRefreshIfChanged("other", p, "", nil, "rebuilt")
	if err != nil {
		t.Fatal(err)
	}
	got, refreshed, err := c.RegisterOrRefreshIfChanged("structural-index", p,
		"", nil, "rebuilt")
	if err != nil {
		t.Fatal(err)
	}
	if got != id || !refreshed {
		t.Fatalf("got id=%q refreshed=%v want a kind migration", got, refreshed)
	}
	evs := refreshEvents(t, c, "artifact.refreshed")
	if len(evs) != 1 {
		t.Fatalf("artifact.refreshed events: %d want 1", len(evs))
	}
	if got := objStr(objAt(evs[0], "data"), "kind_migrated"); got !=
		"other→structural-index" {
		t.Fatalf("kind_migrated: %q", got)
	}
	if got := objStr(mustArtifact(t, c, id), "kind"); got != "structural-index" {
		t.Fatalf("row kind: %q", got)
	}
}

// TestRegisterOrRefreshIfChangedMissingFile: a path that is not there is the
// same error RegisterOrRefresh reports (the path text), never a silent skip.
func TestRegisterOrRefreshIfChangedMissingFile(t *testing.T) {
	c, root := refreshIfChangedCamp(t)
	missing := filepath.Join(root, "nope.json")
	_, _, err := c.RegisterOrRefreshIfChanged("structural-index", missing, "",
		nil, "rebuilt")
	if err == nil {
		t.Fatal("expected a missing-file error")
	}
	if err.Error() != missing {
		t.Fatalf("missing message:\n got %q\nwant %q", err.Error(), missing)
	}
	if n := len(refreshEvents(t, c, "artifact.registered")); n != 0 {
		t.Fatalf("a missing file minted %d rows", n)
	}
}
