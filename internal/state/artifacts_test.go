package state

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/validation"
)

func strp(s string) *string { return &s }

func mustStrPtr(t *testing.T, p *string) string {
	t.Helper()
	if p == nil {
		return "<nil>"
	}
	return *p
}

func lastEvent(t *testing.T, c *Campaign) validation.Value {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("no events")
	}
	return evs[len(evs)-1]
}

// lastStateEvent is state()["events"][-1]: the STATE MIRROR keeps the
// event in insertion order (the jsonl line is canonical/sorted on disk,
// in both twins — values are asserted from the log, key order from here).
func lastStateEvent(t *testing.T, c *Campaign) validation.Value {
	t.Helper()
	evs := objAt(mustState(t, c), "events")
	if len(evs.A) == 0 {
		t.Fatal("no state events")
	}
	return evs.A[len(evs.A)-1]
}

func keyNames(v validation.Value) []string {
	out := make([]string, 0, len(v.O))
	for _, kv := range v.O {
		out = append(out, kv.K)
	}
	return out
}

// --- stage ledger ----------------------------------------------------------

// TestStageStatusPending: an unknown stage gets the {"status":"pending"}
// default (exactly one key).
func TestStageStatusPending(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.StageStatus("scope")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := keyNames(v), []string{"status"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("keys: %v", got)
	}
	if got := objStr(v, "status"); got != "pending" {
		t.Errorf("status: %q", got)
	}
}

// TestStageLedgerAttempts: port of
// test_state.py::test_stage_ledger_attempts + exact key order.
func TestStageLedgerAttempts(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	exec := "deterministic"
	for i := 0; i < 2; i++ {
		if err := c.SetStage("scope", "done", validation.VNull(), &exec); err != nil {
			t.Fatal(err)
		}
	}
	entry, err := c.StageStatus("scope")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(entry, "status"); got != "done" {
		t.Errorf("status: %q", got)
	}
	if got := objAt(entry, "attempts").I; got != 2 {
		t.Errorf("attempts: %d", got)
	}
	if got := objStr(entry, "executor"); got != "deterministic" {
		t.Errorf("executor: %q", got)
	}
	want := []string{"status", "attempts", "last_run_at", "note", "executor"}
	got := keyNames(entry)
	if len(got) != len(want) {
		t.Fatalf("entry keys: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry key %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// TestStageLedgerNoteExecutorRetention: note overwrites only when
// truthy (non-empty); executor only when set; non-done statuses never
// increment attempts.
func TestStageLedgerNoteExecutorRetention(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetStage("s", "ready", validation.VStr("first note"), nil); err != nil {
		t.Fatal(err)
	}
	// empty note (null) + nil executor: both keep their old values,
	// no attempt increment.
	if err := c.SetStage("s", "ready", validation.VNull(), nil); err != nil {
		t.Fatal(err)
	}
	entry, _ := c.StageStatus("s")
	if got := objStr(entry, "note"); got != "first note" {
		t.Errorf("note must be kept: %q", got)
	}
	if got := objAt(entry, "attempts").I; got != 0 {
		t.Errorf("attempts after ready: %d", got)
	}
	exec := "det"
	if err := c.SetStage("s", "ready", validation.VNull(), &exec); err != nil {
		t.Fatal(err)
	}
	entry, _ = c.StageStatus("s")
	if got := objStr(entry, "executor"); got != "det" {
		t.Errorf("executor: %q", got)
	}
	// executor nil again: keep old.
	if err := c.SetStage("s", "ready", validation.VNull(), nil); err != nil {
		t.Fatal(err)
	}
	entry, _ = c.StageStatus("s")
	if got := objStr(entry, "executor"); got != "det" {
		t.Errorf("executor must be kept: %q", got)
	}
	// skipped: still no increment.
	if err := c.SetStage("s", "skipped", validation.VNull(), nil); err != nil {
		t.Fatal(err)
	}
	entry, _ = c.StageStatus("s")
	if got := objAt(entry, "attempts").I; got != 0 {
		t.Errorf("attempts after skipped: %d", got)
	}
	// needs-model increments.
	if err := c.SetStage("s", "needs-model", validation.VStr("second note"), nil); err != nil {
		t.Fatal(err)
	}
	entry, _ = c.StageStatus("s")
	if got := objAt(entry, "attempts").I; got != 1 {
		t.Errorf("attempts after needs-model: %d", got)
	}
	if got := objStr(entry, "note"); got != "second note" {
		t.Errorf("note overwrite: %q", got)
	}
}

// TestStageNoteCapped: notes longer than NOTE_CAP are capped with the
// exact Python marker; exactly-at-cap notes pass through.
func TestStageNoteCapped(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", NOTE_CAP+904)
	if err := c.SetStage("s", "done", validation.VStr(long), nil); err != nil {
		t.Fatal(err)
	}
	entry, _ := c.StageStatus("s")
	want := strings.Repeat("a", NOTE_CAP) + truncationMarker(904)
	if got := objStr(entry, "note"); got != want {
		t.Errorf("capped note:\n got %q (len %d)\nwant %q (len %d)", got, len(got), want, len(want))
	}
	exact := strings.Repeat("b", NOTE_CAP)
	if err := c.SetStage("s", "done", validation.VStr(exact), nil); err != nil {
		t.Fatal(err)
	}
	entry, _ = c.StageStatus("s")
	if got := objStr(entry, "note"); got != exact {
		t.Errorf("at-cap note must pass through (len %d)", len(got))
	}
}

// --- artifacts -------------------------------------------------------------

var artIDRe = regexp.MustCompile(`^REC-[0-9a-f]{8}$`)
var proIDRe = regexp.MustCompile(`^PRO-[0-9a-f]{8}$`)

// TestArtifactRegistrationHashesContent: port of
// test_state.py::test_artifact_registration_hashes_content plus the
// record shape, stored path, and event contract.
func TestArtifactRegistrationHashesContent(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "artifact.json")
	if err := os.WriteFile(fp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("recon", fp, "x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !artIDRe.MatchString(id) {
		t.Errorf("artifact id shape: %q", id)
	}
	a, err := c.Artifact(id)
	if err != nil {
		t.Fatal(err)
	}
	wantSha := validation.Sha256Hex([]byte("{}"))
	if got := objStr(a, "sha256"); got != wantSha {
		t.Errorf("sha256: got %q want %q", got, wantSha)
	}
	wantKeys := []string{"artifact_id", "kind", "path", "registered_at",
		"sha256", "snapshot_id", "note"}
	gotKeys := keyNames(a)
	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("record keys: %v", gotKeys)
	}
	for i := range wantKeys {
		if gotKeys[i] != wantKeys[i] {
			t.Errorf("record key %d: got %q want %q", i, gotKeys[i], wantKeys[i])
		}
	}
	if got := objStr(a, "path"); got != "artifact.json" {
		t.Errorf("stored path (inside root, relative): %q", got)
	}
	if got := objAt(a, "snapshot_id").Kind; got != validation.Null {
		t.Errorf("snapshot_id default: %+v", objAt(a, "snapshot_id"))
	}
	if got := objStr(a, "note"); got != "x" {
		t.Errorf("note: %q", got)
	}
	// the event: ref = id, data {kind, path} with the ORIGINAL path.
	ev := lastEvent(t, c)
	if got := objStr(ev, "type"); got != "artifact.registered" {
		t.Errorf("event type: %q", got)
	}
	if got := objStr(ev, "ref"); got != id {
		t.Errorf("event ref: %q", got)
	}
	data := objAt(lastStateEvent(t, c), "data")
	if got := keyNames(data); len(got) != 2 || got[0] != "kind" || got[1] != "path" {
		t.Errorf("data keys: %v", got)
	}
	if got := objStr(data, "path"); got != fp {
		t.Errorf("log path must be the original argument: %q", got)
	}
	// missing file: the error text is the path itself (FileNotFoundError(p)).
	missing := filepath.Join(root, "missing.json")
	if _, err := c.RegisterArtifact("recon", missing, "", nil); err == nil {
		t.Fatal("expected missing-file error")
	} else if err.Error() != missing {
		t.Errorf("missing message:\n got %q\nwant %q", err.Error(), missing)
	}
}

// TestFirst3Upper: kind[:3].upper() including the short-kind slice.
func TestFirst3Upper(t *testing.T) {
	cases := map[string]string{
		"recon":          "REC",
		"protocol-model": "PRO",
		"p":              "P",
		"po":             "PO",
		"poc":            "POC",
		"other":          "OTH",
	}
	for in, want := range cases {
		if got := first3Upper(in); got != want {
			t.Errorf("first3Upper(%q): got %q want %q", in, got, want)
		}
	}
}

// TestArtifactKindPrefix: a longer kind gets its 3-char uppercase prefix.
func TestArtifactKindPrefix(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "model.json")
	if err := os.WriteFile(fp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("protocol-model", fp, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proIDRe.MatchString(id) {
		t.Errorf("artifact id shape: %q", id)
	}
}

// TestArtifactUnknown: KeyError with the Python repr quoting.
func TestArtifactUnknown(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Artifact("ART-nope1234"); err == nil {
		t.Fatal("expected KeyError")
	} else if err.Error() != "unknown artifact 'ART-nope1234'" {
		t.Errorf("keyerror message: %q", err.Error())
	}
}

// TestArtifactSnapshotID: a provided snapshot id is stored verbatim.
func TestArtifactSnapshotID(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "art.json")
	if err := os.WriteFile(fp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	sid := "SNP-1"
	id, err := c.RegisterArtifact("recon", fp, "", &sid)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Artifact(id)
	if got := objStr(a, "snapshot_id"); got != "SNP-1" {
		t.Errorf("snapshot_id: %q", got)
	}
}

// TestArtifactStoredPathOutsideRoot: a file outside the root is stored by
// absolute (resolved) path; the event keeps the ORIGINAL argument, which
// may be a relative path.
func TestArtifactStoredPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	rel := "outside.txt"
	if err := os.WriteFile(filepath.Join(other, rel), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(other)
	id, err := c.RegisterArtifact("report", rel, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Artifact(id)
	want := resolvePath(filepath.Join(other, rel))
	if got := objStr(a, "path"); got != want {
		t.Errorf("stored path outside root:\n got %q\nwant %q", got, want)
	}
	ev := lastEvent(t, c)
	if got := objStr(objAt(ev, "data"), "path"); got != rel {
		t.Errorf("log path must be the original relative arg: %q", got)
	}
}

// TestPruneArtifact: pop + save + artifact.pruned event (data
// {kind, path, reason}); the removed record is returned.
func TestPruneArtifact(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fa := filepath.Join(root, "a.json")
	fb := filepath.Join(root, "b.json")
	for _, f := range []string{fa, fb} {
		if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	id1, err := c.RegisterArtifact("recon", fa, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := c.RegisterArtifact("recon", fb, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := c.PruneArtifact(id1, "superseded")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(rec, "artifact_id"); got != id1 {
		t.Errorf("returned record: %q", got)
	}
	if got := objStr(rec, "path"); got != "a.json" {
		t.Errorf("returned path: %q", got)
	}
	st := mustState(t, c)
	arts := objAt(st, "artifacts")
	if len(arts.A) != 1 {
		t.Fatalf("artifacts after prune: %d", len(arts.A))
	}
	if got := objStr(arts.A[0], "artifact_id"); got != id2 {
		t.Errorf("survivor: %q", got)
	}
	ev := lastEvent(t, c)
	if got := objStr(ev, "type"); got != "artifact.pruned" {
		t.Errorf("event type: %q", got)
	}
	if got := objStr(ev, "ref"); got != id1 {
		t.Errorf("event ref: %q", got)
	}
	data := objAt(lastStateEvent(t, c), "data")
	if got := keyNames(data); len(got) != 3 || got[0] != "kind" || got[1] != "path" || got[2] != "reason" {
		t.Errorf("data keys: %v", got)
	}
	if got := objStr(data, "kind"); got != "recon" {
		t.Errorf("data.kind: %q", got)
	}
	if got := objStr(data, "path"); got != "a.json" {
		t.Errorf("data.path: %q", got)
	}
	if got := objStr(data, "reason"); got != "superseded" {
		t.Errorf("data.reason: %q", got)
	}
	if _, err := c.PruneArtifact("ART-nope1234", ""); err == nil {
		t.Fatal("expected KeyError")
	} else if err.Error() != "unknown artifact 'ART-nope1234'" {
		t.Errorf("keyerror message: %q", err.Error())
	}
}

// TestRefreshArtifact: sanctioned re-hash — new sha, refresh_count,
// old/new in the event, key order, and the exact error texts.
func TestRefreshArtifact(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "plan.md")
	if err := os.WriteFile(fp, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("plan", fp, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	oldSha := validation.Sha256Hex([]byte("v1"))
	newSha := validation.Sha256Hex([]byte("v2"))
	if err := os.WriteFile(fp, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err := c.RefreshArtifact(id, "report regenerated", "op")
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(rec, "sha256"); got != newSha {
		t.Errorf("sha256: %q", got)
	}
	if got := objAt(rec, "refresh_count").I; got != 1 {
		t.Errorf("refresh_count: %d", got)
	}
	if got := objStr(rec, "refresh_reason"); got != "report regenerated" {
		t.Errorf("refresh_reason: %q", got)
	}
	if got := objStr(rec, "refreshed_at"); got == "" {
		t.Error("refreshed_at empty")
	}
	wantKeys := []string{"artifact_id", "kind", "path", "registered_at",
		"sha256", "snapshot_id", "note", "refreshed_at", "refresh_reason",
		"refresh_count"}
	gotKeys := keyNames(rec)
	if len(gotKeys) != len(wantKeys) {
		t.Fatalf("record keys after refresh: %v", gotKeys)
	}
	for i := range wantKeys {
		if gotKeys[i] != wantKeys[i] {
			t.Errorf("record key %d: got %q want %q", i, gotKeys[i], wantKeys[i])
		}
	}
	ev := lastEvent(t, c)
	if got := objStr(ev, "type"); got != "artifact.refreshed" {
		t.Errorf("event type: %q", got)
	}
	if got := objStr(ev, "ref"); got != id {
		t.Errorf("event ref: %q", got)
	}
	data := objAt(lastStateEvent(t, c), "data")
	if got := keyNames(data); len(got) != 6 || got[0] != "kind" || got[1] != "actor" ||
		got[2] != "reason" || got[3] != "old_sha256" || got[4] != "new_sha256" ||
		got[5] != "refresh_count" {
		t.Errorf("data keys: %v", got)
	}
	if got := objStr(data, "actor"); got != "op" {
		t.Errorf("data.actor: %q", got)
	}
	if got := objStr(data, "old_sha256"); got != oldSha {
		t.Errorf("data.old_sha256: %q", got)
	}
	if got := objStr(data, "new_sha256"); got != newSha {
		t.Errorf("data.new_sha256: %q", got)
	}
	if got := objAt(data, "refresh_count").I; got != 1 {
		t.Errorf("data.refresh_count: %d", got)
	}
	// second refresh increments to 2.
	if _, err := c.RefreshArtifact(id, "drift update", "op"); err != nil {
		t.Fatal(err)
	}
	st := mustState(t, c)
	if got := objAt(objAt(st, "artifacts").A[0], "refresh_count").I; got != 2 {
		t.Errorf("refresh_count: %d", got)
	}
	// empty / whitespace reason.
	if _, err := c.RefreshArtifact(id, "", "op"); err == nil {
		t.Fatal("expected empty-reason error")
	} else if err.Error() != "refresh_artifact requires a written reason" {
		t.Errorf("reason message: %q", err.Error())
	}
	if _, err := c.RefreshArtifact(id, "   ", "op"); err == nil {
		t.Fatal("expected whitespace-reason error")
	} else if err.Error() != "refresh_artifact requires a written reason" {
		t.Errorf("reason message: %q", err.Error())
	}
	// missing file: exact text with the joined (unresolved) path.
	if err := os.Remove(fp); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefreshArtifact(id, "late reason", "op"); err == nil {
		t.Fatal("expected missing-file error")
	} else if want := "artifact file missing, cannot refresh: " + filepath.Join(root, "plan.md"); err.Error() != want {
		t.Errorf("missing message:\n got %q\nwant %q", err.Error(), want)
	}
	// the file check comes BEFORE the reason check.
	if _, err := c.RefreshArtifact(id, "", "op"); err == nil {
		t.Fatal("expected missing-file error")
	} else if want := "artifact file missing, cannot refresh: " + filepath.Join(root, "plan.md"); err.Error() != want {
		t.Errorf("order message:\n got %q\nwant %q", err.Error(), want)
	}
	if _, err := c.RefreshArtifact("ART-nope1234", "r", "op"); err == nil {
		t.Fatal("expected KeyError")
	} else if err.Error() != "unknown artifact 'ART-nope1234'" {
		t.Errorf("keyerror message: %q", err.Error())
	}
}

// TestRegisterOrRefresh: same path + kind refreshes the latest row (no
// ghost row); a different path or a different kind mints a new row.
func TestRegisterOrRefresh(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "plan.md")
	fp2 := filepath.Join(root, "report.md")
	if err := os.WriteFile(fp, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp2, []byte("r1"), 0o644); err != nil {
		t.Fatal(err)
	}
	const defReason = "re-registered (content may have changed)"
	id1, err := c.RegisterOrRefresh("plan", fp, "", nil, defReason)
	if err != nil {
		t.Fatal(err)
	}
	// same path + same kind, content changed -> refresh the same row.
	if err := os.WriteFile(fp, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	id2, err := c.RegisterOrRefresh("plan", fp, "", nil, defReason)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id1 {
		t.Fatalf("expected refresh of %s, got new id %s", id1, id2)
	}
	st := mustState(t, c)
	arts := objAt(st, "artifacts")
	if len(arts.A) != 1 {
		t.Fatalf("rows after same-path re-register: %d", len(arts.A))
	}
	if got := objAt(arts.A[0], "refresh_count").I; got != 1 {
		t.Errorf("refresh_count: %d", got)
	}
	if got := objStr(arts.A[0], "sha256"); got != validation.Sha256Hex([]byte("v2")) {
		t.Errorf("sha256: %q", got)
	}
	ev := lastEvent(t, c)
	if got := objStr(ev, "type"); got != "artifact.refreshed" {
		t.Errorf("event type: %q", got)
	}
	if got := objStr(objAt(ev, "data"), "reason"); got != defReason {
		t.Errorf("refresh reason: %q", got)
	}
	// different path -> new row.
	id3, err := c.RegisterOrRefresh("report", fp2, "", nil, defReason)
	if err != nil {
		t.Fatal(err)
	}
	if id3 == id1 {
		t.Fatal("expected a new row for a different path")
	}
	// same path, different kind -> new row (no refresh).
	id4, err := c.RegisterOrRefresh("report", fp, "", nil, defReason)
	if err != nil {
		t.Fatal(err)
	}
	if id4 == id1 {
		t.Fatal("expected a new row for a different kind")
	}
	st = mustState(t, c)
	arts = objAt(st, "artifacts")
	if len(arts.A) != 3 {
		t.Fatalf("rows: %d", len(arts.A))
	}
	last := arts.A[2]
	if got := objStr(last, "kind"); got != "report" {
		t.Errorf("new row kind: %q", got)
	}
	if got := objAt(last, "refresh_count").Kind; got != validation.Null {
		t.Errorf("new row must not be refreshed: %+v", objAt(last, "refresh_count"))
	}
	ev = lastEvent(t, c)
	if got := objStr(ev, "type"); got != "artifact.registered" {
		t.Errorf("event type: %q", got)
	}
	// missing file: the error text is the path itself.
	missing := filepath.Join(root, "nope.md")
	if _, err := c.RegisterOrRefresh("plan", missing, "", nil, defReason); err == nil {
		t.Fatal("expected missing-file error")
	} else if err.Error() != missing {
		t.Errorf("missing message:\n got %q\nwant %q", err.Error(), missing)
	}
}
