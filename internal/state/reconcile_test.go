package state

// reconcile_test.go — D3 (artifact supersession). The bug the post-mortem
// campaign hit: `report.md` had four registry rows because the first
// registration (artifact-register, default kind "other") and every later
// generation (kind "report") resolved to the same path, and a differing kind
// minted a row instead of reconciling. The audit re-hashes EVERY row, so the
// three non-latest rows kept a stale hash forever and `webv2 audit` was
// permanently red. The fix: one row per resolved path (ghosts pruned, kind
// migrated in place), plus `ReconcileArtifacts` as the operator's escape hatch
// for a batch of rewrites made by something other than the tool.

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// TestRegisterOrRefreshPrunesGhostRows: the morph campaign's four-row shape —
// rows at one resolved path that predate the refresh are retired with an
// artifact.pruned event, so the registry holds one row per path and the audit's
// re-hash loop cannot see a stale row.
func TestRegisterOrRefreshPrunesGhostRows(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "report.md")
	if err := os.WriteFile(fp, []byte("r1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The morph shape: an "other" row registered by hand, then a "report" row
	// from a generation — both at the same path.
	ghost, err := c.RegisterArtifact("other", fp, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	backdateArtifact(t, c, ghost, "2020-01-01T00:00:00+00:00")
	live, err := c.RegisterArtifact("report", fp, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The file is rewritten after both registrations: BOTH rows now hold a
	// stale hash, which is exactly why the audit was permanently red.
	if err := os.WriteFile(fp, []byte("r2"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := c.RegisterOrRefresh("report", fp, "", nil,
		"re-registered (content may have changed)")
	if err != nil {
		t.Fatal(err)
	}
	if got != live {
		t.Fatalf("surviving row: %q want the newest (%q)", got, live)
	}
	st := mustState(t, c)
	arts := validation.ObjAt(st, "artifacts")
	if len(arts.A) != 1 {
		t.Fatalf("rows after reconcile: %d want 1", len(arts.A))
	}
	row := arts.A[0]
	if got := validation.ObjStr(row, "artifact_id"); got != live {
		t.Errorf("surviving row: %q want %q", got, live)
	}
	if got := validation.ObjStr(row, "kind"); got != "report" {
		t.Errorf("surviving kind: %q", got)
	}
	if got := validation.ObjStr(row, "sha256"); got != validation.Sha256Hex([]byte("r2")) {
		t.Errorf("surviving sha256 is stale: %q", got)
	}
	// The retired row is recoverable from the log: artifact.pruned carries its
	// id (as the event subject), kind and path, and the reason names the
	// re-registration.
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	pruned := 0
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "artifact.pruned" {
			continue
		}
		pruned++
		if subj := validation.ObjStr(ev, "ref"); subj != ghost {
			t.Errorf("pruned subject: %q want %q", subj, ghost)
		}
		if got := validation.ObjStr(validation.ObjAt(ev, "data"), "reason"); got !=
			"superseded: same path re-registered as kind report" {
			t.Errorf("prune reason: %q", got)
		}
	}
	if pruned != 1 {
		t.Fatalf("artifact.pruned events: %d want 1", pruned)
	}
}

// TestRegisterOrRefreshSamePathRepeatedlyStaysOneRow: the four-row bug in
// miniature — N generations of one file must leave exactly one row, current.
func TestRegisterOrRefreshSamePathRepeatedlyStaysOneRow(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fp := filepath.Join(root, "report.md")
	id := ""
	for i, content := range []string{"a", "b", "c", "d"} {
		if err := os.WriteFile(fp, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		kind := "other"
		if i > 0 {
			kind = "report"
		}
		got, err := c.RegisterOrRefresh(kind, fp, "", nil, "re-registered")
		if err != nil {
			t.Fatal(err)
		}
		if id == "" {
			id = got
		} else if got != id {
			t.Fatalf("generation %d minted a new row (%s != %s)", i, got, id)
		}
	}
	st := mustState(t, c)
	arts := validation.ObjAt(st, "artifacts")
	if len(arts.A) != 1 {
		t.Fatalf("rows: %d want 1", len(arts.A))
	}
	if got := validation.ObjStr(arts.A[0], "sha256"); got != validation.Sha256Hex([]byte("d")) {
		t.Errorf("sha256: %q", got)
	}
}

// TestReconcileArtifacts: an external rewrite of a registered file is detected
// by hash, refreshed by the live call, only reported by the dry call, and a
// deleted file is reported missing instead of failing the sweep.
func TestReconcileArtifacts(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name, content string) (string, string) {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		id, err := c.RegisterArtifact("other", p, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		return id, p
	}
	changedID, changedPath := mk("changed.md", "one")
	stableID, _ := mk("stable.md", "two")
	goneID, gonePath := mk("gone.md", "three")
	// External rewrites: one file edited, one deleted, one untouched.
	if err := os.WriteFile(changedPath, []byte("one+"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gonePath); err != nil {
		t.Fatal(err)
	}
	before := int64(0)
	if st := mustState(t, c); true {
		before = int64(len(validation.ObjAt(st, "artifacts").A))
	}
	// dry: reports the same finding, writes nothing.
	res, err := c.ReconcileArtifacts(true)
	if err != nil {
		t.Fatal(err)
	}
	if got := intAt(res, "checked"); got != before {
		t.Errorf("dry checked: %d want %d", got, before)
	}
	if got := len(listAt(res, "refreshed")); got != 1 {
		t.Errorf("dry refreshed: %d want 1", got)
	}
	if got := listAt(res, "refreshed")[0].S; got != changedID {
		t.Errorf("dry refreshed id: %q", got)
	}
	if got := intAt(res, "unchanged"); got != 1 {
		t.Errorf("dry unchanged: %d want 1", got)
	}
	miss := listAt(res, "missing")
	if len(miss) != 1 || validation.ObjStr(miss[0], "artifact_id") != goneID {
		t.Fatalf("dry missing: %+v", miss)
	}
	if got := validation.ObjAt(res, "dry"); got.Kind != validation.Bool || !got.B {
		t.Errorf("dry flag: %+v", got)
	}
	if got := validation.ObjStr(mustArtifact(t, c, changedID), "sha256"); got !=
		validation.Sha256Hex([]byte("one")) {
		t.Errorf("dry run refreshed the row: %q", got)
	}
	// live: refreshes the changed row, leaves the rest, logs once.
	res, err = c.ReconcileArtifacts(false)
	if err != nil {
		t.Fatal(err)
	}
	if got := intAt(res, "unchanged"); got != 1 {
		t.Errorf("live unchanged: %d want 1", got)
	}
	if got := validation.ObjStr(mustArtifact(t, c, changedID), "sha256"); got !=
		validation.Sha256Hex([]byte("one+")) {
		t.Errorf("live refresh did not take: %q", got)
	}
	if got := validation.ObjStr(mustArtifact(t, c, stableID), "sha256"); got !=
		validation.Sha256Hex([]byte("two")) {
		t.Errorf("stable row changed: %q", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	refreshed := 0
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == "artifact.refreshed" {
			refreshed++
			if got := validation.ObjStr(validation.ObjAt(ev, "data"), "reason"); got !=
				"reconcile after external rewrite" {
				t.Errorf("refresh reason: %q", got)
			}
		}
	}
	if refreshed != 1 {
		t.Fatalf("artifact.refreshed events: %d want 1", refreshed)
	}
	// Idempotent: a second live call has nothing left to do.
	res, err = c.ReconcileArtifacts(false)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(listAt(res, "refreshed")); got != 0 {
		t.Errorf("second reconcile refreshed %d rows want 0", got)
	}
}

func backdateArtifact(t *testing.T, c *Campaign, id, stamp string) {
	t.Helper()
	doc, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	arts := validation.ObjAt(doc, "artifacts")
	for i, a := range arts.A {
		if validation.ObjStr(a, "artifact_id") == id {
			a.O = validation.SetOrAppend(a.O, "registered_at", validation.VStr(stamp))
			arts.A[i] = a
		}
	}
	doc.O = validation.SetOrAppend(doc.O, "artifacts", arts)
	if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}
}

func mustArtifact(t *testing.T, c *Campaign, id string) validation.Value {
	t.Helper()
	a, err := c.Artifact(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// intAt/listAt live in the audit/validation helpers; the state tests keep a
// local pair so the assertions above read the same way as the CLI's.
func intAt(v validation.Value, key string) int64 {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Int {
		return x.I
	}
	return -1
}

func listAt(v validation.Value, key string) []validation.Value {
	return validation.ObjAt(v, key).A
}
