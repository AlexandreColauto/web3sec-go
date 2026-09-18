package cli

// Task 6 of the production-readiness plan: `index` emits a registry refresh
// event when it rewrites artifact bytes.
//
// The law: any artifact whose bytes the index command changed gets a registry
// row update + artifact.refreshed event in the SAME lock window (r15/r16 —
// the campaign lock spans the whole unit, and a refused ledger event unwinds
// the state write). The corollary the plan's second test pins: a rebuild that
// changes nothing leaves the registry and the ledger alone — an unchanged tree
// must not manufacture a refresh (the build clock is not a tree fact, so a
// naive "rewrite then always refresh" emits an event per run for no reason,
// and two concurrent rebuilds of one tree emit a duplicate refresh for one
// rewrite).
//
// The audit side needs no new section: the artifacts section re-hashes every
// registered row (refreshed or not), so a refreshed index is rendered by the
// existing section — asserted here as a clean `audit` with the refreshed row
// counted.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// t6Tree writes a small solidity tree and returns its directory.
func t6Tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body),
			0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// t6Events is the whole campaign event log.
func t6Events(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// t6Refreshes is the artifact.refreshed events, in ledger order.
func t6Refreshes(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	var out []validation.Value
	for _, e := range t6Events(t, c) {
		if objStr(e, "type") == "artifact.refreshed" {
			out = append(out, e)
		}
	}
	return out
}

// t6IndexPath is the registered structural index artifact on disk.
func t6IndexPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "structural_index.json")
}

// t6IndexRow is the one registered structural-index row.
func t6IndexRow(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	var rows []validation.Value
	for _, a := range objListAt(st, "artifacts") {
		if objStr(a, "kind") == "structural-index" {
			rows = append(rows, a)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("structural-index rows: %d want 1", len(rows))
	}
	return rows[0]
}

// t6Index runs the index verb and fails the test on a non-zero exit.
func t6Index(t *testing.T, root, cid, src string) {
	t.Helper()
	if code, out, errS := run(t, "--root", root, "index", cid,
		"--src", src); code != 0 {
		t.Fatalf("index exit %d: out=%q err=%q", code, out, errS)
	}
}

// t6AuditArtifacts runs `audit --json` and returns the artifacts section plus
// the overall verdict, failing on a red audit.
func t6AuditArtifacts(t *testing.T, root, cid string) (validation.Value, validation.Value) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit exit %d: out=%q err=%q", code, out, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit json: %v (%q)", err, out)
	}
	sec := objAt(objAt(rep, "sections"), "artifacts")
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Fatalf("artifacts section not ok: %s", validation.DumpIndented(sec))
	}
	return sec, rep
}

// TestIndexRefreshEventOnRewrittenArtifact: a rebuild that rewrites the
// registered structural index refreshes the row and logs artifact.refreshed in
// the same window, and the audit renders the refreshed row clean.
func TestIndexRefreshEventOnRewrittenArtifact(t *testing.T) {
	c, root := t15Campaign(t, "index-refresh")
	src := t6Tree(t, map[string]string{
		"A.sol": "contract A { uint x; function f() public { x = 1; } }\n",
	})
	t6Index(t, root, c.CampaignID, src)

	row := t6IndexRow(t, c)
	before := objStr(row, "sha256")
	fileSha, err := validation.Sha256File(t6IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if before != fileSha {
		t.Fatalf("registered sha %q != file sha %q", before, fileSha)
	}
	if n := len(t6Refreshes(t, c)); n != 0 {
		t.Fatalf("the registering index emitted %d artifact.refreshed, want 0", n)
	}

	// The tree moves: the next rebuild rewrites the registered bytes.
	if err := os.WriteFile(filepath.Join(src, "B.sol"),
		[]byte("contract B { function g() public {} }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t6Index(t, root, c.CampaignID, src)

	evs := t6Refreshes(t, c)
	if len(evs) != 1 {
		t.Fatalf("artifact.refreshed events: %d want 1", len(evs))
	}
	ev := evs[0]
	if got, want := objStr(ev, "ref"), objStr(row, "artifact_id"); got != want {
		t.Errorf("refresh ref %q want the registered row %q", got, want)
	}
	d := objAt(ev, "data")
	if got := objStr(d, "old_sha256"); got != before {
		t.Errorf("old_sha256 %q want the pre-rewrite hash %q", got, before)
	}
	row = t6IndexRow(t, c)
	fileSha, err = validation.Sha256File(t6IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(row, "sha256"); got != fileSha {
		t.Errorf("registry hash %q != rewritten bytes %q", got, fileSha)
	}
	if got := objStr(d, "new_sha256"); got != fileSha {
		t.Errorf("new_sha256 %q != rewritten bytes %q", got, fileSha)
	}
	if got := objInt(row, "refresh_count"); got != 1 {
		t.Errorf("refresh_count %d want 1", got)
	}
	sec, rep := t6AuditArtifacts(t, root, c.CampaignID)
	if got := objInt(sec, "checked"); got != 1 {
		t.Errorf("artifacts section checked %d want 1 (the refreshed row)", got)
	}
	if probs := objAt(sec, "problems").A; len(probs) != 0 {
		t.Errorf("artifacts section problems: %v", probs)
	}
	if ok := objAt(rep, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("audit overall not ok")
	}
}

// TestIndexUnchangedTreeEmitsNoEvents: a rebuild of an unchanged tree leaves
// the artifact bytes, the registry row and the ledger untouched.
func TestIndexUnchangedTreeEmitsNoEvents(t *testing.T) {
	c, root := t15Campaign(t, "index-unchanged")
	src := t6Tree(t, map[string]string{
		"A.sol": "contract A { uint x; function f() public { x = 1; } }\n",
	})
	t6Index(t, root, c.CampaignID, src)
	row := t6IndexRow(t, c)
	before := objStr(row, "sha256")
	raw, err := os.ReadFile(t6IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	events := len(t6Events(t, c))

	for i := 0; i < 2; i++ {
		t6Index(t, root, c.CampaignID, src)
	}
	if got := len(t6Events(t, c)); got != events {
		t.Fatalf("unchanged rebuilds appended %d events, want 0:\n%s",
			got-events, validation.DumpIndented(validation.VArr(
				t6Events(t, c)...)))
	}
	if n := len(t6Refreshes(t, c)); n != 0 {
		t.Fatalf("artifact.refreshed events: %d want 0", n)
	}
	after, err := os.ReadFile(t6IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Error("an unchanged rebuild rewrote the index bytes")
	}
	row = t6IndexRow(t, c)
	if got := objStr(row, "sha256"); got != before {
		t.Errorf("row sha256 moved to %q on an unchanged rebuild", got)
	}
	if got := objInt(row, "refresh_count"); got != 0 {
		t.Errorf("refresh_count %d want 0", got)
	}
	t6AuditArtifacts(t, root, c.CampaignID)
}

// TestIndexConcurrentRefresh: ten goroutines drive index over overlapping
// trees. The lock window must hold: one rewrite yields exactly one refresh
// event (never a duplicate), every refresh's old hash is the previous
// refresh's new hash, the final row pins the final bytes, and nothing
// deadlocks — all of it under -race.
func TestIndexConcurrentRefresh(t *testing.T) {
	ensureSeams()
	c, root := t15Campaign(t, "index-concurrent")

	base := map[string]string{}
	for i := 0; i < 8; i++ {
		base[fmt.Sprintf("S%d.sol", i)] = fmt.Sprintf(
			"contract S%d { uint v; }\n", i)
	}
	shared := t6Tree(t, base)
	// Three overlapping trees: the same eight files plus one that differs.
	trees := []string{}
	for i := 0; i < 3; i++ {
		files := map[string]string{}
		for k, v := range base {
			files[k] = v
		}
		files["V.sol"] = fmt.Sprintf(
			"contract V { uint w; function h() public { w = %d; } }\n", i+1)
		trees = append(trees, t6Tree(t, files))
	}

	// Warm up: the shared tree is registered before the race starts.
	t6Index(t, root, c.CampaignID, shared)
	if n := len(t6Refreshes(t, c)); n != 0 {
		t.Fatalf("warm-up refreshes: %d want 0", n)
	}
	// Now the shared tree has moved, so exactly one rewrite is pending.
	if err := os.WriteFile(filepath.Join(shared, "Snew.sol"),
		[]byte("contract Snew { uint z; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	type result struct {
		code int
		out  string
		errS string
	}
	drive := func(trees []string) []result {
		var wg sync.WaitGroup
		res := make([]result, 10)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var out, errS strings.Builder
				res[i].code = Run([]string{"--root", root, "index",
					c.CampaignID, "--src", trees[i%len(trees)]},
					&out, &errS)
				res[i].out, res[i].errS = out.String(), errS.String()
			}(i)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(90 * time.Second):
			t.Fatal("index deadlocked: 10 concurrent rebuilds never returned")
		}
		return res
	}

	// Phase 1 — one tree, ten writers: one rewrite, one refresh event.
	for i, r := range drive([]string{shared}) {
		if r.code != 0 {
			t.Fatalf("goroutine %d exit %d: out=%q err=%q", i, r.code,
				r.out, r.errS)
		}
	}
	if n := len(t6Refreshes(t, c)); n != 1 {
		t.Fatalf("ten concurrent rebuilds of ONE changed tree emitted %d "+
			"artifact.refreshed events, want exactly 1", n)
	}

	// Phase 2 — overlapping trees: every refresh is a real byte change, and
	// the refresh chain has no gaps or repeats.
	for i, r := range drive(trees) {
		if r.code != 0 {
			t.Fatalf("goroutine %d exit %d: out=%q err=%q", i, r.code,
				r.out, r.errS)
		}
	}
	evs := t6Refreshes(t, c)
	if len(evs) < 1 || len(evs) > 10 {
		t.Fatalf("refreshes after the overlapping race: %d want 1..10",
			len(evs))
	}
	prev := ""
	for i, ev := range evs {
		d := objAt(ev, "data")
		oldSha, newSha := objStr(d, "old_sha256"), objStr(d, "new_sha256")
		if oldSha == "" || newSha == "" {
			t.Fatalf("refresh %d has an empty hash pair: %s", i,
				validation.DumpIndented(d))
		}
		if oldSha == newSha {
			t.Fatalf("refresh %d is a no-op event (old == new == %s): one "+
				"rewrite must yield one refresh, not a duplicate", i, newSha)
		}
		if prev != "" && oldSha != prev {
			t.Fatalf("refresh %d old_sha256 %s != the previous refresh's "+
				"new_sha256 %s: the lock window let a rewrite slip between "+
				"the bytes and the row that pins them", i, oldSha, prev)
		}
		prev = newSha
	}
	fileSha, err := validation.Sha256File(t6IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	row := t6IndexRow(t, c)
	if got := objStr(row, "sha256"); got != fileSha {
		t.Fatalf("final row sha256 %q != final bytes %q", got, fileSha)
	}
	if prev != fileSha {
		t.Fatalf("the last refresh pinned %q but the bytes are %q", prev,
			fileSha)
	}
	if got := objInt(row, "refresh_count"); got != int64(len(evs)) {
		t.Fatalf("refresh_count %d != %d refresh events (one event per "+
			"rewrite)", got, len(evs))
	}
	t6AuditArtifacts(t, root, c.CampaignID)
}
