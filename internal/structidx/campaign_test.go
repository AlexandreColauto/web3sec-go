package structidx

// Campaign-level parity tests: index_snapshot / save_index /
// ensure_fresh_index / value_flow_report and the tree-fact hash (spec §5.7).

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

func newCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return c
}

func TestIndexSnapshotStampsCampaign(t *testing.T) {
	c := newCampaign(t, "index-program")
	idx, err := IndexSnapshot(c, filepath.Join("testdata", "structural"),
		DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(idx, "campaign_id") != c.CampaignID {
		t.Fatalf("campaign_id %q", objStr(idx, "campaign_id"))
	}
	if objStr(idx, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", objStr(idx, "snapshot_id"))
	}
	if objStr(idx, "backend") != "regex" {
		t.Fatalf("backend %q", objStr(idx, "backend"))
	}
	nodes := objList(objAt(idx, "nodes"))
	edges := objList(objAt(idx, "edges"))
	if got := objAt(idx, "entry_count"); got.Kind != validation.Int ||
		got.I != int64(len(nodes)+len(edges)) {
		t.Fatalf("entry_count %v want %d", got, len(nodes)+len(edges))
	}
	stats := objAt(idx, "stats")
	for _, key := range []string{"solidity_files", "other_files_listed",
		"contracts", "functions", "state_variables", "entry_points",
		"external_call_edges"} {
		if objAt(stats, key).Kind != validation.Int {
			t.Fatalf("stats.%s missing", key)
		}
	}
	if _, err := SaveIndex(c, idx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}
	if _, err := os.Stat(IndexPath(c)); err != nil {
		t.Fatalf("artifact: %v", err)
	}
}

func TestSaveIndexRejectsStaleParseVersion(t *testing.T) {
	c := newCampaign(t, "index-program")
	idx := validation.VObj(validation.KV{K: "parse_version", V: validation.VStr("2")})
	if _, err := SaveIndex(c, idx); err == nil {
		t.Fatal("v2 index saved")
	} else if _, ok := err.(*StaleIndexError); !ok {
		t.Fatalf("error type %T", err)
	}
}

// pinSnapshot pins a minimal snapshot so active_snapshot_id_or_none() is
// non-nil (the reuse path).
func pinSnapshot(t *testing.T, c *state.Campaign, sid string) {
	t.Helper()
	doc := validation.VObj(
		validation.KV{K: "snapshot_id", V: validation.VStr(sid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "created_at", V: validation.VStr("2026-01-01T00:00:00.000000+00:00")},
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "ladder", V: validation.VStr("no-vcs")},
			validation.KV{K: "content_hash", V: validation.VStr("deadbeef")},
		)},
	)
	if _, err := c.PinSnapshot(doc); err != nil {
		t.Fatalf("PinSnapshot: %v", err)
	}
}

// storedCreatedAt is the artifact's created_at, or "" when unreadable.
func storedCreatedAt(c *state.Campaign) string {
	idx, err := validation.ReadJson(IndexPath(c))
	if err != nil {
		return ""
	}
	return objStr(idx, "created_at")
}

func TestEnsureFreshIndexUnpinnedAlwaysRebuilds(t *testing.T) {
	// Python quirk, verified against the live twin: index_snapshot writes
	// "unpinned" when there is no pin, but ensure_fresh_index compares the
	// stored snapshot_id to None — so an unpinned index is rebuilt on every
	// call. Faithful, not a bug.
	c := newCampaign(t, "fresh-program")
	tree := filepath.Join("testdata", "sink")
	if _, err := EnsureFreshIndex(c, tree); err != nil {
		t.Fatal(err)
	}
	if got := storedCreatedAt(c); got == "" {
		t.Fatal("no artifact")
	}
	stored, err := validation.ReadJson(IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if objStr(stored, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", objStr(stored, "snapshot_id"))
	}
	if err := validation.WriteJson(IndexPath(c),
		setKeyV(stored, "created_at", validation.VStr("SENTINEL")), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureFreshIndex(c, tree); err != nil {
		t.Fatal(err)
	}
	if storedCreatedAt(c) == "SENTINEL" {
		t.Fatal("unpinned index was reused; Python rebuilds it")
	}
}

func TestEnsureFreshIndexReusesPinnedAndRebuildsStale(t *testing.T) {
	c := newCampaign(t, "fresh-program")
	tree := filepath.Join("testdata", "sink")
	pinSnapshot(t, c, "S-0123456789abcdef")
	idx, err := EnsureFreshIndex(c, tree)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(idx, "snapshot_id") != "S-0123456789abcdef" {
		t.Fatalf("snapshot_id %q", objStr(idx, "snapshot_id"))
	}
	if err := validation.WriteJson(IndexPath(c),
		setKeyV(idx, "created_at", validation.VStr("SENTINEL")), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureFreshIndex(c, tree); err != nil {
		t.Fatal(err)
	}
	if storedCreatedAt(c) != "SENTINEL" {
		t.Fatal("matching pinned index was not reused")
	}

	// A stored index from another pin (or an older parse version) must
	// rebuild rather than be read as "no guards".
	for _, mutate := range []func(validation.Value) validation.Value{
		func(v validation.Value) validation.Value {
			return setKeyV(v, "snapshot_id", validation.VStr("S-deadbeef"))
		},
		func(v validation.Value) validation.Value {
			return setKeyV(v, "parse_version", validation.VStr("2"))
		},
	} {
		stored, err := validation.ReadJson(IndexPath(c))
		if err != nil {
			t.Fatal(err)
		}
		if err := validation.WriteJson(IndexPath(c), mutate(stored), ""); err != nil {
			t.Fatal(err)
		}
		rebuilt, err := EnsureFreshIndex(c, tree)
		if err != nil {
			t.Fatal(err)
		}
		if objStr(rebuilt, "snapshot_id") != "S-0123456789abcdef" ||
			objStr(rebuilt, "parse_version") != ParseVersion {
			t.Fatalf("did not rebuild: %v / %v",
				objStr(rebuilt, "snapshot_id"), objStr(rebuilt, "parse_version"))
		}
	}
}

func TestValueFlowReportRegistersAndConverges(t *testing.T) {
	c := newCampaign(t, "flow-program")
	tree := filepath.Join("testdata", "sink")
	rep, err := ValueFlowReport(c, tree)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(rep, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", objStr(rep, "snapshot_id"))
	}
	if objAt(rep, "stats").Kind != validation.Obj {
		t.Fatalf("stats %v", objAt(rep, "stats"))
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, ValueFlowFile)); err != nil {
		t.Fatalf("value_flow artifact: %v", err)
	}
	// Registered under the value-flow kind.
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "kind") == "value-flow" {
			found = true
		}
	}
	if !found {
		t.Fatalf("value-flow not registered: %v", objAt(st, "artifacts"))
	}
	verdict, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.OK {
		t.Fatalf("verify_log not ok: %+v", verdict)
	}
}

func TestIndexShaIgnoresVolatileKeys(t *testing.T) {
	c := newCampaign(t, "sha-program")
	idx, err := IndexSnapshot(c, filepath.Join("testdata", "v1"), DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	sha1 := IndexSha(idx)
	moved := setKeyV(setKeyV(idx, "campaign_id", validation.VStr("C-other")),
		"created_at", validation.VStr("2099-01-01T00:00:00.000000+00:00"))
	if IndexSha(moved) != sha1 {
		t.Fatal("volatile keys moved the tree-fact hash")
	}
	// A tree change must move it.
	other, err := IndexSnapshot(c, filepath.Join("testdata", "sink"), DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if IndexSha(other) == sha1 {
		t.Fatal("different trees hashed equal")
	}
	// CampaignIndexSha reads the saved artifact.
	if CampaignIndexSha(c) != nil {
		t.Fatal("CampaignIndexSha must be nil with no artifact")
	}
	if _, err := SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	got := CampaignIndexSha(c)
	if got == nil || *got != sha1 {
		t.Fatalf("CampaignIndexSha = %v, want %s", got, sha1)
	}
}

// setKeyV replaces or appends a key, preserving key order.
func setKeyV(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, kv := range v.O {
		if kv.K == key {
			out = append(out, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: val})
	}
	return validation.VObj(out...)
}

func TestTreeFactsDropsOnlyVolatileKeys(t *testing.T) {
	idx := validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr("C-x")},
		validation.KV{K: "snapshot_id", V: validation.VStr("S-x")},
		validation.KV{K: "created_at", V: validation.VStr("now")},
		validation.KV{K: "parse_version", V: validation.VStr("3")},
	)
	got := TreeFacts(idx)
	if len(got.O) != 1 || got.O[0].K != "parse_version" {
		t.Fatalf("TreeFacts %v", got)
	}
}

// TestIndexShaVectors pins index_sha against the Python twin's own output on
// every golden index fixture (generated by
// PYTHONPATH=src python3 -c 'probes.index_sha(...)'), so the canonical-JSON
// projection and the volatile-key split cannot drift silently.
func TestIndexShaVectors(t *testing.T) {
	vec, err := validation.ReadJson(filepath.Join("testdata", "index_sha_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range vec.O {
		idx, err := validation.ReadJson(filepath.Join("testdata", kv.K))
		if err != nil {
			t.Fatalf("%s: %v", kv.K, err)
		}
		if got := IndexSha(idx); got != kv.V.S {
			t.Errorf("%s: index_sha %s, want %s", kv.K, got, kv.V.S)
		}
	}
}

// TestCampaignIndexShaSeamSurvivesSetProbes: the probes port owns the rest of
// planner.ProbesAPI and installs it with SetProbes; the structural index's
// §5.7 hash seam must keep working afterwards (SetProbes replaces the whole
// API, so structidx installs the field through SetCampaignIndexSha).
func TestCampaignIndexShaSeamSurvivesSetProbes(t *testing.T) {
	Wire()
	t.Cleanup(func() { planner.SetProbes(planner.ProbesAPI{}) })
	planner.SetProbes(planner.ProbesAPI{
		RegisteredAxes: func() map[string]planner.AxisMeta {
			return map[string]planner.AxisMeta{}
		},
	})
	c := newCampaign(t, "sha-seam")
	if got := planner.PB().CampaignIndexSha(c); got != nil {
		t.Fatalf("index sha = %q before any index was built", *got)
	}
	idx, err := IndexSnapshot(c, filepath.Join("testdata", "structural"),
		DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveIndex(c, idx); err != nil {
		t.Fatal(err)
	}
	got := planner.PB().CampaignIndexSha(c)
	if got == nil {
		t.Fatal("index sha seam was dropped by SetProbes")
	}
	if want := IndexSha(idx); *got != want {
		t.Fatalf("index sha = %q, want %q", *got, want)
	}
}

// TestIndexShaChangesWithGuardAndIsRebuildStable: the §5.7 tree hash is a
// pure function of the tree facts — stable across rebuilds of an unchanged
// tree, and different the moment a guard changes
// (test_probes.py::test_index_sha_changes_when_a_guard_changes_in_the_tree,
// ::test_index_sha_is_rebuild_stable_for_an_unchanged_tree).
func TestIndexShaChangesWithGuardAndIsRebuildStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "G.sol")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("contract G { uint x; function f(uint a) external { " +
		"require(a > 0); x = a; } }")
	first, err := IndexTreeValue(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha := IndexSha(first)
	again, err := IndexTreeValue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := IndexSha(again); got != sha {
		t.Fatalf("sha not rebuild-stable: %q vs %q", got, sha)
	}
	write("contract G { uint x; function f(uint a) external { " +
		"require(a > 1); x = a; } }")
	changed, err := IndexTreeValue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := IndexSha(changed); got == sha {
		t.Fatal("sha did not change when the guard changed")
	}
}
