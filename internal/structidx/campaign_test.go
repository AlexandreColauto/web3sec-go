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

	"websec/internal/snapshot"
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
	if validation.ObjStr(idx, "campaign_id") != c.CampaignID {
		t.Fatalf("campaign_id %q", validation.ObjStr(idx, "campaign_id"))
	}
	if validation.ObjStr(idx, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", validation.ObjStr(idx, "snapshot_id"))
	}
	if validation.ObjStr(idx, "backend") != "regex" {
		t.Fatalf("backend %q", validation.ObjStr(idx, "backend"))
	}
	nodes := objList(validation.ObjAt(idx, "nodes"))
	edges := objList(validation.ObjAt(idx, "edges"))
	if got := validation.ObjAt(idx, "entry_count"); got.Kind != validation.Int ||
		got.I != int64(len(nodes)+len(edges)) {
		t.Fatalf("entry_count %v want %d", got, len(nodes)+len(edges))
	}
	stats := validation.ObjAt(idx, "stats")
	for _, key := range []string{"solidity_files", "other_files_listed",
		"contracts", "functions", "state_variables", "entry_points",
		"external_call_edges"} {
		if validation.ObjAt(stats, key).Kind != validation.Int {
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

// pinTreePinned pins the REAL store for `root`: state row + events via
// PinSnapshot, and the immutable snapshot.json manifest the r13 stamping
// law reads (a state row alone proves nothing — the claim lives in the
// store). Returns the recorded content_hash.
func pinTreePinned(t *testing.T, c *state.Campaign, root string) string {
	t.Helper()
	h, _, err := snapshot.ContentHash(root)
	if err != nil {
		t.Fatal(err)
	}
	sid := "src-content-" + h[:12]
	dir := filepath.Join(c.Dir, "snapshots", sid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := validation.VObj(
		validation.KV{K: "snapshot_id", V: validation.VStr(sid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "created_at", V: validation.VStr("2026-01-01T00:00:00.000000+00:00")},
		validation.KV{K: "pass", V: validation.VInt(1)},
		validation.KV{K: "pinned", V: validation.VBool(true)},
		validation.KV{K: "source", V: validation.VObj(
			validation.KV{K: "ladder", V: validation.VStr("no-vcs")},
			validation.KV{K: "git_commit", V: validation.VNull()},
			validation.KV{K: "git_dirty", V: validation.VNull()},
			validation.KV{K: "content_hash", V: validation.VStr(h)},
			validation.KV{K: "root", V: validation.VStr(root)},
			validation.KV{K: "file_count", V: validation.VInt(1)},
		)},
	)
	if err := validation.WriteJson(filepath.Join(dir, "snapshot.json"),
		meta, "snapshot"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PinSnapshot(meta); err != nil {
		t.Fatalf("PinSnapshot: %v", err)
	}
	return sid
}

// storedCreatedAt is the artifact's created_at, or "" when unreadable.
func storedCreatedAt(c *state.Campaign) string {
	idx, err := validation.ReadJson(IndexPath(c))
	if err != nil {
		return ""
	}
	return validation.ObjStr(idx, "created_at")
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
	if validation.ObjStr(stored, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", validation.ObjStr(stored, "snapshot_id"))
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
	sid := pinTreePinned(t, c, tree)
	idx, err := EnsureFreshIndex(c, tree)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(idx, "snapshot_id") != sid {
		t.Fatalf("snapshot_id %q", validation.ObjStr(idx, "snapshot_id"))
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
			return setKeyV(v, "snapshot_id", validation.VStr("src-content-deadbee"))
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
		if validation.ObjStr(rebuilt, "snapshot_id") != sid ||
			validation.ObjStr(rebuilt, "parse_version") != ParseVersion {
			t.Fatalf("did not rebuild: %v / %v",
				validation.ObjStr(rebuilt, "snapshot_id"), validation.ObjStr(rebuilt, "parse_version"))
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
	if validation.ObjStr(rep, "snapshot_id") != "unpinned" {
		t.Fatalf("snapshot_id %q", validation.ObjStr(rep, "snapshot_id"))
	}
	if validation.ObjAt(rep, "stats").Kind != validation.Obj {
		t.Fatalf("stats %v", validation.ObjAt(rep, "stats"))
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
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(a, "kind") == "value-flow" {
			found = true
		}
	}
	if !found {
		t.Fatalf("value-flow not registered: %v", validation.ObjAt(st, "artifacts"))
	}
	verdict, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.OK {
		t.Fatalf("verify_log not ok: %+v", verdict)
	}
}

// TestValueFlowReportStampsRecon (FIX-8): a sinks run records the light
// recon stamp in the campaign state — verb, src, timestamp, replaced on a
// re-run, never duplicated — and the event log carries the same facts.
func TestValueFlowReportStampsRecon(t *testing.T) {
	c := newCampaign(t, "flow-stamp")
	tree := filepath.Join("testdata", "sink")
	if _, err := ValueFlowReport(c, tree); err != nil {
		t.Fatal(err)
	}
	stamp, err := c.ReconStamp("sinks")
	if err != nil {
		t.Fatal(err)
	}
	if stamp.Kind != validation.Obj {
		t.Fatalf("no sinks stamp: %s", validation.CanonCompact(stamp))
	}
	if validation.ObjStr(stamp, "src") != tree {
		t.Fatalf("stamp src = %q, want %q", validation.ObjStr(stamp, "src"), tree)
	}
	if validation.ObjStr(stamp, "at") == "" {
		t.Fatal("stamp at is empty")
	}
	if got := validation.ObjStr(stamp, "campaign_id"); got != c.CampaignID {
		t.Fatalf("stamp campaign_id = %q, want %q", got, c.CampaignID)
	}
	// the audit trail mirrors the stamp: the valueflow.computed event names
	// the verb and the src
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evts {
		if validation.ObjStr(e, "type") != "valueflow.computed" {
			continue
		}
		data := validation.ObjAt(e, "data")
		if validation.ObjStr(data, "verb") == "sinks" && validation.ObjStr(data, "src") == tree {
			found = true
		}
	}
	if !found {
		t.Fatalf("no valueflow.computed event carrying the stamp facts")
	}
	// idempotence: a second run REPLACES the row — one sinks key, one
	// {campaign_id, src, at}
	if _, err := ValueFlowReport(c, tree); err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	recon := validation.ObjAt(st, "recon")
	if recon.Kind != validation.Obj || len(recon.O) != 1 ||
		recon.O[0].K != "sinks" {
		t.Fatalf("double run left %s", validation.CanonCompact(recon))
	}
	if len(validation.ObjAt(recon, "sinks").O) != 3 {
		t.Fatalf("sinks row keys = %s", validation.CanonCompact(
			validation.ObjAt(recon, "sinks")))
	}
	// FIX-C: the stamp names the campaign it ran under
	if got := validation.ObjStr(validation.ObjAt(recon, "sinks"), "campaign_id"); got != c.CampaignID {
		t.Fatalf("sinks campaign_id = %q, want %q", got, c.CampaignID)
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

// TestForeignTreeNeverClaimsTheActivePin pins r13 issue 2: with a real
// pin active, `--src`-ing a DECOY tree used to stamp the pin's id onto
// the decoy's nodes — registered as a campaign artifact of the pinned
// tree, audit green, provenance a calendar lie. The stamp is a claim by
// proof now: hash unequal ⇒ "unpinned".
func TestForeignTreeNeverClaimsTheActivePin(t *testing.T) {
	c := newCampaign(t, "decoy-program")
	real := filepath.Join("testdata", "sink")
	sid := pinTreePinned(t, c, real)
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "Decoy.sol"),
		[]byte("contract Decoy { mapping(address=>uint256) balances; "+
			"function drain() external {} }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := IndexSnapshot(c, decoy, "regex")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(idx, "snapshot_id"); got != "unpinned" {
		t.Fatalf("decoy content CLAIMED the active pin %s: stamped %q",
			sid, got)
	}
	// And the same tree through the writer path stays honest:
	if _, err := EnsureFreshIndex(c, decoy); err != nil {
		t.Fatal(err)
	}
	stored, err := validation.ReadJson(IndexPath(c))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(stored, "snapshot_id") != "unpinned" {
		t.Fatalf("EnsureFreshIndex persisted a false claim: %q",
			validation.ObjStr(stored, "snapshot_id"))
	}
	// The REAL tree still claims its pin (no over-refusal):
	homing, err := IndexSnapshot(c, real, "regex")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(homing, "snapshot_id") != sid {
		t.Fatalf("the pinned tree lost its stamp: %q",
			validation.ObjStr(homing, "snapshot_id"))
	}
}
