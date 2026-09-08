// protocolgraph_test.go: the Go twin of webv2.protocol_graph pinned to
// Python-generated vectors (testdata/golden_*.json) plus the protocol slice
// of tests/test_lens_exhaustive.py (the gateway protocol_model artifact).
package protocolgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// readTestJson reads a testdata artifact as an ordered Value.
func readTestJson(t *testing.T, name string) validation.Value {
	t.Helper()
	v, err := validation.ReadJson(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return v
}

// objAt is the local dict lookup used to navigate golden vectors.
func dump(v validation.Value) string { return validation.DumpIndented(v) }

// testCamp is the `camp` fixture: a fresh campaign under a temp root.
func testCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// query is one golden vector: a golden key and the Go call it pins.
type query struct {
	key string
	run func(validation.Value) validation.Value
}

// asList wraps a Go slice as a JSON array for the golden comparison.
func asList(items []validation.Value) validation.Value {
	return validation.VArr(items...)
}

// queries is the golden-vector table: every public query, keyed exactly
// as testdata/golden_queries.json keys it.
func queries() []query {
	return append(whoCanQueries(), listQueries()...)
}

// whoCanQueries covers the actor-side surface (who_can / actor_by_id).
func whoCanQueries() []query {
	return []query{
		{"who_can:can_drain", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "can_drain"))
		}},
		{"who_can:can_upgrade", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "can_upgrade"))
		}},
		{"who_can:can_pause", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "can_pause"))
		}},
		{"who_can:upgrade", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "upgrade"))
		}},
		{"who_can:drain", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "drain"))
		}},
		{"who_can:liquidate", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "liquidate"))
		}},
		{"who_can:relay", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "relay"))
		}},
		{"who_can:message", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "message"))
		}},
		{"who_can:role", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "role"))
		}},
		{"who_can:missing", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, "not-a-capability"))
		}},
		{"who_can:empty", func(m validation.Value) validation.Value {
			return asList(WhoCan(m, ""))
		}},
		{"actor_by_id:governor", func(m validation.Value) validation.Value {
			return actorOrNull(m, "governor")
		}},
		{"actor_by_id:user", func(m validation.Value) validation.Value {
			return actorOrNull(m, "user")
		}},
		{"actor_by_id:missing", func(m validation.Value) validation.Value {
			return actorOrNull(m, "nope")
		}},
	}
}

// listQueries covers the collection queries.
func listQueries() []query {
	return []query{
		{"trust_boundary_gaps", func(m validation.Value) validation.Value {
			return asList(TrustBoundaryGaps(m))
		}},
		{"accounting_vars", func(m validation.Value) validation.Value {
			return asList(AccountingVars(m))
		}},
		{"external_assets", func(m validation.Value) validation.Value {
			return asList(ExternalAssets(m))
		}},
		{"critical_edges", func(m validation.Value) validation.Value {
			return asList(CriticalEdges(m))
		}},
		{"privilege_surface", func(m validation.Value) validation.Value {
			return asList(PrivilegeSurface(m))
		}},
		{"oracle_chain", func(m validation.Value) validation.Value {
			return asList(OracleChain(m))
		}},
		{"state_machines", func(m validation.Value) validation.Value {
			return asList(StateMachines(m))
		}},
	}
}

// actorOrNull is actor_by_id: None becomes Null in the vector.
func actorOrNull(m validation.Value, id string) validation.Value {
	a, ok := ActorByID(m, id)
	if !ok {
		return validation.VNull()
	}
	return a
}

// ---- byte-exact query vectors (generated from the Python twin) ------------

var goldenModels = []string{"acme_vault", "gateway", "kitchen_sink"}

// TestGoldenQueriesMatchPythonVectors pins every query against
// testdata/golden_queries.json (produced by the Python reference), comparing
// ordered JSON so both content AND key order must match.
func TestGoldenQueriesMatchPythonVectors(t *testing.T) {
	golden := readTestJson(t, "golden_queries.json")
	qs := queries()
	checked := 0
	for _, name := range goldenModels {
		model := readTestJson(t, name+"_model.json")
		want := objAt(golden, name)
		if want.Kind != validation.Obj {
			t.Fatalf("golden has no %s group", name)
		}
		for _, q := range qs {
			wantV, present := lookupKey(want, q.key)
			if !present {
				t.Errorf("golden %s/%s missing", name, q.key)
				continue
			}
			got := q.run(model)
			if dump(got) != dump(wantV) {
				t.Errorf("%s/%s mismatch\n got: %s\nwant: %s",
					name, q.key, dump(got), dump(wantV))
			}
			checked++
		}
	}
	// completeness: every golden key is exercised, and nothing was skipped
	if len(wantKeys(golden)) != len(goldenModels)*len(qs) {
		t.Errorf("golden key count %d != %d models x %d queries",
			len(wantKeys(golden)), len(goldenModels), len(qs))
	}
	if checked != len(goldenModels)*len(qs) {
		t.Errorf("checked %d vectors, want %d", checked, len(goldenModels)*len(qs))
	}
}

// lookupKey distinguishes an ABSENT golden key from a present null value.
func lookupKey(v validation.Value, key string) (validation.Value, bool) {
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V, true
		}
	}
	return validation.VNull(), false
}

// wantKeys counts the golden keys across every model group.
func wantKeys(golden validation.Value) []string {
	var out []string
	for _, group := range golden.O {
		for _, k := range group.V.O {
			out = append(out, group.K+"/"+k.K)
		}
	}
	return out
}

// TestWhoCanPrivilegeFallbackAndDedup pins the two non-obvious who_can rules:
// a privilege whose role is not an actor id yields the synthetic ROLE actor
// carrying `via`, and an equal actor is appended only once.
func TestWhoCanPrivilegeFallbackAndDedup(t *testing.T) {
	model := readTestJson(t, "kitchen_sink_model.json")
	relay := WhoCan(model, "relay")
	if len(relay) != 1 { // the duplicate privilege row must not double-add
		t.Fatalf("relay hits = %d, want 1: %s", len(relay), dump(validation.VArr(relay...)))
	}
	want := validation.VObj(
		kv("id", validation.VStr("bridge-admin")),
		kv("kind", validation.VStr("ROLE")),
		kv("trust", validation.VStr("trusted")),
		kv("via", validation.VObj(
			kv("role", validation.VStr("bridge-admin")),
			kv("capability", validation.VStr("relay message")),
			kv("mechanism", validation.VStr("messenger")),
		)),
	)
	if dump(relay[0]) != dump(want) {
		t.Errorf("fallback actor\n got: %s\nwant: %s", dump(relay[0]), dump(want))
	}
	// a flag hit is not duplicated by the privilege that names the same actor
	upgrade := WhoCan(model, "upgrade")
	if len(upgrade) != 1 || objStrOf(upgrade[0], "id") != "governor" {
		t.Errorf("upgrade hits = %s, want the single governor actor",
			dump(validation.VArr(upgrade...)))
	}
	// "" matches every privilege ("" in s is always true) and no actor flag
	if got := WhoCan(model, ""); len(got) != 3 {
		t.Errorf(`who_can("") hits = %d, want 3: %s`, len(got),
			dump(validation.VArr(got...)))
	}
}

// objStrOf is the local string field read.
func objStrOf(v validation.Value, key string) string {
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V.S
		}
	}
	return ""
}

// TestExternalAssetsFlagFamilies pins the flag order and the parameterized
// odd-decimals family emitted by external_assets.
func TestExternalAssetsFlagFamilies(t *testing.T) {
	odd := readTestJson(t, "odd_asset_model.json")
	risky := ExternalAssets(odd)
	if len(risky) != 1 {
		t.Fatalf("odd asset risky = %s, want one row", dump(validation.VArr(risky...)))
	}
	want := validation.VObj(
		kv("asset", validation.VStr("A")),
		kv("flags", validation.VArr(validation.VStr("odd-decimals-7"))),
	)
	if dump(risky[0]) != dump(want) {
		t.Errorf("odd asset row\n got: %s\nwant: %s", dump(risky[0]), dump(want))
	}
	sink := ExternalAssets(readTestJson(t, "kitchen_sink_model.json"))
	if len(sink) != 5 {
		t.Fatalf("kitchen sink risky = %s, want 5 rows", dump(validation.VArr(sink...)))
	}
	// flag order is fixed: fee-on-transfer, rebasing, erc777, erc4626,
	// odd-decimals, then the declared nonstandard_behaviors
	flags := objAt(sink[1], "flags")
	if dump(flags) != `[
  "fee-on-transfer",
  "odd-decimals-7"
]` {
		t.Errorf("FEE flags = %s", dump(flags))
	}
	if objStrOf(sink[2], "asset") != "REB" || objStrOf(sink[4], "asset") != "WEIRD" {
		t.Errorf("risky order = %s", dump(validation.VArr(sink...)))
	}
}

// TestCriticalEdgesMutatingRelsOnly pins MUTATING_RELS membership and the
// filter (non-mutating relations never appear).
func TestCriticalEdgesMutatingRelsOnly(t *testing.T) {
	if len(MUTATING_RELS) != 8 {
		t.Errorf("MUTATING_RELS has %d members, want 8", len(MUTATING_RELS))
	}
	for _, rel := range []string{"MINTS", "BURNS", "DEPOSITS", "WITHDRAWS",
		"BORROWS", "LIQUIDATES", "UPGRADES", "BRIDGES"} {
		if _, ok := MUTATING_RELS[rel]; !ok {
			t.Errorf("MUTATING_RELS missing %s", rel)
		}
	}
	model := readTestJson(t, "kitchen_sink_model.json")
	edges := CriticalEdges(model)
	if len(edges) != 8 {
		t.Fatalf("critical edges = %d, want 8: %s", len(edges),
			dump(validation.VArr(edges...)))
	}
	for _, e := range edges {
		if _, ok := MUTATING_RELS[objStrOf(e, "rel")]; !ok {
			t.Errorf("non-mutating relation leaked: %s", dump(e))
		}
	}
}

// TestQueryDefaultsAreEmptyListsNotNil pins the [] (not null) shape of every
// list query on a model that lacks the collection entirely.
func TestQueryDefaultsAreEmptyListsNotNil(t *testing.T) {
	model := readTestJson(t, "gateway_model.json")
	empties := map[string][]validation.Value{
		"trust_boundary_gaps": TrustBoundaryGaps(model),
		"accounting_vars":     AccountingVars(model),
		"external_assets":     ExternalAssets(model),
		"critical_edges":      CriticalEdges(model),
		"privilege_surface":   PrivilegeSurface(model),
		"oracle_chain":        OracleChain(model),
	}
	for name, got := range empties {
		if got == nil {
			t.Errorf("%s returned nil, want an empty slice", name)
			continue
		}
		if dump(validation.VArr(got...)) != "[]" {
			t.Errorf("%s = %s, want []", name, dump(validation.VArr(got...)))
		}
	}
	if len(WhoCan(model, "can_drain")) != 0 || WhoCan(model, "can_drain") == nil {
		t.Errorf("who_can on an actorless model = %s",
			dump(validation.VArr(WhoCan(model, "can_drain")...)))
	}
	// the gateway fixture DOES declare a state machine: it must come back
	if got := StateMachines(model); len(got) != 1 ||
		objStrOf(got[0], "name") != "rollup" {
		t.Errorf("state_machines = %s, want the declared rollup machine",
			dump(validation.VArr(got...)))
	}
}

// ---- load_model / save_model (campaign side effects) ----------------------

// TestLoadModelRegistersArtifactAndLogsEvent is load_model: the artifact row,
// the protocol_model.loaded event and the returned model, pinned to
// testdata/golden_campaign.json (recorded from the Python twin).
func TestLoadModelRegistersArtifactAndLogsEvent(t *testing.T) {
	camp := testCamp(t)
	golden := readTestJson(t, "golden_campaign.json")
	path := filepath.Join(camp.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(path, readTestJson(t, "gateway_model.json"), ""); err != nil {
		t.Fatal(err)
	}
	model, err := LoadModel(camp, path)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if objStrOf(model, "protocol_id") != "gw" {
		t.Errorf("model.protocol_id = %q, want \"gw\"", objStrOf(model, "protocol_id"))
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := objAt(st, "artifacts").A
	if len(arts) != 1 {
		t.Fatalf("artifact rows = %d, want 1", len(arts))
	}
	wantArt := objAt(golden, "artifact")
	if dump(rowOf(arts[0], "kind", "snapshot_id", "note")) != dump(wantArt) {
		t.Errorf("artifact row\n got: %s\nwant: %s",
			dump(rowOf(arts[0], "kind", "snapshot_id", "note")), dump(wantArt))
	}
	sha, err := validation.Sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	if objStrOf(arts[0], "sha256") != sha {
		t.Errorf("artifact sha256 = %q, want %q", objStrOf(arts[0], "sha256"), sha)
	}
	if !strings.HasSuffix(objStrOf(arts[0], "path"),
		objStrOf(golden, "artifact_path_suffix")) {
		t.Errorf("artifact path = %q, want suffix %q", objStrOf(arts[0], "path"),
			objStrOf(golden, "artifact_path_suffix"))
	}
	evs, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	loaded := eventsOfType(evs, "protocol_model.loaded")
	if len(loaded) != 1 {
		t.Fatalf("protocol_model.loaded events = %d, want 1", len(loaded))
	}
	wantEv := objAt(golden, "load_event")
	gotEv := validation.VObj(
		kv("data", objAt(loaded[0], "data")),
		kv("ref", objAt(loaded[0], "ref")),
		kv("type", objAt(loaded[0], "type")),
	)
	if dump(gotEv) != dump(wantEv) {
		t.Errorf("load event\n got: %s\nwant: %s", dump(gotEv), dump(wantEv))
	}
	if len(evs) != 3 { // campaign.created, artifact.registered, loaded
		t.Errorf("event count = %d, want 3", len(evs))
	}
}

// rowOf projects a dict onto the listed keys, in the listed order.
func rowOf(v validation.Value, keys ...string) validation.Value {
	out := make([]validation.KV, 0, len(keys))
	for _, k := range keys {
		out = append(out, kv(k, objAt(v, k)))
	}
	return validation.VObj(out...)
}

// eventsOfType filters the campaign event log by type.
func eventsOfType(evs []validation.Value, typ string) []validation.Value {
	var out []validation.Value
	for _, e := range evs {
		if objStrOf(e, "type") == typ {
			out = append(out, e)
		}
	}
	return out
}

// TestLoadModelSecondLoadRefreshes pins the continuation contract: a second
// load REFRESHES the registered row (no ghost artifact, no second row) and
// logs one more protocol_model.loaded event.
func TestLoadModelSecondLoadRefreshes(t *testing.T) {
	camp := testCamp(t)
	golden := readTestJson(t, "golden_campaign.json")
	path := filepath.Join(camp.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(path, readTestJson(t, "gateway_model.json"), ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := LoadModel(camp, path); err != nil {
			t.Fatalf("LoadModel #%d: %v", i+1, err)
		}
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := objAt(st, "artifacts").A
	if len(arts) != 1 {
		t.Fatalf("artifact rows = %d, want 1 (no ghost row)", len(arts))
	}
	if dump(objAt(arts[0], "refresh_count")) != dump(objAt(golden, "refresh_count")) {
		t.Errorf("refresh_count = %s, want %s", dump(objAt(arts[0], "refresh_count")),
			dump(objAt(golden, "refresh_count")))
	}
	if objStrOf(arts[0], "refresh_reason") != objStrOf(golden, "refresh_reason") {
		t.Errorf("refresh_reason = %q, want %q", objStrOf(arts[0], "refresh_reason"),
			objStrOf(golden, "refresh_reason"))
	}
	evs, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(eventsOfType(evs, "protocol_model.loaded")); got != 2 {
		t.Errorf("protocol_model.loaded events = %d, want 2", got)
	}
	if got := eventTypes(evs); dump(got) != dump(objAt(golden, "event_types_after_two_loads")) {
		t.Errorf("event types\n got: %s\nwant: %s", dump(got),
			dump(objAt(golden, "event_types_after_two_loads")))
	}
}

// eventTypes projects the event log onto its type strings.
func eventTypes(evs []validation.Value) validation.Value {
	out := make([]validation.Value, 0, len(evs))
	for _, e := range evs {
		out = append(out, objAt(e, "type"))
	}
	return validation.VArr(out...)
}

// TestSaveModelDefaultPathAndRefresh is save_model: no path means
// <artifacts_dir>/protocol_model.json. The FIRST save registers the artifact;
// the second REFRESHES it with the "saved" reason (one refreshed event), and
// the registry keeps exactly one row.
func TestSaveModelDefaultPathAndRefresh(t *testing.T) {
	camp := testCamp(t)
	golden := readTestJson(t, "golden_campaign.json")
	model := readTestJson(t, "gateway_model.json")
	path, err := SaveModel(camp, model, "")
	if err != nil {
		t.Fatalf("SaveModel: %v", err)
	}
	if filepath.Dir(path) != camp.ArtifactsDir ||
		filepath.Base(path) != objStrOf(golden, "save_path_suffix") {
		t.Errorf("SaveModel path = %q, want %q/%s", path, camp.ArtifactsDir,
			objStrOf(golden, "save_path_suffix"))
	}
	if _, err := validation.ReadJson(path); err != nil {
		t.Fatalf("saved model unreadable: %v", err)
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := objAt(st, "artifacts").A
	if len(arts) != 1 {
		t.Fatalf("artifact rows = %d, want 1", len(arts))
	}
	// first save: registered, no refresh reason yet
	if got := objAt(arts[0], "refresh_reason"); got.Kind != validation.Null {
		t.Errorf("refresh_reason after first save = %s, want null", dump(got))
	}
	if objStrOf(arts[0], "kind") != objStrOf(golden, "fresh_save_kind") ||
		objStrOf(arts[0], "note") != objStrOf(golden, "fresh_save_note") {
		t.Errorf("first save row = %s", dump(arts[0]))
	}
	// second save: refreshed in place
	if _, err := SaveModel(camp, model, ""); err != nil {
		t.Fatalf("SaveModel #2: %v", err)
	}
	st, err = camp.State()
	if err != nil {
		t.Fatal(err)
	}
	arts = objAt(st, "artifacts").A
	if len(arts) != 1 {
		t.Fatalf("artifact rows after second save = %d, want 1", len(arts))
	}
	if objStrOf(arts[0], "refresh_reason") != objStrOf(golden, "fresh_second_save_reason") {
		t.Errorf("refresh_reason = %q, want %q", objStrOf(arts[0], "refresh_reason"),
			objStrOf(golden, "fresh_second_save_reason"))
	}
	if dump(objAt(arts[0], "refresh_count")) !=
		dump(objAt(golden, "fresh_second_save_refresh_count")) {
		t.Errorf("refresh_count = %s, want %s", dump(objAt(arts[0], "refresh_count")),
			dump(objAt(golden, "fresh_second_save_refresh_count")))
	}
	evs, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != int(objAt(golden, "fresh_second_save_events").I) {
		t.Errorf("event count = %d, want %d", len(evs),
			objAt(golden, "fresh_second_save_events").I)
	}
	if got := eventTypes(evs); dump(got) != dump(validation.VArr(
		validation.VStr("campaign.created"),
		validation.VStr("artifact.registered"),
		validation.VStr("artifact.refreshed"))) {
		t.Errorf("event types = %s", dump(got))
	}
}

// TestSaveModelExplicitPathRegistersSeparateRow pins the path argument: a
// different path is a different artifact.
func TestSaveModelExplicitPathRegistersSeparateRow(t *testing.T) {
	camp := testCamp(t)
	model := readTestJson(t, "gateway_model.json")
	other := filepath.Join(camp.ArtifactsDir, "refined", "protocol_model.json")
	path, err := SaveModel(camp, model, other)
	if err != nil {
		t.Fatalf("SaveModel: %v", err)
	}
	if path != other {
		t.Errorf("SaveModel path = %q, want %q", path, other)
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(st, "artifacts").A); got != 1 {
		t.Errorf("artifact rows = %d, want 1", got)
	}
	if _, err := SaveModel(camp, model, ""); err != nil {
		t.Fatalf("SaveModel default: %v", err)
	}
	st, err = camp.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(st, "artifacts").A); got != 2 {
		t.Errorf("artifact rows after second path = %d, want 2", got)
	}
}

// TestSaveModelValidatesBeforeWriting is save_model's validate-first order:
// a malformed model must not reach the filesystem or the artifact registry,
// and the error text is the same one load_model reports.
func TestSaveModelValidatesBeforeWriting(t *testing.T) {
	golden := readTestJson(t, "golden_campaign.json")
	camp := testCamp(t)
	body := `{"protocol_id":"gw","name":"Gateways","contracts":[],"actors":[],` +
		`"assets":[{"id":"x","kind":"nonsense"}],"relations":[]}`
	bad, err := validation.ParseOrdered([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	_, err = SaveModel(camp, bad, "")
	if err == nil {
		t.Fatal("SaveModel accepted an invalid model")
	}
	if err.Error() != objStrOf(golden, "invalid_model_badkind_error") {
		t.Errorf("error\n got: %s\nwant: %s", err.Error(),
			objStrOf(golden, "invalid_model_badkind_error"))
	}
	if _, statErr := os.Stat(filepath.Join(camp.ArtifactsDir, "protocol_model.json")); statErr == nil {
		t.Error("SaveModel wrote the file despite the schema error")
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(st, "artifacts").A); got != 0 {
		t.Errorf("artifact rows = %d, want 0", got)
	}
}

// TestLoadModelSchemaErrors pins the exact validate() text on three malformed
// models (recorded from the Python twin).
func TestLoadModelSchemaErrors(t *testing.T) {
	golden := readTestJson(t, "golden_campaign.json")
	cases := []struct {
		key  string
		body string
	}{
		{"invalid_model_error", "{}"},
		{"invalid_model_array_error", "[]"},
		{"invalid_model_badkind_error",
			`{"protocol_id":"gw","name":"Gateways","contracts":[],"actors":[],` +
				`"assets":[{"id":"x","kind":"nonsense"}],"relations":[]}`},
	}
	for _, tc := range cases {
		camp := testCamp(t)
		path := filepath.Join(camp.ArtifactsDir, "protocol_model.json")
		if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadModel(camp, path)
		if err == nil {
			t.Errorf("%s: LoadModel succeeded, want a schema error", tc.key)
			continue
		}
		if err.Error() != objStrOf(golden, tc.key) {
			t.Errorf("%s error\n got: %s\nwant: %s", tc.key, err.Error(),
				objStrOf(golden, tc.key))
		}
		st, err := camp.State()
		if err != nil {
			t.Fatal(err)
		}
		if got := len(objAt(st, "artifacts").A); got != 0 {
			t.Errorf("%s: registered %d artifacts despite the schema error", tc.key, got)
		}
	}
}

// TestGatewayModelArtifactRoundTrip ports the protocol slice of
// tests/test_lens_exhaustive.py: _gateway_model_artifact writes the model
// through validation.write_json with schema_name="protocol_model", and the
// loaded model is the one protocol_graph consumes.
func TestGatewayModelArtifactRoundTrip(t *testing.T) {
	camp := testCamp(t)
	model := readTestJson(t, "gateway_model.json")
	path := filepath.Join(camp.ArtifactsDir, "protocol_model.json")
	if err := validation.WriteJson(path, model, "protocol_model"); err != nil {
		t.Fatalf("write_json(protocol_model): %v", err)
	}
	loaded, err := LoadModel(camp, path)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	if dump(loaded) != dump(model) {
		t.Errorf("round trip\n got: %s\nwant: %s", dump(loaded), dump(model))
	}
	if len(StateMachines(loaded)) != 1 {
		t.Errorf("state machines = %s", dump(validation.VArr(StateMachines(loaded)...)))
	}
	if got := len(objAt(loaded, "contracts").A); got != 2 {
		t.Errorf("contracts = %d, want 2", got)
	}
	// the fixture exists in the Python test because the lens re-open pass
	// reads withdraw-family tokens out of the STORED model
	sm := StateMachines(loaded)[0]
	trigger := objStrOf(objAt(sm, "transitions").A[0], "trigger")
	if trigger != "withdraw" {
		t.Errorf("transition trigger = %q, want withdraw", trigger)
	}
	entry := objAt(objAt(loaded, "contracts").A[1], "entry_points")
	if !containsValue(entry.A, validation.VStr("withdraw")) {
		t.Errorf("second contract entry_points = %s, want withdraw", dump(entry))
	}
}

// PORT-NOTE: the remaining tests in tests/test_lens_exhaustive.py exercise
// webv2.planner / report / briefing (lens_families, seed_lenses,
// divergence_status, families_for_finding, save_plan, report.generate,
// build_brief) — none of those modules is ported yet, so they cannot be
// ported here. Their protocol-model INPUT is the fixture above, which is
// pinned byte-for-byte.
