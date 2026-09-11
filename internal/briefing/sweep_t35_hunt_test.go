package briefing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/archetypes"
	"websec/internal/forkdiff"
	"websec/internal/histmining"
	"websec/internal/roles"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// t35HuntCampaign is the role-isolation fixture: a pinned source tree with a
// huntable contract.
func t35HuntCampaign(t *testing.T, body string) (*state.Campaign, string) {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Ctx Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "V.sol"), []byte(body),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	// The structural_index seam (production wires it in cmd_dedup; here the
	// fixture installs the real structidx implementation directly).
	histmining.SetIndexAPI(histmining.IndexAPI{
		EnsureFreshIndex: structidx.EnsureFreshIndex,
		SinkFunctions:    structidx.SinkFunctions,
	})
	t.Cleanup(func() { histmining.SetIndexAPI(histmining.IndexAPI{}) })
	return c, src
}

// t35HuntArtifacts is _make_hunt_artifacts: every analysis artifact against
// the active pin.
func t35HuntArtifacts(t *testing.T, c *state.Campaign, src string) {
	t.Helper()
	if _, err := structidx.ValueFlowReport(c, src); err != nil {
		t.Fatal(err)
	}
	if _, err := archetypes.Prescreen(c, src, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := forkdiff.ForkdiffReport(c, src); err != nil {
		t.Fatal(err)
	}
	if _, err := histmining.RecencyScores(c, src, src); err != nil {
		t.Fatal(err)
	}
}

const t35HuntContract = "contract V { uint256 public totalAssets; " +
	"function sweep(address to) external { totalAssets = 0; } }\n"

// Port of tests/test_role_isolation.py::test_brief_critical_hunt_section.
func TestBriefCriticalHuntSection(t *testing.T) {
	c, src := t35HuntCampaign(t, t35HuntContract)
	t35HuntArtifacts(t, c, src)
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := objAt(b, "critical_hunt")
	matched := objAt(objAt(ch, "prescreen"), "matched")
	found := false
	for _, m := range matched.A {
		if m.S == "unguarded-asset-transfer" {
			found = true
		}
	}
	if !found {
		t.Errorf("prescreen.matched = %v, want unguarded-asset-transfer",
			matched)
	}
	if !pyTruthyInt64Only(objAt(objAt(ch, "fork_diff"), "summary")) {
		t.Error("fork_diff.summary is empty")
	}
	if got := objAt(objAt(ch, "invariant_verification"), "total"); got.I != 0 {
		t.Errorf("invariant_verification.total = %v, want 0", got)
	}
	if got := objAt(ch, "stale_artifacts"); got.Kind != validation.Arr ||
		len(got.A) != 0 {
		t.Errorf("stale_artifacts = %v, want []", got)
	}
}

// t35StaleCampaign is _stale_campaign: artifacts predate a re-pin on a
// changed tree.
func t35StaleCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c, src := t35HuntCampaign(t, "contract V { uint256 public totalAssets; }\n")
	t35HuntArtifacts(t, c, src)
	if err := os.WriteFile(filepath.Join(src, "V.sol"), []byte(
		"contract V { uint256 public totalAssets; function x() external {} }\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c, src
}

// Port of tests/test_role_isolation.py::test_brief_omits_stale_hunt_blocks.
func TestBriefOmitsStaleHuntBlocks(t *testing.T) {
	c, _ := t35StaleCampaign(t)
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := objAt(b, "critical_hunt")
	if objAt(ch, "prescreen").Kind != validation.Null {
		t.Errorf("prescreen = %v, want null", objAt(ch, "prescreen"))
	}
	if objAt(ch, "fork_diff").Kind != validation.Null {
		t.Errorf("fork_diff = %v, want null", objAt(ch, "fork_diff"))
	}
	if got := objAt(ch, "recency_top"); len(got.A) != 0 {
		t.Errorf("recency_top = %v, want []", got)
	}
	amps := objAt(ch, "amplifiers")
	if got := objAt(amps, "boosted_classes"); len(got.A) != 0 {
		t.Errorf("boosted_classes = %v, want []", got)
	}
	if got := objAt(amps, "detected"); got.Kind != validation.Obj ||
		len(got.O) != 0 {
		t.Errorf("amplifiers.detected = %v, want {}", got)
	}
	names := map[string]bool{}
	for _, s := range objAt(ch, "stale_artifacts").A {
		names[objStr(s, "artifact")] = true
		if !pyTruthyInt64Only(objAt(s, "re_run")) {
			t.Errorf("stale %s carries no re-run command", objStr(s, "artifact"))
		}
	}
	for _, want := range []string{"structural_index.json", "value_flow.json",
		"archetype_prescreen.json", "fork_diff.json", "recency.json"} {
		if !names[want] {
			t.Errorf("stale_artifacts omits %s: %v", want, names)
		}
	}
	if got := objAt(ch, "problems"); len(got.A) != 0 {
		t.Errorf("problems = %v, want [] (stale is flagged, not corruption)",
			got)
	}
	// parity: the bundles omit the same blocks the brief omits.
	bundle, err := roles.BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"value_flow", "archetype_prescreen",
		"fork_diff", "recency"} {
		if objAt(bundle, key).Kind != validation.Null {
			t.Errorf("bundle %s = %v, want null", key, objAt(bundle, key))
		}
	}
}

// Port of tests/test_role_isolation.py::test_prescribed_reruns_clear_stale.
func TestPrescribedRerunsClearStale(t *testing.T) {
	c, src := t35StaleCampaign(t)
	stale, err := roles.StaleArtifacts(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) == 0 {
		t.Fatal("fixture must start stale")
	}
	for _, entry := range stale {
		switch objStr(entry, "artifact") {
		case "structural_index.json":
			idx, err := structidx.IndexSnapshot(c, src, structidx.DefaultBackend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := structidx.SaveIndex(c, idx); err != nil {
				t.Fatal(err)
			}
		case "value_flow.json":
			if _, err := structidx.ValueFlowReport(c, src); err != nil {
				t.Fatal(err)
			}
		case "archetype_prescreen.json":
			if _, err := archetypes.Prescreen(c, src, nil); err != nil {
				t.Fatal(err)
			}
		case "fork_diff.json":
			if _, err := forkdiff.ForkdiffReport(c, src); err != nil {
				t.Fatal(err)
			}
		case "recency.json":
			if _, err := histmining.RecencyScores(c, src, src); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("no re-run recipe for %s", objStr(entry, "artifact"))
		}
	}
	stale, err = roles.StaleArtifacts(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 0 {
		t.Fatalf("stale after the prescribed reruns = %v", stale)
	}
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := objAt(b, "critical_hunt")
	if objAt(ch, "prescreen").Kind != validation.Obj {
		t.Error("prescreen must be present after the reruns")
	}
	if objAt(ch, "fork_diff").Kind != validation.Obj {
		t.Error("fork_diff must be present after the reruns")
	}
	if got := objAt(ch, "recency_top"); len(got.A) == 0 {
		t.Error("recency_top must list hot files after the reruns")
	}
	if got := objAt(ch, "amplifiers"); got.Kind != validation.Obj ||
		len(got.O) != 2 {
		t.Errorf("amplifiers shape = %v, want detected+boosted_classes", got)
	}
}

// Port of tests/test_role_isolation.py::test_brief_degrades_on_malformed_recency.
func TestBriefDegradesOnMalformedRecency(t *testing.T) {
	c, src := t35HuntCampaign(t, "contract V { uint256 public totalAssets; }\n")
	t35HuntArtifacts(t, c, src)
	writeArtifact(t, c, "recency.json", map[string]any{
		"snapshot_id": t35ActiveSnapshot(t, c),
		"hot_files": []any{
			map[string]any{"nopath": 1}, "junk",
			map[string]any{"path": "src/V.sol"},
		},
	})
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := objAt(b, "critical_hunt")
	top := objAt(ch, "recency_top")
	if len(top.A) != 2 {
		t.Fatalf("recency_top = %v, want 2 entries", top)
	}
	if got := objAt(top.A[0], "path"); got.S != "?" {
		t.Errorf("default path = %v, want ?", got)
	}
	if got := objAt(top.A[0], "score"); got.Kind != validation.Flt ||
		got.F != 0.0 {
		t.Errorf("default score = %v, want 0.0", got)
	}
	if got := objAt(top.A[0], "days_ago"); got.Kind != validation.Null {
		t.Errorf("default days_ago = %v, want null", got)
	}
	if got := objStr(top.A[1], "path"); got != "src/V.sol" {
		t.Errorf("second path = %q", got)
	}
	if !anyBriefProblem(ch, "recency.json") {
		t.Errorf("problems = %v, want a recency.json note",
			objAt(ch, "problems"))
	}
	writeArtifact(t, c, "recency.json", map[string]any{
		"snapshot_id": t35ActiveSnapshot(t, c),
		"hot_files":   map[string]any{"path": "src/V.sol"},
	})
	b2, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch2 := objAt(b2, "critical_hunt")
	if got := objAt(ch2, "recency_top"); len(got.A) != 0 {
		t.Errorf("recency_top = %v, want [] for a non-list hot_files", got)
	}
	if !anyBriefProblem(ch2, "recency.json") {
		t.Errorf("problems = %v, want a recency.json note",
			objAt(ch2, "problems"))
	}
}

// Port of tests/test_role_isolation.py::test_brief_degrades_on_malformed_structural_index.
func TestBriefDegradesOnMalformedStructuralIndex(t *testing.T) {
	c, src := t35HuntCampaign(t, "contract V { uint256 public totalAssets; }\n")
	t35HuntArtifacts(t, c, src)
	writeArtifact(t, c, "structural_index.json", []any{1, 2, 3})
	b, err := BuildBrief(c, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := objAt(b, "critical_hunt")
	amps := objAt(ch, "amplifiers")
	if objAt(amps, "detected").Kind != validation.Obj ||
		len(objAt(amps, "detected").O) != 0 {
		t.Errorf("detected = %v, want {}", objAt(amps, "detected"))
	}
	if got := objAt(amps, "boosted_classes"); len(got.A) != 0 {
		t.Errorf("boosted_classes = %v, want []", got)
	}
	if !anyBriefProblem(ch, "structural_index.json") {
		t.Errorf("problems = %v, want a structural_index.json note",
			objAt(ch, "problems"))
	}
}

// writeArtifact marshals v into c.ArtifactsDir/name.
func writeArtifact(t *testing.T, c *state.Campaign, name string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir, name), raw,
		0o644); err != nil {
		t.Fatal(err)
	}
}

// anyBriefProblem reports whether the critical_hunt problems mention sub.
func anyBriefProblem(ch validation.Value, sub string) bool {
	for _, p := range objAt(ch, "problems").A {
		if p.Kind == validation.Str &&
			len(p.S) >= len(sub) && containsSub(p.S, sub) {
			return true
		}
	}
	return false
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// t35ActiveSnapshot is active_snapshot_id_or_none.
func t35ActiveSnapshot(t *testing.T, c *state.Campaign) string {
	t.Helper()
	id, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if id == nil {
		t.Fatal("campaign has no active snapshot")
	}
	return *id
}
