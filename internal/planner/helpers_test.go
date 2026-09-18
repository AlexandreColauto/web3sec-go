package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- oracle loading ------------------------------------------------------

var (
	oracleOnce sync.Once
	oracleRoot validation.Value
)

// oracles is testdata/oracles.json, the Python-side contract recorded by
// gen-vectors.py [untracked].
func oracles(t *testing.T) validation.Value {
	t.Helper()
	oracleOnce.Do(func() {
		v, err := validation.ReadJson("testdata/oracles.json")
		if err != nil {
			t.Fatalf("read oracles: %v", err)
		}
		oracleRoot = v
	})
	return oracleRoot
}

// at navigates nested keys.
func at(t *testing.T, v validation.Value, path ...string) validation.Value {
	t.Helper()
	for _, k := range path {
		got, ok := fieldAt(v, k)
		if !ok {
			t.Fatalf("oracle path %v: missing %q", path, k)
		}
		v = got
	}
	return v
}

// atIdx navigates nested keys then an array index.
func atIdx(t *testing.T, v validation.Value, i int, path ...string) validation.Value {
	t.Helper()
	got := at(t, v, path...)
	if got.Kind != validation.Arr || i >= len(got.A) {
		t.Fatalf("oracle path %v[%d]: not an indexable array", path, i)
	}
	return got.A[i]
}

// jsonValue parses an oracle JSON text (test fixture strings).
func jsonValue(t *testing.T, s string) validation.Value {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "v.json")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	v, err := validation.ReadJson(p)
	if err != nil {
		t.Fatalf("parse fixture %q: %v", s, err)
	}
	return v
}

// deepCopy is a structural copy, so a test can mutate a plan in place the way
// Python's mark_answered does without leaking state into the next case.
func deepCopy(t *testing.T, v validation.Value) validation.Value {
	t.Helper()
	return jsonValue(t, validation.CanonCompact(v))
}

// sameJSON compares two JSON-shaped values in canonical form.
func sameJSON(a, b validation.Value) bool {
	return validation.CanonCompact(a) == validation.CanonCompact(b)
}

// requireJSON fails unless got is byte-identical to want.
func requireJSON(t *testing.T, label string, got, want validation.Value) {
	t.Helper()
	if !sameJSON(got, want) {
		t.Fatalf("%s mismatch\n got: %s\nwant: %s", label,
			validation.CanonCompact(got), validation.CanonCompact(want))
	}
}

// requireErr fails unless err is non-nil and renders exactly like Python's
// str(exception).
func requireErr(t *testing.T, label string, err error, want validation.Value) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error %q, got nil",
			label, validation.CanonCompact(want))
	}
	if got := err.Error(); got != validation.ObjStr(want, "msg") {
		t.Fatalf("%s: error mismatch\n got: %q\nwant: %q", label, got,
			validation.ObjStr(want, "msg"))
	}
}

// ---- campaign fixture ----------------------------------------------------

// newCampaign is a fresh campaign under a temp root.
func newCampaign(t *testing.T, tag string) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "T9 "+tag, state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// writeModel installs protocol_model.json so _model_or_empty sees a model.
func writeModel(t *testing.T, c *state.Campaign, model validation.Value) {
	t.Helper()
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"), model, ""); err != nil {
		t.Fatalf("write model: %v", err)
	}
}

// reconOnRecord puts both FIX-8 recon stamps on record for one campaign.
// The planner's test binary cannot import archetypes/structidx (structidx
// wires the planner — an import cycle in test), so the prescreen artifact
// is seeded as a fixture file; the sinks stamp goes through the real
// state.StampRecon write path. The end-to-end real-verb version of this
// setup lives in internal/cli (cmd_recon_gate_test.go), which runs
// `webv2 prescreen` + `webv2 sinks` for truth.
func reconOnRecord(t *testing.T, c *state.Campaign) {
	t.Helper()
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"archetype_prescreen.json"), jsonValue(t,
		`{"snapshot_id":"S-0123456789abcdef"}`), ""); err != nil {
		t.Fatalf("seed prescreen artifact: %v", err)
	}
	if err := c.StampRecon("sinks", "src"); err != nil {
		t.Fatalf("stamp sinks: %v", err)
	}
}

// ---- the fake probes module ---------------------------------------------

// probeRegistry is the subset of probes.PROBES / registered_axes() the
// planner reads, loaded from the recorded registry.
type probeRegistry struct {
	axes   map[string]AxisMeta
	probes map[string]ProbeSpec
}

var (
	regOnce sync.Once
	regVal  probeRegistry
)

func registry(t *testing.T) probeRegistry {
	t.Helper()
	regOnce.Do(func() {
		v, err := validation.ReadJson("testdata/probe_registry.json")
		if err != nil {
			t.Fatalf("read probe registry: %v", err)
		}
		regVal = probeRegistry{axes: map[string]AxisMeta{},
			probes: map[string]ProbeSpec{}}
		for _, k := range sortedMapKeys(listOfMap(v, "axes")) {
			a := validation.ObjAt(validation.ObjAt(v, "axes"), k)
			regVal.axes[k] = AxisMeta{Axis: validation.ObjStr(a, "axis"),
				Probe: validation.ObjStr(a, "probe"), Lens: validation.ObjStr(a, "lens")}
		}
		for _, pid := range sortedMapKeys(listOfMap(v, "probes")) {
			p := validation.ObjAt(validation.ObjAt(v, "probes"), pid)
			anchors := []string{}
			for _, a := range listOf(p, "anchors") {
				anchors = append(anchors, validation.PyStr(a))
			}
			spec := ProbeSpec{Axis: validation.ObjStr(p, "axis"), Lens: validation.ObjStr(p, "lens")}
			if hasKey(p, "anchors") {
				spec.Anchors = &anchors
			}
			regVal.probes[pid] = spec
		}
	})
	return regVal
}

// listOfMap is v.get(key) as an object (for key enumeration).
func listOfMap(v validation.Value, key string) map[string]validation.Value {
	out := map[string]validation.Value{}
	got := validation.ObjAt(v, key)
	if got.Kind != validation.Obj {
		return out
	}
	for _, pair := range got.O {
		out[pair.K] = pair.V
	}
	return out
}

// probeEnv is the per-test probes state the planner reads through the seam.
type probeEnv struct {
	surface *validation.Value
	sha     *string
	blanks  map[string]validation.Value
	index   *validation.Value
}

// withProbes installs a faithful fake probes module for one test.
func withProbes(t *testing.T, env probeEnv) {
	t.Helper()
	reg := registry(t)
	SetProbes(ProbesAPI{
		RegisteredAxes:     func() map[string]AxisMeta { return reg.axes },
		Probes:             reg.probes,
		AnchorAllowed:      anchorAllowed,
		AxisSurfaceBlocker: axisSurfaceBlocker,
		RowShapeSha:        rowShapeSha,
		CampaignSurface: func(*state.Campaign) (*validation.Value, error) {
			return env.surface, nil
		},
		CampaignBlanks: func(*state.Campaign) (map[string]validation.Value,
			error) {
			return env.blanks, nil
		},
		CampaignIndexSha: func(*state.Campaign) *string { return env.sha },
		CampaignIndex: func(*state.Campaign) (*validation.Value, error) {
			return env.index, nil
		},
		RowAnchorValue: rowAnchorValue,
		AnchorRef:      anchorRef,
	})
	t.Cleanup(func() { SetProbes(ProbesAPI{}) })
}

// ---- the fake probes module: pure functions (ported 1:1) ----------------

var shapeAnchorFields = []string{"consumer", "asserter", "guard", "base",
	"actor", "invariant", "cursor", "sentinel", "safety", "rounded", "plain",
	"accumulator", "companion"}

var shapeClassFields = []string{"own_class", "assert_class"}

// rowShapeSha is probes.row_shape_sha: sha256[:16] of the canonical JSON of
// the row's whole coordinate set.
func rowShapeSha(row validation.Value) string {
	slots := []validation.Value{}
	for _, f := range shapeAnchorFields {
		slots = append(slots, validation.VArr(validation.VStr(f),
			validation.ObjAt(row, f), validation.ObjAt(row, f+"_line")))
	}
	for _, f := range shapeClassFields {
		slots = append(slots, validation.VArr(validation.VStr(f), validation.ObjAt(row, f)))
	}
	pairs := []validation.Value{}
	for _, s := range listOf(row, "siblings") {
		pairs = append(pairs, validation.VArr(validation.ObjAt(s, "contract"),
			validation.ObjAt(s, "line")))
	}
	sortPairValues(pairs)
	slots = append(slots, validation.VArr(pairs...))
	stranded := []string{}
	for _, e := range listOf(row, "stranded_entry") {
		stranded = append(stranded, validation.PyStr(e))
	}
	sort.Strings(stranded)
	slots = append(slots, validation.StrArr(stranded))
	sum := sha256.Sum256([]byte(validation.CanonCompact(
		validation.VArr(slots...))))
	return hex.EncodeToString(sum[:])[:16]
}

// sortPairValues is sorted(pairs, key=lambda p: (str(p[0]), str(p[1]))).
func sortPairValues(pairs []validation.Value) {
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0; j-- {
			a, b := pairs[j-1], pairs[j]
			ka, kb := validation.PyStr(a.A[0])+"\x00"+validation.PyStr(a.A[1]),
				validation.PyStr(b.A[0])+"\x00"+validation.PyStr(b.A[1])
			if ka <= kb {
				break
			}
			pairs[j-1], pairs[j] = pairs[j], pairs[j-1]
		}
	}
}

// axisSurfaceBlocker is probes.axis_surface_blocker: "" = no blocker.
func axisSurfaceBlocker(axis validation.Value, blank *validation.Value) string {
	status := validation.ObjStr(axis, "status")
	switch status {
	case "no-sites":
		return ""
	case "blind":
		return blindBlocker(axis, blank)
	case "under-filled":
		return "quota under-filled: " + validation.ObjStr(axis, "probe") + " produced " +
			validation.PyStr(validation.ObjAt(axis, "rows")) + " rows, emitted " +
			validation.PyStr(validation.ObjAt(axis, "emitted")) + " — raise --per-axis or " +
			"disposition the tail"
	}
	return ""
}

// blindBlocker is the blind-status arm of axis_surface_blocker.
func blindBlocker(axis validation.Value, blank *validation.Value) string {
	if blank == nil || !pyTruthyBigNonEmpty(*blank) {
		return validation.ObjStr(axis, "probe") + " saw " + validation.PyStr(validation.ObjAt(axis, "sites")) +
			" sites and rejected every one of them (" +
			itoa(len(listOf(axis, "blind"))) + " blind keys published) — " +
			"close it with `webv2 probes blank --axis " + validation.ObjStr(axis, "lens") +
			" --anchor-blind <key> --reason R --actor A`"
	}
	keys := map[string]struct{}{}
	for _, b := range listOf(axis, "blind") {
		keys[validation.PyStr(validation.ObjAt(b, "key"))] = struct{}{}
	}
	if _, ok := keys[validation.PyStr(validation.ObjAt(*blank, "anchor_blind"))]; !ok {
		return "blank attestation cites " +
			validation.PyRepr(validation.ObjAt(*blank, "anchor_blind")) +
			", which is not in the probe's blind[] keys: " +
			validation.PyRepr(validation.StrArr(validation.SortedKeys(keys)))
	}
	if !pyTruthyBigNonEmpty(validation.ObjAt(*blank, "reason")) || !pyTruthyBigNonEmpty(validation.ObjAt(*blank, "actor")) {
		return "blank attestation needs a written reason and an actor"
	}
	return ""
}

// anchorFields is probes.ANCHOR_FIELDS for the registered probes.
var anchorFields = map[string]map[string]string{
	"assertion-strength": {"consumer": "consumer", "asserter": "asserter",
		"concept": "concept_keys"},
	"custody-primitive": {"consumer": "consumer", "base": "base",
		"custody": "custody", "sibling": "siblings"},
	"trust-assumption": {"actor": "actor", "invariant": "invariant"},
	"sequential-cursor": {"guard": "guard", "cursor": "cursor",
		"stranded_entry": "stranded_entry"},
	"short-circuitable-guard": {"guard": "guard", "sentinel": "sentinel",
		"safety": "safety"},
	"accumulator-basis-skew": {"rounded": "rounded_line", "plain": "plain_line",
		"accumulator": "accumulator", "companion": "companion"},
}

// anchorSite is probes._ANCHOR_SITE (field -> (contract field, line field)).
var anchorSite = map[string][2]string{
	"consumer": {"contract", "consumer_line"},
	"asserter": {"contract", "asserter_line"},
	"guard":    {"contract", "guard_line"},
	"base":     {"base", "base_line"},
	"cursor":   {"contract", "consumer_line"},
	"rounded":  {"contract", "rounded_line"},
	"plain":    {"contract", "plain_line"},
}

// anchorAllowed is probes.anchor_allowed.
func anchorAllowed(probeID, anchor string) bool {
	return slices.Contains(probeAnchors(probeID), anchor)
}

// rowAnchorValue is probes.row_anchor_value.
func rowAnchorValue(row validation.Value,
	anchor string) (validation.Value, error) {
	pid := validation.ObjStr(row, "probe")
	if !anchorAllowed(pid, anchor) {
		return validation.VNull(), errValue("anchor " +
			validation.PyReprStr(anchor) + " is not produced by probe " +
			validation.PyReprStr(pid) + "; allowed: " + pyAnchorsRepr(pid))
	}
	field := anchorFields[pid][anchor]
	if !hasKey(row, field) {
		return validation.VNull(), errValue("row of " +
			validation.PyReprStr(pid) + " has no field " +
			validation.PyReprStr(field))
	}
	return validation.ObjAt(row, field), nil
}

// anchorRef is probes.anchor_ref.
func anchorRef(row validation.Value, anchor string,
	index *validation.Value) (string, error) {
	value, err := rowAnchorValue(row, anchor)
	if err != nil {
		return "", err
	}
	if anchor == "sibling" {
		return siblingRef(row, index, value), nil
	}
	site, ok := anchorSite[anchor]
	if !ok {
		return renderAnchorValue(value), nil
	}
	line := validation.ObjAt(row, site[1])
	if line.Kind == validation.Int && line.I > 0 {
		contract := validation.ObjStr(row, site[0])
		token := contractPaths(index)[contract]
		if token == "" {
			token = contract
			if token == "" {
				token = "?"
			}
		}
		return token + "#L" + itoa(int(line.I)), nil
	}
	return renderAnchorValue(value), nil
}

// siblingRef is the anchor == "sibling" arm of anchor_ref.
func siblingRef(row validation.Value, index *validation.Value,
	value validation.Value) string {
	paths := contractPaths(index)
	pairs := []string{}
	for _, s := range listOf(row, "siblings") {
		line := validation.ObjAt(s, "line")
		if line.Kind != validation.Int || line.I <= 0 {
			continue
		}
		contract := validation.ObjStr(s, "contract")
		token := paths[contract]
		if token == "" {
			token = contract
			if token == "" {
				token = "?"
			}
		}
		pair := token + "#L" + itoa(int(line.I))
		if !slices.Contains(pairs, pair) {
			pairs = append(pairs, pair)
		}
	}
	if len(pairs) == 0 {
		return renderAnchorValue(value)
	}
	return strings.Join(pairs, ", ")
}

// contractPaths is probes._contract_paths: first definition wins, nodes sorted
// by str(id).
func contractPaths(index *validation.Value) map[string]string {
	out := map[string]string{}
	if index == nil {
		return out
	}
	nodes := listOf(*index, "nodes")
	sorted := make([]validation.Value, len(nodes))
	copy(sorted, nodes)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && validation.PyStr(validation.ObjAt(sorted[j-1], "id")) >
			validation.PyStr(validation.ObjAt(sorted[j], "id")); j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	for _, n := range sorted {
		kind := validation.ObjStr(n, "kind")
		name := validation.ObjStr(n, "name")
		if name == "" || (kind != "contract" && kind != "interface" &&
			kind != "library") {
			continue
		}
		if _, seen := out[name]; seen {
			continue
		}
		if path := validation.ObjStr(n, "path"); path != "" {
			out[name] = path
		} else {
			out[name] = name
		}
	}
	return out
}

// renderAnchorValue is probes._render_anchor_value.
func renderAnchorValue(value validation.Value) string {
	switch value.Kind {
	case validation.Arr:
		parts := make([]string, 0, len(value.A))
		for _, v := range value.A {
			parts = append(parts, validation.PyStr(v))
		}
		return strings.Join(parts, ", ")
	case validation.Obj:
		return validation.CanonCompact(value)
	}
	return validation.PyStr(value)
}
