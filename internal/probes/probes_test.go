package probes

// Port of web3sec-final/tests/test_probes.py (42 functions, 1:1). In-package:
// the tests exercise the unexported registry/helpers the Python module
// exposes, exactly as the pytest suite does.

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

const (
	t29ProbesDir   = "testdata/probes"
	t29SiblingsDir = "testdata/siblings"
)

// t29Index is _index: a campaign under a fresh temp root + index_snapshot.
func t29Index(t *testing.T, root string) validation.Value {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Probes", state.InitOpts{})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	idx, err := structidx.IndexSnapshot(c, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatalf("IndexSnapshot(%s): %v", root, err)
	}
	return idx
}

// t29Model is _model(name).
func t29Model(t *testing.T, name string) validation.Value {
	t.Helper()
	v, err := validation.ReadJson(filepath.Join(t29ProbesDir, "models", name))
	if err != nil {
		t.Fatalf("read model %s: %v", name, err)
	}
	return v
}

// t29RankModel is RANK_MODEL.
func t29RankModel(t *testing.T) validation.Value {
	t.Helper()
	v, err := validation.ReadJson(filepath.Join(t29ProbesDir, "ranking", "model.json"))
	if err != nil {
		t.Fatalf("read rank model: %v", err)
	}
	return v
}

// t29Axis is _axis(surface, probe_id).
func t29Axis(t *testing.T, surface validation.Value, probeID string) validation.Value {
	t.Helper()
	for _, a := range vObjList(surface, "axes") {
		if vStr(a, "probe") == probeID {
			return a
		}
	}
	t.Fatalf("no axis for probe %s", probeID)
	return validation.VNull()
}

// t29Rows is `[r for r in surface["rows"] if r["probe"] == pid]`.
func t29Rows(surface validation.Value, probeID string) []validation.Value {
	out := []validation.Value{}
	for _, r := range vObjList(surface, "rows") {
		if vStr(r, "probe") == probeID {
			out = append(out, r)
		}
	}
	return out
}

// t29Raw is spec["fn"](index, model) through the registry entry point.
func t29Raw(t *testing.T, index, model validation.Value, probeID string) validation.Value {
	t.Helper()
	out, err := RawProbe(index, model, probeID)
	if err != nil {
		t.Fatalf("RawProbe(%s): %v", probeID, err)
	}
	return out
}

// t29Clone is a deep copy of a Value (json round trip preserves key order).
func t29Clone(t *testing.T, v validation.Value) validation.Value {
	t.Helper()
	out, err := validation.ParseOrdered([]byte(validation.DumpsOrdered(v, false)))
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	return out
}

// t29JSON is the order-preserving JSON text used for equality assertions.
func t29JSON(v validation.Value) string { return validation.DumpsOrdered(v, false) }

// t29StrJSON compares two string slices as Python lists.
func t29StrJSON(items []string) string { return t29JSON(validation.StrArr(items)) }

// t29SetOf is `{v[k] for v in items}`.
func t29SetOf(items []validation.Value, key string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, it := range items {
		out[vStr(it, key)] = struct{}{}
	}
	return out
}

// t29CopyTree is shutil.copytree.
func t29CopyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copytree %s -> %s: %v", src, dst, err)
	}
}

// t29Write writes one fixture file, creating its parent directory.
func t29Write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// t29Read is Path.read_text().
func t29Read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// t29RankedTree is _ranked_tree: siblings/ + probes/ranking/ in one root.
func t29RankedTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t29CopyTree(t, t29SiblingsDir, filepath.Join(root, "siblings"))
	t29CopyTree(t, filepath.Join(t29ProbesDir, "ranking"), filepath.Join(root, "ranking"))
	return root
}

// t29First is next(... for ... in ...).
func t29First(items []validation.Value, pred func(validation.Value) bool) (validation.Value, bool) {
	for _, it := range items {
		if pred(it) {
			return it, true
		}
	}
	return validation.VNull(), false
}

// ---- registry -------------------------------------------------------------

func TestRegistryShipsTheSixProbesWithRankAndAnchors(t *testing.T) {
	want := []string{"accumulator-basis-skew", "assertion-strength",
		"custody-primitive", "sequential-cursor", "short-circuitable-guard",
		"trust-assumption"}
	if got, w := t29StrJSON(ProbeIDs()), t29StrJSON(want); got != w {
		t.Fatalf("probe_ids() = %s, want %s", got, w)
	}
	wantRank := []string{"tier", "-assertion_gap", "siblings", "function_name"}
	for pid, spec := range probesTable {
		if spec.axis == "" || !strings.HasPrefix(spec.lens, "L-") {
			t.Errorf("%s: axis=%q lens=%q", pid, spec.axis, spec.lens)
		}
		if got, w := t29StrJSON(spec.rank), t29StrJSON(wantRank); got != w {
			t.Errorf("%s: rank = %s, want %s", pid, got, w)
		}
		if !strings.Contains(spec.whyTemplate, "{") {
			t.Errorf("%s: why_template has no placeholder", pid)
		}
		if len(spec.anchors) == 0 {
			t.Errorf("%s: no anchors", pid)
		}
		if spec.fn == nil {
			t.Errorf("%s: fn is not callable", pid)
		}
	}
}

func TestAxisNamesAreUniqueEvenWhenALensCarriesSeveralProbes(t *testing.T) {
	axes := map[string]struct{}{}
	for _, spec := range probesTable {
		axes[spec.axis] = struct{}{}
	}
	if len(axes) != len(probesTable) {
		t.Fatalf("axes %d != probes %d", len(axes), len(probesTable))
	}
	l01 := []string{}
	for pid, spec := range probesTable {
		if spec.lens == "L-01" {
			l01 = append(l01, pid)
		}
	}
	sort.Strings(l01)
	want := []string{"accumulator-basis-skew", "sequential-cursor",
		"short-circuitable-guard"}
	if got, w := t29StrJSON(l01), t29StrJSON(want); got != w {
		t.Fatalf("L-01 probes = %s, want %s", got, w)
	}
	if got, w := t29StrJSON(probesTable["short-circuitable-guard"].anchors),
		t29StrJSON([]string{"guard", "sentinel", "safety"}); got != w {
		t.Fatalf("short-circuit anchors = %s, want %s", got, w)
	}
	if got, w := t29StrJSON(probesTable["accumulator-basis-skew"].anchors),
		t29StrJSON([]string{"rounded", "plain", "accumulator", "companion"}); got != w {
		t.Fatalf("accumulator anchors = %s, want %s", got, w)
	}
	for _, pid := range l01 {
		for _, anchor := range probesTable[pid].anchors {
			field, ok := anchorFields[pid][anchor]
			if !ok {
				t.Errorf("%s: anchor %s has no ANCHOR_FIELDS entry", pid, anchor)
				continue
			}
			if !containsStr(probesTable[pid].fields, field) {
				t.Errorf("%s: anchor %s -> field %s not in fields %v", pid, anchor,
					field, probesTable[pid].fields)
			}
		}
	}
}

func TestPreV2IndexIsRejectedLoudlyByEveryEntryPoint(t *testing.T) {
	stale := validation.VObj(
		kv("parse_version", validation.VStr("1")),
		kv("nodes", validation.VArr()),
		kv("edges", validation.VArr()))
	for _, pid := range ProbeIDs() {
		_, err := RawProbe(stale, validation.VNull(), pid)
		if err == nil || !strings.Contains(err.Error(),
			"webv2 index <campaign> --src <target>") {
			t.Errorf("%s: err = %v", pid, err)
		}
	}
	if _, err := BuildSurface(stale, validation.VNull(), 12, 40, 3, ""); err == nil {
		t.Error("build_surface(stale) did not raise")
	}
}

// ---- per-probe fixture pairs ---------------------------------------------

func TestAssertionStrengthFiresOnBuggyAndIsBlindOnClean(t *testing.T) {
	buggy := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "buggy"))
	out := t29Raw(t, buggy, validation.VNull(), "assertion-strength")
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(vList(out, "rows"), "consumer"))),
		t29StrJSON([]string{"commitBatch"}); got != w {
		t.Fatalf("consumers = %s, want %s", got, w)
	}
	row, ok := t29First(vList(out, "rows"),
		func(r validation.Value) bool { return vStr(r, "concept") == "prev:state:root" })
	if !ok {
		t.Fatalf("no row for concept prev:state:root: %s", t29JSON(out))
	}
	if vStr(row, "contract") != "Rollup" || vStr(row, "asserter") != "finalizeBatch" {
		t.Errorf("contract=%q asserter=%q", vStr(row, "contract"), vStr(row, "asserter"))
	}
	if vInt(row, "own_class") != 0 || vInt(row, "assert_class") != 4 {
		t.Errorf("own_class=%d assert_class=%d", vInt(row, "own_class"),
			vInt(row, "assert_class"))
	}
	if vInt(row, "tier") != 0 || vStr(row, "gate") != "unprivileged" {
		t.Errorf("tier=%d gate=%q", vInt(row, "tier"), vStr(row, "gate"))
	}
	if !(vInt(out, "sites") > len(vList(out, "rows"))) {
		t.Errorf("sites %d <= rows %d", vInt(out, "sites"), len(vList(out, "rows")))
	}

	clean := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "clean"))
	out = t29Raw(t, clean, validation.VNull(), "assertion-strength")
	if len(vList(out, "rows")) != 0 {
		t.Errorf("clean rows = %s", t29JSON(vGet(out, "rows")))
	}
	if !(vInt(out, "sites") > 0) {
		t.Error("clean sites == 0; the concept is seen; it is the asymmetry that is absent")
	}
	if !vTruthy(vGet(out, "blind")) {
		t.Error("a probe that rejects must name what it nearly joined")
	}
}

func TestCustodyPrimitiveFiresInheritedAndIsBlindOnClean(t *testing.T) {
	buggy := t29Index(t, filepath.Join(t29ProbesDir, "custody", "buggy"))
	out := t29Raw(t, buggy, validation.VNull(), "custody-primitive")
	rows := vList(out, "rows")
	if len(rows) != 1 {
		t.Fatalf("rows = %s", t29JSON(out))
	}
	row := rows[0]
	if vStr(row, "contract") != "L1ReverseCustomGateway" ||
		vStr(row, "consumer") != "onDropMessage" ||
		vStr(row, "base") != "L1ERC20Gateway" {
		t.Errorf("row = %s", t29JSON(row))
	}
	if !vBool(row, "inherited") {
		t.Error("inherited is not True")
	}
	if vStr(row, "custody") != "burns" {
		t.Errorf("custody = %q", vStr(row, "custody"))
	}
	if got, w := t29StrJSON(vStrList(row, "forward")), t29StrJSON([]string{"_deposit"}); got != w {
		t.Errorf("forward = %s, want %s", got, w)
	}
	if !(vInt(out, "sites") > 0) {
		t.Error("sites == 0")
	}

	clean := t29Index(t, filepath.Join(t29ProbesDir, "custody", "clean"))
	out = t29Raw(t, clean, validation.VNull(), "custody-primitive")
	if len(vList(out, "rows")) != 0 {
		t.Errorf("clean rows = %s", t29JSON(vGet(out, "rows")))
	}
	if !(vInt(out, "sites") > 0) {
		t.Error("clean sites == 0")
	}
	if !vTruthy(vGet(out, "blind")) {
		t.Error("clean blind is empty")
	}
}

func TestCustodyPrimitiveFiresOnCastFormCallsOnly(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "custody_castform", "buggy"))
	deposit, ok := t29First(vList(idx, "nodes"), func(n validation.Value) bool {
		return vStr(n, "kind") == "function" && vStr(n, "name") == "_deposit"
	})
	if !ok {
		t.Fatal("no _deposit function node")
	}
	if !containsStr(vStrList(deposit, "calls_external"), "IMorphERC20Upgradeable.burn") {
		t.Fatalf("calls_external = %s", t29JSON(vGet(deposit, "calls_external")))
	}
	out := t29Raw(t, idx, validation.VNull(), "custody-primitive")
	rows := vList(out, "rows")
	if len(rows) != 1 {
		t.Fatalf("rows = %s", t29JSON(out))
	}
	row := rows[0]
	if vStr(row, "contract") != "L1ReverseCustomGateway" ||
		vStr(row, "consumer") != "onDropMessage" {
		t.Errorf("row = %s", t29JSON(row))
	}
	if vStr(row, "base") != "L1ERC20Gateway" || !vBool(row, "inherited") {
		t.Errorf("base=%q inherited=%v", vStr(row, "base"), vBool(row, "inherited"))
	}
	if vStr(row, "custody") != "burns" {
		t.Errorf("custody = %q", vStr(row, "custody"))
	}
	if got, w := t29StrJSON(vStrList(row, "forward")), t29StrJSON([]string{"_deposit"}); got != w {
		t.Errorf("forward = %s, want %s", got, w)
	}
}

func TestSequentialCursorFiresWithStrandedEntry(t *testing.T) {
	buggy := t29Index(t, filepath.Join(t29ProbesDir, "cursor", "buggy"))
	out := t29Raw(t, buggy, validation.VNull(), "sequential-cursor")
	rows := vList(out, "rows")
	if len(rows) != 1 {
		t.Fatalf("rows = %s", t29JSON(out))
	}
	row := rows[0]
	if vStr(row, "consumer") != "finalizeBatch" {
		t.Errorf("consumer = %q", vStr(row, "consumer"))
	}
	if vStr(row, "cursor") != "lastFinalizedBatchIndex" {
		t.Errorf("cursor = %q", vStr(row, "cursor"))
	}
	if !strings.Contains(vStr(row, "guard"), "+ 1 ==") {
		t.Errorf("guard = %q", vStr(row, "guard"))
	}
	if got, w := t29StrJSON(vStrList(row, "stranded_entry")),
		t29StrJSON([]string{"commitBatch"}); got != w {
		t.Errorf("stranded_entry = %s, want %s", got, w)
	}
	if vInt(out, "sites") != 1 {
		t.Errorf("sites = %d", vInt(out, "sites"))
	}

	clean := t29Index(t, filepath.Join(t29ProbesDir, "cursor", "clean"))
	out = t29Raw(t, clean, validation.VNull(), "sequential-cursor")
	if len(vList(out, "rows")) != 0 {
		t.Errorf("clean rows = %s", t29JSON(vGet(out, "rows")))
	}
	if vInt(out, "sites") != 0 {
		t.Errorf("clean sites = %d; no cursor+1 shape at all -> no-sites, not blind",
			vInt(out, "sites"))
	}
}

func TestTrustAssumptionJoinsAssumptionCarryingActors(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "clean"))
	out := t29Raw(t, idx, t29Model(t, "buggy_model.json"), "trust-assumption")
	type key struct {
		actor, invariant, trust string
		tier                    int
	}
	got := map[key]struct{}{}
	for _, r := range vList(out, "rows") {
		got[key{vStr(r, "actor"), vStr(r, "invariant"), vStr(r, "trust"),
			vInt(r, "tier")}] = struct{}{}
	}
	want := map[key]struct{}{
		{"sequencer", "INV-1", "semi-trusted", 0}: {},
		{"guardian", "INV-2", "trusted", 2}:       {},
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %s", t29JSON(vGet(out, "rows")))
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing %+v in %s", k, t29JSON(vGet(out, "rows")))
		}
	}
	if vInt(out, "sites") != 2 {
		t.Errorf("sites = %d", vInt(out, "sites"))
	}

	out = t29Raw(t, idx, t29Model(t, "clean_model.json"), "trust-assumption")
	if len(vList(out, "rows")) != 0 {
		t.Errorf("clean rows = %s", t29JSON(vGet(out, "rows")))
	}
	if vInt(out, "sites") != 1 {
		t.Errorf("clean sites = %d", vInt(out, "sites"))
	}
	blind := vList(out, "blind")
	if len(blind) == 0 {
		t.Fatal("clean blind is empty")
	}
	if vStr(blind[0], "actor") != "attacker" {
		t.Errorf("blind[0].actor = %q", vStr(blind[0], "actor"))
	}
	if vStr(blind[0], "kind") != "non-assumption-actor" {
		t.Errorf("blind[0].kind = %q", vStr(blind[0], "kind"))
	}

	out = t29Raw(t, idx, validation.VNull(), "trust-assumption")
	if len(vList(out, "rows")) != 0 || vInt(out, "sites") != 0 {
		t.Errorf("model=None: rows=%s sites=%d", t29JSON(vGet(out, "rows")),
			vInt(out, "sites"))
	}
}

// ---- trust join -----------------------------------------------------------

func TestTrustJoinMapsModifierToActorTrust(t *testing.T) {
	model := t29RankModel(t)
	checks := []struct {
		mods []string
		m    validation.Value
		want int
	}{
		{[]string{"onlyActiveStaker"}, model, 0},
		{[]string{"onlyOwner"}, model, 2},
		{[]string{"onlyGuardian"}, model, 1},
		{[]string{"onlyCounterpart"}, validation.VNull(), 0},
		{[]string{"onlyRollup"}, validation.VNull(), 0},
		{[]string{"onlyMessenger"}, validation.VNull(), 0},
		{[]string{"onlyStaker"}, validation.VNull(), 0},
		{nil, model, 0},
		{[]string{"nonReentrant"}, model, 0},
		{[]string{"onlyOwner", "onlyActiveStaker"}, model, 0},
		{[]string{"onlyOwner"}, validation.VNull(), 1},
	}
	for _, c := range checks {
		if got := TierOfGate(c.mods, c.m); got != c.want {
			t.Errorf("tier_of_gate(%v) = %d, want %d", c.mods, got, c.want)
		}
	}
}

func TestResolveGateReportsActorAndMechanism(t *testing.T) {
	model := t29RankModel(t)
	got := ResolveGate("onlyActiveStaker", model)
	if vStr(got, "actor") != "active_staker" || vStr(got, "trust") != "semi-trusted" {
		t.Errorf("resolve_gate = %s", t29JSON(got))
	}
	if !vBool(got, "resolved") {
		t.Error("resolved is not True")
	}
	got = ResolveGate("onlyCounterpart", validation.VNull())
	if !vBool(got, "inside_boundary") || !vBool(got, "resolved") {
		t.Errorf("resolve_gate(onlyCounterpart) = %s", t29JSON(got))
	}
	got = ResolveGate("onlyGuardian", model)
	if vBool(got, "resolved") || vInt(got, "tier") != 1 {
		t.Errorf("resolve_gate(onlyGuardian) = %s", t29JSON(got))
	}
}

// ---- the measured ranking regression --------------------------------------

func TestRankingRegressionCommitBatchRank1AndSiblingCollapse(t *testing.T) {
	model := t29RankModel(t)
	surface, err := BuildSurface(t29Index(t, t29RankedTree(t)), model, 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis := t29Axis(t, surface, "assertion-strength")
	rows := t29Rows(surface, "assertion-strength")
	if len(rows) == 0 {
		t.Fatalf("no assertion-strength rows: %s", t29JSON(surface))
	}
	r0 := rows[0]
	if vStr(r0, "consumer") != "commitBatch" || vStr(r0, "asserter") != "finalizeBatch" {
		t.Errorf("row0 = %s", t29JSON(r0))
	}
	if vInt(r0, "rank") != 1 {
		t.Errorf("rank = %d", vInt(r0, "rank"))
	}
	if vInt(r0, "tier") != 0 || vInt(r0, "assertion_gap") != 4 {
		t.Errorf("tier=%d gap=%d", vInt(r0, "tier"), vInt(r0, "assertion_gap"))
	}
	if vStr(r0, "contract") != "Rollup" {
		t.Error("the representative is not the mock")
	}
	wantSibs := validation.VArr(
		validation.VObj(kv("contract", validation.VStr("Rollup")),
			kv("line", validation.VInt(45)), kv("test_double", validation.VBool(false))),
		validation.VObj(kv("contract", validation.VStr("MockRollup")),
			kv("line", validation.VInt(45)), kv("test_double", validation.VBool(true))))
	if got, w := t29JSON(vGet(r0, "siblings")), t29JSON(wantSibs); got != w {
		t.Errorf("siblings = %s, want %s", got, w)
	}
	if NSiblings(r0) != 1 {
		t.Errorf("n_siblings = %d, want 1 (a test double is not a second site)", NSiblings(r0))
	}
	mutated := t29Clone(t, r0)
	vSet(&mutated, "siblings", validation.VArr(vList(r0, "siblings")[0]))
	if RankKeyOf(r0) != RankKeyOf(mutated) {
		t.Error("the cockpit key counts real siblings, exactly like the engine")
	}

	collapsed := []validation.Value{}
	for _, r := range rows {
		if vStr(r, "consumer") == "updateTokenMapping" {
			collapsed = append(collapsed, r)
		}
	}
	if len(collapsed) != 1 {
		t.Fatalf("collapsed rows = %d", len(collapsed))
	}
	if n := len(vList(collapsed[0], "siblings")); n != 7 {
		t.Errorf("collapsed siblings = %d, want 7", n)
	}
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(vList(collapsed[0], "siblings"),
		"contract"))), t29StrJSON([]string{"L1ERC20Gateway", "L1GatewayRouter",
		"L1ReverseCustomGateway", "L2CustomGateway", "L2ERC20Gateway",
		"L2GatewayRouter", "L2ReverseCustomGateway"}); got != w {
		t.Errorf("collapsed contracts = %s, want %s", got, w)
	}
	if vInt(collapsed[0], "tier") != 0 || vStr(collapsed[0], "gate") != "onlyCounterpart" {
		t.Errorf("collapsed tier=%d gate=%q", vInt(collapsed[0], "tier"),
			vStr(collapsed[0], "gate"))
	}

	mockOnly := []validation.Value{}
	for _, r := range rows {
		if vStr(r, "consumer") == "setLastFinalizedBatchIndex" {
			mockOnly = append(mockOnly, r)
		}
	}
	if len(mockOnly) != 1 {
		t.Fatalf("mock-only rows = %d", len(mockOnly))
	}
	if vStr(mockOnly[0], "contract") != "MockRollup" {
		t.Errorf("mock-only contract = %q", vStr(mockOnly[0], "contract"))
	}
	for _, s := range vList(mockOnly[0], "siblings") {
		if !vBool(s, "test_double") {
			t.Errorf("mock-only sibling not a test double: %s", t29JSON(s))
		}
	}
	if NSiblings(mockOnly[0]) != 1 {
		t.Errorf("mock-only n_siblings = %d", NSiblings(mockOnly[0]))
	}

	byName := map[string]int{}
	for _, r := range rows {
		byName[vStr(r, "consumer")] = vInt(r, "rank")
	}
	if !(byName["commitBatch"] < byName["challengeState"] &&
		byName["challengeState"] < byName["importGenesisBatch"]) {
		t.Errorf("ranks = %v", byName)
	}
	if !(vInt(axis, "sites") > vInt(axis, "rows")) || vInt(axis, "rows") != len(rows) ||
		len(rows) != 11 {
		t.Errorf("axis sites=%d rows=%d len(rows)=%d", vInt(axis, "sites"),
			vInt(axis, "rows"), len(rows))
	}
	if vInt(axis, "emitted") != 11 || vInt(axis, "tail") != 0 ||
		vStr(axis, "status") != "emitted" {
		t.Errorf("emitted=%d tail=%d status=%q", vInt(axis, "emitted"),
			vInt(axis, "tail"), vStr(axis, "status"))
	}
}

func TestTestDoublePathsAreRecognizedAndRankNeutral(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"contracts/mock/MockRollup.sol", true},
		{"test/Harness.sol", true},
		{"src/tests/Helper.sol", true},
		{"contracts/MockRollup.sol", true},
		{"contracts/RollupMock.sol", true},
		{"contracts/Rollup.t.sol", true},
		{"contracts/l1/rollup/Rollup.sol", false},
		{"contracts/l1/Rollup.sol", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsTestDoublePath(c.path); got != c.want {
			t.Errorf("is_test_double_path(%q) = %v, want %v", c.path, got, c.want)
		}
	}

	real := validation.VObj(kv("contract", validation.VStr("Rollup")),
		kv("line", validation.VInt(1)), kv("test_double", validation.VBool(false)))
	mock := validation.VObj(kv("contract", validation.VStr("MockRollup")),
		kv("line", validation.VInt(1)), kv("test_double", validation.VBool(true)))
	nCases := []struct {
		row  validation.Value
		want int
	}{
		{validation.VObj(kv("siblings", validation.VArr(real))), 1},
		{validation.VObj(kv("siblings", validation.VArr(real, mock))), 1},
		{validation.VObj(kv("siblings", validation.VArr(real, mock, mock))), 1},
		{validation.VObj(kv("siblings", validation.VArr(mock))), 1},
		{validation.VObj(kv("siblings", validation.VInt(4))), 4},
	}
	for i, c := range nCases {
		if got := NSiblings(c.row); got != c.want {
			t.Errorf("n_siblings(case %d) = %d, want %d", i, got, c.want)
		}
	}
	left := validation.VObj(kv("probe", validation.VStr("assertion-strength")),
		kv("tier", validation.VInt(0)), kv("assertion_gap", validation.VInt(4)),
		kv("siblings", validation.VArr(real, mock)), kv("row_id", validation.VStr("a")))
	right := validation.VObj(kv("probe", validation.VStr("assertion-strength")),
		kv("tier", validation.VInt(0)), kv("assertion_gap", validation.VInt(4)),
		kv("siblings", validation.VArr(real)), kv("row_id", validation.VStr("a")))
	if RankKeyOf(left) != RankKeyOf(right) {
		t.Error("the cockpit key and the engine key must agree on real siblings")
	}
}

func TestSiblingCollapseIsOneObligationOnTheRepoFixture(t *testing.T) {
	surface, err := BuildSurface(t29Index(t, t29SiblingsDir), validation.VNull(),
		12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis := t29Axis(t, surface, "assertion-strength")
	rows := t29Rows(surface, "assertion-strength")
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if vStr(rows[0], "consumer") != "updateTokenMapping" {
		t.Errorf("consumer = %q", vStr(rows[0], "consumer"))
	}
	if n := len(vList(rows[0], "siblings")); n != 7 {
		t.Errorf("siblings = %d, want 7", n)
	}
	if !(vInt(axis, "sites") >= 7) || vInt(axis, "rows") != 1 {
		t.Errorf("sites=%d rows=%d", vInt(axis, "sites"), vInt(axis, "rows"))
	}
	if vStr(rows[0], "gate") != "onlyCounterpart" {
		t.Errorf("gate = %q", vStr(rows[0], "gate"))
	}
	if vStr(vList(rows[0], "siblings")[0], "contract") != "L1ERC20Gateway" {
		t.Errorf("first sibling = %s", t29JSON(vList(rows[0], "siblings")[0]))
	}
}

func TestRowIDsAreStableAcrossLineMoves(t *testing.T) {
	src := filepath.Join(t.TempDir(), "tree")
	t29CopyTree(t, filepath.Join(t29ProbesDir, "assertion_strength", "buggy"), src)
	before, err := BuildSurface(t29Index(t, src), validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	rowA := vList(before, "rows")[0]
	p := filepath.Join(src, "Rollup.sol")
	t29Write(t, p, "\n\n"+t29Read(t, p))
	after, err := BuildSurface(t29Index(t, src), validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	rowB := vList(after, "rows")[0]
	if vStr(rowA, "row_id") != vStr(rowB, "row_id") {
		t.Error("a line shift is not a new row")
	}
	if vInt(rowB, "consumer_line") != vInt(rowA, "consumer_line")+2 {
		t.Errorf("consumer_line %d != %d+2", vInt(rowB, "consumer_line"),
			vInt(rowA, "consumer_line"))
	}
}

// ---- per-axis bookkeeping + quota ----------------------------------------

func TestAxisBookkeepingRecordsSitesRowsEmittedTail(t *testing.T) {
	surface, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "cursor", "buggy")),
		validation.VNull(), 12, 40, 3, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	axis := t29Axis(t, surface, "sequential-cursor")
	got := []int{vInt(axis, "sites"), vInt(axis, "rows"), vInt(axis, "emitted"),
		vInt(axis, "tail")}
	if want := []int{1, 1, 1, 0}; t29JSON(intArr(got)) != t29JSON(intArr(want)) {
		t.Errorf("axis counters = %v, want %v", got, want)
	}
	if vStr(axis, "status") != "emitted" {
		t.Errorf("status = %q", vStr(axis, "status"))
	}
	if len(vList(surface, "missing")) != 0 {
		t.Errorf("missing = %s", t29JSON(vGet(surface, "missing")))
	}
	probes := map[string]struct{}{}
	for _, a := range vObjList(surface, "axes") {
		probes[vStr(a, "probe")] = struct{}{}
	}
	if got, w := t29StrJSON(sortedStrSet(probes)), t29StrJSON(ProbeIDs()); got != w {
		t.Errorf("axes probes = %s, want %s", got, w)
	}
	if vInt(vGet(surface, "stats"), "emitted") != len(vList(surface, "rows")) {
		t.Error("stats.emitted != len(rows)")
	}

	clean, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "cursor", "clean")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis = t29Axis(t, clean, "sequential-cursor")
	got = []int{vInt(axis, "sites"), vInt(axis, "rows"), vInt(axis, "emitted")}
	if want := []int{0, 0, 0}; t29JSON(intArr(got)) != t29JSON(intArr(want)) {
		t.Errorf("clean counters = %v, want %v", got, want)
	}
	if vStr(axis, "status") != "no-sites" {
		t.Errorf("clean status = %q", vStr(axis, "status"))
	}
	if len(vList(clean, "rows")) != 0 || len(vList(clean, "missing")) != 0 {
		t.Error("clean rows/missing not empty")
	}

	blind, err := BuildSurface(t29Index(t,
		filepath.Join(t29ProbesDir, "assertion_strength", "clean")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis = t29Axis(t, blind, "assertion-strength")
	if !(vInt(axis, "sites") > 0 && vInt(axis, "rows") == 0) {
		t.Errorf("blind sites=%d rows=%d", vInt(axis, "sites"), vInt(axis, "rows"))
	}
	if vStr(axis, "status") != "blind" {
		t.Errorf("blind status = %q", vStr(axis, "status"))
	}
	if !vTruthy(vGet(axis, "blind")) {
		t.Error("rows==0 with sites>0 must publish the near-keys")
	}
	if len(vList(blind, "rows")) != 0 || len(vList(blind, "missing")) != 0 {
		t.Error("blind rows/missing not empty")
	}
}

func TestQuotaCeilingTrimsFromTheNoisyAxisAndRecordsMissing(t *testing.T) {
	model := t29RankModel(t)
	idx := t29Index(t, t29RankedTree(t))
	surface, err := BuildSurface(idx, model, 12, 2, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	axis := t29Axis(t, surface, "assertion-strength")
	if vInt(axis, "rows") != 11 {
		t.Errorf("rows = %d, want 11", vInt(axis, "rows"))
	}
	if vInt(axis, "emitted") != 2 {
		t.Errorf("emitted = %d, want 2", vInt(axis, "emitted"))
	}
	if vInt(axis, "tail") != 9 {
		t.Errorf("tail = %d, want 9", vInt(axis, "tail"))
	}
	if vStr(axis, "status") != "under-filled" {
		t.Errorf("status = %q", vStr(axis, "status"))
	}
	if len(vList(surface, "rows")) != 2 {
		t.Errorf("surface rows = %d, want 2", len(vList(surface, "rows")))
	}
	ranks := []int{}
	for _, r := range vList(surface, "rows") {
		ranks = append(ranks, vInt(r, "rank"))
	}
	if want := []int{1, 2}; t29JSON(intArr(ranks)) != t29JSON(intArr(want)) {
		t.Errorf("ranks = %v, want %v", ranks, want)
	}
	missing := vList(surface, "missing")
	if len(missing) != 1 {
		t.Fatalf("missing = %s", t29JSON(vGet(surface, "missing")))
	}
	miss := missing[0]
	if vStr(miss, "probe") != "assertion-strength" {
		t.Errorf("missing probe = %q", vStr(miss, "probe"))
	}
	if vStr(miss, "axis") != "enforcement-timing" || vStr(miss, "lens") != "L-03" {
		t.Errorf("missing axis=%q lens=%q", vStr(miss, "axis"), vStr(miss, "lens"))
	}
	if vInt(miss, "rows") != 11 || vInt(miss, "emitted") != 2 || vInt(miss, "floor") != 1 {
		t.Errorf("missing rows=%d emitted=%d floor=%d", vInt(miss, "rows"),
			vInt(miss, "emitted"), vInt(miss, "floor"))
	}
	if !strings.Contains(vStr(miss, "reason"), "per-axis") {
		t.Errorf("missing reason = %q", vStr(miss, "reason"))
	}
}

func TestReservedFloorIsNeverTrimmedByTheCeiling(t *testing.T) {
	model := t29RankModel(t)
	idx := t29Index(t, t29RankedTree(t))
	surface, err := BuildSurface(idx, model, 12, 2, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis := t29Axis(t, surface, "assertion-strength")
	if vInt(axis, "floor") != 3 {
		t.Errorf("floor = %d", vInt(axis, "floor"))
	}
	if vInt(axis, "emitted") != 3 {
		t.Error("the reserved floor outranks the ceiling")
	}
	if vStr(axis, "status") != "under-filled" {
		t.Errorf("status = %q", vStr(axis, "status"))
	}
	if vInt(vList(surface, "missing")[0], "emitted") != 3 {
		t.Errorf("missing.emitted = %d", vInt(vList(surface, "missing")[0], "emitted"))
	}
}

func TestFloorReserveLargerThanTotalIsALoudWarning(t *testing.T) {
	model := t29RankModel(t)
	idx := t29Index(t, t29RankedTree(t))
	surface, err := BuildSurface(idx, model, 12, 2, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
	warnings := vList(surface, "warnings")
	if len(warnings) != 1 {
		t.Fatalf("warnings = %s", t29JSON(vGet(surface, "warnings")))
	}
	warning := warnings[0]
	if vStr(warning, "kind") != "floor-reserve-exceeds-total" {
		t.Errorf("kind = %q", vStr(warning, "kind"))
	}
	msg := vStr(warning, "message")
	for _, needle := range []string{"floor reserve 3", "floor 3 x 1 axes with rows",
		"exceeds --total 2", "Raise --total to >= 3", "lower the floor"} {
		if !strings.Contains(msg, needle) {
			t.Errorf("message %q missing %q", msg, needle)
		}
	}
	if vInt(vGet(surface, "stats"), "emitted") != 3 {
		t.Error("the reserve still outranks it")
	}

	ok, err := BuildSurface(idx, model, 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vList(ok, "warnings")) != 0 {
		t.Error("a ceiling that can win is silent")
	}
	if err := validation.Validate(ok, "probe_surface", 1); err != nil {
		t.Fatalf("validate(ok): %v", err)
	}
}

func TestQuotaKnobsThatWouldRebuildAVacuousClosureAreRejected(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "cursor", "buggy"))
	cases := []struct {
		perAxis, total, floor int
		needle                string
	}{
		{0, 40, 3, "--per-axis"},
		{-1, 40, 3, "--per-axis"},
		{12, 0, 3, "--total"},
		{12, -3, 3, "--total"},
		{12, 40, -1, "--floor"},
	}
	for _, c := range cases {
		_, err := BuildSurface(idx, validation.VNull(), c.perAxis, c.total, c.floor, "")
		if err == nil || !strings.Contains(err.Error(), c.needle) {
			t.Errorf("build_surface(%d,%d,%d) err = %v, want %q", c.perAxis,
				c.total, c.floor, err, c.needle)
		}
	}
	c, err := state.Init(t.TempDir(), "Probes", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = RunProbes(c, idx, validation.VNull(), 0, 40, 3)
	if err == nil || !strings.Contains(err.Error(), "--per-axis") {
		t.Errorf("run_probes(per_axis=0) err = %v", err)
	}
	if _, err := BuildSurface(idx, validation.VNull(), 1, 1, 0, ""); err != nil {
		t.Errorf("boundary knobs are legal: %v", err)
	}
}

func TestNoAxisWithRowsCanReportEmittedWithZeroObligations(t *testing.T) {
	model := t29RankModel(t)
	idx := t29Index(t, t29RankedTree(t))
	surface, err := BuildSurface(idx, model, 1, 1, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, axis := range vObjList(surface, "axes") {
		if vInt(axis, "rows") > 0 && vInt(axis, "emitted") == 0 {
			if vStr(axis, "status") != "under-filled" {
				t.Errorf("axis %s status = %q", vStr(axis, "probe"),
					vStr(axis, "status"))
			}
			found := false
			for _, m := range vObjList(surface, "missing") {
				if vStr(m, "axis") == vStr(axis, "axis") {
					found = true
				}
			}
			if !found {
				t.Errorf("axis %s missing from missing[]", vStr(axis, "axis"))
			}
		}
	}
}

func TestSurfaceBlockersAreTheFourStateClosure(t *testing.T) {
	noSites, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "cursor", "clean")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	noSitesAxis := t29Axis(t, noSites, "sequential-cursor")
	if got := AxisSurfaceBlocker(noSitesAxis, nil); got != "" {
		t.Errorf("no-sites blocker = %q", got)
	}

	blind, err := BuildSurface(t29Index(t,
		filepath.Join(t29ProbesDir, "assertion_strength", "clean")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	blindAxis := t29Axis(t, blind, "assertion-strength")
	msg := AxisSurfaceBlocker(blindAxis, nil)
	if msg == "" || !strings.Contains(msg, "--anchor-blind") {
		t.Errorf("blind blocker = %q", msg)
	}
	key := vStr(vList(blindAxis, "blind")[0], "key")
	ok := validation.VObj(kv("anchor_blind", validation.VStr(key)),
		kv("reason", validation.VStr("looked at the asserter by hand")),
		kv("actor", validation.VStr("operator")))
	if got := AxisSurfaceBlocker(blindAxis, &ok); got != "" {
		t.Errorf("attested blocker = %q", got)
	}
	bad := validation.VObj(kv("anchor_blind", validation.VStr("no-such-key")),
		kv("reason", validation.VStr("looked at the asserter by hand")),
		kv("actor", validation.VStr("operator")))
	if got := AxisSurfaceBlocker(blindAxis, &bad); !strings.Contains(got, "blind[]") {
		t.Errorf("bad-key blocker = %q", got)
	}
	partial := validation.VObj(kv("anchor_blind", validation.VStr(key)))
	if got := AxisSurfaceBlocker(blindAxis, &partial); !strings.Contains(got, "reason") {
		t.Errorf("partial blocker = %q", got)
	}

	model := t29RankModel(t)
	under, err := BuildSurface(t29Index(t, t29RankedTree(t)), model, 12, 2, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	underAxis := t29Axis(t, under, "assertion-strength")
	if got := AxisSurfaceBlocker(underAxis, nil); !strings.Contains(got, "per-axis") {
		t.Errorf("under-filled blocker = %q", got)
	}

	emitted, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "cursor", "buggy")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	emittedAxis := t29Axis(t, emitted, "sequential-cursor")
	if got := AxisSurfaceBlocker(emittedAxis, nil); got != "" {
		t.Errorf("emitted blocker = %q", got)
	}
}

// ---- schema + anchors -----------------------------------------------------

func TestSurfaceValidatesAgainstSchemaAndRejectsRowDrift(t *testing.T) {
	surface, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "cursor", "buggy")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
	expectSchemaError := func(name string, bad validation.Value) {
		t.Helper()
		err := validation.Validate(bad, "probe_surface", 1)
		if err == nil {
			t.Errorf("%s: validate did not raise", name)
			return
		}
		if _, ok := err.(*validation.SchemaError); !ok {
			t.Errorf("%s: err is %T, want *validation.SchemaError", name, err)
		}
	}

	bad := t29Clone(t, surface)
	rows := vList(bad, "rows")
	vSet(&rows[0], "surprise_field", validation.VStr("not in the schema"))
	expectSchemaError("surprise_field", bad)

	bad = t29Clone(t, surface)
	rows = vList(bad, "rows")
	vDel(&rows[0], "row_id")
	expectSchemaError("pop row_id", bad)

	bad = t29Clone(t, surface)
	vSet(&bad, "index_sha", validation.VStr("not-a-sha"))
	expectSchemaError("index_sha", bad)

	bad = t29Clone(t, surface)
	axes := vList(bad, "axes")
	vSet(&axes[0], "status", validation.VStr("maybe"))
	expectSchemaError("axes[0].status", bad)
}

func TestAnchorsArePerProbeAndNameRealRowFields(t *testing.T) {
	cases := []struct {
		pid   string
		root  string
		model validation.Value
	}{
		{"assertion-strength", filepath.Join(t29ProbesDir, "assertion_strength", "buggy"), validation.VNull()},
		{"custody-primitive", filepath.Join(t29ProbesDir, "custody", "buggy"), validation.VNull()},
		{"sequential-cursor", filepath.Join(t29ProbesDir, "cursor", "buggy"), validation.VNull()},
		{"trust-assumption", filepath.Join(t29ProbesDir, "assertion_strength", "clean"), t29Model(t, "buggy_model.json")},
		{"short-circuitable-guard", filepath.Join(t29ProbesDir, "short_circuit", "buggy"), validation.VNull()},
		{"accumulator-basis-skew", filepath.Join(t29ProbesDir, "accumulator", "buggy"), validation.VNull()},
	}
	allAnchors := []string{"consumer", "asserter", "concept", "base", "custody",
		"sibling", "actor", "invariant", "guard", "cursor", "stranded_entry",
		"sentinel", "safety", "rounded", "plain", "accumulator", "companion"}
	for _, c := range cases {
		surface, err := BuildSurface(t29Index(t, c.root), c.model, 12, 40, 3, "")
		if err != nil {
			t.Fatal(err)
		}
		rows := t29Rows(surface, c.pid)
		if len(rows) == 0 {
			t.Fatalf("%s: no rows", c.pid)
		}
		for _, row := range rows {
			for _, anchor := range probesTable[c.pid].anchors {
				if !AnchorAllowed(c.pid, anchor) {
					t.Errorf("%s: anchor_allowed(%s) = false", c.pid, anchor)
				}
				val, err := RowAnchorValue(row, anchor)
				if err != nil || val.Kind == validation.Null {
					t.Errorf("%s: row_anchor_value(%s) = %v, %v", c.pid, anchor, val, err)
				}
			}
			other := ""
			for _, a := range allAnchors {
				if !containsStr(probesTable[c.pid].anchors, a) {
					other = a
					break
				}
			}
			if other == "" {
				t.Fatalf("%s: no non-anchor field", c.pid)
			}
			if AnchorAllowed(c.pid, other) {
				t.Errorf("%s: anchor_allowed(%s) = true", c.pid, other)
			}
			if _, err := RowAnchorValue(row, other); err == nil {
				t.Errorf("%s: row_anchor_value(%s) did not raise", c.pid, other)
			}
		}
	}
}

func TestSurfaceStampsTheTreeHashAndTheSchemaStaysClosed(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "cursor", "buggy"))
	surface, err := BuildSurface(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if vStr(surface, "index_sha") != IndexSha(idx) {
		t.Error("index_sha != index_sha(idx)")
	}
	if t29JSON(vGet(surface, "snapshot_id")) != t29JSON(vGet(idx, "snapshot_id")) {
		t.Error("snapshot_id mismatch")
	}
	if vStr(surface, "parse_version") != "3" {
		t.Errorf("parse_version = %q", vStr(surface, "parse_version"))
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, key := range []string{"index_sha", "snapshot_id", "parse_version"} {
		bad := t29Clone(t, surface)
		vDel(&bad, key)
		if err := validation.Validate(bad, "probe_surface", 1); err == nil {
			t.Errorf("dropping %s did not raise", key)
		}
	}
	bad := t29Clone(t, surface)
	vSet(&bad, "surprise_field", validation.VStr("not in the schema"))
	if err := validation.Validate(bad, "probe_surface", 1); err == nil {
		t.Error("surprise_field did not raise")
	}
}

// ---- artifact write, event, determinism -----------------------------------

func TestRunProbesRegistersSurfaceAndLogsEvent(t *testing.T) {
	camp, err := state.Init(t.TempDir(), "Probe run", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(camp,
		filepath.Join(t29ProbesDir, "cursor", "buggy"), structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := RunProbes(camp, idx, validation.VNull(), 12, 40, 3)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(camp.ArtifactsDir, "probe_surface.json")
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("artifact: %v", err)
	}
	written, err := validation.ReadJson(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(written, "probe_surface", 1); err != nil {
		t.Fatalf("validate artifact: %v", err)
	}
	if vStr(surface, "index_sha") != IndexSha(idx) {
		t.Error("index_sha mismatch")
	}
	if vStr(surface, "parse_version") != "3" {
		t.Errorf("parse_version = %q", vStr(surface, "parse_version"))
	}

	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	kinds := []validation.Value{}
	for _, a := range vObjList(st, "artifacts") {
		if vStr(a, "kind") == "probe-surface" {
			kinds = append(kinds, a)
		}
	}
	if len(kinds) != 1 {
		t.Fatalf("probe-surface artifacts = %d", len(kinds))
	}
	if vStr(kinds[0], "artifact_id") == "" {
		t.Error("artifact_id is empty")
	}
	events := []validation.Value{}
	for _, e := range vObjList(st, "events") {
		if vStr(e, "type") == "probes.run" {
			events = append(events, e)
		}
	}
	if len(events) != 1 {
		t.Fatalf("probes.run events = %d", len(events))
	}
	data := vGet(events[0], "data")
	if vInt(data, "emitted") != 1 {
		t.Errorf("event emitted = %d", vInt(data, "emitted"))
	}
	if vInt(vGet(vGet(data, "axes"), "sequential-cursor"), "sites") != 1 {
		t.Errorf("event axes = %s", t29JSON(vGet(data, "axes")))
	}

	again, err := RunProbes(camp, idx, validation.VNull(), 12, 40, 3)
	if err != nil {
		t.Fatal(err)
	}
	if vStr(again, "index_sha") != vStr(surface, "index_sha") {
		t.Error("index_sha moved on re-run")
	}
	st, err = camp.State()
	if err != nil {
		t.Fatal(err)
	}
	kinds = nil
	for _, a := range vObjList(st, "artifacts") {
		if vStr(a, "kind") == "probe-surface" {
			kinds = append(kinds, a)
		}
	}
	if len(kinds) != 1 {
		t.Error("refresh, never a ghost row")
	}
	events = nil
	for _, e := range vObjList(st, "events") {
		if vStr(e, "type") == "probes.run" {
			events = append(events, e)
		}
	}
	if len(events) != 2 {
		t.Errorf("probes.run events = %d, want 2", len(events))
	}
}

func TestSurfaceIsDeterministic(t *testing.T) {
	idx := t29Index(t, t29RankedTree(t))
	model := t29RankModel(t)
	a, err := BuildSurface(idx, model, 12, 40, 3, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildSurface(idx, model, 12, 40, 3, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if t29JSON(a) != t29JSON(b) {
		t.Error("two surfaces differ")
	}
	ids := map[string]struct{}{}
	for _, r := range vObjList(a, "rows") {
		ids[vStr(r, "row_id")] = struct{}{}
	}
	if len(ids) != len(vList(a, "rows")) {
		t.Error("row ids are not unique within a surface")
	}
}

func TestRowIDsFollowTheDeclaredHash(t *testing.T) {
	row := validation.VObj(
		kv("probe", validation.VStr("assertion-strength")),
		kv("contract", validation.VStr("Rollup")),
		kv("consumer", validation.VStr("commitBatch")),
		kv("asserter", validation.VStr("finalizeBatch")),
		kv("concept_keys", validation.VArr(validation.VStr("prev:state:root"))))
	sum := sha256.Sum256([]byte(strings.Join([]string{"assertion-strength",
		"Rollup", "commitBatch", "finalizeBatch", "prev:state:root"}, "|")))
	want := hex.EncodeToString(sum[:])[:10]
	if got := RowIDFor(row); got != want {
		t.Errorf("row_id_for = %q, want %q", got, want)
	}
}

func TestBlindAxisAlwaysPublishesACitableKey(t *testing.T) {
	surface, err := BuildSurface(t29Index(t,
		filepath.Join(t29ProbesDir, "assertion_strength", "weak")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis := t29Axis(t, surface, "assertion-strength")
	if !(vInt(axis, "sites") > 0 && vInt(axis, "rows") == 0) {
		t.Errorf("sites=%d rows=%d", vInt(axis, "sites"), vInt(axis, "rows"))
	}
	if vStr(axis, "status") != "blind" {
		t.Errorf("status = %q", vStr(axis, "status"))
	}
	if !vTruthy(vGet(axis, "blind")) {
		t.Fatal("an axis with sites and no rows cannot be attested")
	}
	key := vStr(vList(axis, "blind")[0], "key")
	blank := validation.VObj(kv("anchor_blind", validation.VStr(key)),
		kv("reason", validation.VStr("reviewed by hand")),
		kv("actor", validation.VStr("operator")))
	if got := AxisSurfaceBlocker(axis, &blank); got != "" {
		t.Errorf("blocker = %q", got)
	}
}

func TestCollapsedRowKeepsTheWeakestGateAndItsOwnSiteFirst(t *testing.T) {
	surface, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "collapse")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	rows := t29Rows(surface, "assertion-strength")
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	row := rows[0]
	if n := len(vList(row, "siblings")); n != 2 {
		t.Errorf("siblings = %d, want 2", n)
	}
	if vStr(row, "gate") != "unprivileged" {
		t.Errorf("gate = %q", vStr(row, "gate"))
	}
	if vStr(vList(row, "siblings")[0], "contract") != "OpenGateway" {
		t.Errorf("first sibling = %s", t29JSON(vList(row, "siblings")[0]))
	}
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(vList(row, "siblings"), "contract"))),
		t29StrJSON([]string{"GatedGateway", "OpenGateway"}); got != w {
		t.Errorf("contracts = %s, want %s", got, w)
	}
}

func TestMorphRegressionRowsExistInFixtures(t *testing.T) {
	g01, err := BuildSurface(t29Index(t,
		filepath.Join(t29ProbesDir, "assertion_strength", "buggy")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	row := vList(g01, "rows")[0]
	if vStr(row, "consumer") != "commitBatch" {
		t.Errorf("consumer = %q", vStr(row, "consumer"))
	}
	if !containsStr(vStrList(row, "concept_keys"), "prev:state:root") {
		t.Errorf("concept_keys = %s", t29JSON(vGet(row, "concept_keys")))
	}
	if vStr(row, "asserter") != "finalizeBatch" {
		t.Errorf("asserter = %q", vStr(row, "asserter"))
	}

	g02, err := BuildSurface(t29Index(t, filepath.Join(t29ProbesDir, "custody", "buggy")),
		validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	row = vList(g02, "rows")[0]
	if vStr(row, "contract") != "L1ReverseCustomGateway" ||
		vStr(row, "consumer") != "onDropMessage" {
		t.Errorf("row = %s", t29JSON(row))
	}
	if vStr(row, "base") != "L1ERC20Gateway" || !vBool(row, "inherited") {
		t.Errorf("base=%q inherited=%v", vStr(row, "base"), vBool(row, "inherited"))
	}
}

func TestNoisyAxisCannotEvictASparseAxis(t *testing.T) {
	root := t29RankedTree(t)
	t29CopyTree(t, filepath.Join(t29ProbesDir, "custody", "buggy"),
		filepath.Join(root, "custody"))
	t29CopyTree(t, filepath.Join(t29ProbesDir, "cursor", "buggy"),
		filepath.Join(root, "cursor"))
	model := t29RankModel(t)
	surface, err := BuildSurface(t29Index(t, root), model, 12, 4, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	noisy := t29Axis(t, surface, "assertion-strength")
	custody := t29Axis(t, surface, "custody-primitive")
	cursor := t29Axis(t, surface, "sequential-cursor")
	if vInt(noisy, "rows") != 11 || vInt(noisy, "emitted") != 2 {
		t.Errorf("noisy rows=%d emitted=%d", vInt(noisy, "rows"),
			vInt(noisy, "emitted"))
	}
	if vStr(noisy, "status") != "under-filled" {
		t.Errorf("noisy status = %q", vStr(noisy, "status"))
	}
	if vInt(custody, "emitted") != 1 || vInt(cursor, "emitted") != 1 {
		t.Errorf("sparse emitted custody=%d cursor=%d; the sparse axes must "+
			"survive the noisy one's demand", vInt(custody, "emitted"),
			vInt(cursor, "emitted"))
	}
	missing := []string{}
	for _, m := range vObjList(surface, "missing") {
		missing = append(missing, vStr(m, "probe"))
	}
	if got, w := t29StrJSON(missing), t29StrJSON([]string{"assertion-strength"}); got != w {
		t.Errorf("missing = %s, want %s", got, w)
	}
	if len(vList(surface, "rows")) != 4 {
		t.Errorf("rows = %d, want 4", len(vList(surface, "rows")))
	}
	if vInt(vGet(surface, "stats"), "emitted") != 4 {
		t.Errorf("stats.emitted = %d", vInt(vGet(surface, "stats"), "emitted"))
	}
}

// ---- A6: the L-01 tranche (short-circuitable-guard, accumulator-basis-skew) -

func TestShortCircuitableGuardFiresOnTheBuggyGuardAndBlindsOnClean(t *testing.T) {
	buggy := t29Index(t, filepath.Join(t29ProbesDir, "short_circuit", "buggy"))
	out := t29Raw(t, buggy, validation.VNull(), "short-circuitable-guard")
	if vInt(out, "sites") != 1 || len(vList(out, "blind")) != 0 {
		t.Fatalf("sites=%d blind=%s", vInt(out, "sites"),
			t29JSON(vGet(out, "blind")))
	}
	row := vList(out, "rows")[0]
	if vStr(row, "contract") != "EpochQueue" {
		t.Errorf("contract = %q", vStr(row, "contract"))
	}
	if vStr(row, "consumer") != "claimWithdrawRequest" {
		t.Errorf("consumer = %q", vStr(row, "consumer"))
	}
	if vStr(row, "guard") != ("epochEndDate != 0 && " +
		"epochNumber <= lastWithdrawRequest[user]") {
		t.Errorf("guard = %q", vStr(row, "guard"))
	}
	if vStr(row, "sentinel") != "epochEndDate != 0" {
		t.Errorf("sentinel = %q", vStr(row, "sentinel"))
	}
	if vStr(row, "safety") != "epochNumber <= lastWithdrawRequest[user]" {
		t.Errorf("safety = %q", vStr(row, "safety"))
	}
	if !(vInt(row, "guard_line") > 0) {
		t.Errorf("guard_line = %d", vInt(row, "guard_line"))
	}
	if vInt(row, "tier") != 0 || vStr(row, "gate") != "unprivileged" {
		t.Errorf("tier=%d gate=%q", vInt(row, "tier"), vStr(row, "gate"))
	}

	clean := t29Index(t, filepath.Join(t29ProbesDir, "short_circuit", "clean"))
	out = t29Raw(t, clean, validation.VNull(), "short-circuitable-guard")
	if len(vList(out, "rows")) != 0 {
		t.Errorf("clean rows = %s", t29JSON(vGet(out, "rows")))
	}
	if vInt(out, "sites") != 1 {
		t.Errorf("clean sites = %d; the conjunction is seen; the sentinel is absent",
			vInt(out, "sites"))
	}
	kinds := []string{}
	for _, b := range vObjList(out, "blind") {
		kinds = append(kinds, vStr(b, "kind"))
	}
	if got, w := t29StrJSON(kinds), t29StrJSON([]string{"no-sentinel-conjunct"}); got != w {
		t.Errorf("blind kinds = %s, want %s", got, w)
	}
	if vStr(vList(out, "blind")[0], "key") == "" {
		t.Error("a rejected site must be citable")
	}

	// Order matters: the same two conjuncts, swapped, evaluate the safety check
	// FIRST — the sentinel is then a redundant check, not a short circuit.
	swapped := filepath.Join(t.TempDir(), "swapped")
	t29Write(t, filepath.Join(swapped, "src", "Swapped.sol"),
		"contract Swapped {\n"+
			"    uint256 public epochEndDate;\n"+
			"    uint256 public epochNumber;\n"+
			"    function claim(address user) external {\n"+
			"        require(epochNumber <= 1 && epochEndDate != 0);\n"+
			"    }\n"+
			"}\n")
	out = t29Raw(t, t29Index(t, swapped), validation.VNull(), "short-circuitable-guard")
	if len(vList(out, "rows")) != 0 || vInt(out, "sites") != 1 {
		t.Errorf("swapped rows=%s sites=%d", t29JSON(vGet(out, "rows")),
			vInt(out, "sites"))
	}
	kinds = nil
	for _, b := range vObjList(out, "blind") {
		kinds = append(kinds, vStr(b, "kind"))
	}
	if got, w := t29StrJSON(kinds), t29StrJSON([]string{"safety-before-sentinel"}); got != w {
		t.Errorf("swapped blind kinds = %s, want %s", got, w)
	}
}

func TestAccumulatorBasisSkewFiresOnBuggyAndIsSilentOnClean(t *testing.T) {
	buggy := t29Index(t, filepath.Join(t29ProbesDir, "accumulator", "buggy"))
	out := t29Raw(t, buggy, validation.VNull(), "accumulator-basis-skew")
	if vInt(out, "sites") != 1 || len(vList(out, "blind")) != 0 {
		t.Fatalf("sites=%d blind=%s", vInt(out, "sites"), t29JSON(vGet(out, "blind")))
	}
	row := vList(out, "rows")[0]
	if vStr(row, "contract") != "RewardManager" {
		t.Errorf("contract = %q", vStr(row, "contract"))
	}
	if vStr(row, "consumer") != "_updateRewardIndex" {
		t.Errorf("consumer = %q", vStr(row, "consumer"))
	}
	if vStr(row, "accumulator") != "index" {
		t.Errorf("accumulator = %q", vStr(row, "accumulator"))
	}
	if vStr(row, "companion") != "rewardState" {
		t.Errorf("companion = %q", vStr(row, "companion"))
	}
	if !(0 < vInt(row, "rounded_line") && vInt(row, "rounded_line") < vInt(row, "plain_line")) {
		t.Errorf("rounded_line=%d plain_line=%d", vInt(row, "rounded_line"),
			vInt(row, "plain_line"))
	}
	if vInt(row, "tier") != 0 || vStr(row, "gate") != "unprivileged" {
		t.Errorf("tier=%d gate=%q", vInt(row, "tier"), vStr(row, "gate"))
	}

	clean := t29Index(t, filepath.Join(t29ProbesDir, "accumulator", "clean"))
	out = t29Raw(t, clean, validation.VNull(), "accumulator-basis-skew")
	if len(vList(out, "rows")) != 0 || vInt(out, "sites") != 0 {
		t.Errorf("clean rows=%s sites=%d; no rounding primitive -> no site at all",
			t29JSON(vGet(out, "rows")), vInt(out, "sites"))
	}

	blind := t29Index(t, filepath.Join(t29ProbesDir, "accumulator", "blind"))
	out = t29Raw(t, blind, validation.VNull(), "accumulator-basis-skew")
	if len(vList(out, "rows")) != 0 || vInt(out, "sites") != 1 {
		t.Errorf("blind rows=%s sites=%d", t29JSON(vGet(out, "rows")),
			vInt(out, "sites"))
	}
	kinds := []string{}
	for _, b := range vObjList(out, "blind") {
		kinds = append(kinds, vStr(b, "kind"))
	}
	if got, w := t29StrJSON(kinds), t29StrJSON([]string{"no-companion-write"}); got != w {
		t.Errorf("blind kinds = %s, want %s", got, w)
	}
}

const t29TwoShapes = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

contract TwoShapes {
    using PMath for uint256;

    uint256 public epochEndDate;
    uint256 public deadline;
    uint256 public rewardIndex;
    uint256 public rewardRate;
    uint256 public lastBalance;
    mapping(address => uint256) public lastWithdrawRequest;

    function claimWithdraw(address user) external {
        if (epochEndDate != 0 && lastWithdrawRequest[user] >= epochEndDate) {
            revert NotAllowed();
        }
    }

    function finalize(uint256 batchIndex) external {
        if (deadline != 0 && batchIndex >= deadline) {
            revert TooLate();
        }
    }

    function accrueIndex(uint256 accrued, uint256 totalShares) external {
        if (totalShares != 0) {
            rewardIndex += accrued.divDown(totalShares);
        }
        lastBalance += accrued;
    }

    function accrueRate(uint256 accrued, uint256 totalShares) external {
        if (totalShares != 0) {
            rewardRate += accrued.divDown(totalShares);
        }
        lastBalance += accrued;
    }
}
`

func TestTwoRowsOfEachNewProbeGetDistinctRowIDs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shapes")
	t29Write(t, filepath.Join(root, "TwoShapes.sol"), t29TwoShapes)
	surface, err := BuildSurface(t29Index(t, root), validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	guards := t29Rows(surface, "short-circuitable-guard")
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(guards, "sentinel"))),
		t29StrJSON([]string{"deadline != 0", "epochEndDate != 0"}); got != w {
		t.Errorf("sentinels = %s, want %s", got, w)
	}
	skews := t29Rows(surface, "accumulator-basis-skew")
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(skews, "accumulator"))),
		t29StrJSON([]string{"rewardIndex", "rewardRate"}); got != w {
		t.Errorf("accumulators = %s, want %s", got, w)
	}
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(skews, "companion"))),
		t29StrJSON([]string{"lastBalance"}); got != w {
		t.Errorf("companions = %s, want %s", got, w)
	}
	guardIDs := map[string]struct{}{}
	for _, r := range guards {
		guardIDs[vStr(r, "row_id")] = struct{}{}
	}
	if len(guardIDs) != len(guards) {
		t.Error("guard row ids are not distinct")
	}
	skewIDs := map[string]struct{}{}
	for _, r := range skews {
		skewIDs[vStr(r, "row_id")] = struct{}{}
	}
	if len(skewIDs) != len(skews) {
		t.Error("skew row ids are not distinct")
	}
}

func TestNewProbeShapeFollowsTheAnchorLineButRowIDDoesNot(t *testing.T) {
	src := filepath.Join(t.TempDir(), "tree")
	t29CopyTree(t, filepath.Join(t29ProbesDir, "short_circuit", "buggy"), src)
	t29CopyTree(t, filepath.Join(t29ProbesDir, "accumulator", "buggy"),
		filepath.Join(src, "acc"))
	before, err := BuildSurface(t29Index(t, src), validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"EpochQueue.sol", filepath.Join("acc", "RewardManager.sol")} {
		p := filepath.Join(src, name)
		t29Write(t, p, "\n\n"+t29Read(t, p))
	}
	after, err := BuildSurface(t29Index(t, src), validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"short-circuitable-guard", "accumulator-basis-skew"} {
		rowsA := t29Rows(before, pid)
		rowsB := t29Rows(after, pid)
		if len(rowsA) == 0 || len(rowsB) == 0 {
			t.Fatalf("%s: no rows", pid)
		}
		a, b := rowsA[0], rowsB[0]
		if vStr(a, "row_id") != vStr(b, "row_id") {
			t.Errorf("%s: row_id moved", pid)
		}
		if RowShapeSha(a) == RowShapeSha(b) {
			t.Errorf("%s: row_shape_sha did not move", pid)
		}
		for _, field := range []string{"guard_line", "rounded_line"} {
			if !vTruthy(vGet(a, field)) {
				continue
			}
			if vInt(b, field) != vInt(a, field)+2 {
				t.Errorf("%s: %s %d != %d+2", pid, field, vInt(b, field),
					vInt(a, field))
			}
		}
	}
}

func TestNewAxesPublishSitesRowsAndTheFourStateStatus(t *testing.T) {
	surface, err := BuildSurface(t29Index(t,
		filepath.Join(t29ProbesDir, "accumulator", "buggy")), validation.VNull(),
		12, 40, 3, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if vInt(vGet(surface, "stats"), "probes") != 6 {
		t.Errorf("stats.probes = %d", vInt(vGet(surface, "stats"), "probes"))
	}
	axis := t29Axis(t, surface, "accumulator-basis-skew")
	if vStr(axis, "axis") != "accumulator-skew" || vStr(axis, "lens") != "L-01" {
		t.Errorf("axis=%q lens=%q", vStr(axis, "axis"), vStr(axis, "lens"))
	}
	got := []int{vInt(axis, "sites"), vInt(axis, "rows"), vInt(axis, "emitted"),
		vInt(axis, "tail")}
	if want := []int{1, 1, 1, 0}; t29JSON(intArr(got)) != t29JSON(intArr(want)) {
		t.Errorf("counters = %v, want %v", got, want)
	}
	if vStr(axis, "status") != "emitted" || len(vList(axis, "blind")) != 0 {
		t.Errorf("status=%q blind=%s", vStr(axis, "status"),
			t29JSON(vGet(axis, "blind")))
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}

	blind, err := BuildSurface(t29Index(t,
		filepath.Join(t29ProbesDir, "accumulator", "blind")), validation.VNull(),
		12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	axis = t29Axis(t, blind, "accumulator-basis-skew")
	if vStr(axis, "status") != "blind" || vInt(axis, "sites") != 1 {
		t.Errorf("blind status=%q sites=%d", vStr(axis, "status"),
			vInt(axis, "sites"))
	}
	key := vStr(vList(axis, "blind")[0], "key")
	msg := AxisSurfaceBlocker(axis, nil)
	if msg == "" || !strings.Contains(msg, "--anchor-blind") {
		t.Errorf("blocker = %q", msg)
	}
	blank := validation.VObj(kv("anchor_blind", validation.VStr(key)),
		kv("reason", validation.VStr("checked the caller by hand")),
		kv("actor", validation.VStr("operator")))
	if got := AxisSurfaceBlocker(axis, &blank); got != "" {
		t.Errorf("attested blocker = %q", got)
	}
	if err := validation.Validate(blind, "probe_surface", 1); err != nil {
		t.Fatalf("validate(blind): %v", err)
	}
}

func TestBlankStoreKeysTheAxisWhenThreeProbesShareTheLens(t *testing.T) {
	root := t.TempDir()
	t29CopyTree(t, filepath.Join(t29ProbesDir, "accumulator", "blind"),
		filepath.Join(root, "acc"))
	t29CopyTree(t, filepath.Join(t29ProbesDir, "short_circuit", "clean"),
		filepath.Join(root, "guard"))
	camp, err := state.Init(t.TempDir(), "Lens sharing", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(camp, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := BuildSurface(idx, validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatal(err)
	}

	acc := t29Axis(t, surface, "accumulator-basis-skew")
	guard := t29Axis(t, surface, "short-circuitable-guard")
	if vStr(acc, "status") != "blind" || vStr(guard, "status") != "blind" {
		t.Fatalf("statuses acc=%q guard=%q", vStr(acc, "status"),
			vStr(guard, "status"))
	}
	// IMPORTANT 6: the A4 CLI contract spells the axis as the lens. On a
	// shared lens the cited key is what resolves the spelling to ONE axis.
	first, err := SetBlank(camp, "L-01", vStr(vList(acc, "blind")[0], "key"),
		"no companion write in this tree", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if vStr(first, "axis") != "L-01" || vStr(first, "probe_axis") != "accumulator-skew" {
		t.Errorf("first = %s", t29JSON(first))
	}
	second, err := SetBlank(camp, "L-01", vStr(vList(guard, "blind")[0], "key"),
		"the conjunction has no sentinel conjunct", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if vStr(second, "probe_axis") != "guard-short-circuit" {
		t.Errorf("second = %s", t29JSON(second))
	}
	blanks, err := CampaignBlanks(camp)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range blanks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got, w := t29StrJSON(keys),
		t29StrJSON([]string{"accumulator-skew", "guard-short-circuit"}); got != w {
		t.Errorf("blanks = %s, want %s; one lens, two attested axes", got, w)
	}
	if t29JSON(vGet(blanks["accumulator-skew"], "anchor_blind")) !=
		t29JSON(vGet(first, "anchor_blind")) {
		t.Error("accumulator-skew attestation clobbered")
	}
	if t29JSON(vGet(blanks["guard-short-circuit"], "anchor_blind")) !=
		t29JSON(vGet(second, "anchor_blind")) {
		t.Error("guard-short-circuit attestation clobbered")
	}
	// a key NO axis on the lens published fails naming the real blind keys
	_, err = SetBlank(camp, "L-01", "not-a-blind-key",
		"cites a key nobody published", "operator")
	if err == nil {
		t.Fatal("set_blank(not-a-blind-key) did not raise")
	}
	if !strings.Contains(err.Error(), vStr(vList(acc, "blind")[0], "key")) {
		t.Errorf("err = %v does not name the accumulator key", err)
	}
	if !strings.Contains(err.Error(), vStr(vList(guard, "blind")[0], "key")) {
		t.Errorf("err = %v does not name the guard key", err)
	}
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(st, "campaign_state", 1); err != nil {
		t.Fatalf("validate campaign_state: %v", err)
	}
}

// ---- fix round 1: the six review findings ---------------------------------

const t29PlainCopy = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

contract Vault {
    using PMath for uint256;

    uint256 public rewardIndex;
    uint256 public lastBalance;

    function accrue(uint256 accrued, uint256 totalShares) external {
        uint256 index = rewardIndex;
        if (totalShares != 0) {
            index += accrued.divDown(totalShares);
        }
        rewardIndex = index;
        lastBalance += accrued;
    }

    function accrueCompound(uint256 accrued, uint256 totalShares) external {
        uint256 index = rewardIndex;
        if (totalShares != 0) {
            index += accrued.divDown(totalShares);
        }
        rewardIndex += index;
        lastBalance += accrued;
    }
}
`

func TestAccumulatorPersistsThroughAPlainCopy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "plaincopy")
	t29Write(t, filepath.Join(root, "Vault.sol"), t29PlainCopy)
	out := t29Raw(t, t29Index(t, root), validation.VNull(), "accumulator-basis-skew")
	if vInt(out, "sites") != 2 {
		t.Errorf("sites = %d; both rounded accumulator updates are sites",
			vInt(out, "sites"))
	}
	if len(vList(out, "blind")) != 0 {
		t.Errorf("blind = %s", t29JSON(vGet(out, "blind")))
	}
	if got, w := t29StrJSON(sortedStrSet(t29SetOf(vList(out, "rows"), "consumer"))),
		t29StrJSON([]string{"accrue", "accrueCompound"}); got != w {
		t.Errorf("consumers = %s, want %s", got, w)
	}
	for _, row := range vObjList(out, "rows") {
		if vStr(row, "accumulator") != "index" {
			t.Errorf("accumulator = %q", vStr(row, "accumulator"))
		}
		if vStr(row, "companion") != "lastBalance" {
			t.Errorf("companion = %q", vStr(row, "companion"))
		}
		if !(vInt(row, "rounded_line") < vInt(row, "plain_line")) {
			t.Errorf("rounded_line=%d plain_line=%d", vInt(row, "rounded_line"),
				vInt(row, "plain_line"))
		}
	}
}

const t29Inherited = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

contract Base {
    uint256 public rewardIndex;
    uint256 public lastBalance;
}

contract Child is Base {
    using PMath for uint256;

    function accrue(uint256 accrued, uint256 totalShares) external {
        if (totalShares != 0) {
            rewardIndex += accrued.divDown(totalShares);
        }
        lastBalance += accrued;
    }
}
`

func TestAccumulatorRecognizesStateDeclaredInABaseContract(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inherited")
	t29Write(t, filepath.Join(root, "Child.sol"), t29Inherited)
	out := t29Raw(t, t29Index(t, root), validation.VNull(), "accumulator-basis-skew")
	if vInt(out, "sites") != 1 || len(vList(out, "blind")) != 0 {
		t.Fatalf("sites=%d blind=%s", vInt(out, "sites"), t29JSON(vGet(out, "blind")))
	}
	row := vList(out, "rows")[0]
	if vStr(row, "contract") != "Child" {
		t.Errorf("contract = %q", vStr(row, "contract"))
	}
	if vStr(row, "accumulator") != "rewardIndex" {
		t.Errorf("accumulator = %q", vStr(row, "accumulator"))
	}
	if vStr(row, "companion") != "lastBalance" {
		t.Errorf("companion = %q", vStr(row, "companion"))
	}
	if !(vInt(row, "rounded_line") < vInt(row, "plain_line")) {
		t.Errorf("rounded_line=%d plain_line=%d", vInt(row, "rounded_line"),
			vInt(row, "plain_line"))
	}
}

const t29PersistenceCompanion = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library PMath {
    function divDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }
}

contract Solo {
    struct RewardState {
        uint256 index;
        uint256 lastBalance;
    }

    using PMath for uint256;

    mapping(address => RewardState) public rewardState;
    uint256 public totalAccrued;

    // the ONLY other state write is the accumulator's own persistence: no
    // basis skew is established.
    function poke(address token, uint256 accrued, uint256 totalShares) external {
        uint256 index = rewardState[token].index;
        if (totalShares != 0) {
            index += accrued.divDown(totalShares);
        }
        rewardState[token].index = index;
    }

    function pokeWithCompanion(address token, uint256 accrued,
                               uint256 totalShares) external {
        uint256 index = rewardState[token].index;
        if (totalShares != 0) {
            index += accrued.divDown(totalShares);
        }
        rewardState[token].index = index;
        totalAccrued += accrued;
    }
}
`

func TestAccumulatorCompanionIsNotTheAccumulatorsOwnPersistence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "solo")
	t29Write(t, filepath.Join(root, "Solo.sol"), t29PersistenceCompanion)
	out := t29Raw(t, t29Index(t, root), validation.VNull(), "accumulator-basis-skew")
	if vInt(out, "sites") != 2 {
		t.Errorf("sites = %d; both functions round a persisted accumulator",
			vInt(out, "sites"))
	}
	rows := map[string]validation.Value{}
	for _, r := range vObjList(out, "rows") {
		rows[vStr(r, "consumer")] = r
	}
	keys := []string{}
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got, w := t29StrJSON(keys),
		t29StrJSON([]string{"pokeWithCompanion"}); got != w {
		t.Fatalf("rows = %s", t29JSON(vGet(out, "rows")))
	}
	row := rows["pokeWithCompanion"]
	if vStr(row, "accumulator") != "index" {
		t.Errorf("accumulator = %q", vStr(row, "accumulator"))
	}
	if vStr(row, "companion") != "totalAccrued" {
		t.Errorf("companion = %q; the persistence write itself is not a companion",
			vStr(row, "companion"))
	}
	if !(vInt(row, "rounded_line") < vInt(row, "plain_line")) {
		t.Errorf("rounded_line=%d plain_line=%d", vInt(row, "rounded_line"),
			vInt(row, "plain_line"))
	}
	kinds := []string{}
	for _, b := range vObjList(out, "blind") {
		if vStr(b, "function") == "poke" {
			kinds = append(kinds, vStr(b, "kind"))
		}
	}
	if got, w := t29StrJSON(kinds),
		t29StrJSON([]string{"no-companion-write"}); got != w {
		t.Errorf("poke blind kinds = %s, want %s", got, w)
	}
}

func TestLegacyLensAttestationSurvivesASiblingAxisAttestation(t *testing.T) {
	root := t.TempDir()
	t29CopyTree(t, filepath.Join(t29ProbesDir, "accumulator", "blind"),
		filepath.Join(root, "acc"))
	t29CopyTree(t, filepath.Join(t29ProbesDir, "short_circuit", "clean"),
		filepath.Join(root, "guard"))
	t29CopyTree(t, filepath.Join(t29ProbesDir, "assertion_strength", "clean"),
		filepath.Join(root, "blind"))
	camp, err := state.Init(t.TempDir(), "Legacy blanks", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(camp, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	surface, err := BuildSurface(idx, validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"probe_surface.json"), surface, "probe_surface"); err != nil {
		t.Fatal(err)
	}
	acc := t29Axis(t, surface, "accumulator-basis-skew")
	enforce := t29Axis(t, surface, "assertion-strength")
	if vStr(acc, "status") != "blind" || vStr(enforce, "status") != "blind" {
		t.Fatalf("statuses acc=%q enforce=%q", vStr(acc, "status"),
			vStr(enforce, "status"))
	}

	legacyL01 := validation.VObj(
		kv("axis", validation.VStr("L-01")),
		kv("anchor_blind", validation.VStr("Legacy::claim::epochEndDate")),
		kv("reason", validation.VStr("attested before L-01 carried three probes")),
		kv("actor", validation.VStr("operator")),
		kv("at", validation.VStr("2026-01-01T00:00:00Z")))
	legacyL03 := validation.VObj(
		kv("axis", validation.VStr("L-03")),
		kv("anchor_blind", validation.VStr("Legacy::finalize::root")),
		kv("reason", validation.VStr("attested before the store keyed axes")),
		kv("actor", validation.VStr("operator")),
		kv("at", validation.VStr("2026-01-01T00:00:00Z")))
	st, err := camp.State()
	if err != nil {
		t.Fatal(err)
	}
	vSet(&st, "probe_blanks", validation.VArr(legacyL01, legacyL03))
	if err := defaultSaveState(camp, st); err != nil {
		t.Fatal(err)
	}

	if _, err := SetBlank(camp, "accumulator-skew",
		vStr(vList(acc, "blind")[0], "key"),
		"no companion write in this tree", "operator"); err != nil {
		t.Fatal(err)
	}
	st, err = camp.State()
	if err != nil {
		t.Fatal(err)
	}
	entries := vObjList(st, "probe_blanks")
	if len(entries) != 3 {
		t.Fatalf("entries = %d: %s", len(entries), t29JSON(vGet(st, "probe_blanks")))
	}
	hasEntry := func(entry validation.Value) bool {
		for _, e := range entries {
			if t29JSON(e) == t29JSON(entry) {
				return true
			}
		}
		return false
	}
	if !hasEntry(legacyL01) {
		t.Error("the pre-A6 L-01 attestation must survive a sibling axis")
	}
	if !hasEntry(legacyL03) {
		t.Error("an attestation on another lens is untouched")
	}
	blanks, err := CampaignBlanks(camp)
	if err != nil {
		t.Fatal(err)
	}
	// A pre-A6 `axis: L-01` entry has no probe_axis, so it resolves through
	// the LENS fallback: Python builds by_lens from registered_axes(), which
	// is sorted by axis, so L-01 (three probes) resolves to the sorted-last
	// axis on that lens — `liveness`. Repeated so a map-order-dependent
	// implementation cannot hide behind a lucky run.
	seen := map[string]struct{}{}
	for i := 0; i < 20; i++ {
		again, err := CampaignBlanks(camp)
		if err != nil {
			t.Fatal(err)
		}
		seen[vStr(again["liveness"], "anchor_blind")] = struct{}{}
		if t29JSON(again["liveness"]) != t29JSON(legacyL01) {
			t.Errorf("campaign_blanks()[liveness] = %s, want %s (the L-01 lens "+
				"resolves to its sorted-last axis; call %d)",
				t29JSON(again["liveness"]), t29JSON(legacyL01), i)
			break
		}
	}
	if t29JSON(blanks["liveness"]) != t29JSON(legacyL01) {
		t.Errorf("campaign_blanks()[liveness] = %s, want %s (observed %d "+
			"distinct resolutions over 20 calls: %v)",
			t29JSON(blanks["liveness"]), t29JSON(legacyL01), len(seen), seen)
	}
	if vStr(blanks["accumulator-skew"], "probe_axis") != "accumulator-skew" {
		t.Errorf("accumulator-skew probe_axis = %q",
			vStr(blanks["accumulator-skew"], "probe_axis"))
	}

	if _, err := SetBlank(camp, "enforcement-timing",
		vStr(vList(enforce, "blind")[0], "key"),
		"every published near key was audited by hand", "operator"); err != nil {
		t.Fatal(err)
	}
	st, err = camp.State()
	if err != nil {
		t.Fatal(err)
	}
	entries = vObjList(st, "probe_blanks")
	if hasEntry(legacyL03) {
		t.Error("a singleton lens resolves to one axis: re-attesting replaces it")
	}
	l03 := []validation.Value{}
	for _, e := range entries {
		if vStr(e, "axis") == "L-03" {
			l03 = append(l03, e)
		}
	}
	if len(l03) != 1 || vStr(l03[0], "probe_axis") != "enforcement-timing" {
		t.Errorf("L-03 entries = %s", t29JSON(vGet(st, "probe_blanks")))
	}
	if !hasEntry(legacyL01) {
		t.Error("legacy L-01 attestation lost")
	}
	if err := validation.Validate(st, "campaign_state", 1); err != nil {
		t.Fatalf("validate campaign_state: %v", err)
	}
}

func TestEveryNewProbeAnchorFieldMovesTheRowShape(t *testing.T) {
	identityTracked := map[string]struct{}{"concept_keys": {}, "custody": {},
		"trust": {}}
	extraShape := map[string]struct{}{"siblings": {}, "stranded_entry": {}}
	shapeSet := map[string]struct{}{}
	for _, f := range shapeAnchorFields {
		shapeSet[f] = struct{}{}
	}
	for _, pid := range ProbeIDs() {
		for anchor, field := range anchorFields[pid] {
			base := strings.TrimSuffix(field, "_line")
			_, inShape := shapeSet[base]
			_, inIdentity := identityTracked[field]
			_, inExtra := extraShape[field]
			if !inShape && !inIdentity && !inExtra {
				t.Errorf("%s/%s -> %s is pinned nowhere the reopen check can see",
					pid, anchor, field)
			}
		}
	}

	src := filepath.Join(t.TempDir(), "tree")
	t29CopyTree(t, filepath.Join(t29ProbesDir, "short_circuit", "buggy"), src)
	t29CopyTree(t, filepath.Join(t29ProbesDir, "accumulator", "buggy"),
		filepath.Join(src, "acc"))
	surface, err := BuildSurface(t29Index(t, src), validation.VNull(), 12, 40, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"short-circuitable-guard", "accumulator-basis-skew"} {
		rows := t29Rows(surface, pid)
		if len(rows) == 0 {
			t.Fatalf("%s: no rows", pid)
		}
		row := rows[0]
		before := RowShapeSha(row)
		for anchor, field := range anchorFields[pid] {
			base := strings.TrimSuffix(field, "_line")
			for _, name := range []string{base, base + "_line"} {
				if !vTruthy(vGet(row, name)) {
					continue
				}
				mutated := t29Clone(t, row)
				value := vGet(row, name)
				if value.Kind == validation.Int {
					vSet(&mutated, name, validation.VInt(value.I+1))
				} else {
					vSet(&mutated, name, validation.VStr(pyStr(value)+"~"))
				}
				if RowShapeSha(mutated) == before {
					t.Errorf("%s/%s: moving %s did not move row_shape_sha",
						pid, anchor, name)
				}
			}
		}
	}
}

// ---- sentinel-form rows (recall wave, task 1) -----------------------------

// TestAssertionStrengthSentinelGuard pins the sentinel clause: a consumer
// whose own guard is a zero-check carries own_form=own_guard_text and the
// adversarial why; the class-4 join still happens (the row is emitted) —
// the point is that "covered" now demands the passing value.
func TestAssertionStrengthSentinelGuard(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "sentinel"))
	out := t29Raw(t, idx, validation.VNull(), "assertion-strength")
	rows := vList(out, "rows")
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1: %s", len(rows), t29JSON(out))
	}
	surface, err := BuildSurfaceOpts(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z", ProdProbeOpts())
	if err != nil {
		t.Fatalf("BuildSurfaceOpts: %v", err)
	}
	joined := assertionRows(surface)
	if len(joined) != 1 {
		t.Fatalf("surface assertion rows = %d, want 1: %s", len(joined),
			t29JSON(surface))
	}
	row := joined[0]
	if vStr(row, "own_form") != "sentinel" {
		t.Errorf("own_form = %q, want sentinel", vStr(row, "own_form"))
	}
	if !strings.Contains(vStr(row, "own_guard_text"), "!= bytes32(0)") {
		t.Errorf("own_guard_text = %q", vStr(row, "own_guard_text"))
	}
	if !strings.Contains(vStr(row, "why"), "SENTINEL check") ||
		!strings.Contains(vStr(row, "why"), "Name the value that passes") {
		t.Errorf("why = %q — want the adversarial sentinel why", vStr(row, "why"))
	}
}

// TestSentinelFormIsConditional is the negative control for the clause: it is
// NOT a property of every joined row, and it is NOT on the reference surface.
// Two ways to be wrong are pinned — a row whose consumer carries no guard at
// all (own_class 0) keeps the reference why, and the zero ProbeOpts (the
// byte-pinned parity path) never grows the field.
func TestSentinelFormIsConditional(t *testing.T) {
	// (a) an unguarded consumer: joined, but nothing sentinel about it.
	plain, err := BuildSurfaceOpts(parityLoad(t, "index_collapse"),
		parityLoad(t, "model"), 12, 40, 3, "2026-01-01T00:00:00Z",
		ProdProbeOpts())
	if err != nil {
		t.Fatalf("BuildSurfaceOpts: %v", err)
	}
	rows := assertionRows(plain)
	if len(rows) == 0 {
		t.Fatal("collapse fixture has no assertion-strength row")
	}
	for _, row := range rows {
		if _, ok := vGetPresent(row, "own_form"); ok {
			t.Errorf("row %s has own_form %q under a class-%d own guard",
				vStr(row, "row_id"), vStr(row, "own_form"), vInt(row, "own_class"))
		}
		if _, ok := vGetPresent(row, "own_guard_text"); ok {
			t.Errorf("row %s has own_guard_text without own_form",
				vStr(row, "row_id"))
		}
	}

	// (b) the reference surface of the sentinel fixture itself: no clause.
	idx := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "sentinel"))
	reference, err := BuildSurface(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("BuildSurface: %v", err)
	}
	for _, row := range vList(reference, "rows") {
		if _, ok := vGetPresent(row, "own_form"); ok {
			t.Errorf("reference row %s carries own_form — the field is not "+
				"opt-in and a pinned golden would move", vStr(row, "row_id"))
		}
	}
}
