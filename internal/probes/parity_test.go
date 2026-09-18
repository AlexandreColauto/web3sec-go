package probes

// parity_test.go pins the cross-language contract: every golden in
// testdata/golden is the ORDER-PRESERVING JSON dump of the LIVE Python module
// (webv2/probes.py) for one (fixture tree, probe / knobs / vector) input. The
// port must reproduce each byte-for-byte. Regenerate with
// `refdump.py [untracked]` in web3sec-final; never hand-edit a golden.

import (
	"fmt"
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

// parityCases are the fixture trees refdump.py indexed.
var parityCases = []string{"assertion_buggy", "assertion_clean",
	"assertion_weak", "custody_buggy", "custody_clean", "custody_cast",
	"cursor_buggy", "cursor_clean", "short_buggy", "short_clean", "acc_buggy",
	"acc_clean", "acc_blind", "collapse", "siblings"}

func parityLoad(t *testing.T, name string) validation.Value {
	t.Helper()
	v, err := validation.ReadJson(filepath.Join("testdata", "golden", name+".json"))
	if err != nil {
		t.Fatalf("load golden %s: %v", name, err)
	}
	return v
}

// parityEqual compares two values as the module serializes them (insertion
// order, Python float/int text).
func parityEqual(t *testing.T, name string, got, want validation.Value) {
	t.Helper()
	a := validation.DumpsOrdered(got, false)
	b := validation.DumpsOrdered(want, false)
	if a == b {
		return
	}
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	lo := i - 120
	if lo < 0 {
		lo = 0
	}
	hi1, hi2 := i+200, i+200
	if hi1 > len(a) {
		hi1 = len(a)
	}
	if hi2 > len(b) {
		hi2 = len(b)
	}
	t.Fatalf("%s diverges at %d\n got: ...%s...\nwant: ...%s...", name, i,
		a[lo:hi1], b[lo:hi2])
}

// TestParityRawProbes: all six raw probe outputs for every fixture tree.
func TestParityRawProbes(t *testing.T) {
	model := parityLoad(t, "model")
	for _, name := range parityCases {
		index := parityLoad(t, "index_"+name)
		for _, pid := range ProbeIDs() {
			out, err := RawProbe(index, model, pid)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, pid, err)
			}
			parityEqual(t, fmt.Sprintf("raw_%s_%s", name, pid), out,
				parityLoad(t, fmt.Sprintf("raw_%s_%s", name, pid)))
		}
	}
}

// TestParitySurfaces: the assembled surface for every fixture tree, plus the
// ranked tree at three quota settings (the floor-reserve warning arithmetic).
func TestParitySurfaces(t *testing.T) {
	model := parityLoad(t, "model")
	for _, name := range parityCases {
		index := parityLoad(t, "index_"+name)
		got, err := BuildSurface(index, model, 12, 40, 3,
			"2026-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("surface %s: %v", name, err)
		}
		parityEqual(t, "surface_"+name, got, parityLoad(t, "surface_"+name))
	}
	ranked := parityLoad(t, "index_ranked")
	for _, tc := range []struct {
		name                  string
		perAxis, total, floor int
	}{
		{"surface_ranked", 12, 40, 3},
		{"surface_ranked_total2", 12, 2, 1},
		{"surface_ranked_total2f3", 12, 2, 3},
	} {
		got, err := BuildSurface(ranked, model, tc.perAxis, tc.total, tc.floor,
			"2026-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		parityEqual(t, tc.name, got, parityLoad(t, tc.name))
	}
}

// TestParityTrustVectors: the gate/trust join, token normalization and the
// test-double path classifier against the Python vectors.
func TestParityTrustVectors(t *testing.T) {
	model := parityLoad(t, "model")
	trust := validation.VObj()
	set := func(k string, v validation.Value) {
		trust.O = append(trust.O, validation.KV{K: k, V: v})
	}
	tier := func(mods []string) validation.Value {
		return validation.VInt(int64(TierOfGate(mods, model)))
	}
	set("tier_onlyActiveStaker", tier([]string{"onlyActiveStaker"}))
	set("tier_onlyOwner", tier([]string{"onlyOwner"}))
	set("tier_onlyGuardian", tier([]string{"onlyGuardian"}))
	set("tier_onlyCounterpart_none", validation.VInt(int64(
		TierOfGate([]string{"onlyCounterpart"}, validation.VNull()))))
	set("tier_onlyRollup_none", validation.VInt(int64(
		TierOfGate([]string{"onlyRollup"}, validation.VNull()))))
	set("tier_onlyMessenger_none", validation.VInt(int64(
		TierOfGate([]string{"onlyMessenger"}, validation.VNull()))))
	set("tier_onlyStaker_none", validation.VInt(int64(
		TierOfGate([]string{"onlyStaker"}, validation.VNull()))))
	set("tier_empty", validation.VInt(int64(TierOfGate(nil, model))))
	set("tier_nonReentrant", validation.VInt(int64(
		TierOfGate([]string{"nonReentrant"}, model))))
	set("tier_both", validation.VInt(int64(
		TierOfGate([]string{"onlyOwner", "onlyActiveStaker"}, model))))
	set("tier_owner_none", validation.VInt(int64(
		TierOfGate([]string{"onlyOwner"}, validation.VNull()))))
	set("resolve_staker", ResolveGate("onlyActiveStaker", model))
	set("resolve_counterpart", ResolveGate("onlyCounterpart", validation.VNull()))
	set("resolve_guardian", ResolveGate("onlyGuardian", model))
	set("norm_onlyActiveStaker", parityStrArr(NormTokens("onlyActiveStaker")))
	set("norm_active_staker", parityStrArr(NormTokens("active_staker")))
	td := validation.VObj()
	for _, p := range []string{"contracts/mock/MockRollup.sol",
		"test/Harness.sol", "src/tests/Helper.sol", "contracts/MockRollup.sol",
		"contracts/RollupMock.sol", "contracts/Rollup.t.sol",
		"contracts/l1/rollup/Rollup.sol", "contracts/l1/Rollup.sol", ""} {
		td.O = append(td.O, validation.KV{K: p,
			V: validation.VBool(IsTestDoublePath(p))})
	}
	td.O = append(td.O, validation.KV{K: "null",
		V: validation.VBool(IsTestDoublePath(""))})
	set("testdouble", td)
	parityEqual(t, "trust", trust, parityLoad(t, "trust"))
}

// TestParityRowIDVector: the content-derived row id.
func TestParityRowIDVector(t *testing.T) {
	row := validation.VObj(
		validation.KV{K: "probe", V: validation.VStr("assertion-strength")},
		validation.KV{K: "contract", V: validation.VStr("Rollup")},
		validation.KV{K: "consumer", V: validation.VStr("commitBatch")},
		validation.KV{K: "asserter", V: validation.VStr("finalizeBatch")},
		validation.KV{K: "concept_keys", V: parityStrArr([]string{"prev:state:root"})})
	got := validation.VObj(validation.KV{K: "row_id",
		V: validation.VStr(RowIDFor(row))})
	parityEqual(t, "rowid_vector", got, parityLoad(t, "rowid_vector"))
}

func parityStrArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}
