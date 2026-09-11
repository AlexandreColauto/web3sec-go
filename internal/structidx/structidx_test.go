package structidx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"websec/internal/validation"
)

func loadJSON(t *testing.T, path string) validation.Value {
	t.Helper()
	v, err := validation.ReadJson(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return v
}

func canonEqual(t *testing.T, label string, got, want validation.Value) {
	t.Helper()
	g, w := validation.CanonCompact(got), validation.CanonCompact(want)
	if g != w {
		gj, _ := json.MarshalIndent(got, "", "  ")
		wj, _ := json.MarshalIndent(want, "", "  ")
		n := 0
		for n < len(g) && n < len(w) && g[n] == w[n] {
			n++
		}
		lo := n - 200
		if lo < 0 {
			lo = 0
		}
		hi := n + 300
		if hi > len(g) {
			hi = len(g)
		}
		t.Errorf("%s: first divergence at byte %d\n got: ...%s\nwant: ...%s\n--- got ---\n%s\n--- want ---\n%s",
			label, n, slice(g, lo, hi), slice(w, max0(n-200), n+300),
			truncate(string(gj)), truncate(string(wj)))
	}
}

func slice(s string, lo, hi int) string {
	if lo < 0 {
		lo = 0
	}
	if hi > len(s) {
		hi = len(s)
	}
	if lo > hi {
		return ""
	}
	return s[lo:hi]
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func truncate(s string) string {
	if len(s) > 4000 {
		return s[:4000] + "\n...(truncated)"
	}
	return s
}

// TestIndexTreeGolden: _index_tree output must be byte-identical to the LIVE
// Python twin for every fixture tree.
func TestIndexTreeGolden(t *testing.T) {
	// uni pins the Unicode parity layer: identifiers that continue past an
	// ASCII start, keywords/guards preceded by a Unicode word character in a
	// comment or string, and the ensure_ascii split of a non-ASCII filename.
	for _, name := range []string{"structural", "v1", "sink", "sink2", "amp",
		"cast", "uni"} {
		t.Run(name, func(t *testing.T) {
			got, err := IndexTreeValue(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("IndexTreeValue: %v", err)
			}
			want := loadJSON(t, filepath.Join("testdata", name+"_index.json"))
			canonEqual(t, name, got, want)
		})
	}
}

func TestConceptKeysVectors(t *testing.T) {
	vec := loadJSON(t, "testdata/vectors.json")
	for _, c := range objList(objAt(vec, "concept_keys")) {
		expr := objStr(c, "expr")
		want := strList(objAt(c, "keys"))
		got := ConceptKeys(expr)
		if len(got) != len(want) {
			t.Errorf("concept_keys(%q) = %v, want %v", expr, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("concept_keys(%q) = %v, want %v", expr, got, want)
				break
			}
		}
	}
}

func TestSplitIdentVectors(t *testing.T) {
	vec := loadJSON(t, "testdata/vectors.json")
	for _, c := range objList(objAt(vec, "split_ident")) {
		name := objStr(c, "name")
		want := strList(objAt(c, "parts"))
		got := splitIdent(name)
		if len(got) != len(want) {
			t.Errorf("splitIdent(%q) = %v, want %v", name, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("splitIdent(%q) = %v, want %v", name, got, want)
				break
			}
		}
	}
}

func TestParamTypesVectors(t *testing.T) {
	vec := loadJSON(t, "testdata/vectors.json")
	for _, c := range objList(objAt(vec, "param_types")) {
		params := objStr(c, "params")
		want := objStr(c, "types")
		if got := paramTypes(params); got != want {
			t.Errorf("paramTypes(%q) = %q, want %q", params, got, want)
		}
	}
}

func TestGuardStrengthVectors(t *testing.T) {
	vec := loadJSON(t, "testdata/vectors.json")
	for _, c := range objList(objAt(vec, "guard_strength")) {
		cond := objStr(c, "cond")
		want := objAt(c, "class")
		got := validation.VInt(guardStrength(cond))
		if validation.CanonCompact(got) != validation.CanonCompact(want) {
			t.Errorf("guardStrength(%q) = %v, want %v", cond, got, want)
		}
	}
}

func TestValueFlowGolden(t *testing.T) {
	sink := loadJSON(t, "testdata/sink_index.json")
	sink2 := loadJSON(t, "testdata/sink2_index.json")
	v1 := loadJSON(t, "testdata/v1_index.json")
	want := loadJSON(t, "testdata/value_flow.json")

	canonEqual(t, "sink_functions", validation.VArr(SinkFunctions(sink)...),
		validation.VArr(toValues(objList(objAt(want, "sink_functions")))...))
	canonEqual(t, "backward_slice", validation.VArr(BackwardSlice(sink, 8)...),
		validation.VArr(toValues(objList(objAt(want, "backward_slice")))...))
	canonEqual(t, "sink2_functions", validation.VArr(SinkFunctions(sink2)...),
		validation.VArr(toValues(objList(objAt(want, "sink2_functions")))...))
	canonEqual(t, "sink2_slice", validation.VArr(BackwardSlice(sink2, 8)...),
		validation.VArr(toValues(objList(objAt(want, "sink2_slice")))...))
	amp := loadJSON(t, "testdata/amp_index.json")
	canonEqual(t, "amplifier_signals", AmplifierSignals(amp),
		objAt(want, "amplifier_signals"))
	canonEqual(t, "amplifier_signals_v1", AmplifierSignals(v1),
		objAt(want, "amplifier_signals_v1"))
}

func toValues(xs []validation.Value) []validation.Value { return xs }

func TestCriticalityGolden(t *testing.T) {
	crit := loadJSON(t, "testdata/criticality.json")
	for i, key := range []string{"model", "model2", "model3"} {
		model := objAt(crit, key)
		want := objAt(crit, []string{"rank", "rank2", "rank3"}[i])
		got := CriticalityRank(model, validation.VObj())
		canonEqual(t, key, validation.VArr(got...),
			validation.VArr(toValues(objList(want))...))
	}
	for _, c := range objList(objAt(crit, "crit_hit")) {
		name := objStr(c, "name")
		toks := map[string]bool{}
		for _, s := range strList(objAt(c, "tokens")) {
			toks[s] = true
		}
		want := objAt(c, "hit")
		got := validation.VBool(critHit(name, toks))
		if validation.CanonCompact(got) != validation.CanonCompact(want) {
			t.Errorf("critHit(%q, %v) = %v, want %v", name,
				strList(objAt(c, "tokens")), got, want)
		}
	}
	for _, c := range objList(objAt(crit, "index_sha")) {
		idx := objAt(c, "index")
		want := objStr(c, "sha")
		if got := IndexSha(idx); got != want {
			t.Errorf("IndexSha = %s, want %s", got, want)
		}
	}
}

func TestRequireParseVersion(t *testing.T) {
	good := validation.VObj(validation.KV{K: "parse_version",
		V: validation.VStr("3")})
	if err := RequireParseVersion(good, "structural index"); err != nil {
		t.Fatalf("v3 index rejected: %v", err)
	}
	cases := []struct {
		name      string
		index     validation.Value
		want      string
		wantNamed bool
	}{
		{"a v2 index with no campaign_id", validation.VObj(
			validation.KV{K: "parse_version", V: validation.VStr("2")}),
			"structural index has parse_version='2', need '3' — rebuild it: " +
				"`webv2 index <campaign> --src <target>`", false},
		{"a v2 index that carries its campaign_id", validation.VObj(
			validation.KV{K: "parse_version", V: validation.VStr("2")},
			validation.KV{K: "campaign_id", V: validation.VStr("C-abc123")}),
			"structural index has parse_version='2', need '3' — rebuild it: " +
				"`webv2 index C-abc123 --src <target>`", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireParseVersion(tc.index, "structural index")
			if err == nil {
				t.Fatal("v2 index accepted")
			}
			if err.Error() != tc.want {
				t.Errorf("stale message = %q, want %q", err.Error(), tc.want)
			}
			if _, ok := err.(*StaleIndexError); !ok {
				t.Errorf("error type = %T, want *StaleIndexError", err)
			}
			if got := strings.Contains(err.Error(), "C-abc123"); got != tc.wantNamed {
				t.Errorf("message names the campaign id = %v, want %v: %q",
					got, tc.wantNamed, err.Error())
			}
			if tc.wantNamed && strings.Contains(err.Error(), CampaignPlaceholder) {
				t.Errorf("message still carries the placeholder: %q", err.Error())
			}
		})
	}
	none := validation.VObj()
	if err := RequireParseVersion(none, "structural index"); err == nil ||
		err.Error()[:len("structural index has parse_version=None")] !=
			"structural index has parse_version=None" {
		t.Errorf("missing parse_version: %v", err)
	}
}

// setPath rebuilds v with the nested field at path (object keys and decimal
// array indices) replaced. It copies each level, so the input is untouched.
func setPath(v validation.Value, path []string, nv validation.Value) validation.Value {
	if len(path) == 0 {
		return nv
	}
	if v.Kind == validation.Arr {
		i, _ := strconv.Atoi(path[0])
		out := v
		out.A = append([]validation.Value(nil), v.A...)
		out.A[i] = setPath(out.A[i], path[1:], nv)
		return out
	}
	out := v
	out.O = append([]validation.KV(nil), v.O...)
	for i := range out.O {
		if out.O[i].K == path[0] {
			out.O[i].V = setPath(out.O[i].V, path[1:], nv)
			return out
		}
	}
	return out
}

// delPath rebuilds v with the object field `key` removed at path.
func delPath(v validation.Value, path []string, key string) validation.Value {
	if len(path) == 0 {
		out := v
		out.O = out.O[:0:0]
		for _, kv := range v.O {
			if kv.K != key {
				out.O = append(out.O, kv)
			}
		}
		return out
	}
	if v.Kind == validation.Arr {
		i, _ := strconv.Atoi(path[0])
		out := v
		out.A = append([]validation.Value(nil), v.A...)
		out.A[i] = delPath(out.A[i], path[1:], key)
		return out
	}
	out := v
	out.O = append([]validation.KV(nil), v.O...)
	for i := range out.O {
		if out.O[i].K == path[0] {
			out.O[i].V = delPath(out.O[i].V, path[1:], key)
			return out
		}
	}
	return out
}

// TestIndexValidatesAgainstSchema: every golden index satisfies
// schemas/structural_index.schema.json, and the three malformed variants the
// Python twin rejects (guard class out of range, an unknown `uses.kind`, a
// contract_closure entry missing its defining_contract) are rejected too
// (test_index_validates_against_schema, test_v2_index_validates_against_schema,
// test_schema_rejects_malformed_v2_facts).
func TestIndexValidatesAgainstSchema(t *testing.T) {
	c := newCampaign(t, "schema-program")
	for _, name := range []string{"structural", "v1", "sink", "sink2", "amp",
		"cast", "uni"} {
		idx, err := IndexSnapshot(c, filepath.Join("testdata", name),
			DefaultBackend)
		if err != nil {
			t.Fatalf("%s: IndexSnapshot: %v", name, err)
		}
		if err := validation.Validate(idx, "structural_index", 0); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	idx, err := IndexSnapshot(c, filepath.Join("testdata", "structural"),
		DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	nodes := objAt(idx, "nodes")
	fnIdx, ctIdx := -1, -1
	for i, n := range objList(nodes) {
		if fnIdx < 0 && objStr(n, "kind") == "function" &&
			len(objList(objAt(n, "guards"))) > 0 &&
			len(objList(objAt(n, "uses"))) > 0 {
			fnIdx = i
		}
		if ctIdx < 0 && objStr(n, "kind") == "contract" &&
			len(objList(objAt(n, "contract_closure"))) > 0 {
			ctIdx = i
		}
	}
	if fnIdx < 0 || ctIdx < 0 {
		t.Fatalf("fixture lacks a function with guards/uses (%d) or a "+
			"contract with a closure (%d)", fnIdx, ctIdx)
	}
	fn := strconv.Itoa(fnIdx)
	ct := strconv.Itoa(ctIdx)
	cases := []struct {
		label string
		bad   validation.Value
	}{
		{"guard class 9", setPath(idx, []string{"nodes", fn, "guards", "0", "class"},
			validation.VInt(9))},
		{"unknown uses kind", setPath(idx, []string{"nodes", fn, "uses", "0", "kind"},
			validation.VStr("readd"))},
		{"closure without defining_contract",
			delPath(idx, []string{"nodes", ct, "contract_closure", "0"},
				"defining_contract")},
	}
	for _, c := range cases {
		if err := validation.Validate(c.bad, "structural_index", 0); err == nil {
			t.Errorf("%s: schema accepted the malformed index", c.label)
		}
	}
}

func TestCollectFilesOrder(t *testing.T) {
	// Path ordering is the parts tuple: ("a","b.sol") < ("a.sol",).
	dir := t.TempDir()
	for _, p := range []string{"a.sol", "b/c.sol", "a/b.sol", "B.sol"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("contract X {}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := collectFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"B.sol", "a/b.sol", "a.sol", "b/c.sol"}
	if len(got) != len(want) {
		t.Fatalf("collectFiles = %v, want %v", got, want)
	}
	for i := range got {
		rel, _ := filepath.Rel(dir, got[i])
		if filepath.ToSlash(rel) != want[i] {
			t.Errorf("collectFiles[%d] = %s, want %s", i, rel, want[i])
		}
	}
}

// TestNonSolidityTreeDegrades: a tree with no Solidity still indexes — the
// non-Solidity file is listed, not parsed (test_non_solidity_tree_degrades).
func TestNonSolidityTreeDegrades(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.cairo"),
		[]byte("%builtins pedersen"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := IndexTreeValue(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := objAt(idx, "solidity_files"); got.Kind != validation.Int || got.I != 0 {
		t.Fatalf("solidity_files = %v, want 0", got)
	}
	if got := objAt(idx, "other_files_listed"); got.Kind != validation.Int || got.I < 1 {
		t.Fatalf("other_files_listed = %v, want >= 1", got)
	}
	if nodes := objList(objAt(idx, "nodes")); len(nodes) != 0 {
		t.Fatalf("nodes = %d, want 0", len(nodes))
	}
}

// TestIndexDeterministicAndArtifactBytes: the pure tree facts are
// byte-identical across runs and path spellings, and saving the same
// artifact twice produces identical bytes
// (test_index_is_deterministic_across_runs_and_paths,
// test_saved_artifacts_are_byte_identical).
func TestIndexDeterministicAndArtifactBytes(t *testing.T) {
	spellings := []string{
		filepath.Join("testdata", "structural"),
		filepath.Join("testdata", ".", "structural", "."),
	}
	var firstCanon string
	for i, sp := range spellings {
		tree, err := IndexTreeValue(sp)
		if err != nil {
			t.Fatalf("%s: %v", sp, err)
		}
		got := validation.CanonCompact(tree)
		if i == 0 {
			firstCanon = got
		} else if got != firstCanon {
			t.Fatalf("tree facts for %q differ from the first run", sp)
		}
	}
	c := newCampaign(t, "determinism-program")
	idx, err := IndexSnapshot(c, spellings[0], DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	var firstArtifact string
	for i := 0; i < 2; i++ {
		if _, err := SaveIndex(c, idx); err != nil {
			t.Fatalf("SaveIndex: %v", err)
		}
		b, err := os.ReadFile(IndexPath(c))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstArtifact = string(b)
		} else if string(b) != firstArtifact {
			t.Fatal("saved artifact bytes differ between saves")
		}
	}
}
