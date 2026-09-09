package probes

// Port of the three `index_sha` tests in tests/test_probes.py that the 42-test
// port left out (they exercise probes.index_sha through the probes API, and
// the volatile/tree-fact split against the CLOSED index schema).

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// t29VolatileIndexKeys is probes.VOLATILE_INDEX_KEYS.
var t29VolatileIndexKeys = []string{"campaign_id", "snapshot_id", "created_at"}

// t29Mutate is _mutate: a list gains an element, an object gains a key,
// anything else is replaced by a string.
func t29Mutate(v validation.Value) validation.Value {
	switch v.Kind {
	case validation.Arr:
		out := make([]validation.Value, 0, len(v.A)+1)
		out = append(out, v.A...)
		out = append(out, validation.VObj(
			validation.KV{K: "id", V: validation.VStr("injected")},
			validation.KV{K: "kind", V: validation.VStr("function")}))
		return validation.VArr(out...)
	case validation.Obj:
		out := append([]validation.KV(nil), v.O...)
		for i := range out {
			if out[i].K == "injected" {
				out[i].V = validation.VInt(1)
				return validation.VObj(out...)
			}
		}
		return validation.VObj(append(out,
			validation.KV{K: "injected", V: validation.VInt(1)})...)
	default:
		return validation.VStr("injected")
	}
}

func TestIndexShaIsRebuildStableForAnUnchangedTree(t *testing.T) {
	root := filepath.Join(t29ProbesDir, "assertion_strength", "buggy")
	a := t29Index(t, root)
	b := t29Index(t, root)
	if vStr(a, "campaign_id") == vStr(b, "campaign_id") {
		t.Fatal("distinct campaigns must have distinct ids")
	}
	vSet(&b, "created_at", validation.VStr("1999-01-01T00:00:00Z"))
	vSet(&b, "snapshot_id", validation.VStr("src-content-0123456789ab"))
	if vStr(b, "created_at") == vStr(a, "created_at") {
		t.Fatal("created_at fixture did not change")
	}
	if vStr(b, "snapshot_id") == vStr(a, "snapshot_id") {
		t.Fatal("snapshot_id fixture did not change")
	}
	if t29JSON(vGet(a, "nodes")) != t29JSON(vGet(b, "nodes")) ||
		t29JSON(vGet(a, "edges")) != t29JSON(vGet(b, "edges")) {
		t.Fatal("the tree facts themselves must be identical")
	}
	if IndexSha(a) != IndexSha(b) {
		t.Fatal("index_sha moved across a harmless rebuild")
	}
}

func TestIndexShaIgnoresExactlyTheVolatileIndexKeys(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "buggy"))
	base := IndexSha(idx)
	schema, err := validation.ReadJson(filepath.Join("..", "..",
		"assets", "schema", "structural_index.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	props := vGet(schema, "properties")
	if props.Kind != validation.Obj {
		t.Fatal("schema has no properties object")
	}
	moved := map[string]struct{}{}
	still := map[string]struct{}{}
	for _, kv := range props.O {
		probe := t29Clone(t, idx)
		vSet(&probe, kv.K, t29Mutate(vGet(probe, kv.K)))
		if IndexSha(probe) != base {
			moved[kv.K] = struct{}{}
		} else {
			still[kv.K] = struct{}{}
		}
	}
	wantStill := map[string]struct{}{}
	for _, k := range t29VolatileIndexKeys {
		wantStill[k] = struct{}{}
	}
	if len(still) != len(wantStill) {
		t.Fatalf("volatile set = %v, want %v", sortedStrSet(still),
			sortedStrSet(wantStill))
	}
	for k := range wantStill {
		if _, ok := still[k]; !ok {
			t.Fatalf("key %q does not move the hash and must be declared "+
				"volatile (still=%v)", k, sortedStrSet(still))
		}
	}
	for k := range moved {
		if _, ok := wantStill[k]; ok {
			t.Fatalf("volatile key %q moved the hash", k)
		}
	}
	if len(moved) != len(props.O)-len(wantStill) {
		t.Fatalf("moved=%v still=%v over %d schema keys",
			sortedStrSet(moved), sortedStrSet(still), len(props.O))
	}
}

func TestIndexShaChangesWhenAGuardChangesInTheTree(t *testing.T) {
	tree := t.TempDir()
	t29CopyTree(t, filepath.Join(t29ProbesDir, "assertion_strength", "buggy"), tree)
	before := t29Index(t, tree)
	src := filepath.Join(tree, "Rollup.sol")
	text := t29Read(t, src)
	guard := "        require(stateRoot != bytes32(0), \"zero root\");\n"
	if !strings.Contains(text, guard) {
		t.Fatalf("guard fixture not found in %s", src)
	}
	t29Write(t, src, replaceOnce(text, guard, guard+
		"        require(batchIndex != 0, \"zero batch\");\n"))
	after := t29Index(t, tree)
	fn, ok := t29First(vObjList(after, "nodes"), func(n validation.Value) bool {
		return vStr(n, "name") == "commitBatch" && vStr(n, "kind") == "function"
	})
	if !ok {
		t.Fatal("commitBatch not found in the re-indexed tree")
	}
	if got := len(vList(fn, "guards")); got != 2 {
		t.Fatalf("commitBatch guards = %d, want 2 (the guard was really added)",
			got)
	}
	if t29JSON(vGet(before, "nodes")) == t29JSON(vGet(after, "nodes")) {
		t.Fatal("nodes did not change")
	}
	if IndexSha(before) == IndexSha(after) {
		t.Fatal("index_sha did not move when a guard was added")
	}
}

// replaceOnce is str.replace(old, new, 1).
func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
