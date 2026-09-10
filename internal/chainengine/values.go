// values.go: the ordered-JSON helpers chain_engine.py relies on. The
// module is a 1:1 port of webv2/chain_engine.py (port-era provenance; twin retired 2026-09-09); every helper
// here mirrors the exact Python expression it replaces, including
// json.dumps' default separators for the dedup_meta fields.
package chainengine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

// nowIso is now_iso (mirrors state.nowIso, unexported there): WEBV2_NOW pins
// the clock for the cross-twin golden harness.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// chainPath is `campaign.chains_dir / f"{chain_id}.json"`.
func chainPath(c *state.Campaign, chainID string) string {
	return filepath.Join(c.ChainsDir, chainID+".json")
}

// objAt is `d.get(key)` for object values (VNull when absent or not an
// object — Python would raise on a non-dict, the schema forbids it).
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// hasKey is `key in d`.
func hasKey(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// objStr is `d.get(key)` when the field is a string, "" otherwise.
func objStr(v validation.Value, key string) string {
	if f := objAt(v, key); f.Kind == validation.Str {
		return f.S
	}
	return ""
}

// asObj is `d.get(key) or {}`.
func asObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

// listOf is `d.get(key) or []` for list-valued fields.
func listOf(v validation.Value, key string) validation.Value {
	if f := objAt(v, key); f.Kind == validation.Arr {
		return f
	}
	return validation.VArr()
}

// strList renders a list value as Go strings via Python's str() (the same
// rendering normalize_labels() sees).
func strList(v validation.Value) []string {
	if v.Kind != validation.Arr {
		return nil
	}
	out := make([]string, 0, len(v.A))
	for _, item := range v.A {
		out = append(out, pyStr(item))
	}
	return out
}

// capInput is `_norm(caps.get("granted"))`'s input conversion: the schema
// says array-of-string, but normalize_labels() iterates whatever it is
// handed, so a bare string collapses to its characters and an object to its
// keys (the orchestrator port's capList, kept identical here).
func capInput(v validation.Value) []string {
	switch v.Kind {
	case validation.Arr:
		out := make([]string, 0, len(v.A))
		for _, item := range v.A {
			out = append(out, pyStr(item))
		}
		return out
	case validation.Str:
		out := []string{}
		for _, r := range v.S {
			out = append(out, string(r))
		}
		return out
	case validation.Obj:
		out := make([]string, 0, len(v.O))
		for _, kv := range v.O {
			out = append(out, kv.K)
		}
		return out
	}
	return nil
}

// pyStr is Python's str() for the scalar shapes these artifacts carry.
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Null:
		return "None"
	}
	return validation.CanonCompact(v)
}

// pyFloat is `float(v)`: bools are 1.0/0.0, ints/floats convert, and a
// non-numeric value yields ok=false (Python raises ValueError; the finding
// schema forbids the shape, so the caller treats it as absent).
func pyFloat(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Bool:
		if v.B {
			return 1.0, true
		}
		return 0.0, true
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			return f, err == nil
		}
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	}
	return 0.0, false
}

// pyListRepr is Python's repr() of a list of strings: ['a', 'b'].
func pyListRepr(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func sortedStrings(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}

// setOf builds a set from a slice.
func setOf(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, s := range items {
		out[s] = struct{}{}
	}
	return out
}

// subsetOf is `a <= b` for string sets.
func subsetOf(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// unionSets is `a | b`.
func unionSets(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

// setKeys is `sorted(s)` over a string set.
func setKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// strArr renders a []string as a JSON array value.
func strArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.VArr(out...)
}

// valueArr renders a []Value as an array value.
func valueArr(items []validation.Value) validation.Value {
	return validation.VArr(items...)
}

// kvOf is one object entry.
func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}
