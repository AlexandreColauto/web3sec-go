// values.go: the ordered-JSON helpers chain_engine.py relies on. The
// module is a 1:1 port of webv2/chain_engine.py (PYTHON WINS); every helper
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
	"unicode/utf8"

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

// pyJSONDump is json.dumps(v) with the default separators (", " / ": "),
// insertion order and ensure_ascii=True — the encoding of dedup_meta's
// members/capability_links/terminal fields.
func pyJSONDump(v validation.Value) string {
	var b strings.Builder
	writeDump(&b, v)
	return b.String()
}

func writeDump(b *strings.Builder, v validation.Value) {
	switch v.Kind {
	case validation.Null:
		b.WriteString("null")
	case validation.Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case validation.Int:
		b.WriteString(validation.IntText(v))
	case validation.Flt:
		b.WriteString(validation.PythonFloat(v.F))
	case validation.Str:
		writeDumpStr(b, v.S)
	case validation.Arr:
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(", ")
			}
			writeDump(b, e)
		}
		b.WriteByte(']')
	case validation.Obj:
		b.WriteByte('{')
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(", ")
			}
			writeDumpStr(b, kv.K)
			b.WriteString(": ")
			writeDump(b, kv.V)
		}
		b.WriteByte('}')
	}
}

// writeDumpStr is json.dumps' ensure_ascii=True string escaping.
func writeDumpStr(b *strings.Builder, s string) {
	const hexd = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r < 0x20 || r == 0x7f:
			b.WriteString("\\u00")
			b.WriteByte(hexd[(r>>4)&0xf])
			b.WriteByte(hexd[r&0xf])
		case r <= 0x7e:
			b.WriteRune(r)
		default:
			if r > 0xffff {
				r2 := r - 0x10000
				writeU4(b, 0xd800+rune(r2>>10&0x3ff))
				writeU4(b, 0xdc00+rune(r2&0x3ff))
			} else {
				writeU4(b, r)
			}
		}
		i += size
	}
	b.WriteByte('"')
}

func writeU4(b *strings.Builder, r rune) {
	const hexd = "0123456789abcdef"
	b.WriteString("\\u")
	b.WriteByte(hexd[(r>>12)&0xf])
	b.WriteByte(hexd[(r>>8)&0xf])
	b.WriteByte(hexd[(r>>4)&0xf])
	b.WriteByte(hexd[r&0xf])
}

// sortedStrings is Python's sorted(set-or-list of strings).
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

// setOrAppend is `o[key] = v` (replace in place, else append).
func setOrAppend(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}
