// Small shared helpers: field access, KV construction, string/list
// rendering and id generation.

package sharedmem

import (
	"os"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- helpers ---------------------------------------------------------------

func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func strOrNull(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func sortedStrings(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}

func simOf(v validation.Value) float64 {
	if v.Kind == validation.Flt {
		return v.F
	}
	if v.Kind == validation.Int {
		return float64(v.I)
	}
	return 0
}

func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.CanonCompact(v)
}

// pyTuple renders a Python tuple literal: ('a', 'b').
func pyTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyReprList is Python's list repr of strings: ['a', 'b'].
func pyReprList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// idTail is new_id('x', n).split('-')[1].
func idTail(n int) string {
	return strings.SplitN(state.NewID("x", n), "-", 2)[1]
}

// fileSha256 is _file_sha256: "" when the file does not exist.
func fileSha256(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return validation.Sha256Hex(raw)
}
