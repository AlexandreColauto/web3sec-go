// relations_helpers.go: small shared helpers of the relations package.
package relations

import (
	"sort"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- helpers --------------------------------------------------------------

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func strOrNull(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func supportOrNull(s *validation.Value) validation.Value {
	if s == nil || s.Kind != validation.Obj {
		return validation.VNull()
	}
	return *s
}

func supportTruthy(s *validation.Value) bool {
	return s != nil && s.Kind == validation.Obj && len(s.O) > 0
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

func indexOf(list []string, s string) int {
	for i, item := range list {
		if item == s {
			return i
		}
	}
	return -1
}

// head200 is (s or "")[:200] on code points.
func head200(s string) string { return headN(s, 200) }

// head300 is (s or "")[:300] on code points.
func head300(s string) string { return headN(s, 300) }

func headN(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// pyReprList is Python's list repr of strings: ['a', 'b'].
func pyReprList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, pyReprStr(it))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pyReprStr(s string) string { return validation.PyReprStr(s) }

// pyStr is str(value): None renders as "None", strings as themselves.
func pyStr(v validation.Value) string {
	if v.Kind == validation.Null {
		return "None"
	}
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.CanonCompact(v)
}

// pyReprSortedKinds is sorted(RELATION_KINDS) as a Python list repr.
func pyReprSortedKinds() string {
	names := make([]string, 0, len(RelationKinds))
	for _, k := range RelationKinds {
		names = append(names, k.Kind)
	}
	sort.Strings(names)
	return pyReprList(names)
}

// idTail is new_id('x', n).split('-')[1].
func idTail(n int) string {
	return strings.SplitN(state.NewID("x", n), "-", 2)[1]
}
