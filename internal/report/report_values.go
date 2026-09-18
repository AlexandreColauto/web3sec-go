// Shared validation-value access helpers for the report package: small
// typed readers over finding/chain/row JSON shapes, used by every
// section renderer.
package report

import (
	"fmt"
	"os"
	"strings"

	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func listAt(v validation.Value, key string) []validation.Value {
	f := validation.ObjAt(v, key)
	if f.Kind != validation.Arr {
		return nil
	}
	return f.A
}

// pyTruthyInt64Only is a DIVERGENT pyTruthy variant (Wave J Task 7), NOT the
// canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except that an Int reads only the int64
// field I and ignores Big — so an integer that overflowed int64 (Big set,
// I == 0) reads FALSE where validation.PyTruthy reads it true.
func pyTruthyInt64Only(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func strList(v validation.Value) []string {
	out := []string{}
	for _, e := range v.A {
		out = append(out, validation.PyStr(e))
	}
	return out
}

// count is _count: "{n} {singular}" with plain English pluralization.
func count(n int, singular string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

func intAt(v validation.Value, key string) int64 {
	f := validation.ObjAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}

// pathBase is path.Base without importing path at the call sites.
func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// getOr is Python's d.get(key, default) as a string render.
func getOr(v validation.Value, key, def string) string {
	if !validation.HasKey(v, key) {
		return def
	}
	return validation.PyStr(validation.ObjAt(v, key))
}

func ratioOf(rung validation.Value) float64 {
	return floatVal(validation.ObjAt(rung, "extraction_ratio"))
}

func floatVal(v validation.Value) float64 {
	switch v.Kind {
	case validation.Int:
		return float64(v.I)
	case validation.Flt:
		return v.F
	}
	return 0
}
