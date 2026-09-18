// cmd_probes_util: the small package-wide helpers that live with
// the probes verb — axis registrations, truncation, existence and value casts.
package cli

import (
	"os"
	"sort"

	"websec/internal/probes"
	"websec/internal/validation"
)

// t29AxisNames is `", ".join(PB.registered_axes())`.
func t29AxisNames() []string {
	return sortedStringsOf(probes.RegisteredAxes())
}

// t29LensIDs is `sorted({m["lens"] for m in registered_axes().values()})`.
func t29LensIDs() []string {
	seen := map[string]struct{}{}
	for _, meta := range probes.RegisteredAxes() {
		seen[meta.Lens] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringsOf(m map[string]probes.AxisMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// t29Trunc is s[:n].
func t29Trunc(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

func t29FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func strListValue(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

func objBool(v validation.Value, key string) bool {
	got := validation.ObjAt(v, key)
	return got.Kind == validation.Bool && got.B
}
