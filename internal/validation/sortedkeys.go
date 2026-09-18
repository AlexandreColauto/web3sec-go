// sortedkeys.go: the sorted-map-keys helper that a dozen packages re-inlined.

package validation

import (
	"maps"
	"slices"
)

// SortedKeys returns the keys of m in ascending order. It is generic over the
// value type because the clones differed only in how they modelled a set —
// map[string]bool versus map[string]struct{} — while every one of them ended
// in sort.Strings, which is exactly slices.Sorted's order.
//
// The empty case is normalized to a non-nil slice on purpose: every clone
// started from make([]string, 0, len(m)), and slices.Sorted returns nil for an
// empty iterator. Callers marshal these lists into hashed JSON, where nil
// renders as null and an empty slice as [], so the difference is observable.
func SortedKeys[T any](m map[string]T) []string {
	if out := slices.Sorted(maps.Keys(m)); out != nil {
		return out
	}
	return []string{}
}
