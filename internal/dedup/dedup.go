package dedup

import (
	"slices"
	"websec/internal/validation"
)

// kv is the vet-clean keyed KV constructor (unkeyed cross-package literals
// are rejected by go vet). Shared by the tests in this package.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// EconomicCompatGroups is _ECONOMIC_COMPAT_GROUPS: classes that can plausibly
// share an economic effect. Two classes absent from a common group cannot
// tier-3-match. Exported because taxonomy.py unions these groups when it
// builds the canonical class list (_compat_classes).
var EconomicCompatGroups = [][]string{
	{"oracle-manipulation", "flash-loan", "economic-invariant",
		"share-price-inflation", "precision-rounding", "token-integration",
		"logic-error"},
	{"access-control", "authorization", "upgrade-initializer",
		"centralization-risk", "signature-replay"},
	{"reentrancy", "unchecked-external-call", "logic-error", "dos-griefing"},
	{"bridge-message", "cross-chain-replay", "signature-replay"},
	{"liquidation-logic", "oracle-manipulation", "economic-invariant"},
}

// AssetClassHints is _ASSET_CLASS_HINTS: E-classes that are only meaningful
// when both findings' economic impact touches the same asset-class bucket.
// Exported because taxonomy.py unions these values too. Go maps have no
// iteration order; taxonomy only unions the values into a set, so order is
// not observable.
var AssetClassHints = map[string][]string{
	"share-price": {"share-price-inflation", "precision-rounding", "donation"},
	"liquidation": {"liquidation-logic", "oracle-manipulation"},
	"bridge":      {"bridge-message", "cross-chain-replay"},
	"accounting":  {"economic-invariant", "logic-error", "precision-rounding"},
	"authz":       {"access-control", "authorization", "signature-replay"},
}

// ClassesCompatible is classes_compatible: the same class always matches;
// otherwise both classes must sit in one common compatibility group.
func ClassesCompatible(classA, classB string) bool {
	if classA == classB {
		return true
	}
	for _, group := range EconomicCompatGroups {
		if slices.Contains(group, classA) && slices.Contains(group, classB) {
			return true
		}
	}
	return false
}
