// Package capabilities ports webv2.capabilities: the attacker capability
// vocabulary.
//
// A finding is not "vulnerability X exists" — it is "capability X exists".
// Chaining works when one finding's GRANTED capabilities satisfy another's
// REQUIRED ones, so the labels have to be comparable across findings written
// by different models on different passes. This package owns that comparison:
// normalization, the kind taxonomy, and the before/after delta.
package capabilities

import (
	"sort"
	"strings"
	"unicode"

	"websec/internal/validation"
)

// KINDS is KINDS: what kind of power the attacker holds. The vocabulary is
// deliberately small — the point is cross-finding comparability, not nuance.
// The order is contractual: kind_of returns the first kind whose starter
// vocabulary carries the label, and COMMON is declared in this order.
// "liveness" (IMPROVEMENTS B1) is the non-economic terminal kind: the loss
// is the protocol's ability to keep serving, not extractable value.
var KINDS = []string{"authority", "state", "market", "asset", "information",
	"execution", "timing", "liveness"}

// COMMON is COMMON: a starter vocabulary for the recurring Web3 capabilities.
// Free text is allowed (models discover things this list did not anticipate),
// but these spellings are what the chaining engine matches on most reliably.
var COMMON = map[string][]string{
	"authority": {"call_any_entry_point", "hold_governor", "hold_pauser",
		"hold_oracle_updater", "set_implementation", "grant_role"},
	"state": {"write_accounting_state", "force_liquidation",
		"skip_initialization", "reopen_closed_position",
		"control_protocol_pause"},
	"market": {"move_spot_price", "control_perceived_asset_price",
		"access_flash_liquidity", "manipulate_pool_depth"},
	"asset": {"withdraw_unbacked_assets", "extract_protocol_liquidity",
		"retain_extracted_funds", "drain_treasury", "steal_pending_rewards"},
	"information": {"read_private_state", "front_run_internal_call"},
	"execution": {"trigger_callback", "delegatecall_attacker_code",
		"reenter_victim"},
	"timing":   {"act_within_cooldown", "win_auction", "cross_epoch_boundary"},
	"liveness": {"liveness_loss"},
}

// TERMINAL_KINDS is TERMINAL_KINDS: terminal capabilities — the
// terminal-chain search ends when a path grants one of these. Two flavors:
// the economic terminal (asset) means value is already extractable (or has
// already moved) to the attacker; the non-economic terminal (liveness,
// IMPROVEMENTS B1) means the protocol can no longer serve — a frozen chain
// freezes every user's funds, and no USD figure is defensible.
var TERMINAL_KINDS = map[string]struct{}{"asset": {}, "liveness": {}}

// NormalizeLabel is normalize_label: the canonical form of a capability
// label — lowercase, word runs collapsed to single underscores.
// 'control perceived asset price', 'Control-Perceived_Asset  Price' and
// 'control_perceived_asset_price' all become the same key.
func NormalizeLabel(value string) string {
	return strings.Join(pySplit(strings.ReplaceAll(strings.ToLower(value), "-", " ")), "_")
}

// NormalizeLabels is normalize_labels: the normalized, de-duplicated,
// order-stable list. Empty and whitespace-only values are dropped.
func NormalizeLabels(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if pyStrip(v) == "" {
			continue
		}
		n := NormalizeLabel(v)
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// RoleLabel is role_label: the capability label for holding a bounded role
// (3.1) — the deterministic bridge between the protocol model's privilege
// table and the capability graph. A finding that requires a privileged entry
// declares this label in capabilities.required; the EOA baseline never holds
// it, which is what keeps the privileged track separate.
func RoleLabel(role string) string {
	return NormalizeLabel("role " + role)
}

// IsRoleLabel is is_role_label: a "role_" label with a non-empty role id.
func IsRoleLabel(label string) bool {
	n := NormalizeLabel(label)
	return strings.HasPrefix(n, "role_") && len(n) > len("role_")
}

// RoleFromLabel is role_from_label: the normalized role id a role label
// refers to. The second result is false when the label is not a role label
// (Python returns None there).
func RoleFromLabel(label string) (string, bool) {
	if !IsRoleLabel(label) {
		return "", false
	}
	return NormalizeLabel(label)[len("role_"):], true
}

// Granted is granted: the finding's normalized granted-capability list.
func Granted(finding validation.Value) []string {
	return NormalizeLabels(strList(objAt(objAt(finding, "capabilities"), "granted")))
}

// Required is required: what the attacker must already hold. Falls back to
// the recorded preconditions when no explicit capability list exists —
// preconditions are prose, so the fallback is best-effort and flagged as
// such (they land in capability_delta's unclassified bucket).
func Required(finding validation.Value) []string {
	caps := objAt(finding, "capabilities")
	if req := strList(objAt(caps, "required")); len(req) > 0 {
		return NormalizeLabels(req)
	}
	return NormalizeLabels(strList(objAt(finding, "preconditions")))
}

// KindOf is kind_of: which taxonomy bucket a label belongs to. The second
// result is false for free text outside the starter vocabulary (Python
// returns None — not a lie, just unknown).
func KindOf(label string) (string, bool) {
	if IsRoleLabel(label) {
		return "authority", true
	}
	norm := NormalizeLabel(label)
	for _, kind := range KINDS {
		for _, known := range COMMON[kind] {
			if norm == known {
				return kind, true
			}
		}
	}
	return "", false
}

// IsTerminal is is_terminal: true when a path granting *label* has reached a
// terminal state — economic extraction (asset) or the loss of protocol
// liveness (IMPROVEMENTS B1).
func IsTerminal(label string) bool {
	kind, ok := KindOf(label)
	if !ok {
		return false
	}
	_, ok = TERMINAL_KINDS[kind]
	return ok
}

// IsLivenessTerminal is the B1 non-economic test: true when *label* is a
// liveness terminal — the protocol stops serving. No USD figure is
// defensible for it; pricing takes the blast-radius floor instead
// (internal/chainengine).
func IsLivenessTerminal(label string) bool {
	kind, ok := KindOf(label)
	return ok && kind == "liveness"
}

// IsEconomicTerminal is the B1 economic test: true when *label* is an
// economic (asset-kind) terminal — value extractable.
func IsEconomicTerminal(label string) bool {
	kind, ok := KindOf(label)
	return ok && kind == "asset"
}

// CapabilityDelta is capability_delta: the before/after view of one finding —
// what the attacker holds after executing it, what they had to hold before,
// and what the finding itself therefore adds. This is the unit the chaining
// engine searches over. Returned as an ordered object (gained, retained,
// required, kinds, unclassified) so it renders exactly like the Python dict.
func CapabilityDelta(finding validation.Value) validation.Value {
	before := setOf(Required(finding))
	after := setOf(Granted(finding))
	var gained, retained, unclassified []string
	kinds := map[string]struct{}{}
	for a := range after {
		if _, held := before[a]; held {
			retained = append(retained, a)
		} else {
			gained = append(gained, a)
		}
		if kind, ok := KindOf(a); ok {
			kinds[kind] = struct{}{}
		} else {
			unclassified = append(unclassified, a)
		}
	}
	sort.Strings(gained)
	sort.Strings(retained)
	sort.Strings(unclassified)
	return validation.VObj(
		kv("gained", strArr(gained)),
		kv("retained", strArr(retained)),
		kv("required", strArr(keysOf(before))),
		kv("kinds", strArr(keysOf(kinds))),
		kv("unclassified", strArr(unclassified)),
	)
}

// ---- local helpers -------------------------------------------------------

// setOf builds a string set from a slice.
func setOf(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, it := range items {
		s[it] = struct{}{}
	}
	return s
}

// keysOf returns the sorted key set (Python's sorted(set) over strings).
func keysOf(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// strArr renders a []string as a JSON array Value.
func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// strList extracts the string elements of a list Value. Python iterates
// whatever the finding carries: a bare string iterates into its characters,
// so the twin does the same; any other kind yields nothing (Python would
// raise TypeError on a number — a shape the schema forbids).
func strList(v validation.Value) []string {
	switch v.Kind {
	case validation.Arr:
		// Python's normalize_labels runs str() over EVERY element, so a
		// recorded precondition (a dict) becomes its repr and still yields a
		// label — the prose fallback capabilities.required documents.
		out := make([]string, 0, len(v.A))
		for _, e := range v.A {
			if e.Kind == validation.Str {
				out = append(out, e.S)
			} else {
				out = append(out, validation.PyRepr(e))
			}
		}
		return out
	case validation.Str:
		out := make([]string, 0, len(v.S))
		for _, r := range v.S {
			out = append(out, string(r))
		}
		return out
	}
	return nil
}

// objAt is the dict lookup: the value for key, or Null when absent.
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

// kv is the keyed KV constructor (non-test code cannot use a test helper).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// pySplit is Python's str.split(): split on runs of Unicode whitespace and
// drop leading/trailing whitespace. Go's unicode.IsSpace misses the four
// C0 separator controls (U+001C..U+001F) that Python's str.isspace counts.
func pySplit(s string) []string {
	return strings.FieldsFunc(s, pyIsSpace)
}

// pyStrip is Python's str.strip() with the same whitespace set.
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}
