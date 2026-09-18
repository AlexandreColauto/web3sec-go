// Package protocolgraph ports webv2.protocol_graph: load, validate and query
// the structured ProtocolModel that every agent consumes as its common
// semantic layer.
//
// Prose recon artifacts (legacy Stage 01/02) feed this model once; after that
// nothing reasons over prose — they reason over these objects:
//
//	WhoCan(model, "can_drain")   -> every actor able to drain value
//	TrustBoundaryGaps(model)     -> crossings with validated=false
//	AccountingVars(model)        -> every state variable carrying value
//	ExternalAssets(model)        -> tokens with nonstandard behaviors
//	CriticalEdges(model)         -> mint/burn/withdraw/liquidate graph
package protocolgraph

import (
	"math/big"
	"path/filepath"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"websec/internal/state"
	"websec/internal/validation"
)

// MUTATING_RELS is MUTATING_RELS: the relations that move value or code.
// Membership only; the set order is not part of any contract.
var MUTATING_RELS = map[string]struct{}{
	"MINTS": {}, "BURNS": {}, "DEPOSITS": {}, "WITHDRAWS": {},
	"BORROWS": {}, "LIQUIDATES": {}, "UPGRADES": {}, "BRIDGES": {},
}

// pyLower is Python's str.lower() (full Unicode case mapping: U+0130 ->
// "i"+U+0307, the Greek final-sigma rule). who_can's capability match is a
// substring test on lowered strings, so the simple per-rune mapping of
// strings.ToLower would diverge on those characters. x/text is already a
// direct dependency of this module (findings.signatures uses the same caser).
var pyLower = cases.Lower(language.Und)

// kv is the vet-clean keyed KV constructor.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// lookup is the `key in dict` + indexing pair: found reports whether the key
// is PRESENT (a present null is not the same as an absent key).
func lookup(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V, true
		}
	}
	return validation.VNull(), false
}

// pyStr is CPython str(v): raw for strings, "None"/"True"/"False" for the
// scalars, and repr() for the containers (which is what str() does for them).
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	}
	return validation.PyRepr(v)
}

// pyEqual is Python's == over JSON-shaped values: dicts compare by content
// (key order irrelevant), lists elementwise, and the numeric kinds compare
// across types (True == 1, 1 == 1.0). It backs who_can's `a not in hits`.
func pyEqual(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return numericEqual(a, b)
	}
	switch a.Kind {
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	case validation.Int:
		return validation.IntText(a) == validation.IntText(b)
	case validation.Flt:
		return a.F == b.F // NaN != NaN, as in Python
	case validation.Str:
		return a.S == b.S
	case validation.Arr:
		if len(a.A) != len(b.A) {
			return false
		}
		for i := range a.A {
			if !pyEqual(a.A[i], b.A[i]) {
				return false
			}
		}
		return true
	case validation.Obj:
		if len(a.O) != len(b.O) {
			return false
		}
		for _, pair := range a.O {
			other, ok := lookup(b, pair.K)
			if !ok || !pyEqual(pair.V, other) {
				return false
			}
		}
		return true
	}
	return false
}

// numericEqual compares two values as Python numbers (the cross-kind half of
// ==). Non-numeric operands are never equal to each other here.
func numericEqual(a, b validation.Value) bool {
	ra, okA := asRat(a)
	rb, okB := asRat(b)
	if !okA || !okB {
		return false
	}
	return ra.Cmp(rb) == 0
}

// asRat converts a numeric Value to an exact rational; ok is false for
// non-numbers and for NaN/±Inf (which have no rational form).
func asRat(v validation.Value) (*big.Rat, bool) {
	switch v.Kind {
	case validation.Bool:
		if v.B {
			return big.NewRat(1, 1), true
		}
		return big.NewRat(0, 1), true
	case validation.Int:
		r, ok := new(big.Rat).SetString(validation.IntText(v))
		return r, ok
	case validation.Flt:
		r := new(big.Rat).SetFloat64(v.F)
		return r, r != nil
	}
	return nil, false
}

// containsValue is Python's `value in list`.
func containsValue(items []validation.Value, v validation.Value) bool {
	for _, item := range items {
		if pyEqual(item, v) {
			return true
		}
	}
	return false
}

// listField is model.get(key, []) normalised to a non-nil slice (an absent
// collection must render as [], never null).
func listField(model validation.Value, key string) []validation.Value {
	v := validation.ObjAt(model, key)
	if v.Kind != validation.Arr || len(v.A) == 0 {
		return []validation.Value{}
	}
	return v.A
}

// LoadModel is load_model: read + schema-validate the model file, register
// (or refresh) it as the "protocol-model" artifact and log
// protocol_model.loaded. The model is validated BEFORE any side effect.
func LoadModel(campaign *state.Campaign, path string) (validation.Value, error) {
	model, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(model, "protocol_model", 25); err != nil {
		return validation.VNull(), err
	}
	note := "protocol model for " + pyStr(validation.ObjAt(model, "name"))
	_, err = campaign.RegisterOrRefresh("protocol-model", path, note, nil,
		"protocol model (re)loaded")
	if err != nil {
		return validation.VNull(), err
	}
	ref := validation.ObjAt(model, "protocol_id").S
	data := validation.VObj(
		kv("contracts", validation.VInt(int64(len(validation.ObjAt(model, "contracts").A)))),
		kv("invariants", validation.VInt(int64(len(validation.ObjAt(model, "invariants").A)))),
	)
	if _, err := campaign.Log("protocol_model.loaded", &ref, &data); err != nil {
		return validation.VNull(), err
	}
	return model, nil
}

// SaveModel is save_model: validate, write the model (no second schema pass —
// write_json is called without a schema name), then refresh the existing
// registration. A nil/empty path means <artifacts_dir>/protocol_model.json.
func SaveModel(campaign *state.Campaign, model validation.Value, path string) (string, error) {
	if err := validation.Validate(model, "protocol_model", 25); err != nil {
		return "", err
	}
	if path == "" {
		path = filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	}
	if err := validation.WriteJson(path, model, ""); err != nil {
		return "", err
	}
	// the model is a living document: re-saving must refresh the existing
	// registration, not mint a ghost row
	note := "protocol model for " + pyStr(validation.ObjAt(model, "name"))
	_, err := campaign.RegisterOrRefresh("protocol-model", path, note, nil,
		"protocol model saved (LLM refinement or operator edit)")
	if err != nil {
		return "", err
	}
	return path, nil
}

// ActorByID is actor_by_id: the actor with this id, or ok=false for Python's
// None. An actor row without an "id" key is skipped (Python would raise
// KeyError there; the schema requires id, so the case is unreachable for a
// validated model).
func ActorByID(model validation.Value, actorID string) (validation.Value, bool) {
	for _, a := range listField(model, "actors") {
		id, ok := lookup(a, "id")
		if ok && id.Kind == validation.Str && id.S == actorID {
			return a, true
		}
	}
	return validation.VNull(), false
}

// WhoCan is who_can: actors holding this capability, either as a truthy flag
// on the actor (`can_drain`, `can_upgrade`, `can_pause`, ...) or via a
// recorded privilege entry naming it (case-insensitive substring match).
// A privilege whose role is not an actor id yields the synthetic
// {"id", "kind": "ROLE", "trust": "trusted", "via"} actor, and an actor
// equal to one already collected is appended only once.
func WhoCan(model validation.Value, capability string) []validation.Value {
	hits := []validation.Value{}
	for _, a := range listField(model, "actors") {
		if v, ok := lookup(a, capability); ok && validation.PyTruthy(v) {
			hits = append(hits, a)
		}
	}
	needle := pyLower.String(capability)
	for _, p := range listField(model, "privileges") {
		// Python's p.get("capability", "").lower(); a non-string capability
		// would raise AttributeError there (unreachable: the schema requires
		// a string).
		if !strings.Contains(pyLower.String(validation.ObjAt(p, "capability").S), needle) {
			continue
		}
		role := validation.ObjAt(p, "role").S
		a, ok := ActorByID(model, role)
		if !ok {
			a = validation.VObj(
				kv("id", validation.VStr(role)),
				kv("kind", validation.VStr("ROLE")),
				kv("trust", validation.VStr("trusted")),
				kv("via", p),
			)
		}
		if !containsValue(hits, a) {
			hits = append(hits, a)
		}
	}
	return hits
}

// TrustBoundaryGaps is trust_boundary_gaps: crossings that were NOT validated
// in code — the first places to look for integrator/attacker-trajectory bugs.
func TrustBoundaryGaps(model validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, b := range listField(model, "trust_boundaries") {
		if !validation.PyTruthy(validation.ObjAt(b, "validated")) {
			out = append(out, b)
		}
	}
	return out
}

// AccountingVars is accounting_vars: every state variable carrying value,
// projected to {contract, var, kind} in contract/declaration order.
func AccountingVars(model validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, c := range listField(model, "contracts") {
		for _, v := range listField(c, "state_variables") {
			if !validation.PyTruthy(validation.ObjAt(v, "accounting")) {
				continue
			}
			out = append(out, validation.VObj(
				kv("contract", validation.ObjAt(c, "name")),
				kv("var", validation.ObjAt(v, "name")),
				kv("kind", validation.ObjAt(v, "kind")),
			))
		}
	}
	return out
}

// ExternalAssets is external_assets: tokens/positions with nonstandard
// behaviors — fee-on-transfer, rebasing, odd decimals, ERC-777 callbacks,
// ERC-4626 vaults — the classic silent killers. Flag order is contractual:
// fee-on-transfer, rebasing, erc777, erc4626, odd-decimals, then the
// declared nonstandard_behaviors.
func ExternalAssets(model validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, a := range listField(model, "assets") {
		flags := []validation.Value{}
		if validation.PyTruthy(validation.ObjAt(a, "fee_on_transfer")) {
			flags = append(flags, validation.VStr("fee-on-transfer"))
		}
		if validation.PyTruthy(validation.ObjAt(a, "rebasing")) {
			flags = append(flags, validation.VStr("rebasing"))
		}
		erc := validation.ObjAt(a, "erc")
		if erc.Kind == validation.Str && erc.S == "777" {
			flags = append(flags, validation.VStr("erc777-callbacks"))
		}
		if erc.Kind == validation.Str && erc.S == "4626" {
			flags = append(flags, validation.VStr("erc4626-vault"))
		}
		decimals := validation.ObjAt(a, "decimals")
		if decimals.Kind != validation.Null && !standardDecimals(decimals) {
			flags = append(flags, validation.VStr("odd-decimals-"+pyStr(decimals)))
		}
		if nb := validation.ObjAt(a, "nonstandard_behaviors"); validation.PyTruthy(nb) {
			flags = append(flags, extendFlags(nb)...)
		}
		if len(flags) > 0 {
			out = append(out, validation.VObj(
				kv("asset", validation.ObjAt(a, "id")),
				kv("flags", validation.VArr(flags...)),
			))
		}
	}
	return out
}

// extendFlags is Python's list.extend(truthy_value): a list extends itself, a
// string extends with its single-character strings, a dict with its keys. The
// schema requires a list of strings here, so the other kinds are defensive.
func extendFlags(v validation.Value) []validation.Value {
	switch v.Kind {
	case validation.Arr:
		return v.A
	case validation.Str:
		out := []validation.Value{}
		for _, r := range v.S {
			out = append(out, validation.VStr(string(r)))
		}
		return out
	case validation.Obj:
		out := []validation.Value{}
		for _, pair := range v.O {
			out = append(out, validation.VStr(pair.K))
		}
		return out
	}
	return nil
}

// standardDecimals is `decimals in (18, 6, 8)` under Python ==.
func standardDecimals(decimals validation.Value) bool {
	for _, n := range []int64{18, 6, 8} {
		if numericEqual(decimals, validation.VInt(n)) {
			return true
		}
	}
	return false
}

// CriticalEdges is critical_edges: relations that move value or code
// (MUTATING_RELS), in declaration order.
func CriticalEdges(model validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, r := range listField(model, "relations") {
		if _, ok := MUTATING_RELS[validation.ObjAt(r, "rel").S]; ok {
			out = append(out, r)
		}
	}
	return out
}

// PrivilegeSurface is privilege_surface: every (role, capability) pair. The
// D-trajectory (privileged actor) sweeps exactly this list.
func PrivilegeSurface(model validation.Value) []validation.Value {
	return listField(model, "privileges")
}

// OracleChain is oracle_chain: the model's oracle surfaces.
func OracleChain(model validation.Value) []validation.Value {
	return listField(model, "oracles")
}

// StateMachines is state_machines: the model's declared lifecycle machines.
func StateMachines(model validation.Value) []validation.Value {
	return listField(model, "state_machines")
}
