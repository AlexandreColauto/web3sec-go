// api_consumers.go: the additive public surface the index CONSUMERS need.
//
// structural_index.py keeps `_nodes`, `_is_authz_guard` and `_param_types`
// private but corpus_surface.py and archetypes.py import them directly
// (`from .structural_index import _param_types`). Go has no package-private
// import edge, so these three wrappers are the port's spelling of that
// same-module access. They are thin: no behavior lives here.
package structidx

import "websec/internal/validation"

// Nodes is _nodes(index, kind): the nodes of one kind (kind == "" matches
// every node, exactly like `_nodes(index, None)`).
func Nodes(index validation.Value, kind string) []validation.Value {
	return nodesOf(index, kind)
}

// IsAuthzGuard is _is_authz_guard: a modifier name that gates AUTHORIZATION
// (reentrancy/pausability guards do not count).
func IsAuthzGuard(mod string) bool { return isAuthzGuard(mod) }

// ParamTypes is _param_types: the comma-joined first-type tokens with array
// suffixes, the shared normalization PoC shapes and target selectors both
// use so they are directly comparable.
func ParamTypes(paramsText string) string { return paramTypes(paramsText) }
