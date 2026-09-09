package assets

import "embed"

// ArchetypesFS holds the 7 critical-bug archetype YAMLs — the deterministic
// predicates the pre-screen runs over the structural index. They are
// byte-for-byte copies of web3sec-final/archetypes (verified by the
// byte-identity test in internal/archetypes).
//
//go:embed archetypes/*.yaml
var ArchetypesFS embed.FS
