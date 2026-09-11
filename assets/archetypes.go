package assets

import "embed"

// ArchetypesFS holds the 13 critical-bug archetype YAMLs — the deterministic
// predicates the pre-screen runs over the structural index. Seven are
// byte-for-byte copies of the retired twin's web3sec-final/archetypes; six
// are Go-side additions (two in Wave G tranche 3, four bridge predicates in
// Wave I). The embedded pack is pinned by the committed SHA-256 manifest
// (assets.TestAssetPackManifest) — the former twin byte-diff acceptance
// check lives there now.
//
//go:embed archetypes/*.yaml
var ArchetypesFS embed.FS
