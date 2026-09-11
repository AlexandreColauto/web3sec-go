// Package assets embeds the webv2 trust-core data.
package assets

import "embed"

// FS holds the draft-07 JSON schemas. The web3sec-final copies are pinned
// byte-for-byte by the asset manifest (Task 15); taxonomy_aliases (Task 24,
// G12) and operator_facts (Wave I Task 8, I4) are Go-native — no Python twin
// defines them.
//
//go:embed schema/*.schema.json
var FS embed.FS
