// Package assets embeds the webv2 trust-core data.
package assets

import "embed"

// FS holds the 28 draft-07 JSON schemas. The first 27 are byte-for-byte
// copies of web3sec-final/schema (verified by scripts/sync-schemas.sh, Task
// 15); taxonomy_aliases is Go-native (Task 24, G12: no Python twin defines
// it).
//
//go:embed schema/*.schema.json
var FS embed.FS
