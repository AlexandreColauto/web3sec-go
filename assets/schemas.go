// Package assets embeds the webv2 trust-core data.
package assets

import "embed"

// FS holds the 27 draft-07 JSON schemas. They are byte-for-byte copies of
// web3sec-final/schema (verified by scripts/sync-schemas.sh, Task 15).
//
//go:embed schema/*.schema.json
var FS embed.FS
