package assets

import "embed"

// PromptsFS holds the 20 v2 stage prompts under prompts/ — byte-for-byte
// copies of web3sec-final/prompts (verified by the byte-identity test in
// internal/adapter). The pack and the router must never drift apart.
//
//go:embed prompts/*.md
var PromptsFS embed.FS

// LegacyPromptsFS holds the 28 verbatim v1 stage prompts under
// prompts_legacy/ — byte-for-byte copies of web3sec-final/prompts_legacy.
//
//go:embed prompts_legacy/*.md
var LegacyPromptsFS embed.FS
