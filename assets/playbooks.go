package assets

import "embed"

// PlaybooksFS holds the 10 per-bug-class playbook YAMLs — the framework's
// PRIOR for a canonical class (invariants, decomposition templates, hunt
// order, failure modes). Eight are byte-for-byte copies of the retired
// twin's web3sec-final/playbooks; frontend-injection and infra-boundary are
// Go-side additions (Wave G tranche 3). The embedded pack is pinned by the
// committed SHA-256 manifest (assets.TestAssetPackManifest) — the former
// twin byte-diff acceptance check lives there now.
//
//go:embed playbooks/*.yaml
var PlaybooksFS embed.FS
