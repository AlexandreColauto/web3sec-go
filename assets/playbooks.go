package assets

import "embed"

// PlaybooksFS holds the 8 per-bug-class playbook YAMLs — the framework's
// PRIOR for a canonical class (invariants, decomposition templates, hunt
// order, failure modes). They are byte-for-byte copies of
// web3sec-final/playbooks (verified by the byte-identity test in
// internal/playbooks).
//
//go:embed playbooks/*.yaml
var PlaybooksFS embed.FS
