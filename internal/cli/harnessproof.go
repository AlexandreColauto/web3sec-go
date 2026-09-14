package cli

import (
	"crypto/sha256"
	"encoding/hex"

	"websec/internal/validation"
)

// harnessProofDigest fingerprints the proof subtree (canonical JSON of
// the whole object, sha256) so the harness_run EVENT can back a render
// surface the four named fields never covered: k= falls back to
// proof.bounds.loop_bound and the poc: line counts proof.calls —
// without a digest the audit's "backed" stamp vouched for numbers no
// event carried (r23 F1). Null/absent proof digests to the null
// subtree's hash: ABSENCE is pinned too, so a slot-invented sidecar
// burns the backstop instead of slipping through an omitted field.
func harnessProofDigest(proof validation.Value) string {
	sum := sha256.Sum256([]byte(validation.CanonCompact(proof)))
	return hex.EncodeToString(sum[:])
}
