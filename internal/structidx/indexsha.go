// indexsha.go: index_sha / tree_facts (spec §5.7) — the tree-fact content
// hash of a structural index, NOT the artifact hash. The Python twin lives in
// webv2.probes; structural_index owns the artifact it hashes, so the function
// is ported here and wired into the planner's probes seam.
package structidx

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// volatileIndexKeys are the top-level keys that describe the artifact
// *instance* rather than the tree: campaign identity, the snapshot pin the
// index was read at, and the build wall-clock. The same tree indexed twice,
// in two campaigns, at two times, must hash equal.
var volatileIndexKeys = map[string]bool{
	"campaign_id": true, "snapshot_id": true, "created_at": true,
}

// TreeFacts is tree_facts: the rebuild-stable projection of an index.
func TreeFacts(index validation.Value) validation.Value {
	if index.Kind != validation.Obj {
		return index
	}
	out := make([]validation.KV, 0, len(index.O))
	for _, kv := range index.O {
		if volatileIndexKeys[kv.K] {
			continue
		}
		out = append(out, kv)
	}
	return validation.VObj(out...)
}

// IndexSha is index_sha: sha256 of the compact canonical JSON of the tree
// facts (sort_keys, ensure_ascii, separators (",", ":") — Python's
// json.dumps arguments verbatim).
func IndexSha(index validation.Value) string {
	sum := sha256.Sum256([]byte(validation.CanonCompact(TreeFacts(index))))
	return hex.EncodeToString(sum[:])
}

// CampaignIndexSha is probes.campaign_index_sha: the index_sha of the
// campaign's current structural index artifact, or nil when there is no
// readable index. The closure clause fails CLOSED on nil.
func CampaignIndexSha(c *state.Campaign) *string {
	p := filepath.Join(c.ArtifactsDir, StructuralIndexFile)
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	idx, err := validation.ReadJson(p)
	if err != nil {
		return nil
	}
	sha := IndexSha(idx)
	return &sha
}
