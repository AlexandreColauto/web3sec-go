// wire.go: installs this module into every seam that expects the structural
// index. Nothing in Python has an explicit wiring step — the module is just
// imported — so this is the Go spelling of that import edge. Both entry
// points call it: cmd/webv2's init() (so library users get it too) and the
// CLI's ensureSeams() (so tests and in-process callers get it).
package structidx

import (
	"websec/internal/coverage"
	"websec/internal/orchestrator"
	"websec/internal/planner"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// DefaultBackend is index_snapshot's default backend label.
const DefaultBackend = "regex"

// DefaultMaxDepth is path_exists's default depth cap.
const DefaultMaxDepth = 6

// Wire installs the real structural_index implementation on every seam. It is
// idempotent and safe to call from multiple init paths.
func Wire() {
	orchestrator.SetStructuralIndex(orchestrator.StructuralIndexAPI{
		IndexSnapshot: func(c *state.Campaign, root string) (validation.Value, error) {
			return IndexSnapshot(c, root, DefaultBackend)
		},
		SaveIndex: SaveIndex,
	})
	coverage.SetStructuralIndex(coverage.StructuralIndexAPI{
		ExternalSurface:   ExternalSurface,
		ExternalCallSites: ExternalCallSites,
	})
	reproduction.SetStructuralIndex(reproduction.StructuralIndexAPI{
		UnguardedEntryPoints: UnguardedEntryPoints,
		PathExists: func(index validation.Value, src, dst string) ([]string, bool) {
			return PathExists(index, src, dst, DefaultMaxDepth)
		},
	})
	// probes.campaign_index_sha lives in probes.py but hashes THIS module's
	// artifact. The dedicated setter keeps the seam alive even after the
	// probes port calls SetProbes (which replaces the rest of the API).
	planner.SetCampaignIndexSha(CampaignIndexSha)
}
