// wire.go: the import-time seams this package fills (Python's function-level
// `from . import completion as CP` imports). pipeline.run() asks for the
// proof of every handler-less model stage; bounty_policy asks for the
// recorded waivers. Both are installed here so a blank import of
// websec/internal/completion is enough to activate them.
package completion

import (
	"websec/internal/bounty"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

// api is the pipeline.CompletionAPI adapter (ProofStatus has the seam's
// signature already, but the interface keeps the two independent).
type api struct{}

func (api) ProofStatus(c *state.Campaign, stage string) (validation.Value, error) {
	return ProofStatus(c, stage)
}

func init() {
	pipeline.SetCompletion(api{})
	bounty.SetWaivers(Waivers)
}
