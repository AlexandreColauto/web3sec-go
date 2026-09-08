// wire.go: the import-time seams this package fills, mirroring Python's
// function-level `from . import fork_poc as FP` / `from . import immunize as
// IM` imports. Python connects them at call time; Go connects them once at
// init, so a blank-or-named import of websec/internal/immunize (cmd_immunize
// pulls it into the CLI) is enough to activate:
//
//   - bounty_policy check 11 (mainnet-fork-poc) asks fork_poc.fork_poc_status;
//   - bounty_policy check 12 (immunization) asks immunize.immunization_detail;
//   - completion's mainnet-fork-poc proof asks fork_poc.fork_poc_evidence.
//
// The installers are seam-shaped: with this package unimported every default
// matches Python on data those modules have not produced yet.
package immunize

import (
	"websec/internal/bounty"
	"websec/internal/completion"
	"websec/internal/forkpoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// forkPocAPI adapts forkpoc.ForkPocEvidence to completion.ForkPocAPI (the
// interface keeps the two packages independent).
type forkPocAPI struct{}

func (forkPocAPI) ForkPocEvidence(c *state.Campaign,
	f validation.Value) (validation.Value, *string, error) {
	return forkpoc.ForkPocEvidence(c, f)
}

func init() {
	bounty.SetForkPocStatus(forkpoc.ForkPocStatus)
	bounty.SetImmunizationDetail(ImmunizationDetail)
	completion.SetForkPocEvidence(forkPocAPI{})
}
