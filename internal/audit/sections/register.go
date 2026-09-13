// register.go is the single wiring point for the audit sections, in
// Python's audit.py code order (event_log, artifacts, execs, findings,
// projection, snapshots, relations, floor_policy, stage_completions,
// baselines, invariant_verification, sequence_coverage, probe_surface,
// unpriceable) plus the presence-gated G4 eval section appended last: it
// renders only when the campaign matches the eval suite, and AuditCampaign
// omits it otherwise. It deliberately does NOT import the audit package: the
// audit package (and its in-package tests) depend on sections, so a
// sections->audit edge here would be an import cycle. The audit package
// passes its own registerAuditSection so registration lands in the audit
// registry without a cycle.
package sections

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// SectionFunc is one section producer (structurally the audit registry's
// section func; the two are interchangeable by value).
type SectionFunc func(c *state.Campaign) (validation.Value, error)

// RegisterAll calls register(name, producer) for every ported section in
// report (registration) order = Python's code order.
func RegisterAll(register func(name string, fn SectionFunc)) {
	register("event_log", EventLog)
	register("artifacts", Artifacts)
	register("execs", Execs)
	register("findings", Findings)
	register("projection", Projection)
	register("snapshots", Snapshots)
	register("relations", Relations)
	register("floor_policy", FloorPolicy)
	register("stage_completions", StageCompletions)
	register("baselines", Baselines)
	register("invariant_verification", InvariantVerification)
	register("sequence_coverage", SequenceCoverage)
	register("probe_surface", ProbeSurface)
	register("unpriceable", Unpriceable)
	register("eval", Eval)
	// r4: the price-table reconciliation. Registered LAST: the ported
	// audit.py sections keep their relative order, and PRICING is new.
	register("price_table", PriceTable)
}
