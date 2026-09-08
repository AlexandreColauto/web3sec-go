// register.go is the single wiring point for the six P0 audit sections,
// in Python's audit.py code order (event_log, artifacts, execs, findings,
// projection, snapshots). It deliberately does NOT import the audit
// package: the audit package (and its in-package tests) depend on
// sections, so a sections->audit edge here would be an import cycle. The
// audit package passes its own registerAuditSection so registration lands
// in the audit registry without a cycle. A later phase extends this list
// with sections 7-12 — a missing section is simply absent until then (the
// Plan forbids stubbing P1+ sections as always-pass).
package sections

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// SectionFunc is one section producer (structurally the audit registry's
// section func; the two are interchangeable by value).
type SectionFunc func(c *state.Campaign) (validation.Value, error)

// RegisterAll calls register(name, producer) for the six P0 sections in
// report (registration) order.
func RegisterAll(register func(name string, fn SectionFunc)) {
	register("event_log", EventLog)
	register("artifacts", Artifacts)
	register("execs", Execs)
	register("findings", Findings)
	register("projection", Projection)
	register("snapshots", Snapshots)
}
