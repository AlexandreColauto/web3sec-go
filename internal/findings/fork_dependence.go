package findings

// Per-hypothesis fork dependence (framework-plan-v1.6 §2.2). Fork-dependence
// is a property of the HYPOTHESIS, never of the class: an oracle-manipulation
// hypothesis with a mocked feed is decidable locally; the same class against
// real Chainlink state is not. The class-level set survives only as a PRIOR
// (Phase 5's rubric), which a hypothesis overrides with a recorded reason.

import (
	"fmt"
	"slices"

	"websec/internal/state"
	"websec/internal/validation"
)

// ForkDependenceValues are the declared values, weakest first.
var ForkDependenceValues = []string{
	"external-protocol-state", "real-price-feed", "real-balances-liquidity",
	"proxy-implementation", "none",
}

// ForkDependent reports whether a hypothesis needs real fork state (v1.6
// §2.2). Absent is unknown is DEPENDENT: an unrecorded value must never
// silently defund the evidence that would correct it. It lives here rather
// than with the rest of fork_dependence because ValidatePocTierOrder is
// conditional on it, and every task commits green.
func ForkDependent(f validation.Value) bool {
	return validation.ObjStr(f, "fork_dependence") != "none"
}

// ExistenceFundingRequired is §2.2's formula, verbatim:
// existence_funding = E4_satisfied AND fork_dependence != none.
func ExistenceFundingRequired(f validation.Value, e4Satisfied bool) bool {
	return e4Satisfied && ForkDependent(f)
}

// SetForkDependence records the hypothesis's fork dependence with the reason
// the author gives. One event per set, hash-chained, actor-attributed.
func SetForkDependence(c *state.Campaign, findingID, value, reason, actor string) (validation.Value, error) {
	if !slices.Contains(ForkDependenceValues, value) {
		return validation.VNull(), fmt.Errorf(
			"fork_dependence must be one of %v", ForkDependenceValues)
	}
	if reason == "" {
		return validation.VNull(), fmt.Errorf(
			"fork-dependence requires --reason: an override without a recorded reason is a guess")
	}
	finding, err := LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	prior := validation.ObjStr(finding, "fork_dependence") // "" when never set
	finding.O = validation.SetOrAppend(finding.O, "fork_dependence", validation.VStr(value))
	fid := validation.ObjStr(finding, "finding_id")
	if err := SaveThenLog(c, &finding, func() error {
		data := validation.VObj(
			validation.KV{K: "fork_dependence", V: validation.VStr(value)},
			validation.KV{K: "prior_fork_dependence", V: validation.VStr(prior)},
			validation.KV{K: "reason", V: validation.VStr(reason)},
			validation.KV{K: "actor", V: validation.VStr(orDefault(actor, "operator"))},
		)
		_, lerr := c.Log("finding.fork_dependence_set", &fid, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}
