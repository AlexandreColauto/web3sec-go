// priors.go (G3 wPrior): the policy gate for the calibrated acceptance
// prior. `acceptance_priors` is a top-level bounty_policy boolean,
// default false — the same absent-means-off posture as patch_clause's
// absent-means-verification, so every campaign that predates this field
// (and the golden fixtures, and the pinned gate vectors) behaves
// byte-for-byte as before. Risk stays pure: the CALLER resolves this flag
// and the priors; risk only scores what it is handed.
package bounty

import (
	"websec/internal/risk"
	"websec/internal/validation"
)

// PriorsEnabled is the campaign's answer to "does this program want the
// calibrated class base rate in its acceptance scores?" A non-boolean or
// absent key is false — the schema refuses non-booleans at load time, and
// this is the last line of defense for hand-built policies in tests.
func PriorsEnabled(policy validation.Value) bool {
	v := objAt(policy, "acceptance_priors")
	return v.Kind == validation.Bool && v.B
}

// gateAcceptance is the gate's A3 score with the policy gate resolved: the
// plain deterministic score unless the campaign opted into
// acceptance_priors, in which case the score carries the class prior. An
// eval-store failure resolves to nil priors, and nil priors score
// bit-identically to Acceptance — so a broken store degrades to today's
// number, never to an error.
func gateAcceptance(f validation.Value, policy validation.Value) (float64, bool) {
	if !PriorsEnabled(policy) {
		return risk.AcceptanceScore(f)
	}
	priors, global, _ := risk.AcceptancePriors(risk.DefaultMinN)
	e := risk.AcceptanceWithPriors(f, priors, global)
	return e.Score, e.Disqualified
}
