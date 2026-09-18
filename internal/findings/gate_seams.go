package findings

import (
	"regexp"
	"strconv"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- seams into modules that land later (invariants: Task 8; reproduction /
// ---- sequence_poc / planner / taxonomy: their own tasks). The defaults are
// ---- the safe no-ops; Set* wires the real implementation.

// normalizeInvIDFunc is invariants.normalize_inv_id (INV-001 -> INV-1). The
// default is the Python semantics verbatim — every gate comparison keys on
// the canonical spelling, so an identity default would silently split
// INV-005 from INV-5. SetNormalizeInvID re-wires it to the invariants module.
var invIDRe = regexp.MustCompile(`^INV-([0-9]+)$`)

var normalizeInvIDFunc = func(iid string) string {
	m := invIDRe.FindStringSubmatch(iid)
	if m == nil {
		return iid
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return iid
	}
	return "INV-" + strconv.FormatInt(n, 10)
}

// SetNormalizeInvID wires invariants.normalize_inv_id (Task 8).
func SetNormalizeInvID(f func(string) string) {
	if f == nil {
		panic("findings: nil normalize_inv_id")
	}
	normalizeInvIDFunc = f
}

// loadInvariantLinksFunc is invariants.load_links: the registry document
// ({"invariants": {...}}).
var loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
	return validation.VObj(), nil
}

// SetLoadInvariantLinks wires invariants.load_links (Task 8).
func SetLoadInvariantLinks(f func(*state.Campaign) (validation.Value, error)) {
	if f == nil {
		panic("findings: nil invariant links loader")
	}
	loadInvariantLinksFunc = f
}

// documentedInvariantsFunc is invariants.documented_invariants: the ids the
// target documents about itself (keyed by canonical id).
var documentedInvariantsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
	return map[string]validation.Value{}, nil
}

// SetDocumentedInvariants wires invariants.documented_invariants (Task 8).
func SetDocumentedInvariants(f func(*state.Campaign) (map[string]validation.Value, error)) {
	if f == nil {
		panic("findings: nil documented-invariants loader")
	}
	documentedInvariantsFunc = f
}

// invariantVerifiedFunc is invariants._is_verified: the log-anchored verdict.
var invariantVerifiedFunc = func(entry validation.Value, c *state.Campaign,
	iid string, events []validation.Value) bool {
	return false
}

// SetInvariantVerified wires invariants._is_verified (Task 8).
func SetInvariantVerified(f func(validation.Value, *state.Campaign, string,
	[]validation.Value) bool) {
	if f == nil {
		panic("findings: nil invariant verifier")
	}
	invariantVerifiedFunc = f
}

// intentClaimsFunc is invariants.intent_claims: documented invariants whose
// text carries intent language, keyed by canonical id.
var intentClaimsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
	return map[string]validation.Value{}, nil
}

// SetIntentClaims wires invariants.intent_claims (Task 8).
func SetIntentClaims(f func(*state.Campaign) (map[string]validation.Value, error)) {
	if f == nil {
		panic("findings: nil intent-claims loader")
	}
	intentClaimsFunc = f
}

// reproductionTierOrderFunc is reproduction.TIER_ORDER. The default is the
// Python constant verbatim; a wiring agent may override it.
var reproductionTierOrderFunc = func() []string {
	return []string{"none", "T0", "T1", "T2", "T3", "T4"}
}

// SetReproductionTierOrder wires reproduction.TIER_ORDER.
func SetReproductionTierOrder(f func() []string) {
	if f == nil {
		panic("findings: nil tier order")
	}
	reproductionTierOrderFunc = f
}

// onchainSequenceRequiredFunc is sequence_poc.onchain_sequence_required.
var onchainSequenceRequiredFunc = func(*state.Campaign, validation.Value) bool {
	return false
}

// SetOnchainSequenceRequired wires sequence_poc.onchain_sequence_required.
func SetOnchainSequenceRequired(f func(*state.Campaign, validation.Value) bool) {
	if f == nil {
		panic("findings: nil sequence-required predicate")
	}
	onchainSequenceRequiredFunc = f
}

// verifySequenceCoverageFunc is sequence_poc.verify_sequence_coverage:
// (covered, reasons).
var verifySequenceCoverageFunc = func(*state.Campaign, validation.Value,
	validation.Value) (bool, []string) {
	return false, nil
}

// SetVerifySequenceCoverage wires sequence_poc.verify_sequence_coverage.
func SetVerifySequenceCoverage(f func(*state.Campaign, validation.Value,
	validation.Value) (bool, []string)) {
	if f == nil {
		panic("findings: nil sequence coverage verifier")
	}
	verifySequenceCoverageFunc = f
}
