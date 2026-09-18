// reproduction.go: the seams to webv2.reproduction (P2, unported) and
// webv2.sequence_poc (P2, unported).
//
// reproduction_queue calls reproduction.tier_of / next_tier (pure functions
// over the finding's own reproduction block) and verify_independently calls
// reproduction.mint_independent_evidence (which needs the sandbox ledger).
// is_sequence_required is a pure predicate over the finding's declared
// exploit_sequence.
//
// The defaults for the three PURE functions are faithful transcriptions: they
// are the feature-absent behavior that keeps the deterministic queue
// byte-identical to Python when reproduction.py itself is not wired (the
// module contributes no data of its own — it reads the finding). Minting, the
// one path that would invent evidence, fails loudly instead.
package orchestrator

import (
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// TierOrder is reproduction.TIER_ORDER.
var TierOrder = []string{"none", "T0", "T1", "T2", "T3", "T4"}

// ReproductionAPI is the reproduction.py seam. NextTier's bool is Python's
// None (the last rung has no next tier); the error is Python's ValueError for
// a tier name that is not in TIER_ORDER.
type ReproductionAPI struct {
	TierOf                  func(repro validation.Value) string
	NextTier                func(current string) (string, bool, error)
	MintIndependentEvidence func(c *state.Campaign, findingID, execID,
		description, verifier string) (validation.Value, error)
}

// SequencePOCAPI is the sequence_poc.py seam.
type SequencePOCAPI struct {
	IsSequenceRequired func(finding validation.Value) bool
}

// defaultTierOf is reproduction.tier_of: (repro or {}).get("tier_reached",
// "none").
func defaultTierOf(repro validation.Value) string {
	if repro.Kind == validation.Obj {
		for _, kv := range repro.O {
			if kv.K == "tier_reached" {
				if kv.V.Kind == validation.Str {
					return kv.V.S
				}
				return "none"
			}
		}
	}
	return "none"
}

// defaultNextTier is reproduction.next_tier: the next rung, or None at the
// end. An unknown current tier is Python's ValueError("... is not in list").
func defaultNextTier(current string) (string, bool, error) {
	for i, tier := range TierOrder {
		if tier == current {
			if i+1 < len(TierOrder) {
				return TierOrder[i+1], true, nil
			}
			return "", false, nil
		}
	}
	return "", false, errText(validation.PyReprStr(current) + " is not in list")
}

// defaultMintIndependentEvidence is the absent-module behavior: E6 evidence
// cannot be minted without the module that enforces independence.
func defaultMintIndependentEvidence(_ *state.Campaign, findingID, _, _,
	_ string) (validation.Value, error) {
	return validation.VNull(), orchestrationError(
		"reproduction module not wired: cannot mint independent evidence for " +
			findingID)
}

// defaultIsSequenceRequired is sequence_poc.is_sequence_required: the total
// guard (malformed input -> false, never raises) over the finding's declared
// shape — >= 2 steps, or >= 2 distinct non-empty actors among its steps.
func defaultIsSequenceRequired(finding validation.Value) bool {
	if finding.Kind != validation.Obj {
		return false
	}
	seq := validation.ObjAt(finding, "exploit_sequence")
	steps := []validation.Value{}
	if seq.Kind == validation.Arr {
		steps = seq.A
	}
	if len(steps) >= 2 {
		return true
	}
	actors := map[string]struct{}{}
	for _, s := range steps {
		if s.Kind != validation.Obj {
			continue
		}
		if actor := strAt(s, "actor"); actor != "" {
			actors[actor] = struct{}{}
		}
	}
	return len(actors) >= 2
}

var rpAPI = ReproductionAPI{
	TierOf:                  defaultTierOf,
	NextTier:                defaultNextTier,
	MintIndependentEvidence: defaultMintIndependentEvidence,
}

var seqAPI = SequencePOCAPI{IsSequenceRequired: defaultIsSequenceRequired}

// SetReproduction installs the reproduction implementation (P2 wires this). A
// nil argument — or a nil field — restores the default.
func SetReproduction(api ReproductionAPI) {
	if api.TierOf == nil {
		api.TierOf = defaultTierOf
	}
	if api.NextTier == nil {
		api.NextTier = defaultNextTier
	}
	if api.MintIndependentEvidence == nil {
		api.MintIndependentEvidence = defaultMintIndependentEvidence
	}
	rpAPI = api
}

// SetSequencePOC installs the sequence_poc implementation (P2 wires this). A
// nil argument — or a nil field — restores the default.
func SetSequencePOC(api SequencePOCAPI) {
	if api.IsSequenceRequired == nil {
		api.IsSequenceRequired = defaultIsSequenceRequired
	}
	seqAPI = api
}

// nextTierOrT0 is `RP.next_tier(RP.tier_of(repro)) or "T0"`.
func nextTierOrT0(repro validation.Value) (string, error) {
	tier, ok, err := rpAPI.NextTier(rpAPI.TierOf(repro))
	if err != nil {
		return "", err
	}
	if !ok || tier == "" {
		return "T0", nil
	}
	return tier, nil
}

// joinActors renders the actor count note of the reproduction queue.
func joinActors(actors map[string]struct{}) int { return len(actors) }

// declaredSequence is `f.get("exploit_sequence") or []` with its actor count.
func declaredSequence(finding validation.Value) ([]validation.Value, int) {
	seq := validation.ObjAt(finding, "exploit_sequence")
	steps := []validation.Value{}
	if seq.Kind == validation.Arr {
		steps = seq.A
	}
	actors := map[string]struct{}{}
	for _, s := range steps {
		if s.Kind != validation.Obj {
			continue
		}
		if actor := strAt(s, "actor"); actor != "" {
			actors[actor] = struct{}{}
		}
	}
	return steps, joinActors(actors)
}

// tierListRepr renders TIER_ORDER for error messages that need it.
func tierListRepr() string { return strings.Join(TierOrder, ", ") }
