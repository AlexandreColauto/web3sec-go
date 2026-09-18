// dedup_signatures.go: the tier-2/tier-3 signature writers split out of
// dedup.go — root-cause and economic signature recording plus lineage ids.
package dedup

import (
	"fmt"
	"sort"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// SetRootCauseSignature is set_root_cause_signature: record tier-2 after an
// LLM normalization pass. The sentence must be target-agnostic
// ('attacker-controlled exchange rate creates unbacked withdrawal value'),
// not a restatement of the file name. cwe nil/"" is Python's falsy check.
// sigLiveGuard refuses a signature on a row the sweep itself will skip:
// recording one is inert bookkeeping that LOOKS like coverage (critic r3).
// The predicate mirrors the sweep's liveness law exactly.
func sigLiveGuard(f validation.Value, findingID string) error {
	if findings.IsTerminal(validation.ObjStr(f, "status")) {
		return fmt.Errorf("cannot record a dedup signature on %s (%s): the "+
			"sweep only ever compares live rows — this would satisfy "+
			"nothing", findingID, validation.ObjStr(f, "status"))
	}
	return nil
}

func SetRootCauseSignature(campaign *state.Campaign, findingID, normalizedSentence string,
	cwe *string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if err := sigLiveGuard(f, findingID); err != nil {
		return validation.VNull(), err
	}
	sig := findings.TextSignature(normalizedSentence)
	f = setDeep(f, validation.VStr(sig), "dedup", "root_cause_signature")
	if cwe != nil && *cwe != "" {
		f = setDeep(f, validation.VStr(*cwe), "root_cause", "cwe")
	}
	f = setDeep(f, validation.VStr(normalizedSentence), "dedup_meta", "root_cause_sentence")
	// r18 P2: signature stamped with no event = a dedup row the audit
	// can never explain; unwind law applies like everywhere else.
	if err := findings.SaveThenLog(campaign, &f, func() error {
		_, lerr := campaign.Log("dedup.root_cause_set", &findingID, nil)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// SetEconomicSignature is set_economic_signature: record tier-3 after an LLM
// normalization pass over the attacker's ultimate economic effect.
func SetEconomicSignature(campaign *state.Campaign, findingID,
	normalizedEffect string) (validation.Value, error) {
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if err := sigLiveGuard(f, findingID); err != nil {
		return validation.VNull(), err
	}
	sig := findings.TextSignature(normalizedEffect)
	f = setDeep(f, validation.VStr(sig), "dedup", "economic_signature")
	f = setDeep(f, validation.VStr(normalizedEffect), "dedup_meta", "economic_effect_sentence")
	if err := findings.SaveThenLog(campaign, &f, func() error {
		_, lerr := campaign.Log("dedup.economic_set", &findingID, nil)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// LineageIDFor is lineage_id_for: a deterministic lineage id, so the same
// cluster gets the same id on every run (a uuid4 id churned on every sweep,
// which made re-runs look like new discoveries).
func LineageIDFor(signature string, memberIDs []string) string {
	sorted := append([]string(nil), memberIDs...)
	sort.Strings(sorted)
	digest := findings.TextSignature("lineage|" + signature + "|" + strings.Join(sorted, "|"))
	if len(digest) > 8 {
		digest = digest[:8]
	}
	return "LIN-" + digest
}
