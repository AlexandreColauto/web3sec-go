// adversarial.go: the adversarial-game clause (IMPROVEMENTS B2). A liveness
// finding is not "the protocol can be frozen" — it is "the protocol can be
// frozen, and the freeze PAYS SOMEONE". The clause forces that answer into
// the record (who_profits, profit_mechanism, challenge_interplay) so a
// freeze finding can no longer be buried with "liveness-only, the owner can
// revert" without first naming the incentive. The setter records the clause
// as DATA on the finding and logs one finding.adversarial_game_set event;
// the gate (check15) re-validates the stored value, so a hand-edited field
// cannot sneak past.
package findings

import (
	"fmt"

	"websec/internal/capabilities"
	"websec/internal/state"
	"websec/internal/validation"
)

// AdversarialGameFieldMin is the minimum length (in runes) of every
// adversarial_game field — a label is not an argument.
const AdversarialGameFieldMin = 20

// AdversarialGameFields is the clause's field order (schema, setter, gate,
// report all walk it).
var AdversarialGameFields = []string{"who_profits", "profit_mechanism",
	"challenge_interplay"}

// LivenessClasses is the liveness bug-class set: a finding whose
// root_cause.class is one of these owes the clause. (The gate additionally
// triggers on economic_impact.kind == "liveness" — the B1 materialized
// chains — and on findings that grant the liveness_loss terminal
// capability, so "any class whose terminal is LIVENESS_LOSS" is covered.)
var LivenessClasses = map[string]struct{}{
	"chain-freeze":   {},
	"sequencer-halt": {},
	"liveness":       {},
}

// IsLivenessFinding answers the check15 trigger: does this finding owe the
// adversarial-game clause?
func IsLivenessFinding(f validation.Value) bool {
	if cls := objStrAt(f, "root_cause", "class"); cls != "" {
		if _, ok := LivenessClasses[cls]; ok {
			return true
		}
	}
	if kind := objStrAt(f, "economic_impact", "kind"); kind == "liveness" {
		return true
	}
	for _, cap := range strListAt(f, "capabilities", "granted") {
		if capabilities.IsLivenessTerminal(cap) {
			return true
		}
	}
	return false
}

// objStrAt is a two-level object string read (absent = "").
func objStrAt(v validation.Value, k1, k2 string) string {
	sub := objAt(v, k1)
	if sub.Kind != validation.Obj {
		return ""
	}
	return objStr(sub, k2)
}

// strListAt is a two-level string-array read (absent = empty).
func strListAt(v validation.Value, k1, k2 string) []string {
	sub := objAt(v, k1)
	if sub.Kind != validation.Obj {
		return nil
	}
	arr := objAt(sub, k2)
	if arr.Kind != validation.Arr {
		return nil
	}
	out := []string{}
	for _, item := range arr.A {
		if item.Kind == validation.Str {
			out = append(out, item.S)
		}
	}
	return out
}

// AdversarialGameDeficits lists what is wrong with the stored clause:
// "missing" (no clause at all) or one line per absent/short field. Empty =
// the clause is complete (or the finding does not owe one — the caller
// checks IsLivenessFinding first).
func AdversarialGameDeficits(f validation.Value) []string {
	ag := objAt(f, "adversarial_game")
	if ag.Kind != validation.Obj {
		return []string{"missing"}
	}
	out := []string{}
	for _, key := range AdversarialGameFields {
		v := objAt(ag, key)
		if v.Kind != validation.Str ||
			len([]rune(v.S)) < AdversarialGameFieldMin {
			out = append(out, key)
		}
	}
	return out
}

// SetAdversarialGame is set_adversarial_game: record the incentive argument
// for a liveness finding. Every field is mandatory and must reach
// AdversarialGameFieldMin runes (InputError → the CLI exits 2).
func SetAdversarialGame(campaign *state.Campaign, findingID string,
	whoProfits, profitMechanism, challengeInterplay string) (validation.Value, error) {
	fields := map[string]string{
		"who_profits":         whoProfits,
		"profit_mechanism":    profitMechanism,
		"challenge_interplay": challengeInterplay,
	}
	for _, key := range AdversarialGameFields {
		if n := len([]rune(fields[key])); n < AdversarialGameFieldMin {
			return validation.VNull(), &InputError{Msg: fmt.Sprintf(
				"adversarial_game.%s must be >= %d characters (have %d) "+
					"— say who profits, how the profit works, and why the "+
					"challenge path does not undo it", key,
				AdversarialGameFieldMin, n)}
		}
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ag := validation.VObj()
	for _, key := range AdversarialGameFields {
		ag.O = append(ag.O, validation.KV{K: key,
			V: validation.VStr(fields[key])})
	}
	finding.O = validation.SetOrAppend(finding.O, "adversarial_game", ag)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj()
	for _, key := range AdversarialGameFields {
		data.O = append(data.O, validation.KV{
			K: key + "_chars",
			V: validation.VInt(int64(len([]rune(fields[key]))))})
	}
	if _, err := campaign.Log("finding.adversarial_game_set", &findingID,
		&data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}
