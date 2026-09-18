package archetypes

import (
	"fmt"
	"websec/internal/validation"
)

// checkTypes is CHECK_TYPES: the closed set of predicate kinds.
var checkTypes = []string{"state_var_exists", "function_exists",
	"unguarded_function_exists", "delegatecall_present",
	"unguarded_entry_writes", "external_call_pattern",
	"sig_verify_no_separator", "merkle_verify_without_depth_gate",
	"threshold_without_enforcement", "relayer_single_key",
	"merkle_proof_no_length_check", "verifier_default_on"}

// checkKeys is _CHECK_KEYS: the discriminator keys each check type consumes.
// A check carrying a key its type does not use is a silent-filter bug (the
// key is ignored); a check missing a key its type reads is a KeyError at
// evaluate time. Both fail loud at load.
var checkKeys = map[string]map[string]bool{
	"state_var_exists":                 {"names": true, "pattern": true},
	"function_exists":                  {"names": true, "pattern": true},
	"unguarded_function_exists":        {"names": true},
	"delegatecall_present":             {},
	"unguarded_entry_writes":           {"var_pattern": true},
	"external_call_pattern":            {"pattern": true},
	"sig_verify_no_separator":          {"names": true},
	"merkle_verify_without_depth_gate": {"names": true},
	"threshold_without_enforcement":    {"names": true},
	"relayer_single_key":               {"names": true},
	"merkle_proof_no_length_check":     {"names": true},
	"verifier_default_on":              {"names": true},
}

// EvaluatePrecondition is evaluate_precondition: one archetype check against
// the index, returning ("present"|"absent", detail). Deterministic; no model
// involved. A malformed check returns an error naming the type and key —
// never a bare panic — so one bad predicate cannot abort the whole prescreen
// with an unactionable traceback.
func EvaluatePrecondition(check, index validation.Value) (string, string, error) {
	t := validation.ObjStr(check, "type")
	switch t {
	case "state_var_exists", "function_exists":
		return evalNamePresence(t, check, index)
	case "unguarded_function_exists":
		return evalUnguardedFunction(check, index)
	case "delegatecall_present":
		res, detail := evalDelegatecallPresent(index)
		return res, detail, nil
	case "unguarded_entry_writes":
		return evalUnguardedEntryWrites(check, index)
	case "external_call_pattern":
		return evalExternalCallPattern(check, index)
	case "sig_verify_no_separator":
		return evalSigVerifyNoSeparator(check, index)
	case "merkle_verify_without_depth_gate":
		return evalMerkleVerifyWithoutDepthGate(check, index)
	case "threshold_without_enforcement":
		return evalThresholdWithoutEnforcement(check, index)
	case "relayer_single_key":
		return evalRelayerSingleKey(check, index)
	case "merkle_proof_no_length_check":
		return evalMerkleProofNoLengthCheck(check, index)
	case "verifier_default_on":
		return evalVerifierDefaultOn(check, index)
	}
	return "", "", fmt.Errorf("unknown check type %s", validation.PyReprStr(t))
}
