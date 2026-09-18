package harness

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"websec/internal/validation"
)

// witness_storage.go: the layout-grounding half of the L4 bridge — how the
// prover's final_storage readings (keyed by VARIABLE NAME) become
// final_assertions entries read on the fork by SLOT.

const witnessStorageKey = "final_storage"

// witnessDecRe is the sequence_poc schema's final_assertions `value`
// pattern: DECIMAL only (a step's `value` additionally admits 0x hex).
// witnessHexRe is the other concrete spelling a storage reading can take,
// normalized into the schema's decimal language by witnessStorageDecimal.
var (
	witnessDecRe = regexp.MustCompile(`^[0-9]+$`)
	witnessHexRe = regexp.MustCompile(`^0x[0-9a-fA-F]{1,64}$`)
)

// witnessAssertion is one grounded storage reading: the layout key that
// grounded it (the emission sort key), and the schema fields it renders to.
type witnessAssertion struct {
	key    string
	target string
	slot   string
	value  string
}

// witnessFinalAssertions translates final_storage readings into
// final_assertions entries, returning the entries plus m — the number of
// readings the report carried, whether or not each could be grounded (the
// n of m honesty line in BridgeSequenceWithLayout's doc). It is total: a
// report with no final_storage object, a non-object, or nothing groundable
// yields the empty array and m, never an error and never a guess.
//
// targets is the set of bridged step targets an assertion may name; layout
// is the "<Contract>.<var>" -> decimal slot map (nil = no grounding).
func witnessFinalAssertions(obj validation.Value, targets []string,
	layout map[string]string) ([]validation.Value, int) {
	readings, ok := mcField(obj, witnessStorageKey)
	if !ok || readings.Kind != validation.Obj {
		return []validation.Value{}, 0
	}
	grounded := make([]witnessAssertion, 0, len(readings.O))
	for _, kv := range readings.O {
		value, ok := witnessStorageDecimal(kv.V)
		if !ok {
			continue
		}
		a, ok := witnessStorageAssertion(kv.K, value, targets, layout)
		if !ok {
			continue
		}
		grounded = append(grounded, a)
	}
	sort.Slice(grounded, func(i, j int) bool {
		return grounded[i].key < grounded[j].key
	})
	out := make([]validation.Value, 0, len(grounded))
	for i, a := range grounded {
		out = append(out, validation.VObj(
			validation.KV{K: "id", V: validation.VStr(fmt.Sprintf("A%d", i+1))},
			validation.KV{K: "kind", V: validation.VStr("storage")},
			validation.KV{K: "target", V: validation.VStr(a.target)},
			validation.KV{K: "slot", V: validation.VStr(a.slot)},
			validation.KV{K: "op", V: validation.VStr("==")},
			validation.KV{K: "value", V: validation.VStr(a.value)},
		))
	}
	return out, len(readings.O)
}

// witnessStorageDecimal is the concrete-value test and the schema's
// decimal normalizer: a decimal literal passes through VERBATIM (the bridge
// translates, it never re-renders a number), an 0x literal of at most 64
// nibbles is converted EXACTLY to its decimal spelling (lossless — the
// assertion `value` pattern is decimal-only, so hex is either converted or
// dropped, and a conversion is a base change, not a rounding). Everything
// else — "*", "?", a pretty amount, an empty string, a JSON number or
// bool — reports false: a value the prover never pinned grounds no
// assertion.
func witnessStorageDecimal(v validation.Value) (string, bool) {
	if v.Kind != validation.Str {
		return "", false
	}
	if witnessDecRe.MatchString(v.S) {
		return v.S, true
	}
	if witnessHexRe.MatchString(v.S) {
		n, ok := new(big.Int).SetString(v.S[2:], 16)
		if !ok {
			return "", false
		}
		return n.String(), true
	}
	return "", false
}

// witnessStorageAssertion grounds one concrete reading named varName
// against the layout and the bridged targets, returning the assertion or
// false when the reading must be SKIPPED. The rules are the clause list in
// BridgeSequenceWithLayout's doc: an exact "<Contract>.<varName>" layout
// key with a decimal slot, a target derivable as one of the bridged step
// targets (companion address first, then the contract segment itself), and
// EXACTLY one grounding entry — ambiguity is a skip, not a coin toss.
func witnessStorageAssertion(varName, value string, targets []string,
	layout map[string]string) (witnessAssertion, bool) {
	if len(layout) == 0 {
		return witnessAssertion{}, false
	}
	var (
		found witnessAssertion
		hits  int
	)
	for key := range layout {
		dot := strings.LastIndex(key, ".")
		if dot <= 0 || key[dot+1:] != varName {
			continue
		}
		slot := layout[key]
		if !witnessDecRe.MatchString(slot) {
			continue
		}
		target, ok := witnessBridgedTarget(key[:dot], targets, layout)
		if !ok {
			continue
		}
		found = witnessAssertion{key: key, target: target, slot: slot,
			value: value}
		hits++
	}
	if hits != 1 {
		return witnessAssertion{}, false
	}
	return found, true
}

// witnessBridgedTarget resolves the contract a layout key names to one of
// the bridged step targets: layout["<Contract>"] is the companion address
// entry (a layout map may carry "Vault" -> "0x…" beside "Vault.total" ->
// "3"), else the "<Contract>" segment is itself an address literal. The
// comparison is case-insensitive (a checksummed spelling is the same
// address) but the STEP'S OWN bytes are what is emitted, so every assertion
// target is byte-identical to a target in the sequence. An address no
// bridged step calls is not derivable from the sequence: false, and the
// reading is skipped rather than pointed at an address the replay never
// touched.
func witnessBridgedTarget(contract string, targets []string,
	layout map[string]string) (string, bool) {
	addr := ""
	if companion, ok := layout[contract]; ok &&
		witnessAddrRe.MatchString(companion) {
		addr = companion
	} else if witnessAddrRe.MatchString(contract) {
		addr = contract
	}
	if addr == "" {
		return "", false
	}
	for _, t := range targets {
		if strings.EqualFold(t, addr) {
			return t, true
		}
	}
	return "", false
}

// witnessCall is one validated call entry: the fields the spec keeps.
// value is the step's wei literal, "" when the call sent nothing (or
