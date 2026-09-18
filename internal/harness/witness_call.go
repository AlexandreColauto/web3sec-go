package harness

import (
	"fmt"
	"strings"

	"websec/internal/validation"
)

// witness_call.go: the call-entry half of the L4 bridge — validating one
// report call (function, target, step, args, sender, wei value) into the
// step the sequence_poc document carries.

type witnessCall struct {
	function string
	target   string
	args     []validation.Value
	sender   string
	value    string
	reverted bool
}

// witnessCallOf validates one call entry. n is the 1-based position used in
// the refusal text (the array order is the sequence, so an error names
// where it sits); the call's own `step` is required and must be an
// integer, and its value is never copied into the spec (see the file
// comment on step numbering).
func witnessCallOf(call validation.Value, n int) (witnessCall,
	string) {
	var out witnessCall
	fail := func(why string) (witnessCall, string) {
		return witnessCall{}, fmt.Sprintf("unbridgable step: call %d %s", n, why)
	}
	if call.Kind != validation.Obj {
		return fail("is not an object")
	}
	fn, ok := mcField(call, "function")
	if !ok || fn.Kind != validation.Str || fn.S == "" {
		return fail("lacks function")
	}
	target, ok := mcField(call, "target")
	if !ok || target.Kind != validation.Str || target.S == "" {
		return fail("lacks target")
	}
	step, ok := mcField(call, "step")
	if !ok || step.Kind != validation.Int || step.Big != "" {
		return fail("lacks step")
	}
	args, ok := mcField(call, "args")
	argsOut := []validation.Value{}
	if ok && args.Kind != validation.Null {
		if args.Kind != validation.Arr {
			return fail("args is not an array")
		}
		for j, a := range args.A {
			if a.Kind != validation.Str {
				return fail(fmt.Sprintf("arg %d is not a string", j))
			}
			argsOut = append(argsOut, a)
		}
	}
	sender, why := witnessSender(call)
	if why != "" {
		return fail(why)
	}
	if !witnessAddrRe.MatchString(sender) {
		// The prover's free symbols do not survive a chain: an alias for
		// "attacker" would replay as a different address on a fork, so
		// the honest answer is the refusal, not a guessed actor.
		return witnessCall{}, "symbolic senders cannot be fork-repro'd"
	}
	value, valueRefusal := witnessValue(call, n)
	if valueRefusal != "" {
		return witnessCall{}, valueRefusal
	}
	out.function = fn.S
	out.target = target.S
	out.args = argsOut
	out.sender = sender
	out.value = value
	if rv, ok := mcField(call, "reverted"); ok && rv.Kind == validation.Bool {
		out.reverted = rv.B
	}
	return out, ""
}

// witnessValue is the step's wei value as the spec carries it: "" when the
// step sends nothing (the key is absent, or the literal is zero — the
// schema reads an absent key as zero, so both shapes bridge identically),
// the literal VERBATIM when it is schema-legal, and the refusal text
// `unbridgable step: call <n> value <raw> not a wei literal` otherwise.
// The raw value is rendered with Python repr so an operator can see
// exactly what the report said (`'1 ether'` is a string, `None` an
// unevaluated field) and judge it; nothing is parsed, approximated or
// rounded on the way through.
//
// The env object is guaranteed present-and-object here: witnessCallOf
// refuses a call without one before reaching this function. The check is
// repeated anyway because this helper is total on its own — a total read
// cannot turn a malformed report into a panic.
func witnessValue(call validation.Value, n int) (string, string) {
	env, ok := mcField(call, "env")
	if !ok || env.Kind != validation.Obj {
		return "", ""
	}
	raw, ok := mcField(env, witnessValueKey)
	if !ok {
		return "", ""
	}
	if raw.Kind == validation.Str && witnessWeiRe.MatchString(raw.S) {
		if witnessWeiIsZero(raw.S) {
			return "", ""
		}
		return raw.S, ""
	}
	return "", fmt.Sprintf(
		"unbridgable step: call %d value %s not a wei literal", n,
		validation.PyRepr(raw))
}

// witnessWeiIsZero reports whether a schema-legal literal names zero in
// either admitted base: every digit is '0' ("0", "00", "0x0", "0x000").
// The literal is known non-empty (witnessWeiRe requires at least one
// nibble), so an all-zero spelling is a value, not a blank.
func witnessWeiIsZero(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// witnessSender is the step's sender: env["msg.sender"], else the
// flattened env["sender"] alias. The returned reason is the refusal text
// suffix: "" on success, "has no env" when the call carries no env
// object, "has no msg.sender" when the env has no such key or a
// null/empty value (the prover leaves msg.sender null when the model
// never evaluated it) — an unknown actor is not an actor.
//
// Only this one env key is read here; env["msg.value"] is read separately
// by witnessValue, which runs AFTER this check — an actor the fork cannot
// address makes the step unreplayable whatever it sends (see the file
// comment on refusal precedence).
func witnessSender(call validation.Value) (string, string) {
	env, ok := mcField(call, "env")
	if !ok || env.Kind != validation.Obj {
		return "", "has no env"
	}
	v, ok := mcField(env, witnessSenderKey)
	if !ok {
		v, ok = mcField(env, witnessSenderAlias)
	}
	if !ok || v.Kind != validation.Str || v.S == "" {
		return "", "has no " + witnessSenderKey
	}
	return v.S, ""
}
