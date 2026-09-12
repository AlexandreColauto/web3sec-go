// witness.go: the L4 bridge — a minicertora counterexample witness
// compiled into a sequence_poc-shaped document (the T4 rung's input
// artifact, internal/sequencepoc.LoadSequenceSpec).
//
// Where the witness lives. The mapper's proof sidecar (minicertora.go
// mcProof) deliberately carries the prover's report fields only; the
// full witness — `params`, `calls[]`, `initial_storage`, `final_storage`,
// `failed_assertion` — stays in the EXEC stdout artifact, and this
// function takes that verdict-line object (the parsed JSONL line) as its
// input. Nothing here reads disk or runs a tool: the bridge is a pure
// mapper like every other function in this package.
//
// Sender key. minicertora's `_call_env` (minicertora/cli.py) builds each
// step's env as {"msg.sender": <addr or symbol or null>, "msg.value":
// <decimal>} — there is NO bare "sender" key in a minicertora report.
// The vendored corpus fixtures under testdata/ carry only
// `essential_witness` (failed_assertion + final_storage) and have no
// calls/env at all, so the tool's own report shape is the source of
// truth and `witnessSenderKey` is "msg.sender". `witnessSenderAlias`
// ("sender") is accepted as a fallback spelling for a flattened env;
// "msg.sender" wins when both are present.
//
// Value channel. env["msg.value"] is the second env key this bridge
// consumes, and it rides into the step's own `value` key (a schema change
// this wave; the key is OPTIONAL, so every spec written before it stays
// valid). minicertora's `_call_env` writes that field as
// `str(model.eval_bitvec(expr))` — a DECIMAL wei literal, with "0" as the
// default when the rule never pinned it and `null` when the model never
// evaluated it — so the decimal spelling is the one form the tool can
// actually emit, and it is passed through VERBATIM (the bridge translates,
// it never re-renders a number). A hex literal is admitted too, because
// the schema's pattern is the shared value language and `cast send
// --value` parses both; refusing it would make the bridge stricter than
// the schema for no gain. Zero ("0", "00", "0x0") and an absent key are
// written by OMITTING `value`: absent = zero in the schema, so a
// zero-value step bridges to exactly the bytes it bridged before.
//
// A value that is not a wei literal is a REFUSAL, never a round. The
// pinned tool cannot produce one — `_call_env` stringifies an int and its
// pretty-renderer is `str()` too, and a grep of the tool's Python finds no
// unit formatting anywhere — so the refusal lane is the guard for
// everything else that could hand this bridge a report: a future tool
// version, a hand-edited witness, a different producer. "1 ether" refuses
// with the raw value quoted, because a bridge that parsed it would be
// guessing a number and replaying a different transaction than the
// counterexample describes. The same applies to `null` — an unstated
// value is not zero, and replaying it as zero would resume a different
// transaction than the one the prover found.
//
// Refusal law (fail-open-to-honest, the package's house style): the
// bridge either returns a schema-valid sequence_poc or the null value
// plus a refusal byte-pinned in witness_test.go — never a partial spec.
// A symbolic sender is the interesting case: the prover's free symbols
// do not survive a chain, so the refusal text itself is the guidance.
//
// Refusal precedence. Structural call validation is matched BEFORE the
// sender/address check: witnessCallOf checks function, target, step and
// args (in that written order, each shape-only) and only then resolves
// the sender and matches it against witnessAddrRe. A call that is BOTH
// malformed and symbolic therefore reports the structural refusal first
// — "unbridgable step: call N lacks function", not the symbolic-sender
// text — because the structural fault is decidable from the report alone
// while the sender is only meaningful once the call is well-formed. The
// precedence is pinned byte-exactly by the "missing function with a
// symbolic sender" row in witness_test.go. The value is checked LAST, for
// the same reason: what a call sends cannot make an unaddressable actor
// replayable, so a step that is both symbolic and value-malformed refuses
// for the actor.
//
// Step numbering. The spec's `step` is the 1-based ordinal of a call in
// the sequence (sequence_poc.schema.json: integer >= 1), and the array
// order IS the sequence. The prover numbers its calls from 0
// (cli.py `_extract`), so the emitted ordinal is the bridge's own
// 1-based position after the call's own `step` has been checked to be a
// present integer. Order is never inferred from the tool's values.
package harness

import (
	"fmt"
	"regexp"
	"strings"

	"websec/internal/validation"
)

// witnessSenderKey is the env field this bridge reads as the step's
// sender: minicertora's `_call_env` spelling. witnessSenderAlias is the
// fallback spelling for a flattened env (documented above).
// witnessValueKey is the env field read as the step's wei value (see the
// file comment on the value channel).
const (
	witnessSenderKey   = "msg.sender"
	witnessSenderAlias = "sender"
	witnessValueKey    = "msg.value"
)

// witnessAddrRe is the schema's address pattern: an actor must be a real
// 20-byte address for a fork to replay it.
var witnessAddrRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// witnessWeiRe is the schema's step `value` pattern, copied verbatim from
// assets/schema/sequence_poc.schema.json: a decimal integer, or an
// 0x-prefixed hex literal of at most 64 nibbles (the width of a uint256).
// Keeping the bridge's accepted language equal to the schema's is what
// makes the carried value incapable of rendering the bridged spec
// unloadable, and nothing beyond it is guessed.
var witnessWeiRe = regexp.MustCompile(`^(0x[0-9a-fA-F]{1,64}|[0-9]+)$`)

// BridgeSequence compiles a counterexample verdict line into a
// sequence_poc document: (spec, "") when the witness is fork-reproducible,
// (null, refusal) otherwise. specID and findingID are passed through
// verbatim (the caller owns the SEQ-… id it minted).
//
// Mapping:
//   - actors: each distinct sender aliases actor-1, actor-2, … by first
//     appearance, the alias keyed to the sender it names;
//   - steps: {step, actor, target, function, args}, in witness order, plus
//     `value` when the call sent a nonzero, schema-legal wei amount, plus
//     expect_revert present-and-true only when the call reverted;
//   - mine_blocks is never emitted (the witness records no block mining);
//   - final_assertions is ALWAYS the empty array this wave: translating
//     final_storage/initial_storage readings into balance/storage
//     assertions is the fork wave's job (docs/MINICERTORA_ARCHITECTURE.md
//     §L4; the schema allows the empty array, so the bridge emits the key
//     rather than dropping it).
func BridgeSequence(obj validation.Value, specID,
	findingID string) (validation.Value, string) {
	calls, ok := mcField(obj, "calls")
	if !ok || calls.Kind != validation.Arr || len(calls.A) == 0 {
		return validation.VNull(), "no calls to bridge"
	}
	var order []string
	bySender := map[string]string{}
	steps := make([]validation.Value, 0, len(calls.A))
	for i, call := range calls.A {
		n := i + 1
		call1, refusal := witnessCallOf(call, n)
		if refusal != "" {
			return validation.VNull(), refusal
		}
		alias, seen := bySender[call1.sender]
		if !seen {
			alias = fmt.Sprintf("actor-%d", len(order)+1)
			bySender[call1.sender] = alias
			order = append(order, call1.sender)
		}
		kvs := []validation.KV{
			{K: "step", V: validation.VInt(int64(n))},
			{K: "actor", V: validation.VStr(alias)},
			{K: "target", V: validation.VStr(call1.target)},
			{K: "function", V: validation.VStr(call1.function)},
			{K: "args", V: validation.VArr(call1.args...)},
		}
		if call1.value != "" {
			kvs = append(kvs, validation.KV{K: "value",
				V: validation.VStr(call1.value)})
		}
		if call1.reverted {
			kvs = append(kvs, validation.KV{K: "expect_revert",
				V: validation.VBool(true)})
		}
		steps = append(steps, validation.VObj(kvs...))
	}
	actorKVs := make([]validation.KV, 0, len(order))
	for _, sender := range order {
		actorKVs = append(actorKVs, validation.KV{K: bySender[sender],
			V: validation.VStr(sender)})
	}
	return validation.VObj(
		validation.KV{K: "spec_id", V: validation.VStr(specID)},
		validation.KV{K: "finding_id", V: validation.VStr(findingID)},
		validation.KV{K: "actors", V: validation.VObj(actorKVs...)},
		validation.KV{K: "steps", V: validation.VArr(steps...)},
		validation.KV{K: "final_assertions", V: validation.VArr()},
	), ""
}

// witnessCall is one validated call entry: the fields the spec keeps.
// value is the step's wei literal, "" when the call sent nothing (or
// nothing the report states) — the schema's absent-is-zero shape.
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
