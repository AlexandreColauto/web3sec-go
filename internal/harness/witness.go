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
// Layout channel. The prover's final_storage readings are keyed by VARIABLE
// NAME ("total"), while a sequence_poc storage assertion is read on the
// fork by SLOT (sequencepoc's loader requires target+slot for kind
// "storage", and its driver issues `cast storage <target> <slot>`). The
// name->slot map is solc's storage layout, which this package does not own
// — so the translation is parameterized: BridgeSequenceWithLayout takes an
// explicit layout and grounds only what that layout can ground, and
// BridgeSequence passes none, which is why its final_assertions stays the
// empty array. Nothing here is inferred from a name: a reading whose
// contract or slot the layout does not state is SKIPPED, never guessed.
//
// Consumption door. BridgeSequence/BridgeSequenceWithLayout take the parsed
// verdict line; BridgeWitnessLine takes the stdout artifact's bytes and does
// the scan itself, which is how `verify --harness-result` consumes the
// bridge: the stored proof sidecar's `calls` is the presence gate (a
// counterexample with a witness) while the LINE carries the final_storage
// the layout door grounds (see BridgeWitnessLine's doc).
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
// Actor alias spelling. Distinct senders alias `actor_1, actor_2, …` — the
// UNDERSCORE spelling, because the alias becomes a shell variable (`A_<role>`)
// and an env var (`FORK_KEY_<role>`) on the run path, whose field rules accept
// only [A-Za-z][A-Za-z0-9_]* (sequencepoc's roleKeyRe, and driver.go's
// actorFragments). A hyphen is illegal in both, so the bridge's earlier
// `actor-1` spelling made every bridged document unloadable — refused by
// LoadSequenceSpec and by BuildCommand alike, for a reason that had nothing to
// do with what the document said (the gap pinned by wave-M T1, which flipped
// c8e2a299's refusal row into the positive round-trip row). With `actor_N` a
// bridged document is run-path legal NATIVELY: it loads, its driver text
// builds, and its roles reach the fork as FORK_KEY_ACTOR_N with no rename.
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
	"math/big"
	"regexp"
	"sort"
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
//   - actors: each distinct sender aliases actor_1, actor_2, … by first
//     appearance, the alias keyed to the sender it names (the underscore
//     spelling is load-bearing: it is the run path's role-key language — see
//     "Actor alias spelling" above);
//   - steps: {step, actor, target, function, args}, in witness order, plus
//     `value` when the call sent a nonzero, schema-legal wei amount, plus
//     expect_revert present-and-true only when the call reverted;
//   - mine_blocks is never emitted (the witness records no block mining);
//   - final_assertions is the empty array, ALWAYS: this door passes no
//     layout, so no final_storage reading can be grounded in a slot (see
//     BridgeSequenceWithLayout) and the key is emitted empty rather than
//     dropped — the schema allows it and a bridged spec's key set stays
//     stable. Its bytes are exactly the bytes this bridge produced before
//     the layout seam existed.
func BridgeSequence(obj validation.Value, specID,
	findingID string) (validation.Value, string) {
	return bridgeSequence(obj, specID, findingID, nil)
}

// BridgeSequenceWithLayout is BridgeSequence plus the storage-layout door:
// the same document, except that concrete final_storage readings the given
// layout can ground ride out as final_assertions entries (kind "storage",
// op "=="). layout maps a "<Contract>.<var>" key to the variable's slot as
// a DECIMAL string; the zero value (nil) is exactly BridgeSequence.
//
// Grounding, in full — every clause here is a refusal-to-guess:
//
//   - the reading must be a STRING in the schema's concrete language: a
//     decimal literal (passed through VERBATIM — the bridge translates, it
//     never re-renders a number) or a 0x literal of at most 64 nibbles,
//     converted EXACTLY to decimal because the assertion `value` pattern is
//     decimal-only (unlike a step's `value`). Anything else — "*", "?",
//     "attacker", a pretty amount, a JSON number — is a symbolic or
//     foreign-valued reading and is SKIPPED: no assertion is invented from
//     a value the prover never pinned;
//   - the layout key must end in ".<var>" for EXACTLY the reading's name,
//     and its slot must be decimal digits. An indexed reading ("role[?]")
//     matches nothing — an array element's slot needs a keccak, not a
//     layout map — and a non-decimal slot is not a slot;
//   - the target must be one of the BRIDGED STEP TARGETS, byte-for-byte:
//     either layout["<Contract>"] is a companion 0x address (case-insensitive
//     match, the step's own spelling is what is emitted) or the
//     "<Contract>" segment is itself the 0x address. An address the
//     sequence never calls is not derivable from the sequence, so the
//     assertion is SKIPPED — never guessed;
//   - exactly ONE layout entry may ground a reading. Two entries naming the
//     same variable (two contracts, or two slots) make it ambiguous — the
//     report's bare variable name does not say which storage it read — so
//     the reading is SKIPPED rather than resolved arbitrarily.
//
// Emitted assertions sort by layout key and take ids A1, A2, … in that
// order (never the report's object order, so the bytes are a function of
// the inputs). The emitted set is a SUBSET: with m readings in the report
// and n groundable, the bridge emits n of m, and the m-n skipped readings
// are simply absent — the schema's additionalProperties:false allows no
// note on an assertion, so this line is where that honesty lives. A layout
// that grounds nothing (including a nil layout, or an unsupported layout
// whose names the report never mentions) is not an error: the document is
// the layout-less document, final_assertions empty, and the run is
// unaffected.
func BridgeSequenceWithLayout(obj validation.Value, specID, findingID string,
	layout map[string]string) (validation.Value, string) {
	return bridgeSequence(obj, specID, findingID, layout)
}

// BridgeWitnessLine is the CONSUMPTION door: the bridge applied to a whole
// minicertora JSONL stream (an EXEC record's stdout artifact) instead of an
// already-parsed verdict line. It performs the structural scan
// MapMinicertora performs — the single line whose `rule` field matches
// ruleName, blank lines skipped, a non-JSON line or an abort line stopping
// the scan — and then bridges THAT line's own object through
// BridgeSequenceWithLayout.
//
// Why the line and not the stored proof sidecar: the sidecar (mcProof,
// RULING-12KEY) carries `calls` verbatim but deliberately NOT the rest of
// the witness — `final_storage` and `params` stay in the stdout artifact —
// so a sidecar-only bridge could never ground a storage assertion and the
// layout door would be dead at the CLI. The sidecar's `calls` is therefore
// the PRESENCE gate the caller decides on (a counterexample rung with a
// witness), while the bytes bridged are the line the prover actually
// printed. Re-scanning the same bytes with the same rule name is
// deterministic, so a caller that already mapped the stream to a VIOLATED
// rung gets the very line that produced that rung.
//
// The scanner's own refusal text is returned unchanged when the stream has
// no single attributed line — the caller already mapped these bytes, so a
// refusal here is unreachable in practice and is reported rather than
// swallowed (a bridge that silently wrote nothing would be a lie of
// omission). Everything else is BridgeSequenceWithLayout's contract: a
// schema-valid sequence_poc and "", or the null value and a byte-pinned
// refusal, never a partial spec.
func BridgeWitnessLine(raw []byte, ruleName, specID, findingID string,
	layout map[string]string) (validation.Value, string) {
	_, obj, refusal, ok := mcAttributed(raw, ruleName)
	if !ok {
		return validation.VNull(), refusal
	}
	return bridgeSequence(obj, specID, findingID, layout)
}

// bridgeSequence is the shared body: BridgeSequence is this with no layout,
// which is why the two doors produce identical bytes for a nil map.
func bridgeSequence(obj validation.Value, specID, findingID string,
	layout map[string]string) (validation.Value, string) {
	calls, ok := mcField(obj, "calls")
	if !ok || calls.Kind != validation.Arr || len(calls.A) == 0 {
		return validation.VNull(), "no calls to bridge"
	}
	var order []string
	bySender := map[string]string{}
	// targets is the set of addresses the sequence actually calls, in
	// first-appearance order: the pool an assertion target may be drawn
	// from (see BridgeSequenceWithLayout).
	targets := make([]string, 0, len(calls.A))
	seenTarget := map[string]struct{}{}
	steps := make([]validation.Value, 0, len(calls.A))
	for i, call := range calls.A {
		n := i + 1
		call1, refusal := witnessCallOf(call, n)
		if refusal != "" {
			return validation.VNull(), refusal
		}
		alias, seen := bySender[call1.sender]
		if !seen {
			alias = fmt.Sprintf("actor_%d", len(order)+1)
			bySender[call1.sender] = alias
			order = append(order, call1.sender)
		}
		if _, seen := seenTarget[call1.target]; !seen {
			seenTarget[call1.target] = struct{}{}
			targets = append(targets, call1.target)
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
	assertions, _ := witnessFinalAssertions(obj, targets, layout)
	return validation.VObj(
		validation.KV{K: "spec_id", V: validation.VStr(specID)},
		validation.KV{K: "finding_id", V: validation.VStr(findingID)},
		validation.KV{K: "actors", V: validation.VObj(actorKVs...)},
		validation.KV{K: "steps", V: validation.VArr(steps...)},
		validation.KV{K: "final_assertions", V: validation.VArr(assertions...)},
	), ""
}

// witnessStorageKey is the verdict-line field this bridge reads as the
// prover's final storage readings: variable name -> value literal.
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
