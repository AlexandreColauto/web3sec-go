// Witness → sequence-PoC bridge tests (L4). The fixtures are the
// verdict-line shape minicertora's `_extract` prints
// (minicertora/cli.py: `{step, function, target, args[], env, reverted,
// reentrant, overrides}` with `env = {"msg.sender", "msg.value"}`), and
// every happy-path byte row goes through validation.CanonCompact — a
// mapper that moves a key, an order or an alias trips these rows.
package harness

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"websec/internal/validation"
)

const (
	// wTarget is the witness's single call target.
	wTarget = "0x1111111111111111111111111111111111111111"
	// wAlice / wBob are the two distinct senders of the happy path.
	wAlice = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wBob   = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// witnessJSON parses one verdict-line fixture.
func witnessJSON(t *testing.T, s string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(s))
	if err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	return v
}

// wCall is one `_extract` call entry with the real env key spelling.
func wCall(step int, fn, sender string, reverted bool) string {
	rev := "false"
	if reverted {
		rev = "true"
	}
	return fmt.Sprintf(`{"step":%d,"function":%q,"target":%q,"args":["1000"],`+
		`"env":{"msg.sender":%q,"msg.value":"0"},"reverted":%s,`+
		`"reentrant":false,"overrides":{}}`, step, fn, wTarget, sender, rev)
}

// wCallValue is wCall with an explicit msg.value payload, written as the
// report writes it (a JSON scalar — `"0"`/`"1000"` decimal, `null` when
// the model never evaluated the field, and so on).
func wCallValue(step int, fn, sender, valueJSON string) string {
	return fmt.Sprintf(`{"step":%d,"function":%q,"target":%q,"args":["1000"],`+
		`"env":{"msg.sender":%q,"msg.value":%s},"reverted":false,`+
		`"reentrant":false,"overrides":{}}`, step, fn, wTarget, sender,
		valueJSON)
}

// wVerdict wraps call entries in the verdict line that carries them.
func wVerdict(calls ...string) string {
	return `{"rule":"inv_1","verdict":"VIOLATED","confidence":"confirmed",` +
		`"reason":"assertion-violated","failed_assertion":` +
		`{"expression":"total >= before"},"calls":[` +
		strings.Join(calls, ",") + `],"final_storage":{"total":"0"}}`
}

// TestBridgeSequenceHappyPath pins the bridged spec byte-for-byte: two
// distinct senders become actor-1/actor-2 by first appearance, one
// reverted call carries expect_revert (and the other does NOT carry the
// key at all), mine_blocks is never emitted, and final_assertions is the
// empty array the fork wave fills.
func TestBridgeSequenceHappyPath(t *testing.T) {
	obj := witnessJSON(t, wVerdict(
		wCall(0, "deposit", wAlice, false),
		wCall(1, "withdraw", wBob, true),
	))
	got, refusal := BridgeSequence(obj, "SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("refusal = %q, want none", refusal)
	}
	want := `{"actors":{"actor-1":"` + wAlice + `","actor-2":"` + wBob +
		`"},"final_assertions":[],"finding_id":"F-abc123",` +
		`"spec_id":"SEQ-MINI-01","steps":[` +
		`{"actor":"actor-1","args":["1000"],"function":"deposit",` +
		`"step":1,"target":"` + wTarget + `"},` +
		`{"actor":"actor-2","args":["1000"],"expect_revert":true,` +
		`"function":"withdraw","step":2,"target":"` + wTarget + `"}]}`
	if gotBytes := validation.CanonCompact(got); gotBytes != want {
		t.Fatalf("bridged spec =\n%s\nwant\n%s", gotBytes, want)
	}
	// The doc is a sequence_poc: the test validates it against the shipped
	// assets/schema/sequence_poc.schema.json (validation's embedded copy).
	assertSequencePocSchema(t, got)
	// final_assertions is present-and-empty, never omitted: the schema
	// allows it, and the fork wave needs the slot to stay key-stable.
	if fa := getObj(t, got, "final_assertions"); fa.Kind != validation.Arr ||
		len(fa.A) != 0 {
		t.Fatalf("final_assertions = %s, want []", validation.CanonCompact(fa))
	}
	// The verdict line's own bookkeeping never leaks into the spec.
	for _, key := range []string{"rule", "verdict", "reentrant", "overrides",
		"failed_assertion", "final_storage", "confidence", "reason"} {
		if hasKey(got, key) {
			t.Fatalf("bridged spec carries %q", key)
		}
	}
}

// assertSequencePocSchema validates a bridged doc against the sequence_poc
// schema and fails with the schema error text. It first pins schema
// identity BY BYTES: validation.ReadSchemaFile exposes the raw document it
// compiled, which must equal the shipped on-disk asset byte-for-byte (the
// path is package-relative — go test runs with cwd internal/harness). A
// title-substring probe would pass on a stale, truncated or
// differently-configured copy; a byte compare cannot.
func assertSequencePocSchema(t *testing.T, doc validation.Value) {
	t.Helper()
	raw, err := validation.ReadSchemaFile("sequence_poc")
	if err != nil {
		t.Fatalf("read sequence_poc schema: %v", err)
	}
	const diskPath = "../../assets/schema/sequence_poc.schema.json"
	disk, err := os.ReadFile(diskPath)
	if err != nil {
		t.Fatalf("read %s: %v", diskPath, err)
	}
	if !bytes.Equal(raw, disk) {
		t.Fatalf("validation's sequence_poc schema is NOT the shipped %s: "+
			"%d bytes vs %d bytes", diskPath, len(raw), len(disk))
	}
	if err := validation.Validate(doc, "sequence_poc", 1); err != nil {
		t.Fatalf("bridged spec is not a sequence_poc: %v", err)
	}
}

func getObj(t *testing.T, v validation.Value, key string) validation.Value {
	t.Helper()
	out, ok := mcField(v, key)
	if !ok {
		t.Fatalf("missing key %q in %s", key, validation.CanonCompact(v))
	}
	return out
}

func hasKey(v validation.Value, key string) bool {
	_, ok := mcField(v, key)
	return ok
}

// TestBridgeSequenceAliasesByFirstAppearance pins the actor map's
// insertion order: eleven distinct senders alias actor-1 … actor-11 in the
// order they first appear, NOT in canonical (sorted) key order — actor-10
// would otherwise sort before actor-2.
func TestBridgeSequenceAliasesByFirstAppearance(t *testing.T) {
	calls := make([]string, 0, 12)
	for i := 1; i <= 11; i++ {
		calls = append(calls, wCall(i-1, "poke", fmt.Sprintf("0x%040x", i), false))
	}
	// A repeated sender reuses its alias and never mints a new one.
	calls = append(calls, wCall(11, "poke", fmt.Sprintf("0x%040x", 3), false))
	obj := witnessJSON(t, wVerdict(calls...))
	got, refusal := BridgeSequence(obj, "SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("refusal = %q, want none", refusal)
	}
	actors := getObj(t, got, "actors")
	if len(actors.O) != 11 {
		t.Fatalf("actors = %s, want 11", validation.CanonCompact(actors))
	}
	for i, kv := range actors.O {
		want := fmt.Sprintf("actor-%d", i+1)
		if kv.K != want {
			t.Fatalf("actors[%d] key = %q, want %q", i, kv.K, want)
		}
	}
	if step := getObj(t, got, "steps").A[11]; !hasKey(step, "actor") {
		t.Fatalf("repeat step has no actor")
	} else if a := getObj(t, step, "actor"); a.S != "actor-3" {
		t.Fatalf("repeated sender alias = %q, want actor-3", a.S)
	}
}

// TestBridgeSequenceSchemaValidationBites proves the validation in the
// happy path is load-bearing: a doc whose spec_id breaks the schema's
// pattern is rejected by the very call used above.
func TestBridgeSequenceSchemaValidationBites(t *testing.T) {
	obj := witnessJSON(t, wVerdict(wCall(0, "deposit", wAlice, false)))
	got, refusal := BridgeSequence(obj, "not-a-seq-id", "F-abc123")
	if refusal != "" {
		t.Fatalf("refusal = %q", refusal)
	}
	if err := validation.Validate(got, "sequence_poc", 1); err == nil {
		t.Fatalf("spec_id pattern is not enforced by the schema")
	}
}

// TestBridgeSequenceRefusals pins every refusal byte-exactly. A refusal
// returns the null value: no partial spec ever leaves the bridge.
func TestBridgeSequenceRefusals(t *testing.T) {
	tests := []struct {
		name string
		obj  string
		want string
	}{{
		"calls absent",
		`{"rule":"inv_1","verdict":"VIOLATED"}`,
		"no calls to bridge",
	}, {
		"calls empty",
		`{"rule":"inv_1","verdict":"VIOLATED","calls":[]}`,
		"no calls to bridge",
	}, {
		"calls null",
		`{"rule":"inv_1","verdict":"VIOLATED","calls":null}`,
		"no calls to bridge",
	}, {
		"calls not an array",
		`{"rule":"inv_1","verdict":"VIOLATED","calls":{}}`,
		"no calls to bridge",
	}, {
		"symbolic sender",
		wVerdict(wCall(0, "deposit", "attacker", false)),
		"symbolic senders cannot be fork-repro'd",
	}, {
		"symbolic sender in the second call",
		wVerdict(wCall(0, "deposit", wAlice, false),
			wCall(1, "withdraw", "caller_1", true)),
		"symbolic senders cannot be fork-repro'd",
	}, {
		"missing function",
		`{"rule":"inv_1","calls":[{"step":0,"target":"` + wTarget +
			`","args":[],"env":{"msg.sender":"` + wAlice + `"}}]}`,
		"unbridgable step: call 1 lacks function",
	}, {
		// Precedence: structural call validation (function/target/step/
		// args) is matched BEFORE the sender/address check, so a call
		// that is both malformed and symbolic reports the STRUCTURAL
		// refusal. The symbolic sender here is never reached.
		"missing function with a symbolic sender (structural refusal wins)",
		`{"rule":"inv_1","calls":[{"step":0,"target":"` + wTarget +
			`","args":[],"env":{"msg.sender":"attacker"}}]}`,
		"unbridgable step: call 1 lacks function",
	}, {
		"missing target",
		`{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
			`"args":[],"env":{"msg.sender":"` + wAlice + `"}}]}`,
		"unbridgable step: call 1 lacks target",
	}, {
		"missing step",
		`{"rule":"inv_1","calls":[{"function":"deposit","target":"` +
			wTarget + `","args":[],"env":{"msg.sender":"` + wAlice + `"}}]}`,
		"unbridgable step: call 1 lacks step",
	}, {
		"non-integer step",
		`{"rule":"inv_1","calls":[{"step":"1","function":"deposit",` +
			`"target":"` + wTarget + `","args":[],` +
			`"env":{"msg.sender":"` + wAlice + `"}}]}`,
		"unbridgable step: call 1 lacks step",
	}, {
		"non-string args entry",
		`{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
			`"target":"` + wTarget + `","args":["1",7],` +
			`"env":{"msg.sender":"` + wAlice + `"}}]}`,
		"unbridgable step: call 1 arg 1 is not a string",
	}, {
		"args not an array",
		`{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
			`"target":"` + wTarget + `","args":"1",` +
			`"env":{"msg.sender":"` + wAlice + `"}}]}`,
		"unbridgable step: call 1 args is not an array",
	}, {
		"call is not an object",
		`{"rule":"inv_1","calls":["deposit"]}`,
		"unbridgable step: call 1 is not an object",
	}, {
		"call without env",
		`{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
			`"target":"` + wTarget + `","args":[]}]}`,
		"unbridgable step: call 1 has no env",
	}, {
		"env without a sender",
		`{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
			`"target":"` + wTarget + `","args":[],"env":{"msg.value":"0"}}]}`,
		"unbridgable step: call 1 has no msg.sender",
	}, {
		"null sender (the model did not evaluate msg.sender)",
		`{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
			`"target":"` + wTarget + `","args":[],` +
			`"env":{"msg.sender":null}}]}`,
		"unbridgable step: call 1 has no msg.sender",
	}, {
		"the refusal names the failing call in a longer sequence",
		wVerdict(wCall(0, "deposit", wAlice, false),
			`{"step":1,"target":"`+wTarget+`","args":[],`+
				`"env":{"msg.sender":"`+wBob+`"}}`),
		"unbridgable step: call 2 lacks function",
	}, {
		// The refusal text carries the RAW value, Python-repr'd, so an
		// operator sees exactly what the report said and judges it. The
		// pinned tool cannot emit this form — `_call_env` stringifies an
		// int, and its pretty-renderer is `str()` too — so the lane
		// guards a hand-edited or differently-produced witness: a pretty
		// amount is never rounded into wei.
		"msg.value is a pretty amount, not a wei literal",
		wVerdict(wCallValue(0, "deposit", wAlice, `"1 ether"`)),
		"unbridgable step: call 1 value '1 ether' not a wei literal",
	}, {
		// `_call_env` writes null when the model never evaluated the
		// field: an unstated value is NOT zero, so it refuses rather
		// than silently replaying with 0 wei.
		"msg.value null (the model did not evaluate it)",
		wVerdict(wCallValue(0, "deposit", wAlice, `null`)),
		"unbridgable step: call 1 value None not a wei literal",
	}, {
		// The tool stringifies every int (`str(v)`); a bare JSON number
		// is not the report's shape, so it is refused rather than
		// coerced.
		"msg.value is a JSON number, not the report's string",
		wVerdict(wCallValue(0, "deposit", wAlice, `1000`)),
		"unbridgable step: call 1 value 1000 not a wei literal",
	}, {
		"negative msg.value",
		wVerdict(wCallValue(0, "deposit", wAlice, `"-1"`)),
		"unbridgable step: call 1 value '-1' not a wei literal",
	}, {
		"empty msg.value",
		wVerdict(wCallValue(0, "deposit", wAlice, `""`)),
		"unbridgable step: call 1 value '' not a wei literal",
	}, {
		"over-long hex msg.value (65 nibbles)",
		wVerdict(wCallValue(0, "deposit", wAlice,
			`"0x`+strings.Repeat("a", 65)+`"`)),
		"unbridgable step: call 1 value '0x" + strings.Repeat("a", 65) +
			"' not a wei literal",
	}, {
		// Precedence: the value is the LAST field checked. An actor the
		// fork cannot address refuses for the actor's reason (the value
		// is meaningless until the step is replayable at all).
		"symbolic sender refuses before the value is read",
		wVerdict(wCallValue(0, "deposit", "attacker", `"1 ether"`)),
		"symbolic senders cannot be fork-repro'd",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, refusal := BridgeSequence(witnessJSON(t, tc.obj),
				"SEQ-MINI-01", "F-abc123")
			if refusal != tc.want {
				t.Fatalf("refusal = %q, want %q", refusal, tc.want)
			}
			if got.Kind != validation.Null {
				t.Fatalf("refused bridge returned %s, want null",
					validation.CanonCompact(got))
			}
		})
	}
}

// TestBridgeSequenceSenderKeyIsMsgSender documents the sender source: the
// tool's own `_call_env` keys the field `msg.sender` (there is no bare
// `sender` key in a minicertora report). The vendored corpus
// expected.json files carry only `essential_witness`
// (failed_assertion + final_storage) and no calls/env at all, so the
// prover's report is the shape source. A flattened `sender` key is
// accepted as the fallback spelling; `msg.sender` wins when both exist.
func TestBridgeSequenceSenderKeyIsMsgSender(t *testing.T) {
	flat := `{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
		`"target":"` + wTarget + `","args":[],"env":{"sender":"` + wBob + `"}}]}`
	got, refusal := BridgeSequence(witnessJSON(t, flat), "SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("flattened sender key refused: %q", refusal)
	}
	if a := getObj(t, getObj(t, got, "actors"), "actor-1"); a.S != wBob {
		t.Fatalf("actor-1 = %q, want %q", a.S, wBob)
	}
	both := `{"rule":"inv_1","calls":[{"step":0,"function":"deposit",` +
		`"target":"` + wTarget + `","args":[],"env":{"msg.sender":"` +
		wAlice + `","sender":"` + wBob + `"}}]}`
	got, refusal = BridgeSequence(witnessJSON(t, both), "SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("both sender keys refused: %q", refusal)
	}
	if a := getObj(t, getObj(t, got, "actors"), "actor-1"); a.S != wAlice {
		t.Fatalf("msg.sender must win: actor-1 = %q, want %q", a.S, wAlice)
	}
}

// TestBridgeSequenceOptionalFields pins the honesty floor: reverted must be
// boolean-true to emit the key (a false or non-boolean reverted emits
// nothing), mine_blocks is never emitted even when the tool records one,
// and absent args render as the empty array.
func TestBridgeSequenceOptionalFields(t *testing.T) {
	obj := witnessJSON(t, `{"rule":"inv_1","calls":[{`+
		`"step":0,"function":"deposit","target":"`+wTarget+`",`+
		`"env":{"msg.sender":"`+wAlice+`"},"mine_blocks":5,`+
		`"reverted":"yes"}]}`)
	got, refusal := BridgeSequence(obj, "SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("refusal = %q", refusal)
	}
	step := getObj(t, got, "steps").A[0]
	if hasKey(step, "expect_revert") {
		t.Fatalf("non-boolean reverted emitted expect_revert")
	}
	if hasKey(step, "mine_blocks") {
		t.Fatalf("mine_blocks must never be emitted")
	}
	if args := getObj(t, step, "args"); args.Kind != validation.Arr ||
		len(args.A) != 0 {
		t.Fatalf("args = %s, want []", validation.CanonCompact(args))
	}
}

// TestBridgeSequenceCarriesMsgValue pins the value channel byte-for-byte:
// env["msg.value"] — the decimal wei literal minicertora's `_call_env`
// emits (`str(model.eval_bitvec(...))`, with "0" as the default) — rides
// into the step as its own `value` key, and a hex literal (the schema's
// other admitted spelling) passes through UNREFORMATTED: the bridge
// translates, it never re-renders.
func TestBridgeSequenceCarriesMsgValue(t *testing.T) {
	obj := witnessJSON(t, wVerdict(
		wCallValue(0, "deposit", wAlice, `"1000000000000000000"`),
		wCallValue(1, "poke", wBob, `"0x10"`),
	))
	got, refusal := BridgeSequence(obj, "SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("refusal = %q, want none", refusal)
	}
	want := `{"actors":{"actor-1":"` + wAlice + `","actor-2":"` + wBob +
		`"},"final_assertions":[],"finding_id":"F-abc123",` +
		`"spec_id":"SEQ-MINI-01","steps":[` +
		`{"actor":"actor-1","args":["1000"],"function":"deposit",` +
		`"step":1,"target":"` + wTarget + `","value":"1000000000000000000"},` +
		`{"actor":"actor-2","args":["1000"],"function":"poke",` +
		`"step":2,"target":"` + wTarget + `","value":"0x10"}]}`
	if gotBytes := validation.CanonCompact(got); gotBytes != want {
		t.Fatalf("bridged spec =\n%s\nwant\n%s", gotBytes, want)
	}
	// The emitted value is a schema-legal wei literal (the whole point of
	// the pattern: a carried value must not make the spec unloadable).
	assertSequencePocSchema(t, got)
}

// TestBridgeSequenceZeroValueOmitted pins the schema-legal half of the
// value rule: a zero value is written by OMITTING the key (the schema's
// absent = zero, so no campaign byte moves and no older spec breaks), and
// every spelling of zero the tool can emit — the literal "0" default,
// plus the hex and leading-zero forms a hand-written report may carry —
// omits too. The bridged bytes must equal the no-value bridge exactly.
func TestBridgeSequenceZeroValueOmitted(t *testing.T) {
	plain := wVerdict(wCall(0, "deposit", wAlice, false))
	baseline, refusal := BridgeSequence(witnessJSON(t, plain),
		"SEQ-MINI-01", "F-abc123")
	if refusal != "" {
		t.Fatalf("baseline refusal = %q", refusal)
	}
	for _, valueJSON := range []string{`"0"`, `"00"`, `"0x0"`, `"0x00"`} {
		t.Run(valueJSON, func(t *testing.T) {
			got, refusal := BridgeSequence(witnessJSON(t, wVerdict(
				wCallValue(0, "deposit", wAlice, valueJSON))),
				"SEQ-MINI-01", "F-abc123")
			if refusal != "" {
				t.Fatalf("refusal = %q, want none", refusal)
			}
			step := getObj(t, got, "steps").A[0]
			if hasKey(step, "value") {
				t.Fatalf("zero msg.value %s emitted a value key: %s",
					valueJSON, validation.CanonCompact(step))
			}
			if a, b := validation.CanonCompact(got),
				validation.CanonCompact(baseline); a != b {
				t.Fatalf("zero-value spec =\n%s\nwant the no-value spec\n%s",
					a, b)
			}
		})
	}
}
