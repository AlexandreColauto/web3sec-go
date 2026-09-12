// The sequence_poc step `value` law (L-defer T3): the key is OPTIONAL —
// every spec written before this wave stays valid — and when present it is
// a wei literal in one of two exact spellings: a decimal integer or an
// 0x-prefixed hex literal of at most 64 nibbles (a uint256). Anything a
// prover might print in a human form ("1 ether", "1.5e18") is REJECTED at
// the schema, because the executor hands the value straight to
// `cast send --value`: an approximate or unparsed value would replay a
// different transaction than the witness describes.
package validation

import (
	"strings"
	"testing"
)

// seqPocStepValue builds a one-step sequence_poc whose step carries
// valueJSON VERBATIM (including "absent" -> the whole key/vale pair is
// dropped, the pre-T3 spec shape).
func seqPocStepValue(t *testing.T, valueJSON string) Value {
	t.Helper()
	step := `{"step": 1, "actor": "attacker", ` +
		`"target": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", ` +
		`"function": "deposit(uint256)", "args": ["1000"]`
	if valueJSON != "absent" {
		step += `, "value": ` + valueJSON
	}
	step += `}`
	doc := `{"spec_id": "SEQ-TEST-01", "finding_id": "F-abc123",
      "actors": {"attacker": "anvil:0"}, "steps": [` + step + `],
      "final_assertions": []}`
	v, err := ParseOrdered([]byte(doc))
	if err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	return v
}

func TestSequencePocStepValueAccepts(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{{
		"absent (every pre-T3 spec stays valid)",
		"absent",
	}, {
		"zero",
		`"0"`,
	}, {
		"decimal wei",
		`"1000000000000000000"`,
	}, {
		"uint256 max as decimal",
		"\"115792089237316195423570985008687907853269984665640564039457584007913129639935\"",
	}, {
		"hex",
		`"0x10"`,
	}, {
		"uint256 max as hex (64 nibbles)",
		`"0x` + strings.Repeat("f", 64) + `"`,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(seqPocStepValue(t, tc.json), "sequence_poc", 1); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestSequencePocStepValueRejects(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{{
		"pretty amount",
		`"1 ether"`,
	}, {
		"float / scientific notation",
		`"1.5e18"`,
	}, {
		"negative",
		`"-1"`,
	}, {
		"empty string",
		`""`,
	}, {
		"bare whitespace",
		`" "`,
	}, {
		"leading plus",
		`"+1"`,
	}, {
		"hex with no nibbles",
		`"0x"`,
	}, {
		"65-nibble hex (wider than uint256)",
		`"0x` + strings.Repeat("a", 65) + `"`,
	}, {
		"JSON number, not a string",
		`1000`,
	}, {
		"null",
		`null`,
	}, {
		"JSON boolean",
		`true`,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(seqPocStepValue(t, tc.json), "sequence_poc", 1); err == nil {
				t.Fatalf("accepted %s", tc.json)
			}
		})
	}
	// The rejection names the offending field and pins the pattern, so an
	// operator reading the error knows the admitted spellings.
	err := Validate(seqPocStepValue(t, `"1 ether"`), "sequence_poc", 1)
	if err == nil {
		t.Fatal("pretty amount accepted")
	}
	want := "sequence_poc validation failed at steps/0/value: " +
		"'1 ether' does not match '^(0x[0-9a-fA-F]{1,64}|[0-9]+)$' " +
		"(+0 more errors)"
	if err.Error() != want {
		t.Fatalf("value rejection text:\n got %q\nwant %q", err.Error(), want)
	}
}

// TestSequencePocStepValueIsInTheShippedSchema pins that the law lives in
// the schema DOCUMENT (not in a Go-side hack): the step property is present
// and optional — it is not in the step's required list — and carries the
// wei pattern plus its description.
func TestSequencePocStepValueIsInTheShippedSchema(t *testing.T) {
	raw, err := ReadSchemaFile("sequence_poc")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	step := objKey(objKey(objKey(objKey(doc, "properties"), "steps"), "items"),
		"properties")
	value := objKey(step, "value")
	if value.Kind != Obj {
		t.Fatalf("steps.items.properties has no 'value': %s",
			CanonCompact(step))
	}
	if p := objKey(value, "pattern"); p.Kind != Str ||
		p.S != `^(0x[0-9a-fA-F]{1,64}|[0-9]+)$` {
		t.Fatalf("value pattern = %s", CanonCompact(p))
	}
	if d := objKey(value, "description"); d.Kind != Str || d.S == "" {
		t.Fatalf("value description = %s (a wei literal needs to say so)",
			CanonCompact(d))
	}
	required := objKey(objKey(objKey(objKey(doc, "properties"), "steps"), "items"),
		"required")
	for _, r := range required.A {
		if r.Kind == Str && r.S == "value" {
			t.Fatal("value must stay OPTIONAL: older specs have no such key")
		}
	}
}
