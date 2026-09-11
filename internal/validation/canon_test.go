package validation

import (
	"math"
	"testing"
)

// TestCanonJSON table test. Expected bytes are CPython 3.14 json.dumps with
// sort_keys=True, ensure_ascii=True and the given separators (verified against
// the reference interpreter before checking in).
func TestCanonJSON(t *testing.T) {
	// Go constant folding turns the -0.0 literal into +0.0, so build the
	// negative zero at runtime for the sign-bit case.
	negZero := math.Copysign(0, -1)
	tests := []struct {
		name    string
		value   Value
		compact bool
		want    string
	}{
		{"empty obj spaced", VObj(), false, "{}"},
		{"empty obj compact", VObj(), true, "{}"},
		{"empty arr spaced", VArr(), false, "[]"},
		{"empty arr compact", VArr(), true, "[]"},
		{"one int spaced", VObj(KV{K: "a", V: VInt(1)}), false, "{\"a\": 1}"},
		{"one int compact", VObj(KV{K: "a", V: VInt(1)}), true, "{\"a\":1}"},
		{"html raw", VStr("<>&/"), false, "\"<>&/\""},
		{"html raw compact", VStr("<>&/"), true, "\"<>&/\""},
		{"key sort compact", VObj(KV{K: "b", V: VInt(1)}, KV{K: "a", V: VInt(2)}), true, "{\"a\":2,\"b\":1}"},
		{"key sort spaced", VObj(KV{K: "b", V: VInt(1)}, KV{K: "a", V: VInt(2)}), false, "{\"a\": 2, \"b\": 1}"},
		{"arr spaced", VArr(VInt(1), VInt(2), VInt(3)), false, "[1, 2, 3]"},
		{"arr compact", VArr(VInt(1), VInt(2), VInt(3)), true, "[1,2,3]"},
		{"float integral spaced", VFloat(1.0), false, "1.0"},
		{"float integral compact", VFloat(1.0), true, "1.0"},
		{"neg zero", VFloat(negZero), true, "-0.0"},
		{"exponent 1e16", VFloat(1e16), true, "1e+16"},
		{"exponent 1e15 fixed", VFloat(1e15), true, "1000000000000000.0"},
		{"tiny 1e-05", VFloat(1e-5), true, "1e-05"},
		{"tiny 1e-04 fixed", VFloat(1e-4), true, "0.0001"},
		{"0.1", VFloat(0.1), true, "0.1"},
		{"true null", VObj(KV{K: "t", V: VBool(true)}, KV{K: "n", V: VNull()}), true, "{\"n\":null,\"t\":true}"},
		{"nested sort", VObj(KV{K: "k", V: VObj(KV{K: "z", V: VInt(1)}, KV{K: "a", V: VArr(VBool(true), VNull(), VFloat(2.5))})}), true, "{\"k\":{\"a\":[true,null,2.5],\"z\":1}}"},
		{"backslash", VStr("a\\b"), true, "\"a\\\\b\""},
		{"quote", VStr("a\"b"), true, "\"a\\\"b\""},
		{"tab nl cr", VStr("a\tb\nc\rd"), true, "\"a\\tb\\nc\\rd\""},
		{"backspace formfeed", VStr("a\x08b\x0cc"), true, "\"a\\bb\\fc\""},
		{"ctrl low", VStr("\x01"), true, "\"\\u0001\""},
		{"ctrl high", VStr("\x1f"), true, "\"\\u001f\""},
		{"del", VStr("\x7f"), true, "\"\\u007f\""},
		{"nonascii latin", VStr("\u00e9"), true, "\"\\u00e9\""},
		{"nonascii euro", VStr("\u20ac"), true, "\"\\u20ac\""},
		{"nonascii surrogate", VStr("\U0001d11e"), true, "\"\\ud834\\udd1e\""},
		{"mixed str", VStr("a\rb"), true, "\"a\\rb\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Canon(tt.value, tt.compact)
			if got != tt.want {
				t.Errorf("Canon(%v, compact=%v)\n got: %q\nwant: %q", tt.value, tt.compact, got, tt.want)
			}
		})
	}
}

// TestDumpsOrdered pins json.dumps' non-sorted form: insertion order, the
// default ", " / ": " separators, and ensure_ascii on demand. This is the
// costs.jsonl encoder (Canon sorts keys because it is the hash form).
func TestDumpsOrdered(t *testing.T) {
	// CPython 3.14: json.dumps({"b": 1, "a": "é"}) == '{"b": 1, "a": "\u00e9"}'
	v := VObj(KV{K: "b", V: VInt(1)}, KV{K: "a", V: VStr("\u00e9")},
		KV{K: "c", V: VArr(VNull(), VBool(false), VFloat(2.5))})
	if got, want := DumpsOrdered(v, true),
		"{\"b\": 1, \"a\": \"\\u00e9\", \"c\": [null, false, 2.5]}"; got != want {
		t.Errorf("ascii\n got: %q\nwant: %q", got, want)
	}
	if got, want := DumpsOrdered(v, false),
		"{\"b\": 1, \"a\": \"é\", \"c\": [null, false, 2.5]}"; got != want {
		t.Errorf("raw\n got: %q\nwant: %q", got, want)
	}
	// Ints stay ints, nested objects keep their own order.
	nested := VObj(KV{K: "z", V: VObj(KV{K: "y", V: VInt(1)}, KV{K: "x", V: VInt(2)})},
		KV{K: "a", V: VInt(3)})
	if got, want := DumpsOrdered(nested, true),
		"{\"z\": {\"y\": 1, \"x\": 2}, \"a\": 3}"; got != want {
		t.Errorf("nested\n got: %q\nwant: %q", got, want)
	}
	if got := DumpsOrdered(VObj(), true); got != "{}" {
		t.Errorf("empty obj = %q", got)
	}
	if got := DumpsOrdered(VArr(), true); got != "[]" {
		t.Errorf("empty arr = %q", got)
	}
}
