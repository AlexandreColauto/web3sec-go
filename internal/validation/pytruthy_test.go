package validation

// PyTruthy is the Wave J Task 7 canonical truthiness predicate. This test is
// the spec: full matrix over every Kind, including the two boundaries that
// separated the pre-consolidation clones (Big == "" vs Big == "0", and empty
// arrays/objects). It was written before the export existed.

import "testing"

func TestPyTruthy(t *testing.T) {
	cases := []struct {
		name string
		v    Value
		want bool
	}{
		{"null", VNull(), false},
		{"bool_false", VBool(false), false},
		{"bool_true", VBool(true), true},
		{"int_zero", VInt(0), false},
		{"int_three", VInt(3), true},
		{"int_neg", VInt(-1), true},
		{"big_huge", VBigInt("123456789012345678901234567890"), true},
		{"big_zero_literal", VBigInt("0"), false},
		{"float_zero", VFloat(0), false},
		{"float_half", VFloat(0.5), true},
		{"str_empty", VStr(""), false},
		{"str_zero", VStr("0"), true},
		{"str_false", VStr("false"), true},
		{"arr_empty", VArr(), false},
		{"arr_zero", VArr(VInt(0)), true},
		{"obj_empty", VObj(), false},
		{"obj_zero", VObj(KV{K: "a", V: VInt(0)}), true},
	}
	for _, tc := range cases {
		if got := PyTruthy(tc.v); got != tc.want {
			t.Errorf("PyTruthy(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
