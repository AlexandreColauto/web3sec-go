package invariants

// pyTruthy pin (Wave J Task 7): records the truthiness this definition was
// already computing BEFORE the consolidation, so the unify/rename step cannot
// move a gate. Variant: canonical CPython semantics — identical to validation.PyTruthy (Big == "0" reads falsy).
// These expectations are pre-consolidation behavior and must NOT change.

import (
	"testing"

	"websec/internal/validation"
)

func TestPyTruthyPin(t *testing.T) {
	cases := []struct {
		name string
		v    validation.Value
		want bool
	}{
		{"null", validation.VNull(), false},
		{"bool_false", validation.VBool(false), false},
		{"bool_true", validation.VBool(true), true},
		{"int_zero", validation.VInt(0), false},
		{"int_three", validation.VInt(3), true},
		{"int_neg", validation.VInt(-1), true},
		{"float_zero", validation.VFloat(0), false},
		{"float_half", validation.VFloat(0.5), true},
		{"str_empty", validation.VStr(""), false},
		{"str_zero", validation.VStr("0"), true},
		{"str_false", validation.VStr("false"), true},
		{"arr_empty", validation.VArr(), false},
		{"arr_zero", validation.VArr(validation.VInt(0)), true},
		{"obj_empty", validation.VObj(), false},
		{"obj_zero", validation.VObj(validation.KV{K: "a", V: validation.VInt(0)}), true},
		{"big_huge", validation.VBigInt("123456789012345678901234567890"), true},
		{"big_zero_literal", validation.VBigInt("0"), false},
	}
	for _, tc := range cases {
		if got := validation.PyTruthy(tc.v); got != tc.want {
			t.Errorf("validation.PyTruthy(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
