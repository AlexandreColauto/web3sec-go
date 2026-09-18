package jval

import "testing"

// TestAccessorVariantEquivalence pins the three shared accessors against the
// behavior of the per-package clones they replaced. Each clone differed in one
// of three ways: some omitted the Kind != Obj guard, some returned `.S`
// without checking the field's kind, some built the array with append instead
// of make. All of them agree with these assertions — that is the whole claim
// that collapsing 130 clones into one implementation was safe.
func TestAccessorVariantEquivalence(t *testing.T) {
	obj := VObj(KV{K: "name", V: VStr("a")}, KV{K: "n", V: VInt(7)},
		KV{K: "dup", V: VStr("first")}, KV{K: "dup", V: VStr("second")},
		KV{K: "empty", V: VStr("")})
	arr := VArr(VStr("x"))

	// unguarded-clone form of ObjAt: iterate v.O with no kind test at all.
	un := func(v Value, key string) Value {
		for _, e := range v.O {
			if e.K == key {
				return e.V
			}
		}
		return VNull()
	}
	for _, tc := range []struct{ kind, key string }{
		{"obj", "name"}, {"obj", "n"}, {"obj", "absent"}, {"obj", "dup"},
		{"arr", "name"}, {"null", "name"}, {"str", "name"},
	} {
		v := map[string]Value{"obj": obj, "arr": arr, "null": VNull(), "str": VStr("s")}[tc.kind]
		if got, want := ObjAt(v, tc.key), un(v, tc.key); got.Kind != want.Kind || got.S != want.S {
			t.Errorf("ObjAt(%s,%q)=%v, unguarded clone=%v", tc.kind, tc.key, got, want)
		}
	}
	// first match wins on a duplicate key, as every clone did.
	if got := ObjAt(obj, "dup").S; got != "first" {
		t.Errorf(`ObjAt picked %q, want "first"`, got)
	}
	// unguarded-clone form of ObjStr: return .S on the first key hit.
	raw := func(v Value, key string) string {
		for _, e := range v.O {
			if e.K == key {
				return e.V.S
			}
		}
		return ""
	}
	for _, key := range []string{"name", "n", "absent", "empty"} {
		if got, want := ObjStr(obj, key), raw(obj, key); got != want {
			t.Errorf("ObjStr(%q)=%q, unguarded clone=%q", key, got, want)
		}
	}
	// a non-string field reads as "" and a non-object reads as "" too.
	if ObjStr(obj, "n") != "" || ObjStr(VNull(), "name") != "" || ObjStr(arr, "x") != "" {
		t.Error("ObjStr must be \"\" for non-string fields and non-objects")
	}
	// append-built and make-built clones agreed, including nil and empty.
	for _, in := range [][]string{nil, {}, {"a"}, {"a", "b"}} {
		got := StrArr(in)
		alt := []Value{}
		for _, s := range in {
			alt = append(alt, VStr(s))
		}
		if got.Kind != Arr || len(got.A) != len(alt) {
			t.Fatalf("StrArr(%q) len=%d, append-clone len=%d", in, len(got.A), len(alt))
		}
		for i := range got.A {
			if got.A[i].S != alt[i].S {
				t.Errorf("StrArr(%q)[%d]=%q, want %q", in, i, got.A[i].S, alt[i].S)
			}
		}
	}
}
