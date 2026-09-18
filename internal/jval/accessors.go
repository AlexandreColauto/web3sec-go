// accessors.go: the Value field-accessor family shared by every package that
// reads a decoded JSON value. These replace ~130 per-package clones of
// objAt / objStr / strArr; the semantics are the union of what those clones
// did, so a call site that moved here changes nothing:
//
//   - ObjAt on a non-object, or on a missing key, is VNull. The kind guard is
//     free: v.O is only ever populated for Obj, so the unguarded loop some
//     clones used could only fall through to VNull as well.
//   - ObjStr is ObjAt(v, key).S when the field is a string, "" otherwise. It
//     agrees with the clones that skipped the kind test too, because Value.S
//     is the empty string for every non-Str kind.
//   - StrArr is the []string -> array-of-strings form; nil and empty in both
//     the make() and append() clones produced an empty array.

package jval

// ObjAt returns v[key], or VNull when v is not an object or key is absent.
func ObjAt(v Value, key string) Value {
	if v.Kind != Obj {
		return VNull()
	}
	for _, e := range v.O {
		if e.K == key {
			return e.V
		}
	}
	return VNull()
}

// ObjStr returns v[key] when it is a string, "" when absent or not a string.
func ObjStr(v Value, key string) string {
	if f := ObjAt(v, key); f.Kind == Str {
		return f.S
	}
	return ""
}

// StrArr renders a []string as a JSON array value.
func StrArr(items []string) Value {
	out := make([]Value, len(items))
	for i, s := range items {
		out[i] = VStr(s)
	}
	return VArr(out...)
}
