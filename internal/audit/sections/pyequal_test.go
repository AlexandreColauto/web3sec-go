package sections

import (
	"testing"

	"websec/internal/validation"
)

// pyEqual must compare key sets, not just per-key values: objAt returns VNull
// for an ABSENT key, so without a key-set check a differing null-valued key
// ({a:null} vs {b:null}) would compare equal.
func TestPyEqualDistinguishesDifferingNullKeys(t *testing.T) {
	aNull := validation.VObj(KV("a", validation.VNull()))
	bNull := validation.VObj(KV("b", validation.VNull()))
	if pyEqual(aNull, bNull) {
		t.Error("pyEqual({a:null},{b:null}) = true, want false (different keys)")
	}

	// Same keys, same values -> equal.
	x := validation.VObj(KV("a", validation.VInt(1)), KV("b", validation.VNull()))
	y := validation.VObj(KV("a", validation.VInt(1)), KV("b", validation.VNull()))
	if !pyEqual(x, y) {
		t.Error("pyEqual of equal objects = false, want true")
	}

	// Same key count, one shared key, one differing non-null key -> not equal.
	p := validation.VObj(KV("a", validation.VInt(1)), KV("b", validation.VInt(2)))
	q := validation.VObj(KV("a", validation.VInt(1)), KV("c", validation.VInt(2)))
	if pyEqual(p, q) {
		t.Error("pyEqual({a:1,b:2},{a:1,c:2}) = true, want false")
	}

	// Nested: differing null keys inside a nested object.
	n1 := validation.VObj(KV("k", validation.VObj(KV("a", validation.VNull()))))
	n2 := validation.VObj(KV("k", validation.VObj(KV("b", validation.VNull()))))
	if pyEqual(n1, n2) {
		t.Error("nested differing null keys compared equal, want false")
	}
}
