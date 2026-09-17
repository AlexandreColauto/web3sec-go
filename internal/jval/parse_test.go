package jval

import (
	"strings"
	"testing"
)

// TestParseOrderedRejectsDuplicateKeys pins the shared-parser law: a JSON
// object carrying the same key twice is refused outright, before any
// consumer's first-match reader can disagree with the schema walker. The
// same key in SEPARATE objects stays valid — the guard is per-object.
func TestParseOrderedRejectsDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"a":1,"a":2}`,
		`{"outer":{"a":1,"a":2}}`,
		`{"a":1,"\u0061":2}`,
		`{"":1,"":2}`,
	} {
		_, err := ParseOrdered([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), "duplicate object key") {
			t.Errorf("ParseOrdered(%q): want duplicate-key error, got %v", raw, err)
		}
	}
}

func TestParseOrderedAllowsKeysInSeparateObjects(t *testing.T) {
	v, err := ParseOrdered([]byte(`[{"a":1},{"a":2}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(v.A) != 2 || v.A[0].O[0].V.I != 1 || v.A[1].O[0].V.I != 2 {
		t.Fatalf("separate objects changed: %#v", v)
	}
}
