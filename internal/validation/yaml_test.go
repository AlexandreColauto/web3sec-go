// yaml_test.go: the duplicate-mapping-key law for ParseYaml.
//
// yaml.safe_load (PyYAML) keeps the LAST occurrence of a repeated mapping
// key, while the ordered Value bridge used to keep every occurrence; a
// first-reader/last-reader disagreement over the same document is exactly
// the kind of silent divergence this parser hardening refuses. Repeated
// keys across DISTINCT mappings (sequence items, nested siblings, aliases)
// stay legal.
package validation

import (
	"fmt"
	"strings"
	"testing"
)

// TestParseYamlRejectsDuplicateMappingKeys is the regression: every shape of
// repeated key in one mapping must fail loudly with the exact message and a
// Null result, never a silently duplicated entry.
func TestParseYamlRejectsDuplicateMappingKeys(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		key  string
	}{
		{"flat", "a: 1\na: 2\n", "a"},
		{"nested", "outer:\n  a: 1\n  a: 2\n", "a"},
		{"unquoted then quoted", "a: 1\n\"a\": 2\n", "a"},
		{"quoted then unquoted", "\"a\": 1\na: 2\n", "a"},
		{"rendered numeric/string collision", "1: x\n\"1\": y\n", "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseYaml([]byte(tc.raw))
			if err == nil {
				t.Fatalf("ParseYaml(%q) = %s, want duplicate-key error", tc.raw, DumpsOrdered(got, false))
			}
			want := fmt.Sprintf("yaml: duplicate mapping key %q", tc.key)
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ParseYaml(%q) error = %q, want it to contain %q", tc.raw, err.Error(), want)
			}
			if got.Kind != Null || DumpsOrdered(got, false) != "null" {
				t.Errorf("ParseYaml(%q) value = %s, want Null", tc.raw, DumpsOrdered(got, false))
			}
		})
	}
}

// TestParseYamlAcceptsRepeatedKeysAcrossMappings pins the other half of the
// law: the guard is per mapping, so the same key in two different mappings —
// sequence items, nested siblings, aliased mappings, or a merge key beside an
// explicit override — is still accepted with its real values.
func TestParseYamlAcceptsRepeatedKeysAcrossMappings(t *testing.T) {
	t.Run("sequence items", func(t *testing.T) {
		got, err := ParseYaml([]byte("- a: 1\n- a: 2\n"))
		if err != nil {
			t.Fatalf("ParseYaml error = %v, want nil", err)
		}
		if got.Kind != Arr || len(got.A) != 2 {
			t.Fatalf("value = %s, want two sequence items", DumpsOrdered(got, false))
		}
		for i, want := range []int64{1, 2} {
			item := got.A[i]
			if item.Kind != Obj || len(item.O) != 1 || item.O[0].K != "a" {
				t.Fatalf("item %d = %s, want single key \"a\"", i, DumpsOrdered(item, false))
			}
			if item.O[0].V.Kind != Int || item.O[0].V.I != want {
				t.Errorf("item %d a = %s, want %d", i, DumpsOrdered(item.O[0].V, false), want)
			}
		}
		if dump := DumpsOrdered(got, false); dump != `[{"a": 1}, {"a": 2}]` {
			t.Errorf("dump = %s, want [{\"a\": 1}, {\"a\": 2}]", dump)
		}
	})

	t.Run("nested siblings", func(t *testing.T) {
		got, err := ParseYaml([]byte("first:\n  a: 1\nsecond:\n  a: 2\n"))
		if err != nil {
			t.Fatalf("ParseYaml error = %v, want nil", err)
		}
		if dump := DumpsOrdered(got, false); dump != `{"first": {"a": 1}, "second": {"a": 2}}` {
			t.Fatalf("dump = %s, want both sibling mappings intact", dump)
		}
	})

	t.Run("alias to previously defined mapping", func(t *testing.T) {
		got, err := ParseYaml([]byte("base: &b\n  a: 1\nuse: *b\n"))
		if err != nil {
			t.Fatalf("ParseYaml error = %v, want nil", err)
		}
		if dump := DumpsOrdered(got, false); dump != `{"base": {"a": 1}, "use": {"a": 1}}` {
			t.Fatalf("dump = %s, want the alias resolved to the same mapping", dump)
		}
	})

	t.Run("merge key beside explicit key", func(t *testing.T) {
		got, err := ParseYaml([]byte("base: &b\n  a: 1\nderived:\n  <<: *b\n  a: 2\n"))
		if err != nil {
			t.Fatalf("ParseYaml error = %v, want nil (merge semantics untouched)", err)
		}
		if dump := DumpsOrdered(got, false); dump != `{"base": {"a": 1}, "derived": {"<<": {"a": 1}, "a": 2}}` {
			t.Fatalf("dump = %s, want merge key and explicit key both present", dump)
		}
	})

	t.Run("key order preserved", func(t *testing.T) {
		got, err := ParseYaml([]byte("z: 1\na: 2\nm:\n  z: 3\n"))
		if err != nil {
			t.Fatalf("ParseYaml error = %v, want nil", err)
		}
		if dump := DumpsOrdered(got, false); dump != `{"z": 1, "a": 2, "m": {"z": 3}}` {
			t.Errorf("dump = %s, want insertion order preserved", dump)
		}
	})
}
