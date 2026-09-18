// Small validation-shape helpers shared by the ingest_record sections.
package ingest

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

func strPtr(s string) *string { return &s }

// truthy is Python's bool() over the JSON values the records carry.
func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0 || v.Big != "" && v.Big != "0"
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func valsOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

func nullIfAbsent(v validation.Value, key string) validation.Value {
	x := validation.ObjAt(v, key)
	if x.Kind == validation.Null {
		return validation.VNull()
	}
	return x
}

// strOrNil is a nullable string read (None when absent or not a string).
func strOrNil(v validation.Value) *string {
	if v.Kind != validation.Str {
		return nil
	}
	return &v.S
}

// requireStr is _require_str.
func requireStr(record validation.Value, key string, lo, hi int) (string, error) {
	value := validation.ObjAt(record, key)
	if value.Kind != validation.Str {
		return "", fmt.Errorf("record %s: %s must be a string of %d-%d chars",
			validation.PyRepr(validation.ObjAt(record, "id")), validation.PyReprStr(key),
			lo, hi)
	}
	n := utf8.RuneCountInString(value.S)
	if n < lo || n > hi {
		return "", fmt.Errorf("record %s: %s must be a string of %d-%d chars",
			validation.PyRepr(validation.ObjAt(record, "id")), validation.PyReprStr(key),
			lo, hi)
	}
	return value.S, nil
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// pyTuple is Python's tuple repr for the outcome-vocabulary error message.
func pyTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + strings.Join(parts, ", ") + ")"
}
