package boundary

import (
	"websec/internal/validation"
)

// ---- small helpers --------------------------------------------------------

func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Bool:
		return v.B
	case validation.Null:
		return false
	case validation.Str:
		return v.S != ""
	case validation.Int:
		return v.I != 0
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return true
}

func pyTypeName(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Bool:
		return "bool"
	case validation.Null:
		return "NoneType"
	}
	return "dict"
}

func pyTrunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

func scalarText(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	}
	return ""
}

func valueEq(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I && a.Big == b.Big
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	}
	return false
}

func strPtr(s string) *string { return &s }
