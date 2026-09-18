package defihacklabs

import (
	"os"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// pyStr is Python's str(v): raw text for strings, repr otherwise.

// pyStrOrEmpty is Python's str(v or "") for the JSON value types.
func pyStrOrEmpty(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return ""
	case validation.Bool:
		if !v.B {
			return ""
		}
		return "True"
	case validation.Int:
		if v.I == 0 && v.Big == "" {
			return ""
		}
		return validation.IntText(v)
	case validation.Flt:
		if v.F == 0 {
			return ""
		}
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	case validation.Arr:
		if len(v.A) == 0 {
			return ""
		}
		return validation.PyRepr(v)
	case validation.Obj:
		if len(v.O) == 0 {
			return ""
		}
		return validation.PyRepr(v)
	}
	return ""
}

// at is v.get(key) for an object (None otherwise).
func at(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, p := range v.O {
		if p.K == key {
			return p.V
		}
	}
	return validation.VNull()
}

// setKey replaces (or appends) key in an object, returning the new value.
func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, p := range v.O {
		if p.K == key {
			out = append(out, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out = append(out, p)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: val})
	}
	v.O = out
	return v
}

// runeLen is Python's len(str).
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// runeSlice is Python's s[i:j] on a str.
func runeSlice(s string, from, to int) string {
	r := []rune(s)
	if from < 0 {
		from = 0
	}
	if to > len(r) {
		to = len(r)
	}
	if from > to {
		return ""
	}
	return string(r[from:to])
}

// lastIndexRunes is str.rfind(sep) in CHARACTER index space (-1 when absent).
func lastIndexRunes(s, sep string) int {
	rs, rsep := []rune(s), []rune(sep)
	if len(rsep) == 0 {
		return len(rs)
	}
	for i := len(rs) - len(rsep); i >= 0; i-- {
		match := true
		for j := range rsep {
			if rs[i+j] != rsep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// pyStrip is Python's str.strip().
func pyStrip(s string) string { return strings.TrimSpace(s) }

// isFile is Path.is_file().
func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// isDir is Path.is_dir().
func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
