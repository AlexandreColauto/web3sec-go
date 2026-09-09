// helpers.go: the small value/file helpers env.py uses.
package envgo

import (
	"os"
	"path/filepath"

	"websec/internal/validation"
)

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

func boolAt(v validation.Value, key string) bool {
	f := objAt(v, key)
	return f.Kind == validation.Bool && f.B
}

func strAt(v validation.Value, key string) string { return objStr(v, key) }

// setKey replaces key in place (Python's dict assignment keeps the original
// insertion position).
func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	for i, kv := range v.O {
		if kv.K == key {
			v.O[i].V = val
			return v
		}
	}
	v.O = append(v.O, validation.KV{K: key, V: val})
	return v
}

// truthy is Python's bool() for the JSON shapes a snapshot pin holds.
func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0 || v.Big != ""
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

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isDirPath(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// resolvedPath is Path.resolve() for the display-only bind line.
func resolvedPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}
