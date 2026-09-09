package cli

// cmd_corpus_helpers: cli-local Value accessors for the corpus/prescreen
// commands. The *CLI suffix keeps them out of the shared helper namespace
// (concurrent P3 waves add files to this package).

import "websec/internal/validation"

// listAtCLI returns v[key] when it is an array, else nil.
func listAtCLI(v validation.Value, key string) []validation.Value {
	if f := objAt(v, key); f.Kind == validation.Arr {
		return f.A
	}
	return nil
}

// boolAtCLI returns v[key] when it is a bool, else false.
func boolAtCLI(v validation.Value, key string) bool {
	f := objAt(v, key)
	return f.Kind == validation.Bool && f.B
}

// floatAtCLI returns v[key] as a float64 (ints widen), else 0.
func floatAtCLI(v validation.Value, key string) float64 {
	f := objAt(v, key)
	switch f.Kind {
	case validation.Flt:
		return f.F
	case validation.Int:
		return float64(f.I)
	}
	return 0.0
}

// firstRowsCLI is Python's rows[:n] with n < 0 meaning "all" (never happens
// here, but it keeps the slice math obvious).
func firstRowsCLI(rows []validation.Value, n int) []validation.Value {
	if n >= 0 && len(rows) > n {
		return rows[:n]
	}
	return rows
}

// strListAtCLI returns v[key]'s string elements (Python's list of str).
func strListAtCLI(v validation.Value, key string) []string {
	out := []string{}
	for _, e := range listAtCLI(v, key) {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}
