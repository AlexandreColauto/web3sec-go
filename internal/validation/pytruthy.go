package validation

// PyTruthy is the canonical Python-truthiness predicate for a decoded JSON
// value (Wave J Task 7, "canonical format v1").
//
// Contract — the exact rule, not "matches CPython" prose:
//
//	Null            -> false
//	Bool            -> the bool
//	Int             -> false iff the integer is zero; the arbitrary-precision
//	                   big-integer text is honored (Big == "0" is falsy)
//	Flt             -> false iff == 0
//	Str             -> false iff ""
//	Arr / Obj       -> false iff empty
//
// Divergent variants are NOT folded in here; they are named at their call
// sites (pyTruthyBigNonEmpty, pyTruthyInt64Only, pyTruthyLenientContainers,
// pyTruthyCLI). A divergence that is visible is a decision; a hidden one is a
// bug.
func PyTruthy(v Value) bool {
	switch v.Kind {
	case Null:
		return false
	case Bool:
		return v.B
	case Int:
		if v.Big != "" {
			return v.Big != "0"
		}
		return v.I != 0
	case Flt:
		return v.F != 0
	case Str:
		return v.S != ""
	case Arr:
		return len(v.A) > 0
	case Obj:
		return len(v.O) > 0
	}
	return false
}
