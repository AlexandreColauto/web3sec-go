// coverage_pynum.go: Python number arithmetic for the ledger — exact
// rationals carrying Python's int/float distinction through +, min and str().
package coverage

import (
	"math/big"

	"websec/internal/validation"
)

// ---- Python number arithmetic --------------------------------------------

// pynum is a Python number for the ledger arithmetic: an exact rational plus
// the int/float distinction Python carries through +, min and str().
type pynum struct {
	rat     *big.Rat
	isFloat bool
}

// numInt is a Python int literal.
func numInt(n int64) pynum {
	return pynum{rat: new(big.Rat).SetInt64(n)}
}

// numOf is the numeric value of a Value: bool -> 0/1, int exact, float as the
// exact binary value. Non-numbers are 0 (Python would raise TypeError; the
// ledger only ever holds numbers).
func numOf(v validation.Value) pynum {
	switch v.Kind {
	case validation.Bool:
		if v.B {
			return numInt(1)
		}
		return numInt(0)
	case validation.Int:
		if r, ok := new(big.Rat).SetString(validation.IntText(v)); ok {
			return pynum{rat: r}
		}
	case validation.Flt:
		if r := new(big.Rat).SetFloat64(v.F); r != nil {
			return pynum{rat: r, isFloat: true}
		}
		return pynum{rat: new(big.Rat), isFloat: true}
	}
	return numInt(0)
}

// numOrZero is Python's `x or 0`: a falsy value (including a missing key) is
// the int 0.
func numOrZero(v validation.Value) pynum {
	if !validation.PyTruthy(v) {
		return numInt(0)
	}
	return numOf(v)
}

// add is Python's +: the result is a float when either side is.
func (a pynum) add(b pynum) pynum {
	return pynum{rat: new(big.Rat).Add(a.rat, b.rat), isFloat: a.isFloat || b.isFloat}
}

// addInt is + an int literal.
func (a pynum) addInt(n int64) pynum { return a.add(numInt(n)) }

// min is Python's min: the smaller operand, keeping its own int/float type.
func (a pynum) min(b pynum) pynum {
	if a.rat.Cmp(b.rat) <= 0 {
		return a
	}
	return b
}

// div is Python's true division: always a float.
func (a pynum) div(b validation.Value) float64 {
	x, _ := a.rat.Float64()
	y, _ := numOf(b).rat.Float64()
	return x / y
}

// text is str(number): int digits, or the float repr.
func (a pynum) text() string {
	if !a.isFloat && a.rat.IsInt() {
		return a.rat.Num().String()
	}
	f, _ := a.rat.Float64()
	return validation.PythonFloat(f)
}

// value is the JSON Value for the number (int when integral and not a float).
func (a pynum) value() validation.Value {
	if !a.isFloat && a.rat.IsInt() {
		n := a.rat.Num()
		if n.IsInt64() {
			return validation.VInt(n.Int64())
		}
		return validation.VBigInt(n.String())
	}
	f, _ := a.rat.Float64()
	return validation.VFloat(f)
}
