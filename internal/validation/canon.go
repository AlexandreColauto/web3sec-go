package validation

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind tags a JSON value's type.
type Kind byte

const (
	Null Kind = 'n'
	Bool Kind = 'b'
	Int  Kind = 'i'
	Flt  Kind = 'f'
	Str  Kind = 's'
	Arr  Kind = 'a'
	Obj  Kind = 'o'
)

// Value is an ordered JSON value. Objects preserve insertion order so the
// on-disk pretty writer (Task 4) can match CPython dict order byte-for-byte.
// The canonical (hash) encoder sorts object keys before serializing and never
// mutates the stored order.
type Value struct {
	Kind Kind
	B    bool
	I    int64
	// Big holds the decimal text of an integer that does not fit in int64
	// (I is 0 then). Python ints are arbitrary precision; preserving the
	// literal keeps read->write round-trips exact.
	Big string
	F   float64
	S   string
	A   []Value
	O   []KV
}

// KV is an ordered key/value pair inside an object.
type KV struct {
	K string
	V Value
}

// Constructors.
func VNull() Value           { return Value{Kind: Null} }
func VBool(b bool) Value     { return Value{Kind: Bool, B: b} }
func VInt(i int64) Value     { return Value{Kind: Int, I: i} }
func VBigInt(s string) Value { return Value{Kind: Int, Big: s} }
func VFloat(f float64) Value { return Value{Kind: Flt, F: f} }
func VStr(s string) Value    { return Value{Kind: Str, S: s} }
func VArr(a ...Value) Value  { return Value{Kind: Arr, A: a} }
func VObj(o ...KV) Value     { return Value{Kind: Obj, O: o} }

// IntText renders an Int Value: the exact decimal text when it exceeds
// int64, otherwise the int64 digits.
func IntText(v Value) string {
	if v.Big != "" {
		return v.Big
	}
	return strconv.FormatInt(v.I, 10)
}

// FromAny converts a decoded any (json.Number-aware) into a Value, preserving
// the int vs float distinction that json.Number carries.
func FromAny(v any) Value {
	switch x := v.(type) {
	case nil:
		return VNull()
	case bool:
		return VBool(x)
	case int:
		return VInt(int64(x))
	case int64:
		return VInt(x)
	case uint64:
		return VInt(int64(x))
	case float64:
		return VFloat(x)
	case json.Number:
		s := string(x)
		if isJSONInt(s) {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return VInt(i)
			}
			// exceeds int64: keep the exact decimal text
			return VBigInt(s)
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return VFloat(f)
		}
		return VStr(s)
	case string:
		return VStr(x)
	case []any:
		a := make([]Value, len(x))
		for i, e := range x {
			a[i] = FromAny(e)
		}
		return VArr(a...)
	case map[string]any:
		kvs := make([]KV, 0, len(x))
		for k, val := range x {
			kvs = append(kvs, KV{k, FromAny(val)})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].K < kvs[j].K })
		return VObj(kvs...)
	}
	return VNull()
}

func isJSONInt(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.', 'e', 'E':
			return false
		}
	}
	return true
}

// Canon serializes v to canonical JSON matching CPython json.dumps byte-for-byte
// with sort_keys=True, ensure_ascii=True. compact selects the separators
// (compact: ","/":"; spaced: ", "/"": ").
func Canon(v Value, compact bool) string {
	var b strings.Builder
	writeCanon(&b, v, compact)
	return b.String()
}

// CanonSpaced is the spaced flavor (event/context/row hashes).
func CanonSpaced(v Value) string { return Canon(v, false) }

// CanonCompact is the compact flavor (snapshot manifests, spec_hash, fingerprint).
func CanonCompact(v Value) string { return Canon(v, true) }

func writeCanon(b *strings.Builder, v Value, compact bool) {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Int:
		b.WriteString(IntText(v))
	case Flt:
		b.WriteString(PythonFloat(v.F))
	case Str:
		b.WriteByte('"')
		writeEscaped(b, v.S)
		b.WriteByte('"')
	case Arr:
		b.WriteByte('[')
		sep := ","
		if !compact {
			sep = ", "
		}
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(sep)
			}
			writeCanon(b, e, compact)
		}
		b.WriteByte(']')
	case Obj:
		writeCanonObj(b, v, compact)
	}
}

func writeCanonObj(b *strings.Builder, v Value, compact bool) {
	kvs := make([]KV, len(v.O))
	copy(kvs, v.O)
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].K < kvs[j].K })
	sep, colon := ",", ":"
	if !compact {
		sep, colon = ", ", ": "
	}
	b.WriteByte('{')
	for i, kv := range kvs {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteByte('"')
		writeEscaped(b, kv.K)
		b.WriteByte('"')
		b.WriteString(colon)
		writeCanon(b, kv.V, compact)
	}
	b.WriteByte('}')
}

// writeEscaped writes s with CPython ensure_ascii=True escaping.
func writeEscaped(b *strings.Builder, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			writeU4(b, r)
		case r <= 0x7e:
			b.WriteRune(r)
		default:
			if r > 0xffff {
				r2 := r - 0x10000
				writeU4(b, 0xd800+rune(r2>>10&0x3ff))
				writeU4(b, 0xdc00+rune(r2&0x3ff))
			} else {
				writeU4(b, r)
			}
		}
		i += size
	}
}

const hexd = "0123456789abcdef"

// writeU4 writes a \uXXXX escape for a rune <= 0xffff.
func writeU4(b *strings.Builder, r rune) {
	b.WriteString("\\u")
	b.WriteByte(hexd[(r>>12)&0xf])
	b.WriteByte(hexd[(r>>8)&0xf])
	b.WriteByte(hexd[(r>>4)&0xf])
	b.WriteByte(hexd[r&0xf])
}

// DumpIndented renders json.dumps(v, indent=2, ensure_ascii=False):
// insertion order, 2-space indent, raw non-ASCII, no trailing newline
// (WriteJson adds it).
func DumpIndented(v Value) string {
	var b strings.Builder
	writeIndented(&b, v, 0)
	return b.String()
}

func writeIndented(b *strings.Builder, v Value, depth int) {
	pad := strings.Repeat("  ", depth)
	inner := pad + "  "
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Int:
		b.WriteString(IntText(v))
	case Flt:
		b.WriteString(PythonFloat(v.F))
	case Str:
		b.WriteByte('"')
		writeEscapedRaw(b, v.S)
		b.WriteByte('"')
	case Arr:
		if len(v.A) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			writeIndented(b, e, depth+1)
		}
		b.WriteString("\n" + pad + "]")
	case Obj:
		if len(v.O) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			b.WriteByte('"')
			writeEscapedRaw(b, kv.K)
			b.WriteString("\": ")
			writeIndented(b, kv.V, depth+1)
		}
		b.WriteString("\n" + pad + "}")
	}
}

// writeEscapedRaw writes s with CPython ensure_ascii=False escaping: named
// escapes for " \ b f n r t, \uXXXX for other control chars (< 0x20);
// 0x7f and all non-ASCII stay raw.
func writeEscapedRaw(b *strings.Builder, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20:
			writeU4(b, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
}

// PythonFloat formats a float64 to match CPython repr exactly.
func PythonFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	neg := math.Signbit(f)
	s := strconv.FormatFloat(math.Abs(f), 'g', -1, 64)
	digits, e := parseFloatShortest(s)
	var out string
	if e < -4 || e >= 16 {
		out = sciRepr(digits, e)
	} else {
		out = fixedRepr(digits, e)
	}
	if neg {
		out = "-" + out
	}
	return out
}

// parseFloatShortest extracts the significant digits (no leading zeros, no
// decimal point) and the leading-digit exponent e (value = digits[0]*10^e...).
func parseFloatShortest(s string) (digits string, e int) {
	if s[0] == '-' {
		s = s[1:]
	}
	exp := 0
	if idx := strings.IndexByte(s, 'e'); idx >= 0 {
		exp, _ = strconv.Atoi(s[idx+1:])
		s = s[:idx]
	}
	intm, fracm := s, ""
	if idx := strings.IndexByte(s, '.'); idx >= 0 {
		intm, fracm = s[:idx], s[idx+1:]
	}
	if intm != "0" {
		digits = intm + fracm
		e = len(intm) - 1 + exp
	} else {
		digits = strings.TrimLeft(fracm, "0")
		e = -(len(fracm) - len(digits)) - 1 + exp
	}
	return digits, e
}

// sciRepr renders digits with leading-digit exponent e in CPython scientific
// form: d.ddd...e+XX (exponent zero-padded to >= 2 digits).
func sciRepr(digits string, e int) string {
	mant := digits[:1]
	if len(digits) > 1 {
		mant = digits[:1] + "." + digits[1:]
	}
	sign := "+"
	ae := e
	if e < 0 {
		sign, ae = "-", -e
	}
	es := strconv.Itoa(ae)
	if len(es) < 2 {
		es = "0" + es
	}
	return mant + "e" + sign + es
}

// fixedRepr renders digits with leading-digit exponent e in CPython fixed form
// (a float always carries a decimal point).
func fixedRepr(digits string, e int) string {
	pos := e + 1
	var b strings.Builder
	switch {
	case pos <= 0:
		b.WriteString("0.")
		for i := 0; i < -pos; i++ {
			b.WriteByte('0')
		}
		b.WriteString(digits)
	case pos < len(digits):
		b.WriteString(digits[:pos])
		b.WriteByte('.')
		b.WriteString(digits[pos:])
	default:
		b.WriteString(digits)
		for i := 0; i < pos-len(digits); i++ {
			b.WriteByte('0')
		}
		b.WriteString(".0")
	}
	return b.String()
}
