package validation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// pyRepr renders a Value the way CPython's repr() renders the equivalent
// Python object. jsonschema error messages embed repr() of the instance and
// of schema values, and that text is part of the ported contract.
func pyRepr(v Value) string {
	switch v.Kind {
	case Null:
		return "None"
	case Bool:
		if v.B {
			return "True"
		}
		return "False"
	case Int:
		return strconv.FormatInt(v.I, 10)
	case Flt:
		return pythonFloat(v.F)
	case Str:
		return pyReprStr(v.S)
	case Arr:
		return "[" + pyReprJoin(v.A) + "]"
	case Obj:
		parts := make([]string, len(v.O))
		for i, kv := range v.O {
			parts[i] = pyReprStr(kv.K) + ": " + pyRepr(kv.V)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	panic("validation: pyRepr of bad kind " + strconv.Itoa(int(v.Kind)))
}

// pyReprJoin is the ", "-joined repr list body ("" for empty).
func pyReprJoin(items []Value) string {
	parts := make([]string, len(items))
	for i, v := range items {
		parts[i] = pyRepr(v)
	}
	return strings.Join(parts, ", ")
}

// pyReprTuple renders a Go []string as a Python tuple repr: ('a', 'b').
func pyReprTuple(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = pyReprStr(s)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyReprStr is CPython str repr: single-quoted unless the string contains a
// single quote and no double quote, then double-quoted. Escape rules pinned
// against CPython 3.14: \\, the active quote, \n \t \r get named escapes,
// every other non-printable gets \xNN / \uNNNN / \UNNNNNNNN, and all
// printable non-ASCII passes through raw.
func pyReprStr(s string) string {
	q := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			if q == '\'' {
				b.WriteString(`\'`)
			} else {
				b.WriteByte('\'')
			}
		case '"':
			b.WriteByte('"')
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if pyPrintable(r) {
				b.WriteRune(r)
				continue
			}
			switch {
			case r < 0x100:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r < 0x10000:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		}
	}
	b.WriteByte(q)
	return b.String()
}

// pyPrintable mirrors CPython's Py_UNICODE_ISPRINTABLE for repr(): ASCII
// 0x20..0x7e, plus every codepoint outside the escaped table (extracted
// 1:1 from CPython 3.14 over the whole Unicode range).
func pyPrintable(r rune) bool {
	if r < 0x80 {
		return 0x20 <= r && r < 0x7f
	}
	return !inNonPrintableRanges(uint32(r))
}

func inNonPrintableRanges(cp uint32) bool {
	i := sort.Search(len(nonPrintableRanges), func(i int) bool {
		return nonPrintableRanges[i][1] >= cp
	})
	return i < len(nonPrintableRanges) && nonPrintableRanges[i][0] <= cp
}

// anyToValue converts a decoded any (v6 kind parameters use int64/float64/
// bool/string/nil/[]any/map[string]any) into a Value for repr rendering.
func anyToValue(v any) Value {
	switch x := v.(type) {
	case nil:
		return VNull()
	case bool:
		return VBool(x)
	case int:
		return VInt(int64(x))
	case int64:
		return VInt(x)
	case float64:
		return VFloat(x)
	case string:
		return VStr(x)
	case []any:
		a := make([]Value, len(x))
		for i := range x {
			a[i] = anyToValue(x[i])
		}
		return VArr(a...)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // map loses order; v6 params never render order-sensitive
		pairs := make([]KV, len(x))
		for i, k := range keys {
			pairs[i] = KV{K: k, V: anyToValue(x[k])}
		}
		return VObj(pairs...)
	}
	return VStr(fmt.Sprintf("%v", v))
}
