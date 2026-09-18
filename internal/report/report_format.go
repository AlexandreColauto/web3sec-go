// Number- and evidence-level formatting helpers for the report: the
// Python-compatible thousands separators, percent format and the
// evidence-ladder ordering.
package report

import (
	"strconv"
	"strings"
	"websec/internal/validation"
)

func riskScore(f validation.Value) float64 {
	v := validation.AsObj(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "risk")), "validated"))
	s := validation.ObjAt(v, "score")
	switch s.Kind {
	case validation.Int:
		return float64(s.I)
	case validation.Flt:
		return s.F
	}
	return 0
}

// pyCommaAuto is Python's f"{v:,}": thousands separators, no forced decimals.
func pyCommaAuto(v validation.Value) string {
	switch v.Kind {
	case validation.Int:
		return commaInt(validation.IntText(v))
	case validation.Flt:
		s := validation.PythonFloat(v.F)
		return commaFloatText(s)
	}
	return validation.PyStr(v)
}

func commaInt(digits string) string {
	neg := strings.HasPrefix(digits, "-")
	if neg {
		digits = digits[1:]
	}
	out := commaGroups(digits)
	if neg {
		return "-" + out
	}
	return out
}

func commaFloatText(s string) string {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	intPart, frac := s, ""
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i:]
	} else if i := strings.IndexAny(s, "eE"); i >= 0 {
		intPart, frac = s[:i], s[i:]
	}
	out := commaGroups(intPart) + frac
	if neg {
		return "-" + out
	}
	return out
}

func commaGroups(digits string) string {
	var b strings.Builder
	for i, c := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// pyPercent0 is Python's f"{x:.0%}".
func pyPercent0(x float64) string {
	return strconv.FormatFloat(x*100, 'f', 0, 64) + "%"
}

var evidenceOrder = []string{"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7"}

func evidenceIndex(level string) int {
	for i, l := range evidenceOrder {
		if l == level {
			return i
		}
	}
	return -1
}
