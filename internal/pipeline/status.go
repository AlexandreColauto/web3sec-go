// Pipeline status — the campaign status summary and the Python-value formatting helpers it shares (split from pipeline.go; pure structural move).

package pipeline

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// Status is status(): the DAG's progress view.
func Status(c *state.Campaign) (validation.Value, error) {
	p := New(c, nil, nil)
	completed, err := p.Completed()
	if err != nil {
		return validation.VNull(), err
	}
	next, err := p.NextStage()
	if err != nil {
		return validation.VNull(), err
	}
	ready, err := p.ReadyStages()
	if err != nil {
		return validation.VNull(), err
	}
	deps := []validation.KV{}
	joins := []validation.KV{}
	for _, sid := range stageJoinOrder {
		deps = append(deps, kvOf(sid, validation.StrArr(StageDeps[sid])))
		joins = append(joins, kvOf(sid, validation.VStr(StageJoins[sid].Kind)))
	}
	nextV := validation.VNull()
	if next != nil {
		nextV = validation.VStr(*next)
	}
	return validation.VObj(
		kvOf("completed", validation.StrArr(completed)),
		kvOf("next", nextV),
		kvOf("ready", validation.StrArr(ready)),
		kvOf("stages", validation.StrArr(StageIDs)),
		kvOf("deps", validation.VObj(deps...)),
		kvOf("joins", validation.VObj(joins...)),
		kvOf("updated_at", validation.VStr(state.NowIso())),
	), nil
}

// ---- small helpers --------------------------------------------------------

func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func objOr(v validation.Value, key string, def validation.Value) validation.Value {
	if validation.HasKey(v, key) {
		return validation.ObjAt(v, key)
	}
	return def
}

func vset(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
	v.O = append(v.O, kvOf(key, val))
}

func appendTo(v *validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V.A = append(v.O[i].V.A, val)
			return
		}
	}
	v.O = append(v.O, kvOf(key, validation.VArr(val)))
}

func strPtr(s string) *string { return &s }

func executorFor(kind string) *string {
	if kind == "model" {
		return strPtr("model")
	}
	return strPtr("deterministic")
}

// pyTupleRepr renders a Python tuple repr: ('a', 'b'). JOIN_KINDS is a tuple,
// so its repr carries parentheses (not the list brackets of PyRepr).
func pyTupleRepr(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = validation.PyReprStr(s)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyListRepr is Python's repr of a list of strings.

func pyOptIntRepr(v *int) string {
	if v == nil {
		return "None"
	}
	return strconv.Itoa(*v)
}

func stringSlice(v validation.Value, limit int) []string {
	out := []string{}
	if v.Kind != validation.Arr {
		return out
	}
	for i, e := range v.A {
		if i >= limit {
			break
		}
		out = append(out, e.S)
	}
	return out
}

func phaseIndex(phase string) (int, bool) {
	for i, p := range state.Phases {
		if p == phase {
			return i, true
		}
	}
	return 0, false
}

// isAdapterAbsent maps the adapter seam's failures onto Python's
// `except (KeyError, FileNotFoundError)`: a missing prompt is not fatal.
func isAdapterAbsent(err error) bool {
	return errors.Is(err, ErrAdapterNotWired) || errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, errFileNotFound)
}

// errFileNotFound lets an adapter seam report Python's FileNotFoundError
// without importing os (it wraps os.ErrNotExist for errors.Is).
var errFileNotFound = fmt.Errorf("file not found: %w", os.ErrNotExist)

// moneyField formats one budget_status field as Python f"{x:,.2f}".
func moneyField(bstat validation.Value, key string) (string, error) {
	v := validation.ObjAt(bstat, key)
	switch v.Kind {
	case validation.Flt:
		return pyMoney2f(v.F), nil
	case validation.Int:
		f, err := valueFloat(v)
		if err != nil {
			return "", err
		}
		return pyMoney2f(f), nil
	}
	return "", fmt.Errorf("cost status %s is not a number", validation.PyReprStr(key))
}

func valueFloat(v validation.Value) (float64, error) {
	switch v.Kind {
	case validation.Flt:
		return v.F, nil
	case validation.Int:
		if v.Big != "" {
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return 0, errors.New("int too large to convert to float")
			}
			return f, nil
		}
		return float64(v.I), nil
	}
	return 0, fmt.Errorf("float() argument must be a string or a real number, "+
		"not %s", validation.PyReprStr(kindName(v)))
}

func kindName(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "NoneType"
	case validation.Bool:
		return "bool"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Obj:
		return "dict"
	}
	return "NoneType"
}

// pyMoney2f is Python's f"{x:,.2f}": thousands-grouped, two decimals,
// round-half-even on the exact binary value, with CPython's nan/inf
// spellings and a signed "-0.00".
func pyMoney2f(x float64) string {
	switch {
	case math.IsNaN(x):
		return "nan"
	case math.IsInf(x, 1):
		return "inf"
	case math.IsInf(x, -1):
		return "-inf"
	}
	r := validation.PythonRound(x, 2)
	neg := math.Signbit(r)
	s := strconv.FormatFloat(math.Abs(r), 'f', 2, 64)
	intPart, frac := s, "00"
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, frac = s[:i], s[i+1:]
	}
	out := groupThousands(intPart) + "." + frac
	if neg {
		return "-" + out
	}
	return out
}

// groupThousands inserts "," every three digits from the right.
func groupThousands(digits string) string {
	if len(digits) <= 3 {
		return digits
	}
	var b strings.Builder
	lead := len(digits) % 3
	if lead > 0 {
		b.WriteString(digits[:lead])
	}
	for i := lead; i < len(digits); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(digits[i : i+3])
	}
	return b.String()
}
