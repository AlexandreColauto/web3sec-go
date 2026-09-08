package validation

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// objKey returns the value for key in an object Value (zero Value if absent).
func objKey(v Value, key string) Value {
	if v.Kind != Obj {
		return VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return VNull()
}

// indexOfKey is the file order index of key inside an object Value.
func indexOfKey(v Value, key string) int {
	for i, kv := range v.O {
		if kv.K == key {
			return i
		}
	}
	return 0
}

// splitFragment splits a JSON pointer fragment on "/".
func splitFragment(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// orderLeaves assigns each leaf its file-order enumeration position and
// sorts the leaves the way validate() does: stable sort by absolute_path.
func orderLeaves(entry *schemaEntry, data Value, leaves []leaf) []leaf {
	type slot struct {
		ord ordKey
		ok  bool
	}
	ords := make([]slot, len(leaves))
	candsByPath := map[string][]cand{}
	usedCand := map[string]bool{} // "path|candIdx|keyword"
	for li := range leaves {
		kw := keywordOf(leaves[li].kind)
		pkey := strings.Join(leaves[li].path, "\x00")
		cands, ok := candsByPath[pkey]
		if !ok {
			cands = candidatesAt(entry.doc, data, leaves[li].path)
			candsByPath[pkey] = cands
		}
		found := false
		for ci, c := range cands {
			uid := fmt.Sprintf("%s|%d|%s", pkey, ci, kw)
			if !errKeywords[kw] || !nodeHas(c.node, kw) {
				continue
			}
			if usedCand[uid] && kw != "required" {
				continue
			}
			usedCand[uid] = true
			ords[li] = slot{ord: ordKey{enum: c.enum, file: indexOfKey(c.node, kw)}, ok: true}
			found = true
			break
		}
		if !found {
			// Unmatched: keep v6's relative position (stable sort), last.
			ords[li] = slot{ord: ordKey{file: 1 << 30, sub: 1 << 30}}
		}
	}
	type keyed struct {
		seg []pseg
		ord ordKey
		i   int
	}
	keys := make([]keyed, len(leaves))
	for i := range leaves {
		keys[i] = keyed{seg: pathSegs(data, leaves[i].path), ord: ords[i].ord, i: i}
	}
	sort.SliceStable(keys, func(a, b int) bool {
		if c := compareSegs(keys[a].seg, keys[b].seg); c != 0 {
			return c < 0
		}
		return keys[a].ord.less(keys[b].ord)
	})
	out := make([]leaf, len(leaves))
	for a := range keys {
		out[a] = leaves[keys[a].i]
	}
	return out
}

// nodeHas reports whether the (resolved) node carries the error keyword.
func nodeHas(n Value, kw string) bool {
	nn := objKey(n, kw)
	switch kw {
	case "oneOf", "anyOf", "allOf":
		return nn.Kind == Arr
	case "if", "then", "else", "properties", "patternProperties", "items":
		return nn.Kind != 0
	}
	return nn.Kind != 0
}

// keywordOf maps a v6 ErrorKind to the jsonschema validator name.
func keywordOf(k any) string {
	switch k.(type) {
	case *kind.Type:
		return "type"
	case *kind.Enum:
		return "enum"
	case *kind.Const:
		return "const"
	case *kind.Pattern:
		return "pattern"
	case *kind.MinLength:
		return "minLength"
	case *kind.MaxLength:
		return "maxLength"
	case *kind.MinItems:
		return "minItems"
	case *kind.MaxItems:
		return "maxItems"
	case *kind.MinProperties:
		return "minProperties"
	case *kind.MaxProperties:
		return "maxProperties"
	case *kind.UniqueItems:
		return "uniqueItems"
	case *kind.Required:
		return "required"
	case *kind.AdditionalProperties:
		return "additionalProperties"
	case *kind.Minimum:
		return "minimum"
	case *kind.Maximum:
		return "maximum"
	case *kind.ExclusiveMinimum:
		return "exclusiveMinimum"
	case *kind.ExclusiveMaximum:
		return "exclusiveMaximum"
	case *kind.MultipleOf:
		return "multipleOf"
	case *kind.OneOf:
		return "oneOf"
	case *kind.AnyOf:
		return "anyOf"
	}
	return ""
}

// renderLeaf renders a leaf with the ported jsonschema message template.
func renderLeaf(data Value, l leaf) string {
	inst := dataAtValue(data, l.path)
	repr := pyRepr(inst)
	switch k := l.kind.(type) {
	case *kind.Type:
		return fmt.Sprintf("%s is not of type %s", repr, joinRepr(k.Want))
	case *kind.Enum:
		want := make([]Value, len(k.Want))
		for i := range k.Want {
			want[i] = anyToValue(k.Want[i])
		}
		return fmt.Sprintf("%s is not one of %s", repr, pyRepr(VArr(want...)))
	case *kind.Const:
		return fmt.Sprintf("%s was expected", pyRepr(anyToValue(k.Want)))
	case *kind.Pattern:
		return fmt.Sprintf("%s does not match %s", repr, pyReprStr(k.Want))
	case *kind.Required:
		return fmt.Sprintf("%s is a required property", pyReprStr(k.Missing[0]))
	case *kind.MinLength:
		return fmt.Sprintf("%s %s", repr, shortLong(k.Want, true))
	case *kind.MinItems:
		return fmt.Sprintf("%s %s", repr, shortLong(k.Want, true))
	case *kind.MaxLength:
		return fmt.Sprintf("%s %s", repr, shortLong(k.Want, false))
	case *kind.MaxItems:
		return fmt.Sprintf("%s %s", repr, shortLong(k.Want, false))
	case *kind.MinProperties:
		if k.Want == 1 {
			return repr + " should be non-empty"
		}
		return repr + " does not have enough properties"
	case *kind.MaxProperties:
		if k.Want == 0 {
			return repr + " is expected to be empty"
		}
		return repr + " has too many properties"
	case *kind.UniqueItems:
		return repr + " has non-unique elements"
	case *kind.AdditionalProperties:
		extras := append([]string(nil), k.Properties...)
		sort.Strings(extras)
		joined := joinRepr(extras)
		verb := "was"
		if len(extras) != 1 {
			verb = "were"
		}
		return fmt.Sprintf("Additional properties are not allowed (%s %s unexpected)", joined, verb)
	case *kind.Minimum:
		return fmt.Sprintf("%s is less than the minimum of %s", repr, pyRepr(ratToValue(k.Want)))
	case *kind.Maximum:
		return fmt.Sprintf("%s is greater than the maximum of %s", repr, pyRepr(ratToValue(k.Want)))
	case *kind.ExclusiveMinimum:
		return fmt.Sprintf("%s is less than or equal to the minimum of %s", repr, pyRepr(ratToValue(k.Want)))
	case *kind.ExclusiveMaximum:
		return fmt.Sprintf("%s is greater than or equal to the maximum of %s", repr, pyRepr(ratToValue(k.Want)))
	case *kind.MultipleOf:
		return fmt.Sprintf("%s is not a multiple of %s", repr, ratToString(k.Want))
	case *kind.OneOf, *kind.AnyOf:
		return repr + " is not valid under any of the given schemas"
	}
	return repr + " (unrendered " + keywordOf(l.kind) + ")"
}

// shortLong is the min/max length/items phrasing pair.
func shortLong(want int, isMin bool) string {
	if isMin {
		if want == 1 {
			return "should be non-empty"
		}
		return "is too short"
	}
	if want == 0 {
		return "is expected to be empty"
	}
	return "is too long"
}

// joinRepr is ", ".join(repr) over strings.
func joinRepr(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = pyReprStr(s)
	}
	return strings.Join(parts, ", ")
}

// ratToValue converts a v6 *big.Rat (schema bounds) to a Value for repr.
func ratToValue(r *big.Rat) Value {
	if r == nil {
		return VNull()
	}
	if r.IsInt() {
		// schema bounds are small; overflow is undefined per big.Int
		return VInt(r.Num().Int64())
	}
	f, _ := r.Float64()
	return VFloat(f)
}

// ratToString is CPython str() of the schema bound: ints bare, floats via
// repr (identical for floats).
func ratToString(r *big.Rat) string {
	if r == nil {
		return "None"
	}
	if r.IsInt() {
		return fmt.Sprintf("%d", r.Num().Int64())
	}
	f, _ := r.Float64()
	return pythonFloat(f)
}

// dataAtValue walks the instance to the leaf path.
func dataAtValue(data Value, path []string) Value {
	cur := data
	for _, p := range path {
		cur = childAt(cur, p)
	}
	return cur
}

// assemble builds the SchemaError text with validate()'s exact semantics,
// including the "(+0 more errors)" papercut on the max_errors=1 path.
func assemble(name string, data Value, leaves []leaf, maxErrors int) string {
	msgs := make([]string, len(leaves))
	wheres := make([]string, len(leaves))
	for i, l := range leaves {
		msgs[i] = renderLeaf(data, l)
		wheres[i] = whereOf(data, l.path)
	}
	if maxErrors <= 1 {
		return fmt.Sprintf("%s validation failed at %s: %s (+%d more errors)",
			name, wheres[0], msgs[0], len(leaves)-1)
	}
	msg := fmt.Sprintf("%s validation failed at %s: %s", name, wheres[0], msgs[0])
	end := maxErrors
	if end > len(leaves) {
		end = len(leaves)
	}
	for i := 1; i < end; i++ {
		msg += fmt.Sprintf("\n  also at %s: %s", wheres[i], msgs[i])
	}
	if len(leaves) > maxErrors {
		msg += fmt.Sprintf("\n  (+%d more errors)", len(leaves)-maxErrors)
	}
	return msg
}

// whereOf renders the jsonschema "at" pointer (int indices bare).
func whereOf(data Value, path []string) string {
	if len(path) == 0 {
		return "<root>"
	}
	segs := pathSegs(data, path)
	parts := make([]string, len(segs))
	for i, s := range segs {
		if s.num {
			parts[i] = fmt.Sprintf("%d", s.i)
		} else {
			parts[i] = s.s
		}
	}
	return strings.Join(parts, "/")
}
