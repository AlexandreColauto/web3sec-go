package validation

import (
	"regexp"
	"sort"
	"strconv"
	"sync"

	v6 "github.com/santhosh-tekuri/jsonschema/v6"
)

// pseg is one path segment: an object key (s) or an array index (i).
type pseg struct {
	num bool
	i   int64
	s   string
}

// pathSegs converts v6's string path into jsonschema's mixed (str, int)
// absolute_path, using the instance to tell array indices apart.
func pathSegs(data Value, path []string) []pseg {
	segs := make([]pseg, len(path))
	cur := data
	for idx, p := range path {
		if cur.Kind == Arr {
			if n, err := strconv.ParseInt(p, 10, 64); err == nil && int(n) < len(cur.A) {
				segs[idx] = pseg{num: true, i: n}
				cur = cur.A[n]
				continue
			}
		}
		segs[idx] = pseg{s: p}
		if cur.Kind == Obj {
			for _, kv := range cur.O {
				if kv.K == p {
					cur = kv.V
					break
				}
			}
		}
	}
	return segs
}

// compareSegs is Python list comparison on (str, int) paths. Mixed-type
// segments are unreachable in the 27 schemas (an array index can never
// collide with a property name at the same depth); numeric sorts first to
// keep the order deterministic.
func compareSegs(a, b []pseg) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		switch {
		case x.num && y.num:
			if x.i != y.i {
				if x.i < y.i {
					return -1
				}
				return 1
			}
		case x.num != y.num:
			if x.num {
				return -1
			}
			return 1
		case x.s != y.s:
			if x.s < y.s {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// ordKey is a leaf's enumeration position: jsonschema iter_errors yields in
// schema file order, and validate()'s sort is stable, so same-path order is
// the file order of the producing keyword.
type ordKey struct {
	enum []int // composition position: (fileIdx(allOf/if), branch, ...)
	file int   // file index of the keyword inside its node
	sub  int   // required: index in the missing list, else 0
}

func (o ordKey) less(o2 ordKey) bool {
	for i := 0; i < len(o.enum) && i < len(o2.enum); i++ {
		if o.enum[i] != o2.enum[i] {
			return o.enum[i] < o2.enum[i]
		}
	}
	if len(o.enum) != len(o2.enum) {
		return len(o.enum) < len(o2.enum)
	}
	if o.file != o2.file {
		return o.file < o2.file
	}
	return o.sub < o2.sub
}

// cand is a schema node able to produce errors at one instance path: the
// descended node itself plus allOf/if-then branches composing it, each with
// its enumeration position.
type cand struct {
	node Value
	enum []int
}

// errKeywords can produce a leaf error (used for candidate matching).
var errKeywords = map[string]bool{
	"type": true, "enum": true, "const": true, "pattern": true,
	"minLength": true, "maxLength": true, "minItems": true, "maxItems": true,
	"minProperties": true, "maxProperties": true, "uniqueItems": true,
	"required": true, "additionalProperties": true,
	"minimum": true, "maximum": true,
	"exclusiveMinimum": true, "exclusiveMaximum": true, "multipleOf": true,
	"oneOf": true, "anyOf": true, "not": true,
}

// nodeAt returns the candidate nodes at one instance path: the node itself
// plus, recursively, its allOf branches and its active if/then branch, each
// tagged with its enumeration position. inst is the instance at the node's
// level (needed to pick the active if branch).
func nodeAt(node, inst Value, root Value, enum []int, ifConds *map[*Value]*v6.Schema, compiler *v6.Compiler) []cand {
	n := resolveRef(node, root)
	out := []cand{{node: n, enum: enum}}
	for i, kv := range n.O {
		switch kv.K {
		case "allOf":
			for j := range kv.V.A {
				e2 := append(append([]int{}, enum...), i, j)
				out = append(out, nodeAt(kv.V.A[j], inst, root, e2, ifConds, compiler)...)
			}
		case "if":
			taken := ifValid(compiler, ifConds, &kv.V, inst)
			if taken {
				if then := objKey(n, "then"); then.Kind != 0 {
					e2 := append(append([]int{}, enum...), i, 0)
					out = append(out, nodeAt(then, inst, root, e2, ifConds, compiler)...)
				}
			} else if els := objKey(n, "else"); els.Kind != 0 {
				e2 := append(append([]int{}, enum...), i, 1)
				out = append(out, nodeAt(els, inst, root, e2, ifConds, compiler)...)
			}
		}
	}
	return out
}

// candidatesAt descends from the schema root along the instance path and
// returns the candidate nodes at the end, sorted by enumeration order.
func candidatesAt(doc, data Value, path []string) []cand {
	return candidatesAtFrom(doc, doc, data, path)
}

// candidatesAtFrom is candidatesAt with a separate descent start: root is the
// document $refs resolve against, start the node the walk begins at (a
// $definitions entry, when validating a definition on its own).
func candidatesAtFrom(root, start, data Value, path []string) []cand {
	ifConds := map[*Value]*v6.Schema{}
	compiler := v6.NewCompiler()
	var out []cand
	var rec func(node, inst Value, path []string, enum []int)
	rec = func(node, inst Value, path []string, enum []int) {
		cands := nodeAt(node, inst, root, enum, &ifConds, compiler)
		if len(path) == 0 {
			out = append(out, cands...)
			return
		}
		seg, rest := path[0], path[1:]
		for _, c := range cands {
			child := childAt(inst, seg)
			for i, kv := range c.node.O {
				for _, t := range descentTargets(c.node, kv, seg) {
					e2 := append(append([]int{}, c.enum...), i, t.idx)
					rec(t.node, child, rest, e2)
				}
			}
		}
	}
	rec(start, data, path, []int{})
	sort.SliceStable(out, func(a, b int) bool {
		return ordKey{enum: out[a].enum}.less(ordKey{enum: out[b].enum})
	})
	return out
}

// childAt walks one path segment into the instance.
func childAt(data Value, seg string) Value {
	switch data.Kind {
	case Arr:
		if n, err := strconv.ParseInt(seg, 10, 64); err == nil && int(n) < len(data.A) {
			return data.A[n]
		}
	case Obj:
		return objKey(data, seg)
	}
	return VNull()
}

// descentTarget is one subschema the path segment can descend into.
type descentTarget struct {
	node Value
	idx  int // enumeration position of the descent inside the node
}

// descentTargets lists, for one schema keyword entry, the subschemas the
// path segment seg descends into (properties, patternProperties,
// additionalProperties objects, items).
func descentTargets(n Value, kv KV, seg string) []descentTarget {
	switch kv.K {
	case "properties":
		if sub := objKey(kv.V, seg); sub.Kind != 0 {
			return []descentTarget{{sub, indexOfKey(kv.V, seg)}}
		}
	case "patternProperties":
		var out []descentTarget
		for pi, pp := range kv.V.O {
			if patternMatches(pp.K, seg) {
				out = append(out, descentTarget{pp.V, pi})
			}
		}
		return out
	case "additionalProperties":
		if kv.V.Kind == Obj && !keyCovered(n, seg) {
			return []descentTarget{{kv.V, 0}}
		}
	case "items":
		if kv.V.Kind == Obj {
			return []descentTarget{{kv.V, 0}}
		}
	}
	return nil
}

// keyCovered reports whether seg is matched by properties or
// patternProperties of n (draft-07 additionalProperties semantics).
func keyCovered(n Value, seg string) bool {
	for _, kv := range n.O {
		switch kv.K {
		case "properties":
			if objKey(kv.V, seg).Kind != 0 {
				return true
			}
		case "patternProperties":
			for _, pp := range kv.V.O {
				if patternMatches(pp.K, seg) {
					return true
				}
			}
		}
	}
	return false
}

var (
	patternRe   = map[string]*regexp.Regexp{}
	patternReMu sync.Mutex
)

func patternMatches(pattern, s string) bool {
	patternReMu.Lock()
	re, ok := patternRe[pattern]
	if !ok {
		re = regexp.MustCompile(pattern)
		patternRe[pattern] = re
	}
	patternReMu.Unlock()
	return re.MatchString(s)
}

// ifValid evaluates a draft-07 "if" condition with v6, compiling it on
// demand (the 27 schemas' if-conditions are small and ref-free).
func ifValid(compiler *v6.Compiler, cache *map[*Value]*v6.Schema, cond *Value, inst Value) bool {
	if sc, ok := (*cache)[cond]; ok {
		return sc.Validate(toAny(inst)) == nil
	}
	loc := "https://web3sec.local/ifcond/" + strconv.Itoa(len(*cache))
	if err := compiler.AddResource(loc, toAny(*cond)); err != nil {
		panic("validation: if-condition resource: " + err.Error())
	}
	sc, err := compiler.Compile(loc)
	if err != nil {
		panic("validation: if-condition compile: " + err.Error())
	}
	(*cache)[cond] = sc
	return sc.Validate(toAny(inst)) == nil
}

// resolveRef follows draft-07 in-document $refs (#/definitions/...) to the
// referenced node, up to 32 hops.
func resolveRef(node, root Value) Value {
	for steps := 0; node.Kind == Obj; steps++ {
		if steps > 32 {
			panic("validation: $ref cycle")
		}
		ref := objKey(node, "$ref")
		if ref.Kind != Str {
			return node
		}
		node = derefFragment(root, ref.S)
	}
	return node
}

// derefFragment walks a "#/..." fragment from the document root.
func derefFragment(root Value, ref string) Value {
	if len(ref) < 2 || ref[:2] != "#/" {
		panic("validation: unsupported $ref " + ref)
	}
	cur := root
	for _, part := range splitFragment(ref[2:]) {
		switch cur.Kind {
		case Obj:
			cur = objKey(cur, part)
		case Arr:
			n, err := strconv.Atoi(part)
			if err != nil || n < 0 || n >= len(cur.A) {
				panic("validation: bad $ref fragment " + ref)
			}
			cur = cur.A[n]
		}
	}
	if cur.Kind == 0 {
		panic("validation: unresolvable $ref " + ref)
	}
	return cur
}
