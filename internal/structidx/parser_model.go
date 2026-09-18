// parser_model.go: the index node/edge model and its JSON serialization.

package structidx

import (
	"websec/internal/validation"
)

// ---- node / edge model -----------------------------------------------------

type idxEdge struct{ from, rel, to string }

type guardRec struct {
	line  int64
	keys  []string
	class int64
	text  string
}

type useRec struct {
	line int64
	keys []string
	kind string
}

type idxNode struct {
	kind       string
	id         string
	name       string
	path       string
	line       *int64
	visibility string
	isEntry    bool
	mods       []string
	selector   *string
	reads      []string
	writes     []string
	callsInt   []string
	callsExt   []string
	deleg      []string
	guards     []guardRec
	uses       []useRec
	closure    []validation.Value
}

func (n *idxNode) toValue() validation.Value {
	kvs := []validation.KV{
		{K: "id", V: validation.VStr(n.id)},
		{K: "kind", V: validation.VStr(n.kind)},
		{K: "name", V: validation.VStr(n.name)},
		{K: "path", V: validation.VStr(n.path)},
		{K: "line", V: lineValue(n.line)},
	}
	if n.kind == "function" {
		kvs = append(kvs,
			validation.KV{K: "visibility", V: validation.VStr(n.visibility)},
			validation.KV{K: "is_entry_point", V: validation.VBool(n.isEntry)},
			validation.KV{K: "modifiers", V: validation.StrArr(n.mods)},
			validation.KV{K: "guarded_by", V: validation.StrArr(n.mods)},
			validation.KV{K: "selector", V: selValue(n.selector)},
			validation.KV{K: "reads_storage", V: validation.StrArr(n.reads)},
			validation.KV{K: "writes_storage", V: validation.StrArr(n.writes)},
			validation.KV{K: "calls_internal", V: validation.StrArr(n.callsInt)},
			validation.KV{K: "calls_external", V: validation.StrArr(n.callsExt)},
			validation.KV{K: "delegatecalls", V: validation.StrArr(n.deleg)},
			validation.KV{K: "guards", V: guardsValue(n.guards)},
			validation.KV{K: "uses", V: usesValue(n.uses)},
		)
	} else if n.kind == "modifier" {
		kvs = append(kvs,
			validation.KV{K: "reads_storage", V: validation.VArr()},
			validation.KV{K: "writes_storage", V: validation.VArr()},
			validation.KV{K: "calls_internal", V: validation.VArr()},
			validation.KV{K: "calls_external", V: validation.VArr()},
			validation.KV{K: "delegatecalls", V: validation.VArr()},
		)
	}
	if n.closure != nil {
		kvs = append(kvs, validation.KV{K: "contract_closure",
			V: validation.VArr(n.closure...)})
	}
	return validation.VObj(kvs...)
}

func lineValue(line *int64) validation.Value {
	if line == nil {
		return validation.VNull()
	}
	return validation.VInt(*line)
}

func selValue(sel *string) validation.Value {
	if sel == nil {
		return validation.VNull()
	}
	return validation.VStr(*sel)
}

func guardsValue(gs []guardRec) validation.Value {
	out := make([]validation.Value, 0, len(gs))
	for _, g := range gs {
		out = append(out, validation.VObj(
			validation.KV{K: "line", V: validation.VInt(g.line)},
			validation.KV{K: "concept_keys", V: validation.StrArr(g.keys)},
			validation.KV{K: "class", V: validation.VInt(g.class)},
			validation.KV{K: "text", V: validation.VStr(g.text)},
		))
	}
	return validation.VArr(out...)
}

func usesValue(us []useRec) validation.Value {
	out := make([]validation.Value, 0, len(us))
	for _, u := range us {
		out = append(out, validation.VObj(
			validation.KV{K: "line", V: validation.VInt(u.line)},
			validation.KV{K: "concept_keys", V: validation.StrArr(u.keys)},
			validation.KV{K: "kind", V: validation.VStr(u.kind)},
		))
	}
	return validation.VArr(out...)
}
