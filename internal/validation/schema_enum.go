// schema_enum.go: the schema enum walker — schema_enum_paths / enum_legend /
// schema_enum_legend (webv2.validation). The legend is AUTO-GENERATED from
// the schema document: an enum added/removed changes it with no code edit.
package validation

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"websec/assets"
)

// EnumPath is one closed enum in a schema: the path that reaches it and its
// allowed values, in schema document order.
type EnumPath struct {
	Path   string
	Values []Value
}

// schemaDirOverride is SCHEMA_DIR: Python monkeypatches the module global to
// prove the legend is derived from the schema FILE, never a hand-maintained
// list. The empty string reads the embedded assets.
var (
	schemaDirMu       sync.RWMutex
	schemaDirOverride string
)

// SetSchemaDir points schema reads at an alternate directory and clears the
// compiled-schema cache (Python's load_schema.cache_clear()). The empty
// string restores the embedded assets.
func SetSchemaDir(dir string) {
	schemaDirMu.Lock()
	schemaDirOverride = dir
	schemaDirMu.Unlock()
	schemaMu.Lock()
	schemaCache = map[string]*schemaEntry{}
	schemaMu.Unlock()
}

// ResetSchemaDir restores the embedded schemas.
func ResetSchemaDir() { SetSchemaDir("") }

// ReadSchemaFile reads one schema document, from the override directory when
// one is set, else from the embedded assets.
func ReadSchemaFile(name string) ([]byte, error) {
	schemaDirMu.RLock()
	dir := schemaDirOverride
	schemaDirMu.RUnlock()
	if dir != "" {
		return os.ReadFile(filepath.Join(dir, name+".schema.json"))
	}
	return assets.FS.ReadFile("schema/" + name + ".schema.json")
}

// SchemaEnumPaths is schema_enum_paths: every closed enum in *schema* as
// (path, values), in schema document order (properties in their written
// order, arrays as `path[]`), with local $refs resolved so referenced
// definitions appear at the path that uses them. Recursive refs are visited
// once per path.
//
// Map schemas are walked too: a dict-valued additionalProperties or
// patternProperties holds a schema for keys the document does not name, and a
// closed enum under one is still a closed enum (the dedup/candidate_verdicts
// verdicts were invisible to the legend until this descended into them).
func SchemaEnumPaths(schema Value) []EnumPath {
	out := []EnumPath{}
	walkEnums(schema, schema, "", nil, &out)
	return out
}

func walkEnums(root, node Value, path string, refs []string,
	out *[]EnumPath) {
	if node.Kind != Obj {
		return
	}
	if ref := vObjStr(node, "$ref"); ref != "" {
		const prefix = "#/definitions/"
		if strings.HasPrefix(ref, prefix) && !inStrList(ref, refs) {
			walkEnums(root, vObjAt(vObjAt(root, "definitions"), ref[len(prefix):]),
				path, append(refs, ref), out)
		}
		return
	}
	if enum := vObjAt(node, "enum"); enum.Kind == Arr {
		*out = append(*out, EnumPath{Path: path, Values: enum.A})
	}
	for _, kv := range vObjAt(node, "properties").O {
		walkEnums(root, kv.V, pathJoin(path, kv.K), refs, out)
	}
	if sub := vObjAt(node, "additionalProperties"); sub.Kind == Obj {
		walkEnums(root, sub, pathJoin(path, "additionalProperties"), refs, out)
	}
	for _, kv := range vObjAt(node, "patternProperties").O {
		walkEnums(root, kv.V, pathJoin(path, "patternProperties/"+kv.K), refs,
			out)
	}
	if items := vObjAt(node, "items"); items.Kind == Obj {
		walkEnums(root, items, path+"[]", refs, out)
	}
}

// pathJoin is `f"{path}/{name}" if path else name`.
func pathJoin(path, name string) string {
	if path == "" {
		return name
	}
	return path + "/" + name
}

// vObjAt is dict lookup returning a null Value for a missing key.
func vObjAt(v Value, key string) Value {
	if v.Kind == Obj {
		for _, kv := range v.O {
			if kv.K == key {
				return kv.V
			}
		}
	}
	return VNull()
}

// vObjStr is str(v[key]) when the member is a string, else "".
func vObjStr(v Value, key string) string {
	if got := vObjAt(v, key); got.Kind == Str {
		return got.S
	}
	return ""
}

func inStrList(x string, items []string) bool {
	for _, it := range items {
		if it == x {
			return true
		}
	}
	return false
}

// EnumLegend is enum_legend: the rendered lines, `path: a|b|c`.
func EnumLegend(schema Value) []string {
	paths := SchemaEnumPaths(schema)
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		vals := make([]string, 0, len(p.Values))
		for _, v := range p.Values {
			vals = append(vals, LegendValue(v))
		}
		out = append(out, p.Path+": "+strings.Join(vals, "|"))
	}
	return out
}

// SchemaEnumLegend is schema_enum_legend: the legend for a named schema.
func SchemaEnumLegend(name string) ([]string, error) {
	raw, err := ReadSchemaFile(name)
	if err != nil {
		return nil, err
	}
	schema, err := ParseOrdered(raw)
	if err != nil {
		return nil, err
	}
	return EnumLegend(schema), nil
}

// LegendValue is _legend_value: one enum value as an operator types it (JSON
// literals, not Python).
func LegendValue(v Value) string {
	switch v.Kind {
	case Null:
		return "null"
	case Bool:
		if v.B {
			return "true"
		}
		return "false"
	case Str:
		return v.S
	case Int:
		return IntText(v)
	case Flt:
		return PythonFloat(v.F)
	}
	return ""
}
