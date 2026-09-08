package validation

import (
	"fmt"
	"slices"
	"strconv"
	"sync"

	v6 "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

// knownSchemas is the port of webv2.validation.KNOWN_SCHEMAS. The order is
// contractual: it appears verbatim in the unknown-schema error text.
var knownSchemas = []string{
	"finding", "snapshot", "campaign_state", "protocol_model", "campaign_plan",
	"coverage", "chain", "bounty_policy", "sandbox_execution", "memory",
	"drift_report", "structural_index", "relation", "shared_signature",
	"shared_memory_row", "variant_ladder", "price_table", "assumption",
	"model_request", "model_response", "trajectory", "playbook",
	"evaluation_case", "archetype", "sequence_poc", "sequence_result",
	"sft_example", "probe_surface",
}

// SchemaError is the port of webv2.validation.SchemaError. Msg holds the
// exact multi-line text the Python version would raise.
type SchemaError struct{ Msg string }

func (e *SchemaError) Error() string { return e.Msg }

type schemaEntry struct {
	compiled *v6.Schema
	doc      Value // schema document in file order (for tie-break walk)
}

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]*schemaEntry{}
)

// loadSchema is the port of webv2.validation.load_schema (minus the
// lru_cache; the map cache is unbounded like lru_cache(maxsize=None)).
func loadSchema(name string) (*schemaEntry, error) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if e, ok := schemaCache[name]; ok {
		return e, nil
	}
	if !slices.Contains(knownSchemas, name) {
		return nil, fmt.Errorf("unknown schema %s; known: %s",
			PyReprStr(name), pyReprTuple(knownSchemas))
	}
	raw, err := ReadSchemaFile(name)
	if err != nil {
		// unreachable: the embedded FS is built from the same 27 files
		return nil, fmt.Errorf("schema file missing: schema/%s.schema.json", name)
	}
	doc, err := ParseOrdered(raw)
	if err != nil {
		return nil, err
	}
	compiler := v6.NewCompiler()
	loc := "https://web3sec.local/schema/" + name + ".schema.json"
	if err := compiler.AddResource(loc, toAny(doc)); err != nil {
		return nil, err
	}
	sc, err := compiler.Compile(loc)
	if err != nil {
		// v6 rejects schemas jsonschema's check_schema would accept (or
		// vice versa) only on malformed schemas; the embedded set is
		// byte-identical to the Python tree, so this is unreachable.
		return nil, err
	}
	e := &schemaEntry{compiled: sc, doc: doc}
	schemaCache[name] = e
	return e, nil
}

// Validate is the port of webv2.validation.validate. v6 supplies the
// validation semantics (OQ3: verdicts agree with jsonschema 4.26 on all 27
// schemas); the error model is mapped back to jsonschema's (required
// expansion, $ref/allOf unwrapping, file-order tie-break) and messages are
// re-rendered with the ported jsonschema templates.
func Validate(data Value, name string, maxErrors int) error {
	entry, err := loadSchema(name)
	if err != nil {
		return err
	}
	ve := entry.compiled.Validate(toAny(data))
	if ve == nil {
		return nil
	}
	leaves := flattenError(ve.(*v6.ValidationError))
	leaves = orderLeaves(entry, data, leaves)
	return &SchemaError{Msg: assemble(name, data, leaves, maxErrors)}
}

// DefViolation is one failed $definitions validation: the instance path
// (jsonschema's absolute_path) and the message rendered exactly as
// jsonschema's ValidationError.message would be.
type DefViolation struct {
	Path    []string
	Message string
}

// ValidateDefinition validates one value against a named $definitions entry
// of a schema — the port of findings._validate_evidence_item, which wraps
// the definition in a synthetic schema
// ({"$schema": ..., "$ref": "#/definitions/<def>", "definitions": ...}).
// It returns nil when the value is valid, a *DefViolation when it is not,
// and a non-nil error only when the schema itself cannot be built.
func ValidateDefinition(data Value, name, def string) (*DefViolation, error) {
	entry, err := loadSchema(name)
	if err != nil {
		return nil, err
	}
	defs := objKey(entry.doc, "definitions")
	if objKey(defs, def).Kind != Obj {
		return nil, fmt.Errorf("schema %s has no definitions.%s", name, def)
	}
	wrapper := VObj(
		KV{K: "$schema", V: objKey(entry.doc, "$schema")},
		KV{K: "$ref", V: VStr("#/definitions/" + def)},
		KV{K: "definitions", V: defs},
	)
	loc := "https://web3sec.local/schema/" + name + ".schema.json"
	compiler := v6.NewCompiler()
	if err := compiler.AddResource(loc, toAny(wrapper)); err != nil {
		return nil, err
	}
	sc, err := compiler.Compile(loc)
	if err != nil {
		return nil, err
	}
	ve := sc.Validate(toAny(data))
	if ve == nil {
		return nil, nil
	}
	leaves := flattenError(ve.(*v6.ValidationError))
	if len(leaves) == 0 {
		return &DefViolation{Message: "is invalid"}, nil
	}
	// The definition node is the instance root here: walk from it (with the
	// wrapper as the $ref resolution root) so each leaf carries the schema
	// node jsonschema would have reported from.
	leaves = orderLeavesFrom(wrapper, objKey(defs, def), data, leaves)
	// jsonschema raises the FIRST error its walk produces; the leaf order
	// here is that same file order over the same instance.
	return &DefViolation{Path: leaves[0].path,
		Message: renderLeaf(data, leaves[0])}, nil
}

// toAny converts an ordered Value into the plain any v6 validates.
func toAny(v Value) any {
	switch v.Kind {
	case Null:
		return nil
	case Bool:
		return v.B
	case Int:
		if v.Big != "" {
			// v6 cannot see *big.Int; the float64 approximation keeps the
			// integer/number verdicts (the 27 schemas' bounds are small)
			f, err := strconv.ParseFloat(v.Big, 64)
			if err != nil {
				return f
			}
			return f
		}
		return v.I
	case Flt:
		return v.F
	case Str:
		return v.S
	case Arr:
		a := make([]any, len(v.A))
		for i := range v.A {
			a[i] = toAny(v.A[i])
		}
		return a
	case Obj:
		m := make(map[string]any, len(v.O))
		for _, kv := range v.O {
			m[kv.K] = toAny(kv.V)
		}
		return m
	}
	panic("validation: toAny of bad kind " + strconv.Itoa(int(v.Kind)))
}

// leaf is one jsonschema-shaped error: a path plus the v6 kind that carries
// the rendering parameters (expanded: one leaf per missing required prop).
// node is the schema node that produced it, when the ordering walk could
// match one (renderLeaf needs it for schema-order message rendering).
type leaf struct {
	path []string
	kind any
	node Value
}

// flattenError maps v6's error tree onto jsonschema's flat iter_errors set:
// $ref errors resolve to their inner error, allOf (and root Schema) groups
// expand into branch errors, required bundles expand per property, and
// oneOf/anyOf stay single group errors.
func flattenError(top *v6.ValidationError) []leaf {
	if len(top.Causes) == 0 {
		return []leaf{{path: top.InstanceLocation, kind: top.ErrorKind}}
	}
	var out []leaf
	for _, c := range top.Causes {
		out = append(out, flattenCause(c)...)
	}
	return out
}

func flattenCause(e *v6.ValidationError) []leaf {
	switch e.ErrorKind.(type) {
	case *kind.Reference:
		// A $ref is transparent: every failing keyword of the referenced
		// schema surfaces as its own error (possibly several at once).
		if len(e.Causes) == 0 {
			return []leaf{{path: e.InstanceLocation, kind: e.ErrorKind}}
		}
		var out []leaf
		for _, c := range e.Causes {
			out = append(out, flattenCause(c)...)
		}
		return out
	case *kind.AllOf, *kind.Schema, *kind.Group:
		// AllOf/Schema are composition wrappers; Group is how v6 bundles
		// several failing keywords at the same level (jsonschema's
		// iter_errors yields them flat, so expand).
		var out []leaf
		for _, c := range e.Causes {
			out = append(out, flattenCause(c)...)
		}
		return out
	default:
		out := []leaf{{path: e.InstanceLocation, kind: e.ErrorKind}}
		if r, ok := e.ErrorKind.(*kind.Required); ok && len(r.Missing) > 1 {
			out = nil
			for _, m := range r.Missing { // schema order: v6 preserves it
				out = append(out, leaf{path: e.InstanceLocation,
					kind: &kind.Required{Missing: []string{m}}})
			}
		}
		return out
	}
}
