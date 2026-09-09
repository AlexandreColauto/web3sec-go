package validation

import (
	"fmt"
	"strings"

	v6 "github.com/santhosh-tekuri/jsonschema/v6"
)

// ValidateDefinitionFailures is the multi-error flavor of
// ValidateDefinition: EVERY failure against a named $definitions entry,
// rendered as jsonschema's "<absolute_path or <root>>: <message>" and sorted
// by absolute_path — the port of model_boundary._schema_failures and
// trajectory._contract_failures (which sort iter_errors by
// list(e.absolute_path) and slice the first five).
//
// It returns nil when the value is valid, and a non-nil error only when the
// schema itself cannot be built.
func ValidateDefinitionFailures(data Value, name, def string) ([]string, error) {
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
		return []string{"<root>: is invalid"}, nil
	}
	// orderLeavesFrom already sorts by absolute_path (compareSegs), the
	// same key Python's sorted(iter_errors) uses.
	leaves = orderLeavesFrom(wrapper, objKey(defs, def), data, leaves)
	out := make([]string, len(leaves))
	for i, l := range leaves {
		where := strings.Join(l.path, "/")
		if where == "" {
			where = "<root>"
		}
		out[i] = where + ": " + renderLeaf(data, l)
	}
	return out, nil
}
