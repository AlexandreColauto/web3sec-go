package classweights

// Task 24 (G12): the OWASP alias read path. aliases.json pins the standard
// ids the framework may display next to a canonical class; the pack embeds
// the id list it was checked against, and the loader refuses alias targets
// outside it (a recalled id fails here, never in a report).

import (
	"fmt"
	"sync"

	"websec/assets"
	"websec/internal/validation"
)

var (
	aliasOnce sync.Once
	aliasDoc  validation.Value
	aliasErr  error
)

// LoadAliases parses the embedded aliases.json table and validates it once
// against the taxonomy_aliases schema (sibling-loader entry
// validation.Validate, maxErrors 1), then against the embedded standards
// list (checkAliases). The error is sticky: every caller sees the same
// verdict.
func LoadAliases() (validation.Value, error) {
	aliasOnce.Do(func() {
		raw, err := assets.TaxonomyFS.ReadFile("taxonomy/aliases.json")
		if err != nil {
			aliasErr = err
			return
		}
		doc, err := validation.ParseOrdered(raw)
		if err != nil {
			aliasErr = fmt.Errorf("aliases.json: %w", err)
			return
		}
		if err := validation.Validate(doc, "taxonomy_aliases", 1); err != nil {
			aliasErr = fmt.Errorf("aliases.json invalid: %w", err)
			return
		}
		if err := checkAliases(doc); err != nil {
			aliasErr = err
			return
		}
		aliasDoc = doc
	})
	return aliasDoc, aliasErr
}

// checkAliases enforces the two G12 pinning rules on a parsed aliases
// document: every classes[].owasp id is a member of the embedded
// standards.owasp id list, and every class key is a class the weights table
// carries (the T5-owned class list, itself drift-tested against
// taxonomy.CanonicalClasses() plus the unmapped bucket).
func checkAliases(doc validation.Value) error {
	ids := map[string]bool{}
	for _, s := range listAt(objAt(objAt(doc, "standards"), "owasp")) {
		ids[objAt(s, "id").S] = true
	}
	known := map[string]bool{}
	if wdoc, err := Load(); err == nil {
		for _, kv := range objAt(wdoc, "classes").O {
			known[kv.K] = true
		}
	}
	for _, kv := range objAt(doc, "classes").O {
		if !known[kv.K] {
			return fmt.Errorf("aliases.json: class %q is not a known taxonomy class",
				kv.K)
		}
		if kv.V.Kind != validation.Obj {
			return fmt.Errorf("aliases.json: class %q row is not an object", kv.K)
		}
		id := objAt(kv.V, "owasp").S
		if !ids[id] {
			return fmt.Errorf("aliases.json: class %q aliases %q, not in the embedded standards list",
				kv.K, id)
		}
	}
	return nil
}

// listAt is the array flavor of objAt (empty when absent or not an array).
func listAt(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

// Alias returns the classes[cls] alias row and true, or (Null, false) when
// the class carries no alias (honest absence: no standard counterpart, no
// row — partial coverage, never an invented mapping).
func Alias(class string) (validation.Value, bool) {
	doc, err := LoadAliases()
	if err != nil {
		return validation.VNull(), false
	}
	row := objAt(doc, "classes")
	if row.Kind != validation.Obj {
		return validation.VNull(), false
	}
	got := objAt(row, class)
	if got.Kind != validation.Obj {
		return validation.VNull(), false
	}
	return got, true
}

// ClassAliasSuffix is the display suffix for a class: "[OWASP SC05]" when
// the class carries an alias, "" when it does not (callers render the
// suffix presence-gated, so unmapped classes move zero bytes).
func ClassAliasSuffix(class string) string {
	row, ok := Alias(class)
	if !ok {
		return ""
	}
	if id := objAt(row, "owasp").S; id != "" {
		return "[OWASP " + id + "]"
	}
	return ""
}
