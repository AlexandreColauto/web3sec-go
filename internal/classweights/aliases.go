package classweights

// Task 24 (G12): the OWASP alias read path. aliases.json pins the standard
// ids the framework may display next to a canonical class; the pack embeds
// the id list it was checked against, and the loader refuses alias targets
// outside it (a recalled id fails here, never in a report).

import (
	"fmt"
	"strings"
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

// checkAliases enforces the G12/I6 pinning rules on a parsed aliases
// document: every classes[].owasp id is a member of the embedded
// standards.owasp id list, every classes[].swc id (when present) is a member
// of the embedded standards.swc list, and every class key is a class the
// weights table carries (the T5-owned class list, itself drift-tested against
// taxonomy.CanonicalClasses() plus the unmapped bucket).
//
// The SWC half is ADDITIVE: a pack with no standards.swc key carries no swc
// ids and validates unchanged.
func checkAliases(doc validation.Value) error {
	ids := map[string]bool{}
	for _, s := range listAt(validation.ObjAt(validation.ObjAt(doc, "standards"), "owasp")) {
		ids[validation.ObjAt(s, "id").S] = true
	}
	swcIDs := map[string]bool{}
	for _, s := range listAt(validation.ObjAt(validation.ObjAt(doc, "standards"), "swc")) {
		swcIDs[validation.ObjAt(s, "id").S] = true
	}
	known := map[string]bool{}
	if wdoc, err := Load(); err == nil {
		for _, kv := range validation.ObjAt(wdoc, "classes").O {
			known[kv.K] = true
		}
	}
	for _, kv := range validation.ObjAt(doc, "classes").O {
		if !known[kv.K] {
			return fmt.Errorf("aliases.json: class %q is not a known taxonomy class",
				kv.K)
		}
		if kv.V.Kind != validation.Obj {
			return fmt.Errorf("aliases.json: class %q row is not an object", kv.K)
		}
		id := validation.ObjAt(kv.V, "owasp").S
		if !ids[id] {
			return fmt.Errorf("aliases.json: class %q aliases %q, not in the embedded standards list",
				kv.K, id)
		}
		if swc := validation.ObjAt(kv.V, "swc").S; swc != "" && !swcIDs[swc] {
			return fmt.Errorf("aliases.json: class %q aliases %q, not in the embedded SWC standards list",
				kv.K, swc)
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
	row := validation.ObjAt(doc, "classes")
	if row.Kind != validation.Obj {
		return validation.VNull(), false
	}
	got := validation.ObjAt(row, class)
	if got.Kind != validation.Obj {
		return validation.VNull(), false
	}
	return got, true
}

// ClassAliasSuffix is the display suffix for a class: "[OWASP SC05]" when the
// class carries an OWASP alias, "[OWASP SC05; SWC-107]" when it also carries
// an SWC cross-reference (I6), "" when it does not (callers render the suffix
// presence-gated, so unmapped classes move zero bytes). The OWASP-only bytes
// are unchanged from before I6.
func ClassAliasSuffix(class string) string {
	row, ok := Alias(class)
	if !ok {
		return ""
	}
	return suffixOf(row)
}

// suffixOf renders one alias row's display suffix. It is the pure core of
// ClassAliasSuffix (and the seam the byte-law test drives with synthetic
// rows): standard ids in a pinned order, "; " separated, bracketed; the empty
// suffix when the row carries no id at all.
func suffixOf(row validation.Value) string {
	parts := []string{}
	if id := validation.ObjAt(row, "owasp").S; id != "" {
		parts = append(parts, "OWASP "+id)
	}
	if id := validation.ObjAt(row, "swc").S; id != "" {
		parts = append(parts, id)
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, "; ") + "]"
}
