// Package classweights loads the G2 per-class three-weight table. It is the
// ONLY door through which historical-loss data may reach ranking, and the
// door ships LOCKED: every weight starts 1.0 (neutral) and only a G3
// backtest win on held-out data may move a number — in the JSON, never in
// code. severity_default is DISPLAY-only: internal/floors and internal/risk
// refuse it at their boundaries (Task 6 pins that).
package classweights

import (
	"fmt"
	"sort"
	"sync"

	"websec/assets"
	"websec/internal/validation"
)

var (
	once  sync.Once
	docV  validation.Value
	docEr error
)

// Load parses the embedded class_weights.json table and validates it once
// against the class_weights schema (the sibling-loader entry
// validation.Validate, maxErrors 1). The error is sticky: every caller
// sees the same verdict.
func Load() (validation.Value, error) {
	once.Do(func() {
		raw, err := assets.TaxonomyFS.ReadFile("taxonomy/class_weights.json")
		if err != nil {
			docEr = err
			return
		}
		doc, err := validation.ParseOrdered(raw)
		if err != nil {
			docEr = fmt.Errorf("class_weights.json: %w", err)
			return
		}
		if err := validation.Validate(doc, "class_weights", 1); err != nil {
			docEr = fmt.Errorf("class_weights.json invalid: %w", err)
			return
		}
		docV = doc
	})
	return docV, docEr
}

// objAt is the 4-line dict helper, per-package convention.
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// classes returns the "classes" object of the loaded table, or Null when
// the table failed to load (callers default to 1.0, never to silence).
func classes() validation.Value {
	doc, err := Load()
	if err != nil {
		return validation.VNull()
	}
	return objAt(doc, "classes")
}

// SearchFactor returns classes[cls].search; a missing class (or a failed
// table load) returns 1.0 — unknown must never be silenced.
func SearchFactor(class string) float64 {
	row := objAt(classes(), class)
	if row.Kind != validation.Obj {
		return 1.0
	}
	v := objAt(row, "search")
	if v.Kind == validation.Flt {
		return v.F
	}
	if v.Kind == validation.Int {
		return float64(v.I)
	}
	return 1.0
}

// Row returns the classes[cls] row and true, or (Null, false) when the
// class is absent.
func Row(class string) (validation.Value, bool) {
	row := objAt(classes(), class)
	if row.Kind != validation.Obj {
		return validation.VNull(), false
	}
	return row, true
}

// ClassesWithNonNeutralWeights lists the classes whose search or
// acceptance weight differs from 1.0, sorted. Empty until a G3 backtest
// graduates a class; the G3 graduation gate consumes this.
func ClassesWithNonNeutralWeights() []string {
	out := []string{}
	for _, kv := range classes().O {
		if objAt(kv.V, "search").F != 1.0 || objAt(kv.V, "acceptance").F != 1.0 {
			out = append(out, kv.K)
		}
	}
	sort.Strings(out)
	return out
}
