package assets_test

import (
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// evalObjAt is the 4-line dict helper the brief's skeleton calls objAtS:
// the assets package has no existing dict helper, so the test carries one.
func evalObjAt(v validation.Value, key string) validation.Value {
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

func TestEvalSuiteSchemaAndCoverage(t *testing.T) {
	cases, err := assets.LoadEvalCases()
	if err != nil {
		t.Fatalf("LoadEvalCases: %v", err)
	}
	if len(cases) < 16 {
		t.Fatalf("G4 requires >=16 cases, got %d", len(cases))
	}
	known := taxonomy.CanonicalClasses()
	classes := map[string]int{}
	control := 0
	for i := range cases {
		c := cases[i]
		// schema contract — the SAME entry evalstore.AddCase validates
		// through (internal/evalstore/evalstore.go L121):
		// validation.Validate(doc, "evaluation_case", 1).
		if err := validation.Validate(c, "evaluation_case", 1); err != nil {
			t.Fatalf("case %d invalid: %v", i, err)
		}
		part := evalObjAt(c, "partition").S
		if part != "dev" && part != "held-out" {
			t.Fatalf("partition must be dev|held-out, got %q", part)
		}
		cls := evalObjAt(c, "gold").O // bug_class lives under gold
		bc := ""
		for _, kv := range cls {
			if kv.K == "bug_class" {
				bc = kv.V.S
			}
			if kv.K == "outcome" && kv.V.S == "confirmed-not-exploitable" {
				control++ // the clean control protocol
			}
		}
		if bc == "" {
			t.Fatal("every gold needs bug_class")
		}
		if _, ok := known[bc]; !ok {
			t.Fatalf("gold.bug_class %q is not canonical", bc)
		}
		classes[bc]++
		// G7 provenance discipline on every row
		src := evalObjAt(c, "source")
		url := ""
		for _, kv := range src.O {
			if kv.K == "url" {
				url = kv.V.S
			}
		}
		if !strings.HasPrefix(url, "https://") && url != "internal://evalsuite" {
			t.Fatalf("source.url must be primary-or-internal, got %q", url)
		}
	}
	if len(classes) < 8 {
		t.Fatalf("G4 requires >=8 classes, got %d: %v", len(classes), classes)
	}
	if control != 2 { // ES17 clean control + ES16 ack decoy share the
		t.Fatalf("exactly two confirmed-not-exploitable rows required, got %d", control)
	}
	for _, must := range []string{"access-control", "reentrancy", "oracle-manipulation",
		"share-price-inflation", "precision-rounding", "upgrade-initializer",
		"cross-chain-replay", "dos-griefing"} {
		if classes[must] == 0 {
			t.Fatalf("required class %s missing", must)
		}
	}
}
