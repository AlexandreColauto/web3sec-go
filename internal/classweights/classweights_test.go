package classweights

import (
	"testing"

	"websec/internal/taxonomy"
	"websec/internal/validation"
)

func TestEveryCanonicalClassPresentOnce(t *testing.T) {
	doc, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	classes := objAt(doc, "classes")
	known := taxonomy.CanonicalClasses()
	for cls := range known {
		if objAt(classes, cls).Kind == validation.Null {
			t.Fatalf("canonical class %s missing from class_weights.json", cls)
		}
	}
	if objAt(classes, "unmapped").Kind == validation.Null {
		t.Fatal("unmapped bucket missing")
	}
	if len(classes.O) != len(known)+1 {
		t.Fatalf("table carries %d rows, want %d (+unmapped)", len(classes.O), len(known))
	}
}

func TestBootstrapNeutralAndProvenanceHygiene(t *testing.T) {
	doc, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	classes := objAt(doc, "classes")
	for _, kv := range classes.O {
		if f := objAt(kv.V, "search").F; f != 1.0 {
			t.Fatalf("%s: search=%v — tranche-2 law: all 1.0 until a backtest wins", kv.K, f)
		}
		if f := objAt(kv.V, "acceptance").F; f != 1.0 {
			t.Fatalf("%s: acceptance=%v — must stay 1.0 (G3 gate)", kv.K, f)
		}
		prov := objAt(kv.V, "provenance").A
		if len(prov) == 0 {
			t.Fatalf("%s: provenance rows required (G7)", kv.K)
		}
		for _, pr := range prov {
			if objAt(pr, "checked_date").S == "" || objAt(pr, "source_url").S == "" {
				t.Fatalf("%s: provenance row incomplete", kv.K)
			}
		}
	}
	if got := ClassesWithNonNeutralWeights(); len(got) != 0 {
		t.Fatalf("non-neutral weights before graduation: %v", got)
	}
}

func TestSearchFactorMissingClassIsNeutral(t *testing.T) {
	if SearchFactor("no-such-class") != 1.0 {
		t.Fatal("unknown class must be 1.0, never 0/silence")
	}
}
