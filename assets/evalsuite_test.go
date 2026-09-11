package assets_test

import (
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/findings"
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
		// confirmed-not-exploitable outcome; the per-row law (which row is
		// the ack decoy, which is the clean control, and that each still
		// carries/omits its ack) is pinned by
		// TestEvalSuiteAckDecoyAndCleanControl below — this count only
		// fixes the cardinality.
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

// TestEvalSuiteAckDecoyAndCleanControl (H6) pins the TWO decoy/control rows
// by PRESENCE, not by the aggregate count above: the count proves two
// controls exist, it does not prove ES16 still carries the acknowledgement
// its decoy semantics depend on, nor that ES17 stayed ack-free (an ack
// accidentally added to the clean control would silently make it a second
// decoy, and the aggregate count would not notice). "Carries an ack" is
// asked of the scanner's own vocabulary
// (findings.ContainsAckPhrase) — not a hand-copied literal.
func TestEvalSuiteAckDecoyAndCleanControl(t *testing.T) {
	cases, err := assets.LoadEvalCases()
	if err != nil {
		t.Fatalf("LoadEvalCases: %v", err)
	}
	byRecord := map[string]validation.Value{}
	for i := range cases {
		byRecord[evalObjAt(evalObjAt(cases[i], "source"), "record_id").S] =
			cases[i]
	}
	for _, tc := range []struct {
		record  string
		outcome string
		class   string
		fixture string // repo-root-relative, as gold.locations[].file
		wantAck bool
	}{
		// ES16: the in-code-ack decoy — a reentrancy-labelled row that is
		// NOT exploitable precisely because the code acknowledges the
		// reviewed pattern, so the fixture must carry the ack.
		{"evalsuite-ES16", "confirmed-not-exploitable", "reentrancy",
			"assets/evalsuite/src/ES16AckDecoyVault.sol", true},
		// ES17: the clean control — zero findings by construction, so an
		// ack phrase anywhere in it would falsify the control's premise.
		{"evalsuite-ES17", "confirmed-not-exploitable", "access-control",
			"assets/evalsuite/src/ES17CleanControl.sol", false},
	} {
		c, ok := byRecord[tc.record]
		if !ok {
			t.Fatalf("the suite no longer carries %s", tc.record)
		}
		gold := evalObjAt(c, "gold")
		if got := evalObjAt(gold, "outcome").S; got != tc.outcome {
			t.Errorf("%s outcome = %q, want %q", tc.record, got, tc.outcome)
		}
		if got := evalObjAt(gold, "bug_class").S; got != tc.class {
			t.Errorf("%s bug_class = %q, want %q", tc.record, got, tc.class)
		}
		locs := evalObjAt(gold, "locations")
		if len(locs.A) != 1 {
			t.Fatalf("%s carries %d locations, want exactly 1", tc.record,
				len(locs.A))
		}
		file := evalObjAt(locs.A[0], "file").S
		if file != tc.fixture {
			t.Fatalf("%s fixture = %q, want %q", tc.record, file, tc.fixture)
		}
		raw, err := assets.EvalSuiteFS.ReadFile(
			strings.TrimPrefix(file, "assets/"))
		if err != nil {
			t.Fatalf("%s fixture missing from the embedded pack: %v",
				tc.record, err)
		}
		if got := findings.ContainsAckPhrase(string(raw)); got != tc.wantAck {
			t.Errorf("%s ack presence = %v, want %v (the decoy must carry "+
				"the acknowledgement it is named for; the clean control "+
				"must stay ack-free)", tc.record, got, tc.wantAck)
		}
	}
}
