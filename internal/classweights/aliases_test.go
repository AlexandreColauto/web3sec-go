package classweights

// Task 24 (G12): OWASP/SCVS taxonomy aliases as pinned data. Every alias id
// must come from the fetched primary page (see assets/taxonomy/aliases.json
// provenance); the tests below refuse invented mappings.

import (
	"testing"

	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// TestAliasesLoadValidates: the aliases pack loads and is schema-valid.
func TestAliasesLoadValidates(t *testing.T) {
	if _, err := LoadAliases(); err != nil {
		t.Fatal(err)
	}
}

// TestAliasTargetsPinnedToStandards: every classes[].owasp id is a member of
// the embedded standards.owasp id list — the data file embeds the list it
// was checked against, so a typo'd or recalled id fails here, not in prod.
func TestAliasTargetsPinnedToStandards(t *testing.T) {
	doc, err := LoadAliases()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAliases(doc); err != nil {
		t.Fatal(err)
	}
	// The refusal path: a synthetic doc whose alias points outside the
	// standards list must be rejected.
	standards := objAt(doc, "standards")
	bad := validation.VObj(
		kvOf("schema_version", validation.VStr("1")),
		kvOf("standards", standards),
		kvOf("classes", validation.VObj(
			kvOf("reentrancy", validation.VObj(
				kvOf("owasp", validation.VStr("SC99")))))),
		kvOf("provenance", validation.VArr()),
	)
	if err := checkAliases(bad); err == nil {
		t.Fatal("alias SC99 (not in the standards list) was accepted")
	}
	// And a class key outside the taxonomy must be rejected too.
	badClass := validation.VObj(
		kvOf("schema_version", validation.VStr("1")),
		kvOf("standards", standards),
		kvOf("classes", validation.VObj(
			kvOf("reentrancy-2", validation.VObj(
				kvOf("owasp", validation.VStr("SC05")))))),
		kvOf("provenance", validation.VArr()),
	)
	if err := checkAliases(badClass); err == nil {
		t.Fatal("alias key reentrancy-2 (not a canonical class) was accepted")
	}
}

// TestAliasKeysAreCanonical: alias keys ⊆ CanonicalClasses ∪ {unmapped}, and
// the unmapped bucket itself carries no alias (absence is the honest signal;
// an invented mapping would be worse than none).
func TestAliasKeysAreCanonical(t *testing.T) {
	doc, err := LoadAliases()
	if err != nil {
		t.Fatal(err)
	}
	known := taxonomy.CanonicalClasses()
	for _, kv := range objAt(doc, "classes").O {
		if kv.K == taxonomy.UNMAPPED {
			continue
		}
		if _, ok := known[kv.K]; !ok {
			t.Fatalf("alias key %q is not a canonical class", kv.K)
		}
	}
	if _, ok := Alias(taxonomy.UNMAPPED); ok {
		t.Fatal("unmapped must carry no alias")
	}
}

// TestAliasReaderTableDriven: the read path over the committed pack.
func TestAliasReaderTableDriven(t *testing.T) {
	for _, tc := range []struct {
		class   string
		wantID  string
		wantSfx string
		wantOK  bool
	}{
		{"reentrancy", "SC05", "[OWASP SC05]", true},
		{"access-control", "SC01", "[OWASP SC01]", true},
		{"oracle-manipulation", "SC02", "[OWASP SC02]", true},
		{"logic-error", "SC03", "[OWASP SC03]", true},
		{"unchecked-external-call", "SC06", "[OWASP SC06]", true},
		{"flash-loan", "SC07", "[OWASP SC07]", true},
		{"dos-griefing", "SC10", "[OWASP SC10]", true},
		// Honest absence: no standard counterpart, no row, no suffix.
		{"authorization", "", "", false},
		{"bridge-message", "", "", false},
		{"signature-replay", "", "", false},
		{"upgrade-initializer", "", "", false},
		{"precision-rounding", "", "", false},
		{"unmapped", "", "", false},
		{"no-such-class", "", "", false},
	} {
		row, ok := Alias(tc.class)
		if ok != tc.wantOK {
			t.Errorf("Alias(%q) ok = %v, want %v", tc.class, ok, tc.wantOK)
			continue
		}
		if !tc.wantOK {
			if got := ClassAliasSuffix(tc.class); got != "" {
				t.Errorf("ClassAliasSuffix(%q) = %q, want silent", tc.class, got)
			}
			continue
		}
		if got := objAt(row, "owasp").S; got != tc.wantID {
			t.Errorf("Alias(%q).owasp = %q, want %q", tc.class, got, tc.wantID)
		}
		if got := ClassAliasSuffix(tc.class); got != tc.wantSfx {
			t.Errorf("ClassAliasSuffix(%q) = %q, want %q", tc.class, got, tc.wantSfx)
		}
	}
}

// kvOf is the local KV constructor (classweights.go owns objAt; kv would
// collide with nothing here but the name keeps the alias layer distinct).
func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}
