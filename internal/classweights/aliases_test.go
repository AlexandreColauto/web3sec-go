package classweights

// Task 24 (G12): OWASP/SCVS taxonomy aliases as pinned data. Every alias id
// must come from the fetched primary page (see assets/taxonomy/aliases.json
// provenance); the tests below refuse invented mappings.

import (
	"strings"
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
	standards := validation.ObjAt(doc, "standards")
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
	for _, kv := range validation.ObjAt(doc, "classes").O {
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
		wantSWC string
		wantSfx string
		wantOK  bool
	}{
		{"reentrancy", "SC05", "SWC-107", "[OWASP SC05; SWC-107]", true},
		{"access-control", "SC01", "", "[OWASP SC01]", true},
		{"oracle-manipulation", "SC02", "", "[OWASP SC02]", true},
		{"logic-error", "SC03", "", "[OWASP SC03]", true},
		{"unchecked-external-call", "SC06", "SWC-104", "[OWASP SC06; SWC-104]", true},
		{"flash-loan", "SC07", "", "[OWASP SC07]", true},
		{"dos-griefing", "SC10", "", "[OWASP SC10]", true},
		// Honest absence: no standard counterpart, no row, no suffix.
		{"authorization", "", "", "", false},
		{"bridge-message", "", "", "", false},
		{"signature-replay", "", "", "", false},
		{"upgrade-initializer", "", "", "", false},
		{"precision-rounding", "", "", "", false},
		{"unmapped", "", "", "", false},
		{"no-such-class", "", "", "", false},
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
		if got := validation.ObjAt(row, "owasp").S; got != tc.wantID {
			t.Errorf("Alias(%q).owasp = %q, want %q", tc.class, got, tc.wantID)
		}
		if got := validation.ObjAt(row, "swc").S; got != tc.wantSWC {
			t.Errorf("Alias(%q).swc = %q, want %q", tc.class, got, tc.wantSWC)
		}
		if got := ClassAliasSuffix(tc.class); got != tc.wantSfx {
			t.Errorf("ClassAliasSuffix(%q) = %q, want %q", tc.class, got, tc.wantSfx)
		}
	}
}

// ---- I6 (Task 9): the SWC alias half ---------------------------------------

// TestAliasSWCTargetsPinnedToStandards: the SWC id-membership rule. A class
// row may only cite an id the embedded standards.swc list carries — the same
// pinning rule the OWASP half has, so a hand-typed id fails here, never in a
// report.
func TestAliasSWCTargetsPinnedToStandards(t *testing.T) {
	doc, err := LoadAliases()
	if err != nil {
		t.Fatal(err)
	}
	standards := validation.ObjAt(doc, "standards")
	if row := validation.ObjAt(standards, "swc"); row.Kind != validation.Arr || len(row.A) == 0 {
		t.Fatal("standards.swc is absent or empty — the fetched table is not embedded")
	}
	synth := func(swc string) validation.Value {
		row := validation.VObj(kvOf("owasp", validation.VStr("SC06")))
		if swc != "" {
			row.O = append(row.O, kvOf("swc", validation.VStr(swc)))
		}
		return validation.VObj(
			kvOf("schema_version", validation.VStr("1")),
			kvOf("standards", standards),
			kvOf("classes", validation.VObj(
				kvOf("unchecked-external-call", row))),
			kvOf("provenance", validation.ObjAt(doc, "provenance")))
	}
	if err := checkAliases(synth("SWC-104")); err != nil {
		t.Fatalf("a fetched swc id was refused: %v", err)
	}
	// The refusal path: an id absent from the fetched list (the shape a
	// hand-typed id takes) must be rejected.
	if err := checkAliases(synth("SWC-999")); err == nil {
		t.Fatal("swc SWC-999 (not in the fetched standards list) was accepted")
	}
	if err := checkAliases(synth("")); err != nil {
		t.Fatalf("a row without an swc key must stay valid: %v", err)
	}
}

// TestAliasSWCAdditiveTolerance: a pack with NO standards.swc key still
// validates — the SWC half is additive, so a future pack that drops it (or
// never fetched it) is not a schema break.
func TestAliasSWCAdditiveTolerance(t *testing.T) {
	doc, err := LoadAliases()
	if err != nil {
		t.Fatal(err)
	}
	owaspOnly := validation.VObj(kvOf("owasp", validation.ObjAt(validation.ObjAt(doc, "standards"), "owasp")))
	synth := validation.VObj(
		kvOf("schema_version", validation.VStr("1")),
		kvOf("standards", owaspOnly),
		kvOf("classes", validation.VObj(
			kvOf("reentrancy", validation.VObj(
				kvOf("owasp", validation.VStr("SC05")))))),
		kvOf("provenance", validation.ObjAt(doc, "provenance")))
	if err := validation.Validate(synth, "taxonomy_aliases", 1); err != nil {
		t.Fatalf("standards.required must stay [owasp]: %v", err)
	}
	if err := checkAliases(synth); err != nil {
		t.Fatalf("a pack with no standards.swc key must still validate: %v", err)
	}
}

// TestAliasSWCSuffixRender: the byte law. A row with both ids grows to
// "[OWASP SC05; SWC-107]"; a row with the OWASP id alone renders exactly as
// it did before I6; a row with neither stays silent.
func TestAliasSWCSuffixRender(t *testing.T) {
	both := validation.VObj(
		kvOf("owasp", validation.VStr("SC05")),
		kvOf("swc", validation.VStr("SWC-107")))
	if got := suffixOf(both); got != "[OWASP SC05; SWC-107]" {
		t.Errorf("suffixOf(owasp+swc) = %q, want %q", got, "[OWASP SC05; SWC-107]")
	}
	owaspOnly := validation.VObj(kvOf("owasp", validation.VStr("SC05")))
	if got := suffixOf(owaspOnly); got != "[OWASP SC05]" {
		t.Errorf("suffixOf(owasp only) = %q, want the pre-I6 bytes %q",
			got, "[OWASP SC05]")
	}
	if got := suffixOf(validation.VObj()); got != "" {
		t.Errorf("suffixOf(empty row) = %q, want silent", got)
	}
}

// TestAliasSWCTableIsVerbatim: the embedded id->title pairs are the registry's
// own bytes, spot-pinned here so a retyped title fails the suite. The full
// list is the fetched entries/index.md table; these four are its ends and its
// two mapped ids.
func TestAliasSWCTableIsVerbatim(t *testing.T) {
	doc, err := LoadAliases()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range listAt(validation.ObjAt(validation.ObjAt(doc, "standards"), "swc")) {
		got[validation.ObjAt(e, "id").S] = validation.ObjAt(e, "title").S
	}
	for id, title := range map[string]string{
		"SWC-136": "Unencrypted Private Data On-Chain",
		"SWC-107": "Reentrancy",
		"SWC-104": "Unchecked Call Return Value",
		"SWC-100": "Function Default Visibility",
	} {
		if got[id] != title {
			t.Errorf("standards.swc[%s] = %q, want %q", id, got[id], title)
		}
	}
	if len(got) != 37 {
		t.Errorf("standards.swc carries %d id(s), want the fetched table's 37",
			len(got))
	}
}

// TestAliasSWCProvenanceCarriesTheCaveat: the registry's own staleness
// warning is recorded with the fetch URL and date — the alias is a
// cross-reference for a human reader, never an authority claim.
func TestAliasSWCProvenanceCarriesTheCaveat(t *testing.T) {
	doc, err := LoadAliases()
	if err != nil {
		t.Fatal(err)
	}
	var prov validation.Value
	for _, p := range listAt(validation.ObjAt(doc, "provenance")) {
		if strings.Contains(validation.ObjAt(p, "source_url").S, "SWC-registry") {
			prov = p
			break
		}
	}
	if prov.Kind != validation.Obj {
		t.Fatal("no provenance entry for the SWC registry source")
	}
	if got := validation.ObjAt(prov, "source_url").S; got !=
		"https://raw.githubusercontent.com/SmartContractSecurity/"+
			"SWC-registry/master/entries/index.md" {
		t.Errorf("swc provenance source_url = %q", got)
	}
	if got := validation.ObjAt(prov, "checked_date").S; !isISODate(got) {
		t.Errorf("swc provenance checked_date = %q, want YYYY-MM-DD", got)
	}
	note := validation.ObjAt(prov, "note").S
	for _, want := range []string{
		"not been thoroughly updated since 2020",
		"incomplete",
		"may contain errors",
		"EthTrust",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("swc provenance note lacks %q:\n%s", want, note)
		}
	}
}

// kvOf is the local KV constructor (classweights.go owns objAt; kv would
// collide with nothing here but the name keeps the alias layer distinct).
func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// isISODate is the YYYY-MM-DD shape check the schema also pins (the test
// avoids a regexp import for one assertion).
func isISODate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, r := range s {
		if i == 4 || i == 7 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
