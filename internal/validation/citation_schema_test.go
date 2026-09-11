package validation

import (
	"strings"
	"testing"
)

// H5: affected[].citations is the additive, optional home for the
// machine-checkable citation hashes whose payloads stay stringly
// (dedup_meta.mitigation_present is a JSON string; component citations ride
// evidence description text). These tests pin three laws:
//
//  1. the citation object is ACCEPTED when well-formed (the new surface),
//  2. it is REJECTED when malformed (a hash pattern that actually bites),
//  3. it is OPTIONAL, and the stringly channels are byte-unchanged — the
//     affected item's required list stays ["path"] and
//     dedup_meta.mitigation_present stays `type: string`.
//
// findingWithAffected splices an affected[] entry into the shared OQ3 base
// finding.

const (
	citSHA256 = "0123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef"
	citSHA12 = "0123456789ab"
)

func findingWithAffected(t *testing.T, affected string) Value {
	t.Helper()
	mut := strings.Replace(validFindingJSON, `"evidence": [],`,
		`"affected": [`+affected+`], "evidence": [],`, 1)
	return mustParse(t, mut)
}

func mustParse(t *testing.T, raw string) Value {
	t.Helper()
	v, err := ParseOrdered([]byte(raw))
	if err != nil {
		t.Fatalf("ParseOrdered: %v", err)
	}
	return v
}

// TestFindingSchemaAcceptsAffectedCitationHashes — the additive surface:
// both citation channels accept a sha256 digest, and the sha12-length
// convention (the codebase's existing 12-hex-char derivations) composes.
func TestFindingSchemaAcceptsAffectedCitationHashes(t *testing.T) {
	cases := []struct {
		name     string
		affected string
	}{
		{"both channels, sha256", `{"path": "src/Vault.sol", ` +
			`"citations": {"mitigation_present": "` + citSHA256 + `", ` +
			`"component": "` + citSHA256 + `"}}`},
		{"mitigation only, sha12", `{"path": "src/Vault.sol", ` +
			`"citations": {"mitigation_present": "` + citSHA12 + `"}}`},
		{"component only, sha12", `{"path": "src/Vault.sol", ` +
			`"citations": {"component": "` + citSHA12 + `"}}`},
		{"empty citation object", `{"path": "src/Vault.sol", ` +
			`"citations": {}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(findingWithAffected(t, tc.affected),
				"finding", 1); err != nil {
				t.Fatalf("citation shape rejected: %v", err)
			}
		})
	}
}

// TestFindingSchemaRejectsMalformedCitationHashes — the pattern bites:
// uppercase hex, too-short digests, non-hex and a non-string are all
// rejected at the affected/0/citations/... path (so a producer that mints a
// truncated or uppercased digest fails loudly at write time).
func TestFindingSchemaRejectsMalformedCitationHashes(t *testing.T) {
	cases := []struct {
		name     string
		affected string
		wantPath string
	}{
		{"uppercase hex", `{"path": "p", "citations": ` +
			`{"mitigation_present": "` + strings.ToUpper(citSHA12) + `"}}`,
			"affected/0/citations/mitigation_present"},
		{"too short", `{"path": "p", "citations": ` +
			`{"mitigation_present": "0123456789a"}}`,
			"affected/0/citations/mitigation_present"},
		{"non-hex", `{"path": "p", "citations": ` +
			`{"component": "zzzzzzzzzzzz"}}`,
			"affected/0/citations/component"},
		{"non-string", `{"path": "p", "citations": ` +
			`{"component": 123456789012}}`,
			"affected/0/citations/component"},
		{"unknown citation channel", `{"path": "p", "citations": ` +
			`{"severity": "` + citSHA12 + `"}}`,
			"affected/0/citations"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(findingWithAffected(t, tc.affected), "finding", 1)
			var se *SchemaError
			if !asSchemaError(err, &se) {
				t.Fatalf("malformed citation accepted: %v", err)
			}
			if !strings.Contains(se.Msg, tc.wantPath) {
				t.Fatalf("error does not name %s: %s", tc.wantPath, se.Msg)
			}
		})
	}
}

// TestFindingSchemaCitationFieldsAreOptional pins the byte-law half of H5:
// the citation object is additive and optional, so every pre-H5 finding
// validates unchanged, and the stringly channels are untouched
// (dedup_meta.mitigation_present is still `type: string`, not an object or a
// hash; affected's required list is still exactly ["path"]).
func TestFindingSchemaCitationFieldsAreOptional(t *testing.T) {
	if err := Validate(findingWithAffected(t, `{"path": "src/Vault.sol"}`),
		"finding", 1); err != nil {
		t.Fatalf("citation-free affected entry rejected: %v", err)
	}
	raw, err := ReadSchemaFile("finding")
	if err != nil {
		t.Fatal(err)
	}
	schema := mustParse(t, string(raw))
	affected := vObjAt(vObjAt(vObjAt(vObjAt(schema, "properties"),
		"affected"), "items"), "properties")
	cits := vObjAt(affected, "citations")
	if cits.Kind != Obj {
		t.Fatal("affected items must carry the citations object")
	}
	for _, ch := range []string{"mitigation_present", "component"} {
		prop := vObjAt(vObjAt(cits, "properties"), ch)
		if vObjAt(prop, "type").S != "string" {
			t.Errorf("citations.%s must be a string", ch)
		}
		if vObjAt(prop, "pattern").S != "^[0-9a-f]{12,64}$" {
			t.Errorf("citations.%s pattern = %q", ch,
				vObjAt(prop, "pattern").S)
		}
	}
	// The stringly record stays a string: no shape drift on the channel
	// this migration is supposed to leave byte-identical.
	mp := vObjAt(vObjAt(vObjAt(vObjAt(schema, "properties"), "dedup_meta"),
		"properties"), "mitigation_present")
	if mp.Kind != Obj || vObjAt(mp, "type").S != "string" {
		t.Fatalf("dedup_meta.mitigation_present drifted: %s",
			CanonCompact(mp))
	}
	// affected's required list is unchanged: an entry with only `path`
	// (the pre-H5 shape) is still complete.
	req := vObjAt(vObjAt(vObjAt(schema, "properties"), "affected"),
		"items")
	if got := CanonCompact(vObjAt(req, "required")); got != `["path"]` {
		t.Fatalf("affected required = %s, want [\"path\"]", got)
	}
	if vObjAt(req, "additionalProperties").Kind != Bool ||
		vObjAt(req, "additionalProperties").B {
		t.Fatal("affected additionalProperties must stay false")
	}
}
