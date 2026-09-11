package findings

// citation_test.go: H5 — affected[].citations. The mirror law: the digest is
// stamped on the affected entry the mitigation record cites, it equals the
// digest of the stored string, the stringly record stays byte-identical, the
// clean-scan half clears the mirror (and only the mirror), and the stamped
// finding still validates against the finding schema.

import (
	"testing"

	"websec/internal/validation"
)

// citFinding builds a finding with the given affected entries.
func citFinding(paths ...string) validation.Value {
	entries := []validation.Value{}
	for _, p := range paths {
		entries = append(entries, validation.VObj(
			validation.KV{K: "path", V: validation.VStr(p)}))
	}
	return validation.VObj(
		validation.KV{K: "affected", V: validation.VArr(entries...)})
}

// citOf reads affected[i].citations.<key>.
func citOf(f validation.Value, i int, key string) validation.Value {
	aff := objAt(f, "affected")
	if aff.Kind != validation.Arr || i >= len(aff.A) {
		return validation.VNull()
	}
	return objAt(objAt(aff.A[i], CitationsKey), key)
}

func TestCitationStampPicksTheCitedEntry(t *testing.T) {
	f := citFinding("src/A.sol", "src/B.sol")
	f = StampMitigationCitation(f, "src/B.sol", "rec-b")
	if got := citOf(f, 1, MitigationCitationKey).S; got != CitationDigest("rec-b") {
		t.Errorf("affected[1] digest = %q, want %q", got,
			CitationDigest("rec-b"))
	}
	if got := citOf(f, 0, MitigationCitationKey); got.Kind != validation.Null {
		t.Errorf("affected[0] must stay uncited, got %v", got)
	}
	// The entries that were not cited keep their exact key set.
	if aff := objAt(f, "affected"); len(aff.A[0].O) != 1 {
		t.Errorf("affected[0] gained keys: %v", aff.A[0].O)
	}
}

func TestCitationStampFallsBackToTheFirstEntry(t *testing.T) {
	f := citFinding("src/A.sol", "src/B.sol")
	f = StampMitigationCitation(f, "src/elsewhere.sol", "rec")
	if got := citOf(f, 0, MitigationCitationKey).S; got != CitationDigest("rec") {
		t.Errorf("fallback digest = %q, want %q", got, CitationDigest("rec"))
	}
	if got := citOf(f, 1, MitigationCitationKey); got.Kind != validation.Null {
		t.Errorf("affected[1] must stay uncited, got %v", got)
	}
}

func TestCitationStampIsANoOpWithoutAffected(t *testing.T) {
	bare := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr("F-0123456789ab")})
	got := StampMitigationCitation(bare, "src/A.sol", "rec")
	if validation.CanonCompact(got) != validation.CanonCompact(bare) {
		t.Errorf("stamp invented surface: %s", validation.CanonCompact(got))
	}
	empty := validation.VObj(
		validation.KV{K: "affected", V: validation.VArr()})
	got = StampMitigationCitation(empty, "src/A.sol", "rec")
	if validation.CanonCompact(got) != validation.CanonCompact(empty) {
		t.Errorf("stamp wrote to an empty affected: %s",
			validation.CanonCompact(got))
	}
	// A second stamp of the same record is idempotent (no duplicate keys).
	f := StampMitigationCitation(citFinding("src/A.sol"), "src/A.sol", "rec")
	again := StampMitigationCitation(f, "src/A.sol", "rec")
	if validation.CanonCompact(again) != validation.CanonCompact(f) {
		t.Errorf("re-stamp drifted:\n got %s\nwant %s",
			validation.CanonCompact(again), validation.CanonCompact(f))
	}
}

func TestCitationStampPreservesOtherChannels(t *testing.T) {
	f := validation.VObj(validation.KV{K: "affected", V: validation.VArr(
		validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/A.sol")},
			validation.KV{K: CitationsKey, V: validation.VObj(
				validation.KV{K: ComponentCitationKey,
					V: validation.VStr("0123456789ab")})}))})
	f = StampMitigationCitation(f, "src/A.sol", "rec")
	if got := citOf(f, 0, ComponentCitationKey).S; got != "0123456789ab" {
		t.Errorf("component channel lost: %q", got)
	}
	if got := citOf(f, 0, MitigationCitationKey).S; got != CitationDigest("rec") {
		t.Errorf("mitigation channel = %q", got)
	}
}

func TestCitationClearRemovesOnlyTheMirror(t *testing.T) {
	f := validation.VObj(validation.KV{K: "affected", V: validation.VArr(
		// entry 0: both channels — the component citation survives
		validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/A.sol")},
			validation.KV{K: CitationsKey, V: validation.VObj(
				validation.KV{K: MitigationCitationKey, V: validation.VStr("aaaaaaaaaaaa")},
				validation.KV{K: ComponentCitationKey, V: validation.VStr("bbbbbbbbbbbb")})}),
		// entry 1: mitigation only — the empty citations object goes too
		validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/B.sol")},
			validation.KV{K: CitationsKey, V: validation.VObj(
				validation.KV{K: MitigationCitationKey, V: validation.VStr("cccccccccccc")})}),
	)})
	got := ClearMitigationCitation(f)
	if v := citOf(got, 0, MitigationCitationKey); v.Kind != validation.Null {
		t.Errorf("entry 0 still cites a mitigation: %v", v)
	}
	if v := citOf(got, 0, ComponentCitationKey).S; v != "bbbbbbbbbbbb" {
		t.Errorf("entry 0 component channel = %q", v)
	}
	aff := objAt(got, "affected")
	for _, kv := range aff.A[1].O {
		if kv.K == CitationsKey {
			t.Error("entry 1 kept an empty citations object")
		}
	}
	// Clearing twice is a no-op.
	if again := ClearMitigationCitation(got); validation.CanonCompact(again) !=
		validation.CanonCompact(got) {
		t.Error("second clear drifted")
	}
}

// TestMitigationCitationMirrorsTheStoredRecord is the end-to-end law: after
// the ingest hook's mitigation scan, the stored finding carries BOTH the
// stringly record (byte-identical shape) and its digest on the affected
// entry the record cites, and the whole document still validates.
func TestMitigationCitationMirrorsTheStoredRecord(t *testing.T) {
	c := mitigCamp(t, "ES17CleanControl.sol")
	payload := hypoPayload()
	payload = withField(payload, "affected", validation.VArr(
		validation.VObj(
			kv("path", validation.VStr("src/ES17CleanControl.sol")),
			kv("function", validation.VStr("withdraw")))))
	payload = withField(payload, "root_cause", validation.VObj(
		kv("class", validation.VStr("unclassified")),
		kv("description", validation.VStr(
			"the withdraw handler forwards deposits via call after "+
				"zeroing"))))
	f, err := IngestHypothesis(c, payload, "code", "discovery", "")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := LoadFinding(c, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	mp := objAt(objAt(stored, "dedup_meta"), "mitigation_present")
	if mp.Kind != validation.Str {
		t.Fatalf("mitigation_present = %v, want the stringly record", mp)
	}
	if err := validation.Validate(stored, "finding", 1); err != nil {
		t.Fatalf("stamped finding fails the schema: %v", err)
	}
	if got := citOf(stored, 0, MitigationCitationKey).S; got !=
		CitationDigest(mp.S) {
		t.Errorf("mirror = %q, want sha12 of the record %q", got,
			CitationDigest(mp.S))
	}
	// The cited path is the record's file, so the mirror lands on the entry
	// the record names (here affected[0] is the only entry).
	if _, file, _, _, ok := ParseMitigationPresent(mp.S); !ok ||
		file != "src/ES17CleanControl.sol" {
		t.Fatalf("record file = %q, want the affected path", file)
	}
}
