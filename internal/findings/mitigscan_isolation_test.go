package findings

// mitigscan_isolation_test.go (Task 15, law half b): the soundness-vs-policy
// separation law from mitigscan's side — mitigscan OWNS
// dedup_meta.mitigation_present and NOTHING else.
//
// The companion halves live where their packages allow (Go forbids the
// import cycle a single-file suite would need: risk and report both import
// findings): the acceptance half in internal/risk/acceptance_test.go, the
// report half in internal/report/mitigation_report_test.go, and the
// check13/matcher half in internal/bounty/accepted_risk_test.go.

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"websec/internal/validation"
)

// TestMitigationScanLeavesBountyByteIdentical is law half (b):
// RecordMitigationScan on a finding carrying bounty.accepted_risk MUST NOT
// modify the bounty object — the bounty subtree marshals byte-identical
// pre/post while the scan still records its hit.
func TestMitigationScanLeavesBountyByteIdentical(t *testing.T) {
	c := mitigCamp(t, "ES17CleanControl.sol")
	f := mitigFinding(t, c, "src/ES17CleanControl.sol", "withdraw",
		"the withdraw handler forwards deposits via call after zeroing")
	fid := saveAckFinding(t, c, f)
	// Attach the POLICY layer's record first (the shape check13 writes).
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	stored.O = validation.SetOrAppend(stored.O, "bounty", validation.VObj(
		kv("accepted_risk", validation.VObj(
			kv("pattern", validation.VStr("price skew")),
			kv("kind", validation.VStr("accepted-risk"))))))
	if err := SaveFinding(c, &stored); err != nil {
		t.Fatal(err)
	}
	before, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	beforeBounty := validation.CanonCompact(validation.ObjAt(before, "bounty"))
	// The scan must still fire (a skipped scan proves nothing about the
	// writer surface — ES17 withdraw is the cei-order positive).
	if hit, err := RecordMitigationScan(c, fid); err != nil {
		t.Fatal(err)
	} else if !hit {
		t.Fatal("ES17 withdraw must hit cei-order; without a write the " +
			"bounty comparison is vacuous")
	}
	after, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.CanonCompact(validation.ObjAt(after, "bounty")); got !=
		beforeBounty {
		t.Errorf("mitigscan touched bounty:\n before %s\n after  %s",
			beforeBounty, got)
	}
	// And the soundness record landed where it belongs.
	mp := validation.ObjAt(validation.ObjAt(after, "dedup_meta"), "mitigation_present")
	if pattern, _, _, _, ok := ParseMitigationPresent(mp.S); !ok ||
		pattern != "cei-order" {
		t.Errorf("mitigation_present = %q, want a cei-order record", mp.S)
	}
}

// TestMitigationRecordCarriesNoPolicyKeys is the field-level half of the
// law: the mitigation JSON is exactly {pattern,file,line,evidence} — no
// policy-layer key (url, reference_url, cites, reference, note, kind,
// excluded_by) may ever ride it. (Both layers legitimately use the NAME
// "pattern" — the separation is at the OBJECT level: dedup_meta vs
// bounty — so the assertion is on the policy's OTHER keys, not the
// shared name.)
func TestMitigationRecordCarriesNoPolicyKeys(t *testing.T) {
	raw := MitigRecord("cei-order", "src/Escrow.sol", 23,
		"last write at L23 precedes call at L26")
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("MitigRecord must be JSON: %v", err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"evidence", "file", "line", "pattern"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("mitigation keys = %v, want %v", keys, want)
	}
	for _, banned := range []string{"url", "reference_url", "cites",
		"reference", "note", "kind", "excluded_by"} {
		if _, ok := m[banned]; ok {
			t.Errorf("mitigation record carries policy key %q: %s",
				banned, raw)
		}
	}
}
