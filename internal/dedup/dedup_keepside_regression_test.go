package dedup

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

// The cross-snapshot rule applies to EITHER side of a pair. This test puts
// the KEEP (the earlier finding) on a different snapshot and the dup on the
// active one. Before the autoMergePair fix only the dup was checked, so this
// pair was auto-MERGED (evidence gathered against different code) instead of
// flagged for re-verification.
func TestAutoMergePairKeepSideCrossSnapshotFlags(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	a := hypo(t, c, "Keep-side cross A finding") // earlier -> the keep
	b := hypo(t, c, "Keep-side cross B finding") // later -> the dup
	// The KEEP is the one on a different snapshot.
	rec, err := findings.LoadFinding(c, fid(a))
	if err != nil {
		t.Fatal(err)
	}
	rec = setDeep(rec, validation.VStr("SNAP-deadbeef"), "snapshot_ids", "source")
	if err := findings.SaveFinding(c, &rec); err != nil {
		t.Fatal(err)
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	// Must be flagged (cross-snapshot on the keep side), never merged.
	assertCanon(t, "keep-side cross report", report,
		`{"cross_snapshot_flags":[{"flagged":"<B>","kept":"<A>"}],"tier1_merges":[],`+
			`"tier2_clusters":[],"tier3_flags":[],"untouched":2}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"})
	// The dup stays LIVE (flagged, not merged).
	flagged, err := findings.LoadFinding(c, fid(b))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(flagged, "status"); got != "HYPOTHESIS" {
		t.Fatalf("dup status = %q, want HYPOTHESIS (flagged, not merged)", got)
	}
}
