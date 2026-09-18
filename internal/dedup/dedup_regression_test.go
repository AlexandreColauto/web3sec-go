package dedup

import (
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

// A DISPROVED / CHAIN / INFORMATIONAL / SUPERSEDED finding sharing a
// technical signature with a live finding must be EXCLUDED from the sweep,
// not treated as a live duplicate. Before the live-filter fix it was live
// and, as a later member of the group, the sweep aborted trying to mark it
// DUPLICATE (an illegal transition from a non-duplicatable state).
func TestRunDedupExcludesNonDuplicatableStates(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	const cls, path, fn = "oracle-manipulation", "src/V.sol", "round"
	// A: the single live finding (the would-be "keep"); it stays untouched.
	_ = hypoAt(t, c, "Live keep finding", cls, path, fn)

	stamp := func(f validation.Value, status string) {
		rec, err := findings.LoadFinding(c, fid(f))
		if err != nil {
			t.Fatal(err)
		}
		rec = setDeep(rec, validation.VStr(status), "status")
		if err := findings.SaveFinding(c, &rec); err != nil {
			t.Fatal(err)
		}
	}
	b := hypoAt(t, c, "Disproved dup", cls, path, fn)
	stamp(b, "DISPROVED")
	ch := hypoAt(t, c, "Chain finding", cls, path, fn)
	stamp(ch, "CHAIN")
	in := hypoAt(t, c, "Informational finding", cls, path, fn)
	stamp(in, "INFORMATIONAL")
	sup := hypoAt(t, c, "Superseded finding", cls, path, fn)
	stamp(sup, "SUPERSEDED")

	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatalf("RunDedup aborted on a non-duplicatable finding: %v", err)
	}
	// Only A is live; B/C/D/E are excluded, so nothing merges and A is the
	// single untouched live finding.
	if got := validation.ObjAt(report, "untouched").I; got != 1 {
		t.Errorf("untouched = %d, want 1 (the four non-duplicatable findings are excluded)", got)
	}
	if got := validation.ObjAt(report, "tier1_merges").Kind; got != validation.Arr ||
		len(validation.ObjAt(report, "tier1_merges").A) != 0 {
		t.Errorf("tier1_merges should be empty (no live duplicate), got %v",
			validation.CanonCompact(report))
	}
}
