// dedup_findings_seams.go: the call-back seams into findings.py helpers
// split out of dedup.go (mark_duplicate / flag_possible_duplicate /
// fold_into_lineage) with their fail-loud defaults.
package dedup

import (
	"fmt"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- seams into findings.py helpers internal/findings does not export yet ----
//
// mark_duplicate (findings.py:1458), flag_possible_duplicate (:1467) and
// fold_into_lineage (:1451) are not ported. The defaults FAIL LOUDLY: a sweep
// that cannot record its own decision must not look successful. The real
// implementations are installed with the Set* functions once findings exports
// them (they need findings.transition, which is also not ported yet).

// dedupHelperFn is the shared shape of the three findings.py helpers this
// package calls back into.
type dedupHelperFn func(*state.Campaign, string, string) (validation.Value, error)

// notWired is a seam default that fails loudly until a real helper is
// installed: a sweep that cannot record its own decision must not look
// successful.
func notWired(name string) dedupHelperFn {
	return func(*state.Campaign, string, string) (validation.Value, error) {
		return validation.VNull(), fmt.Errorf("dedup: %s is not wired", name)
	}
}

// markDuplicateFunc is the findings.mark_duplicate seam.
var markDuplicateFunc = notWired("findings.mark_duplicate")

// SetMarkDuplicate installs findings.mark_duplicate; nil restores the
// fail-loud default.
func SetMarkDuplicate(fn dedupHelperFn) {
	if fn == nil {
		markDuplicateFunc = notWired("findings.mark_duplicate")
		return
	}
	markDuplicateFunc = fn
}

// flagPossibleDuplicateFunc is the findings.flag_possible_duplicate seam.
var flagPossibleDuplicateFunc = notWired("findings.flag_possible_duplicate")

// SetFlagPossibleDuplicate installs findings.flag_possible_duplicate; nil
// restores the fail-loud default.
func SetFlagPossibleDuplicate(fn dedupHelperFn) {
	if fn == nil {
		flagPossibleDuplicateFunc = notWired("findings.flag_possible_duplicate")
		return
	}
	flagPossibleDuplicateFunc = fn
}

// foldIntoLineageFunc is the findings.fold_into_lineage seam.
var foldIntoLineageFunc = notWired("findings.fold_into_lineage")

// SetFoldIntoLineage installs findings.fold_into_lineage; nil restores the
// fail-loud default.
func SetFoldIntoLineage(fn dedupHelperFn) {
	if fn == nil {
		foldIntoLineageFunc = notWired("findings.fold_into_lineage")
		return
	}
	foldIntoLineageFunc = fn
}
