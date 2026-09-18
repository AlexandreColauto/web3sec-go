package report

// Task 24 (G12): mapped classes render the OWASP alias suffix, unmapped
// classes render byte-identical to before (presence-gated: no alias row, no
// suffix, zero byte move).

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// reclassForAlias rewrites a saved finding's root-cause class (the same seam
// the credit-scope tests use).
func reclassForAlias(t *testing.T, camp *state.Campaign, f validation.Value, class string) {
	t.Helper()
	rc := validation.ObjAt(f, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "class", validation.VStr(class))
	f.O = validation.SetOrAppend(f.O, "root_cause", rc)
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatal(err)
	}
}

// TestConfirmedSummaryRendersAliasSuffix: the Results rollup names a mapped
// class with its pinned OWASP id.
func TestConfirmedSummaryRendersAliasSuffix(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	reclassForAlias(t, camp, fs[0], "reentrancy")
	reclassForAlias(t, camp, fs[1], "reentrancy")
	text := mustGenerate(t, camp)
	if !strings.Contains(text, "2 reentrancy [OWASP SC05; SWC-107]") {
		t.Errorf("confirmed summary lacks the reentrancy alias suffix:\n%s", text)
	}
}

// TestConfirmedSummaryUnmappedSilent: a class with no alias row renders with
// zero byte move (share-price-inflation has no standard counterpart).
func TestConfirmedSummaryUnmappedSilent(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	text := mustGenerate(t, camp)
	if !strings.Contains(text, "4 share-price-inflation") {
		t.Errorf("confirmed summary lost the bare class count:\n%s", text)
	}
	if strings.Contains(text, "share-price-inflation [OWASP") {
		t.Errorf("unmapped class gained a suffix:\n%s", text)
	}
	_ = fs
}

// TestFindingBlockRendersAliasSuffix: the per-finding bug-class line carries
// the suffix for mapped classes and stays bare otherwise.
func TestFindingBlockRendersAliasSuffix(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	reclassForAlias(t, camp, fs[0], "reentrancy")
	text := mustGenerate(t, camp)
	sec := reportFindingSection(t, text, validation.ObjStr(fs[0], "finding_id"))
	if !strings.Contains(sec,
		"- bug class: `reentrancy` [OWASP SC05; SWC-107]") {
		t.Errorf("finding block lacks the alias suffix: %q", sec)
	}
	secUnmapped := reportFindingSection(t, text, validation.ObjStr(fs[2], "finding_id"))
	if !strings.Contains(secUnmapped, "- bug class: `share-price-inflation`") {
		t.Errorf("finding block lost the bare class line: %q", secUnmapped)
	}
	if strings.Contains(secUnmapped, "[OWASP") {
		t.Errorf("unmapped finding block gained a suffix: %q", secUnmapped)
	}
}
