// IMPROVEMENTS B2 — report rendering for the adversarial-game clause and the
// liveness-findings subsection. Both blocks are presence-gated: a campaign
// with neither the clause nor a liveness finding renders exactly as it did
// before B2 (asserted here, not assumed).
package report

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// The three clause arguments, each well past the 20-rune floor.
const (
	rvWho = "the sequencer operator — every frozen hour pays their " +
		"uptime fees while rival bridges lose the deposits in transit"
	rvMech = "freezing withdrawals lets the operator's own staked " +
		"position absorb the fee flow while the halted bridge bleeds " +
		"TVL to competitors"
	rvInter = "the timelock challenge path expires into a no-op once " +
		"the upgrade queue is blocked, so the freeze cannot be voted " +
		"away before the challenge window closes"
)

// classifyLiveness rewrites a finding's economic_impact as the B1
// non-economic terminal (kind: "liveness") — the trigger both check15 and
// the report's liveness subsection key off.
func classifyLiveness(t *testing.T, camp *state.Campaign, fid string) {
	t.Helper()
	vf, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	vf.O = validation.SetOrAppend(vf.O, "economic_impact", validation.VObj(
		kv("kind", validation.VStr("liveness"))))
	if err := findings.SaveFinding(camp, &vf); err != nil {
		t.Fatal(err)
	}
}

// TestReportRendersAdversarialGameClause: the clause renders as three lines
// inside the finding's own section once the data is present, and the sibling
// without the data keeps the pre-B2 shape (no lines at all).
func TestReportRendersAdversarialGameClause(t *testing.T) {
	camp := clusterCamp(t)
	answered := mk(t, camp, "ag1", "deposit",
		"Operator profits from the freeze")
	control := mk(t, camp, "ag2", "donate",
		"Sibling surface without the clause")
	afid := validation.ObjStr(answered, "finding_id")
	if _, err := findings.SetAdversarialGame(camp, afid, rvWho, rvMech,
		rvInter); err != nil {
		t.Fatal(err)
	}
	gen := mustGenerate(t, camp)
	sec := reportFindingSection(t, gen, afid)
	for _, want := range []string{
		"- adversarial game: who profits — " + rvWho,
		"-   mechanism: " + rvMech,
		"-   challenge interplay: " + rvInter,
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("answered section missing %q\n---\n%s", want, sec)
		}
	}
	other := reportFindingSection(t, gen, validation.ObjStr(control, "finding_id"))
	if strings.Contains(other, "adversarial game") {
		t.Errorf("clause rendered without the data:\n---\n%s", other)
	}
	// Neither finding is a liveness finding, so the subsection stays away.
	if strings.Contains(gen, "### LIVENESS FINDINGS") {
		t.Error("liveness section rendered without a liveness finding")
	}
}

// TestReportLivenessSectionSurfacesWhoProfits: a liveness finding at any
// status appears in the subsection, first as UNANSWERED, then carrying the
// stored who_profits answer on the next generate.
func TestReportLivenessSectionSurfacesWhoProfits(t *testing.T) {
	camp := clusterCamp(t)
	f := mk(t, camp, "lv1", "deposit",
		"Upgrade queue can be blocked to freeze withdrawals")
	fid := validation.ObjStr(f, "finding_id")
	classifyLiveness(t, camp, fid)

	gen := mustGenerate(t, camp)
	if !strings.Contains(gen, "### LIVENESS FINDINGS — who profits from the freeze") {
		t.Fatalf("no liveness section:\n%s", gen)
	}
	openRow := "- `" + fid + "` (CONFIRMED): UNANSWERED (gate check15)"
	if !strings.Contains(gen, openRow) {
		t.Errorf("liveness row missing %q\n%s", openRow, gen)
	}

	if _, err := findings.SetAdversarialGame(camp, fid, rvWho, rvMech,
		rvInter); err != nil {
		t.Fatal(err)
	}
	gen = mustGenerate(t, camp)
	answeredRow := "- `" + fid + "` (CONFIRMED): " + rvWho
	if !strings.Contains(gen, answeredRow) {
		t.Errorf("liveness row did not pick up who_profits:\n%s", gen)
	}
	if strings.Contains(gen, "UNANSWERED (gate check15)") {
		t.Error("answered liveness finding still reports UNANSWERED")
	}
	// the same answer is also visible in the finding's own section.
	sec := reportFindingSection(t, gen, fid)
	if !strings.Contains(sec, "who profits — "+rvWho) {
		t.Errorf("finding section missing the clause:\n%s", sec)
	}
}

// TestReportWithoutLivenessFindingHasNoSection: an economic-only campaign
// renders neither the subsection nor any clause line.
func TestReportWithoutLivenessFindingHasNoSection(t *testing.T) {
	camp := clusterCamp(t)
	mk(t, camp, "e1", "deposit", "Ordinary economic finding")
	gen := mustGenerate(t, camp)
	if strings.Contains(gen, "### LIVENESS FINDINGS") {
		t.Error("liveness section rendered for an economic-only campaign")
	}
	if strings.Contains(gen, "adversarial game") {
		t.Error("adversarial-game clause rendered without the data")
	}
}
