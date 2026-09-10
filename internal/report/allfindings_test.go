package report

// allfindings_test.go — D1: the "All findings" table. The post-mortem report
// opened with `confirmed: 0` while 23 findings were critic-confirmed, because
// the Results section counted only status and rendered only CONFIRMED/CHAIN.
// The precision block (A3) fixed the counting but is capped by the submission
// budget, skips DUPLICATE/OUT_OF_SCOPE, and renders only when scores or a
// budget exist — so a policy-less campaign still hid everything. This table is
// the ungated inventory: every finding, sorted by acceptance score.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// tableOrder pulls the finding ids in table order out of a rendered report.
func tableOrder(t *testing.T, body string) []string {
	t.Helper()
	start := strings.Index(body, "### All findings")
	if start < 0 {
		t.Fatalf("report has no All findings table:\n%s", body)
	}
	var out []string
	for _, line := range strings.Split(body[start:], "\n") {
		switch {
		case strings.HasPrefix(line, "  | F-"):
			out = append(out, strings.Fields(strings.TrimPrefix(line, "  | "))[0])
		case strings.HasPrefix(line, "  | "):
			continue // the column header and its separator
		default:
			if len(out) > 0 {
				return out // the blank line that closes the table
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no rows parsed from the table:\n%s", body[start:])
	}
	return out
}

// TestAllFindingsTableShowsEveryStatus: a dismissed and a duplicate finding
// must appear, not only the confirmed ones.
func TestAllFindingsTableShowsEveryStatus(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Inventory Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	live := mkBareHypothesis(t, camp, "still a hypothesis")
	dup := mkBareHypothesis(t, camp, "duplicate of the live one")
	if _, err := findings.MarkDuplicate(camp, dup, live); err != nil {
		t.Fatal(err)
	}
	// A DISPROVED finding, written the way the states are written in this
	// package's other tests.
	dead := mkBareHypothesis(t, camp, "disproved by the ladder")
	f, err := findings.LoadFinding(camp, dead)
	if err != nil {
		t.Fatal(err)
	}
	f = setField(f, "status", validation.VStr("DISPROVED"))
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatal(err)
	}
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, id := range []string{live, dup, dead} {
		if !strings.Contains(body, id+" ") && !strings.Contains(body, id+" |") {
			t.Errorf("%s missing from the report:\n%s", id, body)
		}
	}
	if !strings.Contains(body, "### All findings (3)") {
		t.Errorf("table header does not count every finding:\n%s", body)
	}
	if !strings.Contains(body, "DISPROVED") {
		t.Errorf("the dismissed finding's status is not rendered:\n%s", body)
	}
}

// TestAllFindingsTableSortsByAcceptanceScore: the order is the LIVE acceptance
// score (descending), the same key the precision table and `webv2 rank` use, so
// a stored score that disagrees with the calibration cannot reorder the table.
// Ties fall back to the finding id.
func TestAllFindingsTableSortsByAcceptanceScore(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Sorted Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mkBand := func(title, band string) string {
		t.Helper()
		id := mkBareHypothesis(t, camp, title)
		setFindingFields(t, camp, id, validation.VObj(
			kv("validated", validation.VObj(kv("band", validation.VStr(band))))))
		return id
	}
	low := mkBand("the low-band finding", "low")
	high := mkBand("the high-band finding", "high")
	critical := mkBand("the critical-band finding", "critical")
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := tableOrder(t, string(raw))
	want := []string{critical, high, low}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("table order %v want %v (bands critical > high > low)",
			got, want)
	}
}

// TestAllFindingsTablePutsDisprovedLast: a critic-disproved finding can carry
// a high live score (the band survives the verdict in the arithmetic), so an
// inventory sorted by score alone would lead with a finding the critic killed.
// It sorts last, exactly as risk.AcceptanceRanking orders the precision table.
func TestAllFindingsTablePutsDisprovedLast(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Disproved Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	live := mkBareHypothesis(t, camp, "the live low-band finding")
	dead := mkBareHypothesis(t, camp, "the disproved critical finding")
	// live: low band, no verdict.
	setFindingFields(t, camp, live, validation.VObj(
		kv("validated", validation.VObj(kv("band", validation.VStr("low"))))))
	// dead: critical band AND a disproved verdict.
	setFindingFields(t, camp, dead, validation.VObj(
		kv("validated", validation.VObj(kv("band", validation.VStr("critical"))))))
	deadF, err := findings.LoadFinding(camp, dead)
	if err != nil {
		t.Fatal(err)
	}
	deadF = setField(deadF, "verification", validation.VObj(
		kv("critic_verdict", validation.VStr("disproved"))))
	if err := findings.SaveFinding(camp, &deadF); err != nil {
		t.Fatal(err)
	}
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := tableOrder(t, string(raw))
	want := []string{live, dead}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("table order %v want %v (disproved last despite its band)",
			got, want)
	}
	if !strings.Contains(string(raw), "critic-disproved finding(s) sorted last") {
		t.Errorf("the ordering note is missing:\n%s", string(raw))
	}
}

// setFindingFields merges fields into a finding's risk object.
func setFindingFields(t *testing.T, camp *state.Campaign, id string,
	riskObj validation.Value) {
	t.Helper()
	f, err := findings.LoadFinding(camp, id)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "risk", riskObj)
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatal(err)
	}
}

// TestAllFindingsTableStatusLeadsTheScore — the golden campaign's shape, and
// the reason the order is status-first: a HYPOTHESIS whose band was stamped has
// a non-zero live score while three CONFIRMED findings with no validated band
// score zero, so a score-only order opened the inventory with an unproven claim
// above the confirmed ones.
func TestAllFindingsTableStatusLeadsTheScore(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Status First Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	claim := mkBareHypothesis(t, camp, "the unproven claim with a band")
	setFindingFields(t, camp, claim, validation.VObj(
		kv("validated", validation.VObj(kv("band", validation.VStr("critical"))))))
	confirmed := mkBareHypothesis(t, camp, "the confirmed finding with no band")
	confF, err := findings.LoadFinding(camp, confirmed)
	if err != nil {
		t.Fatal(err)
	}
	confF = setField(confF, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(camp, &confF); err != nil {
		t.Fatal(err)
	}
	dup := mkBareHypothesis(t, camp, "the dismissed duplicate claim")
	if _, err := findings.MarkDuplicate(camp, dup, confirmed); err != nil {
		t.Fatal(err)
	}
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := tableOrder(t, string(raw))
	want := []string{confirmed, claim, dup}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("table order %v want %v (confirmed → hypothesis → dismissed)",
			got, want)
	}
	if !strings.Contains(string(raw), "ordered by status (confirmed/chain → hypothesis → dismissed), then live acceptance score") {
		t.Errorf("the table does not state its order:\n%s", string(raw))
	}
}

// TestAllFindingsTableRendersUnscoped: no policy, no stored scores — the table
// still renders (that is the case the post-mortem was in).
func TestAllFindingsTableRendersUnscoped(t *testing.T) {
	root := t.TempDir()
	camp, err := state.Init(root, "Unscoped Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	mkBareHypothesis(t, camp, "no score anywhere")
	path, err := Generate(camp)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "### All findings (1)") {
		t.Fatalf("unscoped campaign hides its findings:\n%s", body)
	}
	if !strings.Contains(body, "NO POLICY LOADED") {
		t.Fatalf("unscoped notice missing too:\n%s", body)
	}
	// A campaign with no findings prints no table at all.
	empty, err := state.Init(t.TempDir(), "Empty Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Generate(empty)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw2), "### All findings") {
		t.Errorf("an empty campaign printed a table:\n%s", string(raw2))
	}
}
