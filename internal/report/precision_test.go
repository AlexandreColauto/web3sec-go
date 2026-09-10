package report

// precision_test.go — IMPROVEMENTS A3: the Results precision block. Pinned
// to the real critic_verdict enum (confirmed is the only positive;
// disproved disqualifies), the dual critic/evidence counts with the
// false-positive ratio, the top-K table (default, budget-capped), and the
// disqualified line.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// mkBareHypothesis ingests a bare HYPOTHESIS (no evidence, no critic) — the
// "critic-confirmed but not evidence-confirmed" member of the precision
// fixture.
func mkBareHypothesis(t *testing.T, camp *state.Campaign, title string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(camp, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("share-price-inflation")),
			kv("description", validation.VStr(
				"the vault prices shares from an attacker-movable source")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/ShareVault.sol")),
			kv("contract", validation.VStr("ShareVault")),
			kv("function", validation.VStr("borrow"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr()),
			kv("required", validation.VArr()))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return objStr(f, "finding_id")
}

// persistAcceptanceScore emulates the gate storing the A3 score on a
// finding. The report recomputes scores live, so the value only matters
// for presence — the section's gate key is the stored field itself.
func persistAcceptanceScore(t *testing.T, camp *state.Campaign,
	fid string, score float64) {
	t.Helper()
	f, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	r := objAt(f, "risk")
	if r.Kind != validation.Obj {
		r = validation.VObj()
	}
	r.O = validation.SetOrAppend(r.O, "acceptance_score", validation.VFloat(score))
	f.O = validation.SetOrAppend(f.O, "risk", r)
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatal(err)
	}
}

func TestReportPrecisionBlock(t *testing.T) {
	camp := clusterCamp(t)

	// f1: full CONFIRMED finding — critic confirmed, E4+E7 (clears the E4
	// floor): critic-confirmed AND evidence-confirmed.
	f1 := mk(t, camp, "d1", "deposit", "Empty-pool 1:1 mint via deposit")
	fid1 := objStr(f1, "finding_id")

	// f2: bare HYPOTHESIS with a confirmed critic — critic-confirmed but
	// zero evidence (not evidence-confirmed).
	fid2 := mkBareHypothesis(t, camp, "Bare hypothesis price skew")
	if _, err := findings.SetCriticVerdict(camp, fid2, "confirmed",
		"the mechanism is real"); err != nil {
		t.Fatal(err)
	}

	// f3: bare HYPOTHESIS the critic DISPROVED — disqualified, and (being
	// evidence-less) it keeps evidence-confirmed below critic-confirmed so
	// the ratio is a non-trivial 50.0%.
	fid3 := mkBareHypothesis(t, camp, "Donation inflates the share price")
	if _, err := findings.SetCriticVerdict(camp, fid3, "disproved",
		"the donation path caps the mint"); err != nil {
		t.Fatal(err)
	}

	// the section is presence-gated: persist the gate's stored score on
	// f1 (the report recomputes the score live — the stored field only
	// switches the section on, the additive convention)
	persistAcceptanceScore(t, camp, fid1, 4.5)

	text := mustGenerate(t, camp)

	// the dual counts + ratio: 2 critic-confirmed (f1, f2), 1
	// evidence-confirmed (f1), ratio (2-1)/2 = 50.0%
	wantLine := "- **precision:** critic-confirmed: 2  - " +
		"evidence-confirmed: 1  - false-positive ratio: 50.0%"
	if !strings.Contains(text, wantLine) {
		t.Fatalf("missing %q\n---\n%s", wantLine, resultsSection(text))
	}

	// no policy: uncapped default (top 10) renders the 2 QUALIFIED rows
	// (f1 4.50 = E7+confirmed, f2 1.50 = confirmed only) — f3 is
	// disqualified and out of the table.
	if !strings.Contains(text, "- **top 2 by acceptance:**") {
		t.Fatalf("missing top-2 header\n---\n%s", resultsSection(text))
	}
	region := tableRegion(text, "- **top 2 by acceptance:**")
	if !strings.Contains(region,
		"  | # | finding | band | evidence | critic | score |") {
		t.Fatalf("missing table header\n---\n%s", region)
	}
	i1 := strings.Index(region, fid1)
	i2 := strings.Index(region, fid2)
	if i1 < 0 || i2 < 0 || i1 > i2 {
		t.Fatalf("f1 must rank above f2 (i1=%d i2=%d)\n---\n%s",
			i1, i2, region)
	}
	if i3 := strings.Index(region, fid3); i3 >= 0 {
		t.Fatalf("disqualified %s must not appear in the table\n---\n%s",
			fid3, region)
	}
	wantDq := "- disqualified (critic disproved): " + fid3 +
		" — excluded from the table"
	if !strings.Contains(text, wantDq) {
		t.Fatalf("missing %q\n---\n%s", wantDq, resultsSection(text))
	}
}

// tableRegion is the indented block under a precision-table header (table
// rows and the cap note, both two-space indented) — the finding sections
// elsewhere in the report also carry the ids, so membership claims must be
// made against this region, not the whole text.
func tableRegion(text, header string) string {
	i := strings.Index(text, header)
	if i < 0 {
		return ""
	}
	lines := strings.Split(text[i:], "\n")
	out := []string{lines[0]}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "  ") {
			break
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// TestReportPrecisionBudget pins the policy's submission_budget: the cap
// (max_findings) shrinks the table with a cap note, and the default K (0)
// leaves it uncapped.
func TestReportPrecisionBudget(t *testing.T) {
	camp := clusterCamp(t)
	f1 := mk(t, camp, "d1", "deposit", "Empty-pool 1:1 mint via deposit")
	fid1 := objStr(f1, "finding_id")
	f2 := mk(t, camp, "d2", "deposit", "Deposit share-price set by first actor")
	fid2 := objStr(f2, "finding_id")

	patchPolicy := func(t *testing.T, budget validation.Value) {
		t.Helper()
		policy := privilegedPolicy("Cluster Program")
		if budget.Kind != validation.Null {
			policy.O = validation.SetOrAppend(policy.O, "submission_budget", budget)
		}
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := validation.WriteJson(path, policy, ""); err != nil {
			t.Fatal(err)
		}
		doc, err := validation.ReadJson(camp.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(path))
		if err := validation.WriteJson(camp.StatePath, doc,
			"campaign_state"); err != nil {
			t.Fatal(err)
		}
	}

	// max_findings 1: the table holds ONE qualified row + the cap note.
	// Both findings tie on the score (E7+confirmed), so WHICH row survives
	// the tie-break is the finding_id order — assert membership, not order.
	patchPolicy(t, validation.VObj(
		kv("max_findings", validation.VInt(1)),
		kv("rank_by", validation.VStr("acceptance"))))
	text := mustGenerate(t, camp)
	if !strings.Contains(text,
		"- **top 1 by acceptance:** (submission budget)") {
		t.Fatalf("missing capped header\n---\n%s", resultsSection(text))
	}
	region := tableRegion(text, "- **top 1 by acceptance:**")
	in1, in2 := strings.Contains(region, fid1), strings.Contains(region, fid2)
	if in1 == in2 {
		t.Fatalf("exactly one of the two qualified rows must survive the "+
			"cap (in1=%v in2=%v)\n---\n%s", in1, in2, region)
	}
	if !strings.Contains(region,
		"  - capped at 1 by the submission budget: 1 more qualified "+
			"finding(s) not shown") {
		t.Fatalf("missing cap note\n---\n%s", region)
	}

	// max_findings 0: uncapped — both rows, no cap note
	patchPolicy(t, validation.VObj(
		kv("max_findings", validation.VInt(0))))
	text = mustGenerate(t, camp)
	if !strings.Contains(text, "- **top 2 by acceptance:**") {
		t.Fatalf("missing uncapped header\n---\n%s", resultsSection(text))
	}
	if strings.Contains(text, "capped at") {
		t.Fatalf("uncapped table must not carry the cap note")
	}
}

// TestReportPrecisionAbsence pins the additive convention: with no A3
// field present (no stored score, no submission_budget) the block renders
// nothing — a pre-A3 campaign's report bytes are unchanged.
func TestReportPrecisionAbsence(t *testing.T) {
	camp := clusterCamp(t)
	mk(t, camp, "d1", "deposit", "Empty-pool 1:1 mint via deposit")
	text := mustGenerate(t, camp)
	if strings.Contains(text, "**precision:**") ||
		strings.Contains(text, "by acceptance") ||
		strings.Contains(text, "disqualified (critic disproved)") {
		t.Fatalf("no A3 field present — the precision block must not "+
			"render\n---\n%s", resultsSection(text))
	}
}

// resultsSection is the report's "## Results" section (the precision block
// lives there) for failure output.
func resultsSection(text string) string {
	i := strings.Index(text, "## Results")
	if i < 0 {
		return text
	}
	tail := text[i:]
	if j := strings.Index(tail, "\n## "); j != -1 {
		return tail[:j]
	}
	return tail
}
