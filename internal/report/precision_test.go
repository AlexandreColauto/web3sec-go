package report

// precision_test.go — IMPROVEMENTS A3: the Results precision block. Pinned
// to the real critic_verdict enum (confirmed is the only positive;
// disproved disqualifies), the dual critic/evidence counts with the
// false-positive ratio, the top-K table (default, budget-capped), and the
// disqualified line.

import (
	"path/filepath"
	"regexp"
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
	// evidence-confirmed (f1); of the critic-confirmed, only f2 lacks the
	// evidence floor, so the false-positive share is 1/2 = 50.0%
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

// mkEvidenceOnlyFinding is mk() minus the critic's assent: the full
// evidence-backed CONFIRMED fixture, then a critic verdict that is not
// "confirmed". The result is LIVE and evidence-confirmed, but contributes
// nothing to criticN — the member the campaign's 5-vs-4 shape carries.
func mkEvidenceOnlyFinding(t *testing.T, camp *state.Campaign, hint,
	function, title, verdict string) string {
	t.Helper()
	fid := objStr(mk(t, camp, hint, function, title), "finding_id")
	if _, err := findings.SetCriticVerdict(camp, fid, verdict,
		"the claimed mechanism does not carry the exploit"); err != nil {
		t.Fatal(err)
	}
	return fid
}

// precisionLine is the rendered "- **precision:** ..." line.
func precisionLine(t *testing.T, text string) string {
	t.Helper()
	const marker = "- **precision:** "
	i := strings.Index(text, marker)
	if i < 0 {
		t.Fatalf("no precision line\n---\n%s", resultsSection(text))
	}
	line := text[i:]
	if j := strings.IndexByte(line, '\n'); j != -1 {
		line = line[:j]
	}
	return line
}

// precisionRatioField is the ratio value on the precision line (from after
// "false-positive ratio: " to the end of the line).
func precisionRatioField(t *testing.T, text string) string {
	t.Helper()
	const key = "false-positive ratio: "
	line := precisionLine(t, text)
	i := strings.Index(line, key)
	if i < 0 {
		t.Fatalf("precision line has no ratio field: %q", line)
	}
	return line[i+len(key):]
}

// TestReportPrecisionRatioNeverNegative pins D6: the ratio is the share of
// critic-confirmed LIVE findings that fail the evidence floor, so it is
// bounded to [0, 100] — it cannot go negative when evidence-confirmed
// outnumbers critic-confirmed (the campaign printed -25.0% for exactly
// that shape, 4 critic-confirmed against 5 evidence-confirmed).
func TestReportPrecisionRatioNeverNegative(t *testing.T) {
	negative := regexp.MustCompile(`-\d`)
	cases := []struct {
		name  string
		seed  func(t *testing.T, camp *state.Campaign)
		ratio string
	}{
		{
			// The campaign's shape: one critic-confirmed finding against
			// two evidence-confirmed ones. Every critic-confirmed finding
			// cleared the floor, so the share is 0 — the old subtraction
			// printed (1-2)/1 = -100.0%.
			name: "evidence-confirmed exceeds critic-confirmed",
			seed: func(t *testing.T, camp *state.Campaign) {
				fid := objStr(mk(t, camp, "d1", "deposit",
					"Empty-pool 1:1 mint via deposit"), "finding_id")
				persistAcceptanceScore(t, camp, fid, 4.5)
				mkEvidenceOnlyFinding(t, camp, "d2", "deposit",
					"Deposit share-price set by first actor", "disproved")
			},
			ratio: "0.0%",
		},
		{
			// The numerator is real: one of the two critic-confirmed
			// findings never cleared the floor.
			name: "half the critic-confirmed findings lack evidence",
			seed: func(t *testing.T, camp *state.Campaign) {
				fid := objStr(mk(t, camp, "d1", "deposit",
					"Empty-pool 1:1 mint via deposit"), "finding_id")
				persistAcceptanceScore(t, camp, fid, 4.5)
				bare := mkBareHypothesis(t, camp,
					"Bare hypothesis price skew")
				if _, err := findings.SetCriticVerdict(camp, bare,
					"confirmed", "the mechanism is real"); err != nil {
					t.Fatal(err)
				}
			},
			ratio: "50.0%",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			camp := clusterCamp(t)
			tc.seed(t, camp)
			got := precisionRatioField(t, mustGenerate(t, camp))
			if got != tc.ratio {
				t.Fatalf("false-positive ratio = %q, want %q", got, tc.ratio)
			}
			if negative.MatchString(got) {
				t.Fatalf("false-positive ratio %q is negative — D6: the "+
					"metric must never go negative", got)
			}
		})
	}
}

// TestReportPrecisionRatioNoCriticConfirmed pins the empty-denominator
// text: with no critic-confirmed live finding there is no share to
// compute, and the line must say so exactly.
func TestReportPrecisionRatioNoCriticConfirmed(t *testing.T) {
	const want = "n/a (no critic-confirmed findings)"
	cases := []struct {
		name string
		seed func(t *testing.T, camp *state.Campaign)
	}{
		{
			name: "evidence-confirmed but critic disproved",
			seed: func(t *testing.T, camp *state.Campaign) {
				fid := mkEvidenceOnlyFinding(t, camp, "d1", "deposit",
					"Empty-pool 1:1 mint via deposit", "disproved")
				persistAcceptanceScore(t, camp, fid, 4.5)
			},
		},
		{
			name: "live hypothesis with neither evidence nor verdict",
			seed: func(t *testing.T, camp *state.Campaign) {
				fid := mkBareHypothesis(t, camp,
					"Bare hypothesis price skew")
				persistAcceptanceScore(t, camp, fid, 1.5)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			camp := clusterCamp(t)
			tc.seed(t, camp)
			line := precisionLine(t, mustGenerate(t, camp))
			if !strings.Contains(line, "false-positive ratio: "+want) {
				t.Fatalf("precision line = %q, want ratio %q", line, want)
			}
			if !strings.Contains(line, "critic-confirmed: 0  - ") {
				t.Fatalf("precision line = %q, want critic-confirmed: 0",
					line)
			}
		})
	}
}

// TestReportPrecisionExcludesSuperseded pins G14 fix round 2: a SUPERSEDED
// finding leaves the precision block (counts + top-K table) and renders
// under the dismissed rows with its "superseded by <new>" reason (the
// Transition history row Supersede writes — the link the new finding's
// dedup_meta.supersedes points back from).
func TestReportPrecisionExcludesSuperseded(t *testing.T) {
	camp := clusterCamp(t)
	f1 := mk(t, camp, "d1", "deposit", "Empty-pool 1:1 mint via deposit")
	fid1 := objStr(f1, "finding_id")
	old := mk(t, camp, "d2", "deposit",
		"Deposit share-price set by first actor")
	oldID := objStr(old, "finding_id")
	newID := mkBareHypothesis(t, camp, "ShareVault restated inflation")
	if _, err := findings.Supersede(camp, newID, oldID, "model"); err != nil {
		t.Fatal(err)
	}
	persistAcceptanceScore(t, camp, fid1, 4.5)

	text := mustGenerate(t, camp)

	// counts: critic-confirmed 1 (f1 — the superseded old finding no longer
	// counts); evidence-confirmed 2 (f1 plus the successor, which inherits
	// the old finding's re-parented evidence copies and so still clears
	// the floor). Ratio 0.0%: the one critic-confirmed finding has
	// evidence.
	wantLine := "- **precision:** critic-confirmed: 1  - " +
		"evidence-confirmed: 2  - false-positive ratio: 0.0%"
	if !strings.Contains(text, wantLine) {
		t.Fatalf("missing %q\n---\n%s", wantLine, resultsSection(text))
	}

	// top-K: f1 + the new live hypothesis; the superseded old finding is
	// out of the table bytes.
	region := tableRegion(text, "- **top 2 by acceptance:**")
	if region == "" {
		t.Fatalf("missing top-2 header\n---\n%s", resultsSection(text))
	}
	if !strings.Contains(region, fid1) || !strings.Contains(region, newID) {
		t.Fatalf("live f1 and its superseding successor must rank\n---\n%s",
			region)
	}
	if strings.Contains(region, oldID) {
		t.Fatalf("superseded %s must not appear in the table\n---\n%s",
			oldID, region)
	}

	// dismissed rows: the old finding renders as SUPERSEDED with its
	// Transition reason.
	i := strings.Index(text, "## Dismissed candidates (with reasons)")
	if i < 0 {
		t.Fatalf("no dismissed section\n---\n%s", text)
	}
	sec := text[i:]
	if j := strings.Index(sec, "\n## "); j != -1 {
		sec = sec[:j]
	}
	if !strings.Contains(sec, "`"+oldID+"` **SUPERSEDED**") {
		t.Fatalf("superseded finding not rendered as dismissed\n---\n%s", sec)
	}
	if !strings.Contains(sec, "reason: superseded by "+newID) {
		t.Fatalf("superseded row missing its successor reason\n---\n%s", sec)
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
