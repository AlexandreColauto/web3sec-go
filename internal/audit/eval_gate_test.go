// Task 4 gate proof: the presence-gated eval section is omitted from
// the audit report when the campaign matches no suite case (an unpriced,
// unmatched campaign keeps exactly the 14 unconditional sections) and
// present when it does. price_table follows the same law for pricing.
package audit

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// gatePayload is a hypothesis payload whose anchor keys
// (root_cause.class, affected[0].path) hit CASE-000000000003
// (ES03BankReentrancy, reentrancy @ ES03BankReentrancy.sol).
func gatePayload() validation.Value {
	return validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Bank reenters before updating its balance")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("reentrancy")},
			validation.KV{K: "description", V: validation.VStr("withdraw() calls out before zeroing the balance")},
		)},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/ES03BankReentrancy.sol")},
			validation.KV{K: "contract", V: validation.VStr("Bank")},
			validation.KV{K: "function", V: validation.VStr("withdraw")},
		))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr(validation.VStr("withdraw"))},
		)},
	)
}

// gateCampaign opens a scratch campaign pinning program and ingests n
// live findings through IngestHypothesis (schema-valid on disk, so the
// findings section stays clean).
func gateCampaign(t *testing.T, program string, n int) *state.Campaign {
	t.Helper()
	Setup()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := findings.IngestHypothesis(c, gatePayload(), "code", "t", ""); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func hasSection(report validation.Value, name string) bool {
	for _, kv := range objAt(report, "sections").O {
		if kv.K == name {
			return true
		}
	}
	return false
}

// TestEvalAbsentWithoutMatch: a campaign matching no suite case audits
// to exactly the 14 ported sections — no eval key, no ## eval text.
func TestEvalAbsentWithoutMatch(t *testing.T) {
	report, err := AuditCampaign(gateCampaign(t, "nothing-here", 0))
	if err != nil {
		t.Fatal(err)
	}
	if hasSection(report, "eval") {
		t.Fatal("report carries an eval section for an unmatched campaign")
	}
	if got := sectionNames(t, report); len(got) != 14 {
		t.Fatalf("sections = %v, want the 14 ported names", got)
	}
	if text := validation.DumpIndented(report); strings.Contains(text, "## eval") {
		t.Fatal("report text contains ## eval for an unmatched campaign")
	}
}

// TestEvalPresentWithMatch: a suite-matching campaign carries the eval
// section with the pinned lines, and the audit stays ok.
func TestEvalPresentWithMatch(t *testing.T) {
	report, err := AuditCampaign(gateCampaign(t, "ES03BankReentrancy", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !hasSection(report, "eval") {
		t.Fatal("report lacks the eval section for a matched campaign")
	}
	var sec validation.Value
	for _, kv := range objAt(report, "sections").O {
		if kv.K == "eval" {
			sec = kv.V
		}
	}
	var lines []string
	for _, l := range objAt(sec, "lines").A {
		lines = append(lines, l.S)
	}
	// The ingested hypothesis carries no risk/evidence fields, so it scores
	// 0.0 and lands in the single non-empty bucket [0,1) — anchored, hence
	// 1/1 — and nothing was retracted, so the fabrication ledger is absent.
	// J-perclass appends the per-class cell for the one matched class.
	want := []string{
		"## eval",
		"- suite: 1 gold cases matched (1 dev, 0 held-out)",
		"- recall: 1/1 (95% CI 20.7–100.0%)",
		"- precision: 1/1 (95% CI 20.7–100.0%)",
		"- false positives (unanchored live findings): 0",
		"- acceptance-band precision (gold-anchored / live findings in suite-matched programs):",
		"  - [0,1): 1/1 (95% CI 20.7–100.0%)",
		"- recall/precision by gold class (small cells — read the intervals, not the ratios):",
		"  - reentrancy: recall 1/1 (95% CI 20.7–100.0%), precision 1/1 (95% CI 20.7–100.0%)",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines = %q\nwant %q", lines, want)
	}
	if !reportOK(report) {
		t.Fatalf("matched eval section must not fail the audit: %v", sectionOKFlags(report))
	}
}
