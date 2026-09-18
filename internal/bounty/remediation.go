// The REMEDIATION catalog and `gate explain`: every failing check names
// the exact command that clears it.

package bounty

import (
	"fmt"
	"sort"

	"websec/internal/validation"
)

// BountyRemediation is BOUNTY_REMEDIATION: every failing bounty gate check
// carries a REMEDIATION — the exact command that clears it. `webv2 gate
// explain <check>` shows these without a run; the gate itself renders the
// <campaign> entries with the campaign in hand (findings.NameCampaign), so a
// printed fix line names the campaign.
var BountyRemediation = map[string]string{
	"security-confirmed":   "webv2 verdict <campaign> <fid> --verdict confirmed --reason '<reasoning>' + webv2 recall <campaign> --finding <fid> + webv2 mint <fid> --exec <EXEC>  (see `webv2 gate explain` for the full CONFIRMED checklist)",
	"snapshot-pinned":      "webv2 snap   (re-pin, then re-run the gate)",
	"in-scope":             "re-check the target against the program scope; if it is a different component, re-aim the hypothesis",
	"known-issue-check":    "read the matched exclusion on the program page \u2014 if it truly does not apply, record the reasoning in the report; if it does, drop the finding (webv2 status <fid> OUT_OF_SCOPE ...)",
	"severity-floor":       "quantify the impact (economic_impact) so a severity rule matches, or read the program's terms for the band",
	"evidence-sufficient":  "webv2 mint <fid> --exec <EXEC>   (reproduce at the required tier)",
	"fork-repro":           "webv2 mint <fid> --exec <EXEC>   (a T3/T4 fork reproduction)",
	"economic-quantified":  "set economic_impact.extractable_usd from a MEASURED PoC run, priced against the campaign price table (webv2 price set ...)",
	"maximal-exploitation": "webv2 ladder start <fid> ... webv2 ladder complete <fid>   (or: webv2 ladder waive <fid> --reason '...' \u2014 the named escape hatch)",
	"e7-price-basis":       "webv2 price set <asset> <usd> --source '<where the price came from>' then webv2 price-basis <fid> <PRICE-ID>   (USD figures must name their price row \u2014 no unattributed $)",
	"claim-drift":          "make the claim and the measurement agree: fix the title, or re-run the PoC and re-measure extraction_ratio",
	"precondition-audit":   "webv2 ladder add <fid> ... --removes '<precondition>' then webv2 ladder repro <fid> <rung> --exec <EXEC>   (or: webv2 shield the precondition as code-enforced if the PoC assumption was wrong)",
	"mainnet-fork-poc":     "webv2 exec <campaign> --profile fork-runner --command 'forge test --fork-url <pinned-rpc> --fork-block-number <pin> --match-test test_exploit' --finding <fid>   then webv2 mint <fid> --exec <EXEC-ID> --type fork-test   (unit tests prove semantics; only the fork proves mainnet)",
	"immunization":         "webv2 immunize <fid> --poc-exec <FORK-EXEC-ID> --patch '<the fix>' --mutations 'm1;m2;m3'   (the patch must block the FORK PoC and all 3 boundary mutations \u2014 a unit-test patch is not a patch; if a bypass is real, fix the patch and re-verify)",
	"accepted-risk":        "the program documented this as an accepted risk \u2014 not a payable vulnerability as written. If this particular finding IS payable despite the acceptance, record the decision: webv2 waive <campaign> accepted-risk --subject <fid> --reason 'why this one is payable' --actor <who>   (or: drop the finding \u2014 webv2 status <fid> OUT_OF_SCOPE \u2014 if it is genuinely the accepted behavior)",
	"paid-exploitability":  "webv2 exploit <campaign> <fid> --paid --arg 'who pays, and why this bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable' \u2014 a reasoned not-payable decision is a legitimate answer; or: webv2 waive <campaign> paid-exploitability --subject <fid> --reason '...' to record a named decision)",
	"adversarial-game":     "webv2 adversarial-game <campaign> <fid> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (each field >= 20 chars; or: webv2 waive <campaign> adversarial-game --subject <fid> --reason '...' if the incentive argument lives elsewhere, e.g. the chain narrative)",
}

// GateExplain is gate_explain: human-facing explanation + remediation for one
// check id — the `webv2 gate explain` backend. Covers both the CONFIRMED gate
// (findings) and the bounty gate; an unknown id is a loud KeyError, not a
// guess.
func GateExplain(checkID string) (validation.Value, error) {
	if rem, ok := confirmedRemediation[checkID]; ok {
		return validation.VObj(
			validation.KV{K: "check", V: validation.VStr(checkID)},
			validation.KV{K: "gate", V: validation.VStr("confirmed")},
			validation.KV{K: "remediation", V: validation.VStr(rem)},
		), nil
	}
	if rem, ok := BountyRemediation[checkID]; ok {
		return validation.VObj(
			validation.KV{K: "check", V: validation.VStr(checkID)},
			validation.KV{K: "gate", V: validation.VStr("bounty")},
			validation.KV{K: "remediation", V: validation.VStr(rem)},
		), nil
	}
	known := make([]string, 0, len(confirmedRemediation)+len(BountyRemediation))
	for k := range confirmedRemediation {
		known = append(known, k)
	}
	for k := range BountyRemediation {
		known = append(known, k)
	}
	sort.Strings(known)
	// dedupe: the two maps can share a check id (claim-drift is in both).
	var uniq []string
	for i, k := range known {
		if i == 0 || known[i-1] != k {
			uniq = append(uniq, k)
		}
	}
	msg := fmt.Sprintf("unknown check id %s (known: %s)",
		validation.PyReprStr(checkID), validation.PyListRepr(uniq))
	return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(msg))
}
