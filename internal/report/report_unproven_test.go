// IMPROVEMENTS B3 — report rendering for unproven (hypothesis-level) chains:
// their own section, their own count line, and never a CHAIN: heading or a
// row in the confirmed/submission surface. Presence-gated: a campaign with
// no unproven chain renders exactly as it did before B3.
package report

import (
	"strings"
	"testing"

	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

func uStrArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, it := range items {
		out = append(out, validation.VStr(it))
	}
	return validation.VArr(out...)
}

// uph ingests a HYPOTHESIS with the given capability surface (no evidence,
// so its evidence level is E0).
func uph(t *testing.T, camp *state.Campaign, title, class string,
	granted, required []string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(camp, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr(
				"the mechanism is described in detail")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/ShareVault.sol")),
			kv("contract", validation.VStr("ShareVault")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", uStrArr(granted)),
			kv("required", uStrArr(required)))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(f, "finding_id")
}

// unprovenCampaign is the B3 fixture: the two-member freeze chain at
// HYPOTHESIS, materialized with --unproven.
func unprovenCampaign(t *testing.T) (*state.Campaign, validation.Value, string) {
	t.Helper()
	camp := clusterCamp(t)
	f1 := uph(t, camp, "Pause gate reachable by arbitrary EOA",
		"access-control", []string{"control_protocol_pause"}, nil)
	f2 := uph(t, camp, "Pause with no timelock freezes withdrawals",
		"chain-freeze", []string{"liveness_loss"},
		[]string{"control_protocol_pause"})
	ch, err := chainengine.MaterializeChainOpts(camp, []string{f1, f2},
		"Freeze chain without a recovery path",
		"EOA pauses; nobody can unpause; every withdrawal stops", nil, nil,
		chainengine.MaterializeOpts{Unproven: true})
	if err != nil {
		t.Fatal(err)
	}
	return camp, ch, f1
}

// TestReportRendersUnprovenChainSection: the marked section, the count line,
// and no CHAIN heading / confirmation claim anywhere.
func TestReportRendersUnprovenChainSection(t *testing.T) {
	camp, ch, f1 := unprovenCampaign(t)
	gen := mustGenerate(t, camp)
	ids := strList(validation.ObjAt(ch, "members"))
	f2 := ids[1]
	if !strings.Contains(gen, "## Unproven chains (hypothesis-level)") {
		t.Fatalf("no unproven section:\n%s", gen)
	}
	for _, want := range []string{
		"### UNPROVEN CHAIN: Freeze chain without a recovery path",
		"- id: `" + validation.ObjStr(ch, "chain_id") +
			"` — provenance unproven, evidence floor E0",
		"- members: `" + f1 + "`, `" + f2 + "`",
		"- narrative: EOA pauses; nobody can unpause; every withdrawal stops",
		"- `" + f1 + "` grants *control_protocol_pause* → `" + f2 +
			"` requires it (from-member evidence E0)",
		"- terminal: *liveness_loss* via `" + f2 + "` — UNPROVEN",
		"- chains materialized: **0**",
		"- unproven chains (hypothesis-level): 1 — leads only, never counted " +
			"as confirmed",
	} {
		if !strings.Contains(gen, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// never in the submission surface: no CHAIN: heading, no confirmation
	// claim, and the chain id appears exactly once — in its own section.
	if strings.Contains(gen, "### CHAIN: Freeze chain") {
		t.Error("unproven chain rendered under a CHAIN: heading")
	}
	if n := strings.Count(gen, validation.ObjStr(ch, "chain_id")); n != 1 {
		t.Errorf("chain id appears %d times, want exactly once (its own "+
			"section)", n)
	}
	if !strings.Contains(gen, "- **confirmed: 0**") {
		t.Error("unproven chain changed the confirmed count")
	}
}

// TestReportUnprovenSectionPresenceGated: without an unproven chain the
// report is byte-identical to the pre-B3 shape (no section, no count line).
func TestReportUnprovenSectionPresenceGated(t *testing.T) {
	camp := clusterCamp(t)
	mk(t, camp, "gate1", "deposit", "A hypothesis with no chain")
	gen := mustGenerate(t, camp)
	if strings.Contains(gen, "Unproven chains") {
		t.Error("unproven section rendered without an unproven chain")
	}
	if strings.Contains(gen, "unproven chains (hypothesis-level)") {
		t.Error("unproven count line rendered without an unproven chain")
	}
	if !strings.Contains(gen, "- chains materialized: **0**") {
		t.Error("pre-B3 count line changed")
	}
}
