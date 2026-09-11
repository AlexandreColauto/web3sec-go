package report

// Task 4 (G10 table rendering) report tests — the chain-assumptions block.
//
// TDD: written BEFORE the chainAssumptionsBlock hookup; must FAIL
// (undefined chainAssumptionsBlock) until report.go renders it.

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

// assumptionModel mirrors the briefing Task 4 fixture: one declared chain,
// one untouched-by-entry chain on a shared BRIDGES hop.
func assumptionModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("nn")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("chains", validation.VArr(
			validation.VStr("mainnet"), validation.VStr("arbitrum"))),
		kv("chain_assumptions", validation.VArr(validation.VObj(
			kv("chain", validation.VStr("mainnet")),
			kv("finality", validation.VStr("probabilistic")),
			kv("confirmation_depth", validation.VInt(12)),
			kv("messenger", validation.VStr("canonical")),
			kv("separator", validation.VStr("chainid")),
		))),
		kv("relations", validation.VArr(validation.VObj(
			kv("from", validation.VStr("mainnet-vault")),
			kv("rel", validation.VStr("BRIDGES")),
			kv("to", validation.VStr("arbitrum-inbox")),
		))),
	)
}

func legacyChainsModel() validation.Value {
	return validation.VObj(
		kv("protocol_id", validation.VStr("p")),
		kv("name", validation.VStr("nn")),
		kv("contracts", validation.VArr()),
		kv("actors", validation.VArr()),
		kv("assets", validation.VArr()),
		kv("chains", validation.VArr(validation.VStr("mainnet"))),
		kv("relations", validation.VArr()),
	)
}

func TestChainAssumptionsAbsentWithoutModel(t *testing.T) {
	camp := clusterCamp(t)
	if got := chainAssumptionsBlock(camp); len(got) != 0 {
		t.Fatalf("no model must render no block, got %q", got)
	}
	text := mustGenerate(t, camp)
	if strings.Contains(text, "Chain assumptions") ||
		strings.Contains(text, "ASSUMPTION GAP") {
		t.Fatal("assumptions block rendered without a model")
	}
}

func TestChainAssumptionsAbsentForLegacy(t *testing.T) {
	camp := clusterCamp(t)
	if _, err := protocolgraph.SaveModel(camp, legacyChainsModel(),
		filepath.Join(camp.ArtifactsDir, "protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	if got := chainAssumptionsBlock(camp); len(got) != 0 {
		t.Fatalf("legacy chains-only model must render no block, got %q", got)
	}
	text := mustGenerate(t, camp)
	if strings.Contains(text, "Chain assumptions") ||
		strings.Contains(text, "ASSUMPTION GAP") {
		t.Fatal("assumptions block rendered for a chains-only legacy model")
	}
}

func TestChainAssumptionsRendersRowsAndGap(t *testing.T) {
	camp := clusterCamp(t)
	if _, err := protocolgraph.SaveModel(camp, assumptionModel(),
		filepath.Join(camp.ArtifactsDir, "protocol_model.json")); err != nil {
		t.Fatal(err)
	}
	block := chainAssumptionsBlock(camp)
	if len(block) == 0 {
		t.Fatal("assumptions block missing with an assumed model")
	}
	joined := strings.Join(block, "\n")
	for _, want := range []string{
		"## Chain assumptions",
		"- mainnet: finality=probabilistic confirmations=12 messenger=canonical separator=chainid",
		"- arbitrum: finality=declared: none confirmations=declared: none messenger=declared: none separator=declared: none",
		"- ASSUMPTION GAP mainnet-vault->arbitrum-inbox arbitrum: missing-assumptions",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("block missing %q:\n%s", want, joined)
		}
	}
	text := mustGenerate(t, camp)
	for _, want := range []string{
		"- mainnet: finality=probabilistic confirmations=12 messenger=canonical separator=chainid",
		"- ASSUMPTION GAP mainnet-vault->arbitrum-inbox arbitrum: missing-assumptions",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated report missing %q", want)
		}
	}
}
