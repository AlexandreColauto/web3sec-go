// Command webv2 is the P1 trust-core CLI: init/status/snap/log/audit/
// verify over filesystem-backed campaigns. All output flows through the
// cli Runner's writers; main only maps the exit code and wires the
// cross-module seams (Python's import-time connections, in one place).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"websec/internal/cli"
	"websec/internal/dedup"
	"websec/internal/findings"
	"websec/internal/forkpoc"
	"websec/internal/invariants"
	"websec/internal/orchestrator"
	"websec/internal/reproduction"
	"websec/internal/sequencepoc"
	"websec/internal/taxonomy"
	// init() side effects: taxonomy wires findings.SetClassAdvisory,
	// floors wires findings.SetEffectiveFloor (Python import-time seams),
	// completion wires pipeline.SetCompletion + bounty.SetWaivers — without
	// this import the scheduler would silently auto-complete nothing and the
	// bounty gate would never see a stage waiver. immunize wires the T21
	// seams (bounty.SetForkPocStatus/SetImmunizationDetail,
	// completion.SetForkPocEvidence); cli already imports it, the blank
	// import keeps the wiring visible in this one place.
	_ "websec/internal/completion"
	_ "websec/internal/floors"
	_ "websec/internal/immunize"
)

func init() {
	// dedup -> findings duplicate helpers (Python: dedup imports findings).
	dedup.SetMarkDuplicate(findings.MarkDuplicate)
	dedup.SetFlagPossibleDuplicate(findings.FlagPossibleDuplicate)
	dedup.SetFoldIntoLineage(findings.FoldIntoLineage)
	// taxonomy -> dedup compat-class tables (Python: _compat_classes()
	// reads dedup._ECONOMIC_COMPAT_GROUPS and dedup._ASSET_CLASS_HINTS).
	taxonomy.SetCompatClasses(func() []string {
		out := []string{}
		for _, g := range dedup.EconomicCompatGroups {
			out = append(out, g...)
		}
		for _, names := range dedup.AssetClassHints {
			out = append(out, names...)
		}
		return out
	})
	// invariants 2.1 guardrail (Python: _assert_invariants_verified).
	findings.SetInvariantGuard(invariants.AssertInvariantsVerified)
	// reproduction -> findings/orchestrator (Python: import-time module
	// access). Without this the tier ladder is invisible to the gate and E6
	// minting is the absent-module refusal.
	findings.SetReproductionTierOrder(func() []string {
		return reproduction.TierOrder
	})
	orchestrator.SetReproduction(orchestrator.ReproductionAPI{
		TierOf:                  reproduction.TierOf,
		NextTier:                reproduction.NextTier,
		MintIndependentEvidence: reproduction.MintIndependentEvidence,
	})
	// sequence_poc -> findings/forkpoc/orchestrator (Python: import-time
	// module access). Without this the sequence gate is fail-open on the
	// CONFIRMED path and the queue never flags a multi-tx finding.
	findings.SetOnchainSequenceRequired(sequencepoc.OnchainSequenceRequired)
	findings.SetVerifySequenceCoverage(sequencepoc.VerifySequenceCoverage)
	forkpoc.SetOnchainSequenceRequired(sequencepoc.OnchainSequenceRequired)
	forkpoc.SetVerifySequenceCoverage(sequencepoc.VerifySequenceCoverage)
	orchestrator.SetSequencePOC(orchestrator.SequencePOCAPI{
		IsSequenceRequired: sequencepoc.IsSequenceRequired,
	})
	// Golden-suite hook: Python's findings.new_finding_id mints a RAW
	// uuid4, so the WEBV2_UUID pin never reaches it and the reference twin
	// emits a fresh finding id per run. The cross-twin golden harness sets
	// WEBV2_FINDING_IDS=pin plus WEBV2_FINDING_ID_SEQ (the running count of
	// finding ids the recipe has minted, since each CLI command is a fresh
	// process) and patches the identical minter into Python via
	// scripts/golden/sitecustomize.py: sha256("<seed>:fid:<n>")[:12].
	// Unset: plain uuid4, no behavior change.
	if os.Getenv("WEBV2_FINDING_IDS") == "pin" {
		base, _ := strconv.Atoi(os.Getenv("WEBV2_FINDING_ID_SEQ"))
		draw := 0
		seed := os.Getenv("WEBV2_UUID")
		findings.SetFindingIDSource(func() string {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s:fid:%d", seed, base+draw)))
			draw++
			return "F-" + hex.EncodeToString(sum[:])[:12]
		})
	}
}

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
