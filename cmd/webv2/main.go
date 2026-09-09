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
	"websec/internal/costs"
	"websec/internal/dedup"
	"websec/internal/envgo"
	"websec/internal/findings"
	"websec/internal/forkdiff"
	"websec/internal/forkpoc"
	"websec/internal/histmining"
	"websec/internal/invariants"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/reproduction"
	"websec/internal/sandbox"
	"websec/internal/sequencepoc"
	"websec/internal/structidx"
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
	// T26 seams: env (D17), costs, and the structural index that
	// histmining's recency scores read. Same targets as cli.ensureSeams,
	// which the command handlers call for in-process callers.
	sandbox.SetClassifyFailure(envgo.ClassifyFailure)
	sandbox.SetSandboxPreflight(envgo.SandboxPreflight)
	sandbox.SetDockerImageProbe(envgo.DockerImageProbe)
	pipeline.SetCosts(costs.API{})
	structidx.Wire()
	histmining.SetIndexAPI(histmining.IndexAPI{
		EnsureFreshIndex: structidx.EnsureFreshIndex,
		SinkFunctions:    structidx.SinkFunctions,
	})
	forkdiff.Wire()
	// T28 seams: learning (D18 memory queue), relations, shared_memory.
	cli.WireT28Seams()
	// T33 seams: eval_store (trajectory/metrics case_partition, corpus
	// class_inventory).
	cli.WireT33Seams()
	// T34 seam: the DeFiHackLabs record loader (corpus_surface attribution
	// + the WEBV2_POC_ROOT root patch).
	cli.WireT34Seams()
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
	// Same hook for cost ids (costs.record_cost mints a RAW uuid4 too):
	// WEBV2_COST_IDS=pin + WEBV2_COST_ID_SEQ draws the identical
	// sha256("<seed>:fid:<n>")[:12] stream the Python shim patches into
	// uuid.uuid4, so costs.jsonl compares byte-for-byte across twins.
	if os.Getenv("WEBV2_COST_IDS") == "pin" {
		base, _ := strconv.Atoi(os.Getenv("WEBV2_COST_ID_SEQ"))
		draw := 0
		seed := os.Getenv("WEBV2_UUID")
		costs.SetCostIDSource(func() string {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s:fid:%d", seed, base+draw)))
			draw++
			return "COST-" + hex.EncodeToString(sum[:])[:12]
		})
	}
	// Same seam for the baseline store: the reference hangs it off its own
	// package root (read-only for this port, D24) while the Go twin uses
	// cwd/baselines. The golden harness pins both at one scratch dir so
	// baseline add/list/remove/forkdiff compare cross-twin without
	// mutating either repo. Unset: cwd/baselines, no behavior change.
	if dir := os.Getenv("WEBV2_BASELINES_DIR"); dir != "" {
		forkdiff.SetBaselinesDir(dir)
	}
}

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
