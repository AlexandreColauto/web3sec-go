// Package adapter is the port of webv2/adapter.py — model routing + context
// adapter: the ONLY boundary between the deterministic core and the LLM pack.
//
// One table, two jobs. Stages maps every stage id to (budget class, prompt
// file); there is exactly one place that says what a stage is, so a stage can
// never be routable-but-promptless. build_context() bundles exactly the
// artifacts a stage needs — referenced by id, bounded by a character budget —
// and returns the prompt text to run. This module NEVER calls a model.
package adapter

import (
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// RepoRoot is REPO_ROOT: the tree config/ and the prompt dirs hang off.
// Python resolves it from __file__; a Go binary has no repo, so the prompts
// are embedded (assets.PromptsFS) and this root only locates the optional
// deployment config and the on-disk prompt mirror used for prompt_path.
var RepoRoot = "."

// PromptsDir / LegacyPromptsDir are the on-disk mirrors of the embedded pack.
var (
	PromptsDir       = filepath.Join(RepoRoot, "assets", "prompts")
	LegacyPromptsDir = filepath.Join(RepoRoot, "assets", "prompts_legacy")
)

// SetRepoRoot repoints REPO_ROOT and the derived prompt dirs.
func SetRepoRoot(root string) {
	RepoRoot = root
	PromptsDir = filepath.Join(root, "assets", "prompts")
	LegacyPromptsDir = filepath.Join(root, "assets", "prompts_legacy")
}

func init() {
	if wd, err := os.Getwd(); err == nil {
		SetRepoRoot(wd)
	}
}

// BudgetHints is BUDGET_HINTS: the budget-class vocabulary (declaration order).
var BudgetHints = []struct{ Class, Hint string }{
	{"deterministic", "no model — code runs this stage"},
	{"cheap", "local small model fine (extraction, normalization, formatting)"},
	{"standard", "mid-tier model (specialist sweeps, PoC drafting)"},
	{"expensive", "frontier model (economic reasoning, hostile review, chaining)"},
}

// BudgetHintOf returns the hint for a class, or "" when unknown.
func BudgetHintOf(class string) (string, bool) {
	for _, h := range BudgetHints {
		if h.Class == class {
			return h.Hint, true
		}
	}
	return "", false
}

// BudgetClassNames is sorted(BUDGET_HINTS) — the error-message order.
func BudgetClassNames() []string {
	out := make([]string, 0, len(BudgetHints))
	for _, h := range BudgetHints {
		out = append(out, h.Class)
	}
	sort.Strings(out)
	return out
}

// Stage is one row of STAGES: (budget class, prompt path or "").
type Stage struct {
	ID          string
	BudgetClass string
	Prompt      string // repo-relative, "" for deterministic stages
}

// Stages is STAGES in declaration order (the order prompt_inventory,
// load_routing and routing_table emit).
var Stages = []Stage{
	{"scope", "deterministic", ""},
	{"snapshot", "deterministic", ""},
	{"structural-index", "deterministic", ""},
	{"bounty-gate", "deterministic", ""},
	{"coverage-accounting", "deterministic", ""},

	{"protocol-reconstruction", "standard", "prompts_legacy/01_protocol_reconstruction.md"},
	// feedback-triage A4: the campaign's protocol-model bootstrap runs the
	// current knowledge-graph prompt (prompts/37); the legacy 02 prompt was
	// the pre-knowledge-graph draft. Intentional divergence from the
	// reference (KNOWN_DIVERGENCES).
	{"protocol-model", "standard", "prompts/37_protocol_knowledge_graph.md"},
	{"protocol-knowledge-graph", "standard", "prompts/37_protocol_knowledge_graph.md"},
	{"invariant-generation", "standard", "prompts_legacy/04_invariant_generation.md"},
	{"economics-model", "expensive", "prompts_legacy/05_accounting_economic_audit.md"},

	{"campaign-planning", "expensive", "prompts/38_campaign_planning.md"},
	{"trajectory-dispatch", "standard", "prompts/39_trajectory_dispatch.md"},

	{"discovery-specialist", "standard", "prompts/39_trajectory_dispatch.md"},
	{"discovery-accounting", "standard", "prompts_legacy/05_accounting_economic_audit.md"},
	{"discovery-access-control", "standard", "prompts_legacy/06_access_control_audit.md"},
	{"discovery-oracle", "standard", "prompts_legacy/07_oracle_pricing_audit.md"},
	{"discovery-upgradeability", "standard", "prompts_legacy/08_upgradeability_initialization_audit.md"},
	{"discovery-cross-contract", "standard", "prompts_legacy/09_cross_contract_audit.md"},
	{"discovery-token", "standard", "prompts_legacy/10_token_behavior_audit.md"},
	{"discovery-math", "standard", "prompts_legacy/11_share_asset_decimal_math_audit.md"},
	{"discovery-reentrancy", "standard", "prompts_legacy/12_reentrancy_callbacks_audit.md"},
	{"discovery-signature", "standard", "prompts_legacy/13_signature_replay_authorization_audit.md"},
	{"discovery-liquidation", "standard", "prompts_legacy/14_liquidation_state_machine_audit.md"},
	{"discovery-flash-loan", "expensive", "prompts_legacy/15_flash_loan_manipulation_audit.md"},
	{"discovery-dos", "cheap", "prompts_legacy/16_dos_griefing_audit.md"},
	{"deployment-vs-source", "standard", "prompts/40_deployment_vs_source.md"},
	{"drift-analysis", "standard", "prompts/40_deployment_vs_source.md"},

	{"hypothesis-triage", "cheap", "prompts_legacy/17_hypothesis_triage.md"},
	{"dedup-normalization", "cheap", "prompts/33_tiered_dedup.md"},
	{"tiered-dedup", "cheap", "prompts/33_tiered_dedup.md"},
	{"findings-state", "cheap", "prompts/32_findings_state_discipline.md"},

	{"poc-generation", "standard", "prompts_legacy/18_foundry_poc_generation.md"},
	{"fuzzing-targeted", "standard", "prompts_legacy/19_targeted_fuzzing.md"},
	{"fuzzing-sequence", "standard", "prompts_legacy/20_sequence_fuzzing.md"},
	{"symbolic-validation", "expensive", "prompts_legacy/21_symbolic_validation.md"},
	{"adversarial-critic", "expensive", "prompts_legacy/22_adversarial_critic.md"},
	{"independent-reproduction", "expensive", "prompts_legacy/23_independent_reproduction.md"},
	{"maximal-exploitation", "expensive", "prompts/44_maximal_exploitation.md"},
	{"independent-verification", "expensive", "prompts/45_independent_verification.md"},
	{"mainnet-fork-poc", "expensive", "prompts/46_mainnet_fork_poc.md"},
	{"finding-gate", "expensive", "prompts_legacy/24_final_finding_gate.md"},
	{"tiered-reproduction", "standard", "prompts/41_tiered_reproduction.md"},
	{"sandbox-isolation", "cheap", "prompts/36_sandbox_isolation.md"},

	{"exploit-chaining", "expensive", "prompts/35_exploit_chaining.md"},
	{"risk-calibration", "cheap", "prompts/34_risk_calibration.md"},

	{"report-generation", "cheap", "prompts/43_report_and_submission.md"},
	{"report-submission", "cheap", "prompts/43_report_and_submission.md"},
	{"history-mining", "cheap", "prompts/31_history_and_audit_mining.md"},
	{"regression-test", "cheap", "prompts_legacy/26_regression_test.md"},
	{"memory-promotion", "cheap", "prompts_legacy/27_memory_promotion.md"},
	{"detector-extraction", "standard", "prompts_legacy/28_detector_extraction.md"},
	{"benchmark", "cheap", "prompts_legacy/29_benchmark.md"},
	{"audit-cycle", "cheap", "prompts_legacy/30_audit_cycle_and_memory.md"},
	{"reflection", "cheap", "prompts/42_learning_memory_reflection.md"},
	{"learning-reflection", "cheap", "prompts/42_learning_memory_reflection.md"},

	{"model-proposer", "standard", "prompts/47_proposer_system.md"},
	{"model-critic", "expensive", "prompts/48_critic_system.md"},
	{"model-reproducer", "standard", "prompts/49_reproducer_system.md"},

	{"simulation-mode", "standard", "prompts/50_adversarial_simulation.md"},
}

// stagesByID is the STAGES lookup (Python's dict membership).
var stagesByID = func() map[string]Stage {
	m := make(map[string]Stage, len(Stages))
	for _, s := range Stages {
		m[s.ID] = s
	}
	return m
}()

// StageIDs is sorted(STAGES).
func StageIDs() []string {
	out := make([]string, 0, len(Stages))
	for _, s := range Stages {
		out = append(out, s.ID)
	}
	sort.Strings(out)
	return out
}

// KnownStage reports STAGES membership.
func KnownStage(stage string) bool {
	_, ok := stagesByID[stage]
	return ok
}

// PipelineAdapter is the pipeline.AdapterAPI implementation: pipeline calls
// adapter.build_context(c, stage, extra_paths) with max_chars at its default
// (60000). cmd_run installs it with pipeline.SetAdapter before running.
type PipelineAdapter struct{}

// BuildContext is the two-argument seam (pipeline's AdapterAPI).
func (PipelineAdapter) BuildContext(c *state.Campaign, stage string,
	extraPaths []string) (validation.Value, error) {
	return BuildContext(c, stage, 0, extraPaths)
}
