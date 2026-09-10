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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"websec/assets"
	"websec/internal/findings"
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

// boundaryStages are the stages that get the boundary matrix.
var boundaryStages = map[string]bool{
	"discovery": true, "reproduction": true, "hostile-review": true,
	"independent-verification": true,
}

var stageRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// BoundaryMatrix is _boundary_matrix(): the trust boundary between the model
// and the deterministic core as a compact matrix.
func BoundaryMatrix() string {
	rows := [][3]string{
		{"evidence E0-E3", "may claim, with written reasoning",
			"stored after schema validation"},
		{"evidence E4+", "CANNOT claim — must name a real EXEC id from THIS campaign",
			"add_evidence() verifies profile, exit 0, captured output"},
		{"independent repro", "must be a DIFFERENT verifier + different exec",
			"mint_independent_evidence enforces it"},
		{"status transitions", "may propose via the API",
			"code enforces the state machine; illegal moves raise"},
		{"CONFIRMED floor", "no authority — floors are data, not opinion",
			"the gate uses the campaign effective floor (override or default)"},
		{"floor overrides", "CANNOT set",
			"operator-only: floors.set_floor_policy, actor+reason, logged"},
		{"bug classes", "use taxonomy.known_classes()",
			"unknown classes raise an intake advisory + default E5 floor"},
		{"discovery budget", "each ingest consumes a slot",
			"code enforces max_discovery_findings"},
		{"repro evidence mint", "propose tier + evidence_type",
			"mint validates the type and is idempotent (same exec -> same finding)"},
	}
	out := []string{"BOUNDARY MATRIX — trust boundary between you and the deterministic core.",
		"You may produce the left column; ONLY code performs the right column:"}
	for _, r := range rows {
		out = append(out, fmt.Sprintf("  %-22s | %-52s | %s", r[0], r[1], r[2]))
	}
	out = append(out, "An evidence claim that names no real EXEC id, or a status jump the")
	out = append(out, "state machine forbids, is rejected — never assumed true.")
	return strings.Join(out, "\n")
}

// RoutingConfig is ROUTING_CONFIG (REPO_ROOT/config/stage_routing.json).
func RoutingConfig() string {
	return filepath.Join(RepoRoot, "config", "stage_routing.json")
}

// routingOverride is _routing_override(): deployment overrides. A missing
// file is normal (defaults apply); malformed JSON is a loud error.
func routingOverride() (validation.Value, error) {
	p := RoutingConfig()
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return validation.VObj(), nil
		}
		return validation.VNull(), err
	}
	data, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("%s must contain a JSON object", p)
	}
	return data, nil
}

// StageConfig is stage_config(): effective (budget_class, prompt) after
// overrides.
func StageConfig(stage string) (budgetClass, prompt string, err error) {
	base := stagesByID[stage]
	if _, ok := stagesByID[stage]; !ok {
		base = Stage{ID: stage, BudgetClass: "standard"}
	}
	budgetClass, prompt = base.BudgetClass, base.Prompt
	ov, err := routingOverride()
	if err != nil {
		return "", "", err
	}
	entry := objAt(ov, stage)
	if entry.Kind != validation.Obj {
		return budgetClass, prompt, nil
	}
	if v := objAt(entry, "budget_class"); v.Kind == validation.Str {
		budgetClass = v.S
	}
	if v := objAt(entry, "prompt"); v.Kind == validation.Str {
		prompt = v.S
	} else if v := objAt(entry, "prompt"); v.Kind == validation.Null {
		prompt = ""
	}
	return budgetClass, prompt, nil
}

// LoadRouting is load_routing(): stage -> budget class, campaign-local
// routing.json winning over the global config, which wins over defaults.
// The returned object preserves Python's dict order.
func LoadRouting(c *state.Campaign) (validation.Value, error) {
	out := validation.VObj()
	seen := map[string]bool{}
	for _, s := range Stages {
		cls, _, err := StageConfig(s.ID)
		if err != nil {
			return validation.VNull(), err
		}
		out.O = append(out.O, validation.KV{K: s.ID, V: validation.VStr(cls)})
		seen[s.ID] = true
	}
	if c == nil {
		return out, nil
	}
	override := filepath.Join(c.Dir, "routing.json")
	raw, err := os.ReadFile(override)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return validation.VNull(), err
	}
	data, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("%s must contain a JSON object", override)
	}
	for _, kv := range data.O {
		val := kv.V
		if val.Kind == validation.Obj {
			val = objAt(val, "budget_class")
		}
		if val.Kind != validation.Null && val.Kind != validation.Str {
			return validation.VNull(), fmt.Errorf(
				"%s: budget class for %s must be a string", override,
				validation.PyReprStr(kv.K))
		}
		if seen[kv.K] {
			setObj(out, kv.K, val)
		} else {
			out.O = append(out.O, validation.KV{K: kv.K, V: val})
			seen[kv.K] = true
		}
	}
	return out, nil
}

// Route is route(): the budget class a stage routes to.
func Route(c *state.Campaign, stage string) (string, error) {
	if !stageRe.MatchString(stage) {
		return "", fmt.Errorf("bad stage id %s", validation.PyReprStr(stage))
	}
	if !KnownStage(stage) {
		return "", fmt.Errorf("unknown stage %s; known stages: %s",
			validation.PyReprStr(stage), strings.Join(StageIDs(), ", "))
	}
	routing, err := LoadRouting(c)
	if err != nil {
		return "", err
	}
	cls := objAt(routing, stage)
	if cls.Kind != validation.Str {
		return "", fmt.Errorf("stage %s routed to unknown budget class %s; "+
			"known: %s", validation.PyReprStr(stage), validation.PyRepr(cls),
			strings.Join(BudgetClassNames(), ", "))
	}
	if _, ok := BudgetHintOf(cls.S); !ok {
		return "", fmt.Errorf("stage %s routed to unknown budget class %s; "+
			"known: %s", validation.PyReprStr(stage), validation.PyRepr(cls),
			strings.Join(BudgetClassNames(), ", "))
	}
	return cls.S, nil
}

// RoutingTable is routing_table(): stage -> {budget_class, hint, prompt}.
func RoutingTable(c *state.Campaign) (validation.Value, error) {
	routing, err := LoadRouting(c)
	if err != nil {
		return validation.VNull(), err
	}
	out := validation.VObj()
	for _, kv := range routing.O {
		cls := kv.V.S
		_, prompt, err := StageConfig(kv.K)
		if err != nil {
			return validation.VNull(), err
		}
		hint, _ := BudgetHintOf(cls)
		out.O = append(out.O, validation.KV{K: kv.K, V: validation.VObj(
			validation.KV{K: "budget_class", V: validation.VStr(cls)},
			validation.KV{K: "hint", V: validation.VStr(hint)},
			validation.KV{K: "prompt", V: nullableStr(prompt)},
		)})
	}
	return out, nil
}

// promptFS maps the repo-relative prompt path onto the embedded pack.
func promptFS(rel string) (fs.FS, string, bool) {
	switch {
	case strings.HasPrefix(rel, "prompts_legacy/"):
		return assets.LegacyPromptsFS, "prompts_legacy/" +
			strings.TrimPrefix(rel, "prompts_legacy/"), true
	case strings.HasPrefix(rel, "prompts/"):
		return assets.PromptsFS, rel, true
	}
	return nil, "", false
}

// PromptText returns the embedded bytes of a repo-relative prompt path.
func PromptText(rel string) (string, error) {
	fsys, name, ok := promptFS(rel)
	if !ok {
		return "", fmt.Errorf("prompt file missing for stage prompt %s", rel)
	}
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", fmt.Errorf("prompt file missing: %s", rel)
	}
	return string(raw), nil
}

// PromptPath is resolve_prompt(): the on-disk path of a stage's prompt.
// Python resolves REPO_ROOT/<rel>; the Go port serves the embedded mirror and
// returns its on-disk path when present (the path the operator can read).
func PromptPath(stage string) (string, error) {
	_, rel, err := StageConfig(stage)
	if err != nil {
		return "", err
	}
	if rel == "" {
		if KnownStage(stage) {
			return "", fmt.Errorf("stage %s is deterministic — no prompt; "+
				"the code runs this stage", validation.PyReprStr(stage))
		}
		return "", fmt.Errorf("unknown stage %s; known stages: %s",
			validation.PyReprStr(stage), strings.Join(StageIDs(), ", "))
	}
	if _, err := PromptText(rel); err != nil {
		return "", fmt.Errorf("prompt file missing for stage %s: %s",
			validation.PyReprStr(stage), filepath.Join(RepoRoot, rel))
	}
	// Python resolves REPO_ROOT/<rel> because prompts/ sits at its repo root.
	// The Go repo keeps the pack under assets/ (go:embed cannot reach outside
	// the embedding package), so try the Python layout first — a tree that
	// mirrors it — then the embed mirror. Either way the returned path names
	// a file the operator can read.
	for _, disk := range []string{filepath.Join(RepoRoot, rel),
		filepath.Join(RepoRoot, "assets", rel)} {
		if _, err := os.Stat(disk); err == nil {
			if abs, err := filepath.Abs(disk); err == nil {
				return abs, nil
			}
			return disk, nil
		}
	}
	// No on-disk mirror (a deployed binary): the embedded prompt is the
	// source, so name it by its repo-relative path.
	return rel, nil
}

// PromptInventory is prompt_inventory(): stage -> resolved prompt path (Null
// for deterministic stages). Order follows STAGES.
func PromptInventory() (validation.Value, error) {
	out := validation.VObj()
	for _, s := range Stages {
		_, rel, err := StageConfig(s.ID)
		if err != nil {
			return validation.VNull(), err
		}
		if rel == "" {
			out.O = append(out.O, validation.KV{K: s.ID, V: validation.VNull()})
			continue
		}
		disk := filepath.Join(RepoRoot, rel)
		p := rel
		if _, err := os.Stat(disk); err == nil {
			if abs, err := filepath.Abs(disk); err == nil {
				p = abs
			}
		}
		out.O = append(out.O, validation.KV{K: s.ID, V: validation.VStr(p)})
	}
	return out, nil
}

// UnmappedPrompts is unmapped_prompts(): prompt files no stage routes to.
func UnmappedPrompts() ([]string, error) {
	mapped := map[string]bool{}
	inv, err := PromptInventory()
	if err != nil {
		return nil, err
	}
	for _, kv := range inv.O {
		if kv.V.Kind == validation.Str {
			mapped[filepath.Base(kv.V.S)] = true
		}
	}
	loose := []string{}
	for _, dir := range []struct {
		fsys fs.FS
		rel  string
	}{{assets.PromptsFS, "prompts"}, {assets.LegacyPromptsFS, "prompts_legacy"}} {
		entries, err := fs.ReadDir(dir.fsys, dir.rel)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			// README.md is pack metadata; 02_protocol_model.md is
			// intentionally orphaned by feedback-triage A4 — the
			// protocol-model stage now routes to the current
			// prompts/37 knowledge-graph prompt.
			if n == "README.md" || n == "02_protocol_model.md" ||
				mapped[n] {
				continue
			}
			loose = append(loose, dir.rel+"/"+n)
		}
	}
	return loose, nil
}

// structuredOutputs is the stable map of ingest functions a model must use.
func structuredOutputs() validation.Value {
	return validation.VObj(
		validation.KV{K: "hypotheses", V: validation.VStr("findings.ingest_hypothesis(campaign, payload, trajectory=...)")},
		validation.KV{K: "dedup_signatures", V: validation.VStr("dedup.set_root_cause_signature / set_economic_signature")},
		validation.KV{K: "drifts", V: validation.VStr("learning.record_drifts(campaign, snapshot_id, drifts)")},
		validation.KV{K: "memory", V: validation.VStr("learning.queue_memory(...)")},
		validation.KV{K: "evidence", V: validation.VStr("findings.add_evidence(campaign, finding_id, item)")},
		validation.KV{K: "critic_verdict", V: validation.VStr("findings.set_critic_verdict(campaign, finding_id, verdict, reasoning)")},
		validation.KV{K: "repro_attempt", V: validation.VStr("reproduction.record_attempt(campaign, finding_id, outcome, ...)")},
		validation.KV{K: "exploitability", V: validation.VStr("webv2 exploit <campaign> <finding> --paid --arg 'who pays, and why the bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable')")},
	)
}

// blockBuilder accumulates context blocks against a character budget; once
// the budget is spent further blocks are dropped (never truncated to empty).
type blockBuilder struct {
	budget int64
	blocks []validation.Value
}

// add appends one block, truncating its text to the remaining budget.
// The budget is counted in CHARACTERS, exactly like the reference
// (`text = text[:budget]; budget -= len(text)`), so a multi-byte rune
// straddling the boundary must not shorten the block (or drain extra budget).
func (b *blockBuilder) add(title, text string) {
	if b.budget <= 0 {
		return
	}
	runes := []rune(text)
	if int64(len(runes)) > b.budget {
		runes = runes[:b.budget]
	}
	b.budget -= int64(len(runes))
	text = string(runes)
	b.blocks = append(b.blocks, validation.VObj(
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "text", V: validation.VStr(text)}))
}

// BuildContext is build_context(): the bounded context bundle a stage needs.
func BuildContext(c *state.Campaign, stage string, maxChars int64,
	extraPaths []string) (validation.Value, error) {
	if maxChars == 0 {
		maxChars = 60000
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	bb := &blockBuilder{budget: maxChars}
	if err := gatherContextBlocks(c, st, stage, extraPaths, bb); err != nil {
		return validation.VNull(), err
	}
	promptPath, err := PromptPath(stage)
	if err != nil {
		return validation.VNull(), err
	}
	promptText, err := PromptText(mustRel(stage))
	if err != nil {
		return validation.VNull(), err
	}
	budgetClass, _, err := StageConfig(stage)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "stage", V: validation.VStr(stage)},
		validation.KV{K: "prompt_path", V: validation.VStr(promptPath)},
		validation.KV{K: "prompt", V: validation.VStr(promptText)},
		validation.KV{K: "budget_class", V: validation.VStr(budgetClass)},
		validation.KV{K: "blocks", V: validation.VArr(bb.blocks...)},
		validation.KV{K: "structured_outputs", V: structuredOutputs()},
	), nil
}

// addArtifactBlocks is the three artifact texts build_context injects, each
// capped, in order: protocol model, campaign plan, coverage.
func addArtifactBlocks(c *state.Campaign, bb *blockBuilder) error {
	for _, b := range []struct {
		title string
		file  string
		cap   int
	}{
		{"protocol_model", "protocol_model.json", 20000},
		{"campaign_plan", "campaign_plan.json", 8000},
		{"coverage", "coverage.json", 6000},
	} {
		text, err := readTextIfExists(filepath.Join(c.ArtifactsDir, b.file))
		if err != nil {
			return err
		}
		if text != nil {
			bb.add(b.title, truncate(*text, b.cap))
		}
	}
	return nil
}

// gatherContextBlocks fills the budget in build_context's order: the campaign
// header, the pinned snapshot, the structural index stats, the three artifact
// texts, the boundary matrix for boundary stages, the finding index, then the
// operator's extra paths.
func gatherContextBlocks(c *state.Campaign, st validation.Value, stage string,
	extraPaths []string, bb *blockBuilder) error {
	phase := objAt(st, "phase")
	program := objAt(st, "program")
	activeSnapshot := objAt(st, "active_snapshot_id")
	pass := objAt(objAt(st, "budget"), "pass")
	bb.add("campaign", fmt.Sprintf("campaign_id: %s\nprogram: %s\nphase: %s\n"+
		"active_snapshot: %s\npass: %s", c.CampaignID, scalarStr(program),
		scalarStr(phase), scalarStr(activeSnapshot), scalarStr(pass)))
	if sid := scalarStr(activeSnapshot); sid != "None" {
		snap := filepath.Join(c.Dir, "snapshots", sid, "snapshot.json")
		if text, err := readTextIfExists(snap); err != nil {
			return err
		} else if text != nil {
			bb.add("snapshot", truncate(*text, 4000))
		}
	}
	idx := filepath.Join(c.ArtifactsDir, "structural_index.json")
	if text, err := readTextIfExists(idx); err != nil {
		return err
	} else if text != nil {
		ix, err := validation.ParseOrdered([]byte(*text))
		if err != nil {
			return err
		}
		bb.add("structural_index_stats",
			validation.DumpsOrdered(objAt(ix, "stats"), true))
	}
	if err := addArtifactBlocks(c, bb); err != nil {
		return err
	}
	if boundaryStages[stage] {
		bb.add("boundary_matrix", BoundaryMatrix())
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return err
	}
	if len(all) > 0 {
		lines := []string{}
		for i, f := range all {
			if i >= 80 {
				break
			}
			lines = append(lines, findingIndexLine(f))
		}
		bb.add("finding_index", strings.Join(lines, "\n"))
	}
	for _, p := range extraPaths {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			continue
		}
		text, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		bb.add(filepath.Base(p), string(text))
	}
	return nil
}

// findingIndexLine is one finding_index JSON line (Python json.dumps).
func findingIndexLine(f validation.Value) string {
	levels := validation.VArr()
	for _, e := range objAt(f, "evidence").A {
		levels.A = append(levels.A, objAt(e, "level"))
	}
	line := validation.VObj(
		validation.KV{K: "finding_id", V: objAt(f, "finding_id")},
		validation.KV{K: "title", V: objAt(f, "title")},
		validation.KV{K: "status", V: objAt(f, "status")},
		validation.KV{K: "trajectory", V: objAt(f, "trajectory")},
		validation.KV{K: "bug_class", V: objAt(objAt(f, "root_cause"), "class")},
		validation.KV{K: "evidence_levels", V: levels},
	)
	return validation.DumpsOrdered(line, true)
}

// mustRel resolves a stage's prompt path, panicking only on a routing config
// that named a prompt for a deterministic/unknown stage (unreachable after
// PromptPath succeeded).
func mustRel(stage string) string {
	_, rel, err := StageConfig(stage)
	if err != nil || rel == "" {
		return ""
	}
	return rel
}

// truncate is Python's `s[:n]`: a CHARACTER slice (the reference caps block
// text with `[:cap]` before the budget clip).
func truncate(s string, n int) string {
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func readTextIfExists(path string) (*string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

func nullableStr(s string) validation.Value {
	if s == "" {
		return validation.VNull()
	}
	return validation.VStr(s)
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func setObj(v validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
}

// scalarStr renders a scalar the way Python's str() would inside an f-string.
func scalarStr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return ""
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
