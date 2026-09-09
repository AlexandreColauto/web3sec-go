// Package routing is the port of webv2/routing.py — assumption-driven
// next-action routing (§4.3 of the plan).
//
// After each loop step the framework — never the model — deterministically
// ranks what to do next: which blocking, still-unresolved assumption to check,
// and with which registry tool. This is DISTINCT from the stage-budget routing
// in adapter.py (which model/budget per stage): this module routes *evidence
// work* inside one finding, the adapter routes *model spend* across stages.
//
// Policy-as-data: the weights, per-tool evidence tiers, and per-tool costs
// live in JSON (config/assumption_routing.json, overridable per campaign), not
// in code. Scoring is deterministic: a stable sort with an
// assumption_id/tool_id tiebreak, no wall clock, no randomness — the same
// finding and policy always yield the same ranking.
package routing

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/adapter"
	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/playbooks"
	"websec/internal/state"
	"websec/internal/validation"
)

// WeightKeys is WEIGHT_KEYS.
var WeightKeys = []string{"dependency_impact", "evidence_value", "cost",
	"gate_value"}

// CostRank is COST_RANK: the budget-class enum to numeric penalty.
// "deterministic" (no model spend — code runs it) costs nothing, like "cheap".
var CostRank = map[string]float64{"deterministic": 0, "cheap": 0,
	"standard": 1, "expensive": 2}

// Unresolved is UNRESOLVED: statuses that still need work. The assumption
// schema only admits UNKNOWN/SUPPORTED/REFUTED, but UNVERIFIED appears in
// older/proposer-side payloads — routing treats it as unresolved rather than
// crashing on it.
var Unresolved = []string{"UNKNOWN", "UNVERIFIED"}

// PolicyConfig is POLICY_CONFIG (REPO_ROOT/config/assumption_routing.json).
func PolicyConfig() string {
	return filepath.Join(adapter.RepoRoot, "config", "assumption_routing.json")
}

// DefaultPolicy is DEFAULT_POLICY, matching
// config/assumption_routing.example.json. Every tool id in the registry
// appears in BOTH maps (a missing id is a config error, caught by
// ValidatePolicy).
func DefaultPolicy() validation.Value {
	return validation.VObj(
		validation.KV{K: "weights", V: validation.VObj(
			validation.KV{K: "dependency_impact", V: validation.VFloat(1.0)},
			validation.KV{K: "evidence_value", V: validation.VFloat(1.0)},
			validation.KV{K: "cost", V: validation.VFloat(0.5)},
			validation.KV{K: "gate_value", V: validation.VFloat(1.5)})},
		validation.KV{K: "tool_evidence_tier", V: validation.VObj(
			validation.KV{K: "callgraph", V: validation.VInt(1)},
			validation.KV{K: "source-slice", V: validation.VInt(1)},
			validation.KV{K: "static-analysis", V: validation.VInt(1)},
			validation.KV{K: "capability-coverage", V: validation.VInt(1)},
			validation.KV{K: "resemble", V: validation.VInt(1)},
			validation.KV{K: "host-readonly", V: validation.VInt(1)},
			validation.KV{K: "invariant-check", V: validation.VInt(2)},
			validation.KV{K: "fuzzing", V: validation.VInt(2)},
			validation.KV{K: "docker-networkless", V: validation.VInt(2)},
			validation.KV{K: "docker-gvisor", V: validation.VInt(2)},
			validation.KV{K: "vm-snapshot", V: validation.VInt(3)},
			validation.KV{K: "symbolic", V: validation.VInt(3)},
			validation.KV{K: "fork", V: validation.VInt(4)},
			validation.KV{K: "fork-runner", V: validation.VInt(4)},
			validation.KV{K: "trace", V: validation.VInt(4)},
			validation.KV{K: "balance-delta", V: validation.VInt(4)})},
		validation.KV{K: "tool_cost", V: validation.VObj(
			validation.KV{K: "callgraph", V: validation.VStr("cheap")},
			validation.KV{K: "source-slice", V: validation.VStr("cheap")},
			validation.KV{K: "static-analysis", V: validation.VStr("standard")},
			validation.KV{K: "capability-coverage", V: validation.VStr("cheap")},
			validation.KV{K: "resemble", V: validation.VStr("cheap")},
			validation.KV{K: "host-readonly", V: validation.VStr("cheap")},
			validation.KV{K: "invariant-check", V: validation.VStr("standard")},
			validation.KV{K: "fuzzing", V: validation.VStr("standard")},
			validation.KV{K: "docker-networkless", V: validation.VStr("standard")},
			validation.KV{K: "docker-gvisor", V: validation.VStr("standard")},
			validation.KV{K: "vm-snapshot", V: validation.VStr("standard")},
			validation.KV{K: "symbolic", V: validation.VStr("expensive")},
			validation.KV{K: "fork", V: validation.VStr("standard")},
			validation.KV{K: "fork-runner", V: validation.VStr("standard")},
			validation.KV{K: "trace", V: validation.VStr("standard")},
			validation.KV{K: "balance-delta", V: validation.VStr("standard")})})
}

// registry is _registry(): every tool id the policy must cover. The brief
// names this findings.tool_registry(), but the registry lives in
// model_boundary (sandbox execution profiles + the analysis-tool vocabulary).
func registry() []string { return boundary.ToolRegistry() }

func registrySet() map[string]bool {
	set := map[string]bool{}
	for _, t := range registry() {
		set[t] = true
	}
	return set
}

// ValidatePolicy is _validate_policy: fail loud on any malformed policy.
func ValidatePolicy(policy validation.Value, source string) error {
	if policy.Kind != validation.Obj {
		return fmt.Errorf("%s: policy must be a JSON object", source)
	}
	weights := objAt(policy, "weights")
	if weights.Kind != validation.Obj {
		return fmt.Errorf("%s: 'weights' must be an object", source)
	}
	if err := validatePolicyWeights(weights, source); err != nil {
		return err
	}
	return validatePolicyToolMaps(policy, source)
}

// validatePolicyWeights is the weights half: every declared key present, no
// unknown keys, every value numeric.
func validatePolicyWeights(weights validation.Value, source string) error {
	missing := []string{}
	for _, k := range WeightKeys {
		if objAt(weights, k).Kind == validation.Null {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s: weights missing keys %s (need all of %s)",
			source, pyListRepr(missing), pyListRepr(WeightKeys))
	}
	extra := []string{}
	for _, kv := range weights.O {
		if !contains(WeightKeys, kv.K) {
			extra = append(extra, kv.K)
		}
	}
	if len(extra) > 0 {
		return fmt.Errorf("%s: unknown weight keys %s (known: %s)", source,
			pyListRepr(extra), pyListRepr(WeightKeys))
	}
	for _, kv := range weights.O {
		if kv.V.Kind != validation.Int && kv.V.Kind != validation.Flt {
			return fmt.Errorf("%s: weight %s must be numeric, got %s", source,
				validation.PyReprStr(kv.K), pyRepr(kv.V))
		}
	}
	return nil
}

// validatePolicyToolMaps is the tool half: both maps present, every registry
// tool covered, no unknown ids, tiers 1-4, costs a declared budget class.
func validatePolicyToolMaps(policy validation.Value, source string) error {
	reg := registrySet()
	tiers := objAt(policy, "tool_evidence_tier")
	costs := objAt(policy, "tool_cost")
	if tiers.Kind != validation.Obj {
		return fmt.Errorf("%s: 'tool_evidence_tier' must be an object", source)
	}
	if costs.Kind != validation.Obj {
		return fmt.Errorf("%s: 'tool_cost' must be an object", source)
	}
	regSorted := registry()
	sort.Strings(regSorted)
	for _, tool := range regSorted {
		if objAt(tiers, tool).Kind == validation.Null {
			return fmt.Errorf("%s: tool_evidence_tier missing tool id %s",
				source, validation.PyReprStr(tool))
		}
		if objAt(costs, tool).Kind == validation.Null {
			return fmt.Errorf("%s: tool_cost missing tool id %s", source,
				validation.PyReprStr(tool))
		}
	}
	for _, tool := range sortedKeysNotIn(tiers, reg) {
		return fmt.Errorf("%s: tool_evidence_tier names unknown tool id %s "+
			"(not in the tool registry)", source, validation.PyReprStr(tool))
	}
	for _, tool := range sortedKeysNotIn(costs, reg) {
		return fmt.Errorf("%s: tool_cost names unknown tool id %s (not in "+
			"the tool registry)", source, validation.PyReprStr(tool))
	}
	for _, kv := range tiers.O {
		if kv.V.Kind != validation.Int || kv.V.I < 1 || kv.V.I > 4 ||
			kv.V.Big != "" {
			return fmt.Errorf("%s: tier for tool %s must be an integer 1-4, "+
				"got %s", source, validation.PyReprStr(kv.K), pyRepr(kv.V))
		}
	}
	for _, kv := range costs.O {
		c := kv.V
		if c.Kind != validation.Str {
			return fmt.Errorf("%s: cost for tool %s must be one of %s, got %s",
				source, validation.PyReprStr(kv.K),
				pyListRepr(adapter.BudgetClassNames()), pyRepr(c))
		}
		if _, ok := adapter.BudgetHintOf(c.S); !ok {
			return fmt.Errorf("%s: cost for tool %s must be one of %s, got %s",
				source, validation.PyReprStr(kv.K),
				pyListRepr(adapter.BudgetClassNames()), pyRepr(c))
		}
	}
	return nil
}

// LoadPolicy is load_policy: hardcoded defaults <- the global
// config/assumption_routing.json (when present) <- campaign.dir/
// assumption_routing.json (wins).
func LoadPolicy(campaign *state.Campaign) (validation.Value, error) {
	policy := DefaultPolicy()
	type layer struct{ path string }
	layers := []string{PolicyConfig()}
	campaignPolicy := ""
	if campaign != nil {
		campaignPolicy = filepath.Join(campaign.Dir, "assumption_routing.json")
		layers = append(layers, campaignPolicy)
	}
	for _, path := range layers {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return validation.VNull(), err
		}
		data, err := validation.ParseOrdered(raw)
		if err != nil {
			return validation.VNull(), fmt.Errorf("%s: not valid JSON: %v",
				path, err)
		}
		if data.Kind != validation.Obj {
			return validation.VNull(), fmt.Errorf("%s must contain a JSON object",
				path)
		}
		policy, err = applyPolicyLayer(policy, path, data)
		if err != nil {
			return validation.VNull(), err
		}
	}
	source := policySourceName(campaignPolicy)
	if err := ValidatePolicy(policy, source); err != nil {
		return validation.VNull(), err
	}
	return policy, nil
}

// applyPolicyLayer merges one policy layer: weights merge key-by-key, tool
// maps replace wholesale (a layer that names a map owns it, so a dropped tool
// id fails loud in ValidatePolicy). Unknown keys are rejected, `_`-prefixed
// keys are comments.
func applyPolicyLayer(policy validation.Value, path string,
	data validation.Value) (validation.Value, error) {
	for _, key := range []string{"weights", "tool_evidence_tier", "tool_cost"} {
		v := objAt(data, key)
		if v.Kind == validation.Null {
			continue
		}
		if v.Kind != validation.Obj {
			return validation.VNull(), fmt.Errorf("%s: %s must be an object",
				path, validation.PyReprStr(key))
		}
		if key == "weights" {
			merged := objAt(policy, "weights")
			for _, kv := range v.O {
				merged = setKey(merged, kv.K, kv.V)
			}
			policy = setKey(policy, "weights", merged)
			continue
		}
		policy = setKey(policy, key, copyValue(v))
	}
	for _, kv := range data.O {
		if strings.HasPrefix(kv.K, "_") {
			continue
		}
		if kv.K != "weights" && kv.K != "tool_evidence_tier" &&
			kv.K != "tool_cost" {
			return validation.VNull(), fmt.Errorf("%s: unknown policy key "+
				"%s (known: weights, tool_evidence_tier, tool_cost)", path,
				validation.PyReprStr(kv.K))
		}
	}
	return policy, nil
}

// policySourceName is the file the winning layer came from, for error text:
// the campaign override when it exists, else the global config, else defaults.
func policySourceName(campaignPolicy string) string {
	source := "defaults"
	if _, err := os.Stat(PolicyConfig()); err == nil {
		source = PolicyConfig()
	}
	if campaignPolicy != "" {
		if _, err := os.Stat(campaignPolicy); err == nil {
			source = campaignPolicy
		}
	}
	return source
}

// DependencyImpact is dependency_impact: count of UNRESOLVED assumptions that
// transitively depend on this one (walk dependencies edges from dependents
// back; cycle-safe).
func DependencyImpact(finding validation.Value, assumptionID string) (int, error) {
	if _, err := byID(finding, assumptionID); err != nil {
		return 0, err
	}
	dependents := map[string][]string{}
	statusOf := map[string]string{}
	for _, a := range assumptions(finding) {
		aid := objStr(a, "id")
		statusOf[aid] = objStr(a, "status")
		if deps := objAt(a, "dependencies"); deps.Kind == validation.Arr {
			for _, d := range deps.A {
				if d.Kind == validation.Str {
					dependents[d.S] = append(dependents[d.S], aid)
				}
			}
		}
	}
	seen := map[string]bool{assumptionID: true}
	stack := append([]string{}, dependents[assumptionID]...)
	count := 0
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		st, ok := statusOf[cur]
		if !ok {
			continue // dangling edge: not our assumption, ignore
		}
		if contains(Unresolved, st) {
			count++
		}
		stack = append(stack, dependents[cur]...)
	}
	return count, nil
}

// floorNumber is _floor_number: the finding class's evidence floor as a
// tier-scale number.
func floorNumber(finding validation.Value) int {
	bugClass := objStr(asObj(objAt(finding, "root_cause")), "class")
	if bugClass == "" {
		return 2
	}
	pb, found, err := playbooks.PlaybookForClass(bugClass)
	if err != nil || !found {
		return 2
	}
	if floor := objStr(pb, "evidence_floor"); floor != "" {
		playbookFloor, ok := parseFloor(floor)
		if !ok {
			return 2
		}
		confirmFloor, ok := parseFloor(findings.RequiredLevelFor("CONFIRMED",
			bugClass))
		if !ok {
			confirmFloor = playbookFloor
		}
		return max(playbookFloor, confirmFloor)
	}
	return 2
}

// parseFloor is int(str(level)[1:]) with ValueError/IndexError -> not ok.
func parseFloor(level string) (int, bool) {
	r := []rune(level)
	if len(r) < 2 {
		return 0, false
	}
	n := 0
	for _, c := range r[1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// currentLevel is _current_level: highest evidence level index on the finding.
func currentLevel(finding validation.Value) int {
	best := 0
	if ev := objAt(finding, "evidence"); ev.Kind == validation.Arr {
		for _, e := range ev.A {
			lvl := objStr(e, "level")
			if n, ok := parseFloor(lvl); ok && len([]rune(lvl)) == 2 {
				best = max(best, n)
			}
		}
	}
	return best
}

// GateValue is gate_value: how much this assumption's verification could
// close the finding's evidence gap.
func GateValue(finding validation.Value, assumptionID string,
	policy validation.Value) (float64, error) {
	assumption, err := byID(finding, assumptionID)
	if err != nil {
		return 0, err
	}
	floor := floorNumber(finding)
	if currentLevel(finding) >= floor {
		return 0.0, nil
	}
	tiers := objAt(policy, "tool_evidence_tier")
	reg := registrySet()
	usable := []int{}
	if opts := objAt(assumption, "verification_options"); opts.Kind == validation.Arr {
		for _, t := range opts.A {
			if t.Kind != validation.Str || !reg[t.S] {
				continue
			}
			if tier := objAt(tiers, t.S); tier.Kind == validation.Int {
				usable = append(usable, int(tier.I))
			}
		}
	}
	if len(usable) == 0 {
		return 0.0, nil
	}
	sort.Ints(usable)
	gap := floor - usable[0]
	if gap < 0 {
		gap = 0
	}
	v := float64(gap) / 4.0
	if v > 1.0 {
		return 1.0, nil
	}
	return v, nil
}

// ScoreCandidate is score_candidate: the deterministic sort key for one
// (assumption, tool) pair: (dependency_impact, evidence_value, -cost_rank,
// gate_value) each multiplied by its weight.
func ScoreCandidate(assumption, toolID string, finding, policy validation.Value,
	impact int, gate float64) ([4]float64, error) {
	weights := objAt(policy, "weights")
	tiers := objAt(policy, "tool_evidence_tier")
	costs := objAt(policy, "tool_cost")
	evidenceValue := 0.0
	if t := objAt(tiers, toolID); t.Kind == validation.Int {
		evidenceValue = float64(t.I)
	} else if t.Kind == validation.Flt {
		evidenceValue = t.F
	}
	costRank := 0.0
	if c := objAt(costs, toolID); c.Kind == validation.Str {
		costRank = CostRank[c.S]
	}
	w := func(k string) float64 {
		v := objAt(weights, k)
		if v.Kind == validation.Int {
			return float64(v.I)
		}
		if v.Kind == validation.Flt {
			return v.F
		}
		return 0
	}
	return [4]float64{
		w("dependency_impact") * float64(impact),
		w("evidence_value") * evidenceValue,
		w("cost") * -costRank,
		w("gate_value") * gate,
	}, nil
}

// executedTools is _executed_tools: tool ids already brought to bear on this
// finding.
func executedTools(finding validation.Value, campaign *state.Campaign) []string {
	reg := registrySet()
	done := map[string]bool{}
	if ev := objAt(finding, "evidence"); ev.Kind == validation.Arr {
		for _, e := range ev.A {
			if t := objStr(e, "type"); reg[t] {
				done[t] = true
			}
		}
	}
	if campaign != nil {
		events, err := campaign.Events()
		if err != nil {
			events = nil
		}
		fid := objAt(finding, "finding_id")
		for _, ev := range events {
			ref := objAt(ev, "ref")
			if fid.Kind != validation.Null && ref.Kind != validation.Null &&
				!valueEq(ref, fid) {
				continue
			}
			data := objAt(ev, "data")
			tools := []validation.Value{}
			if t := objAt(data, "tools"); t.Kind == validation.Arr {
				tools = append(tools, t.A...)
			}
			if tid := objAt(data, "tool_id"); tid.Kind != validation.Null {
				tools = append(tools, tid)
			}
			for _, t := range tools {
				if t.Kind == validation.Str && reg[t.S] {
					done[t.S] = true
				}
			}
		}
	}
	out := make([]string, 0, len(done))
	for t := range done {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// fallbackTool is _fallback_tool: first hunt_order tool for the finding's
// class not yet executed.
func fallbackTool(finding validation.Value, campaign *state.Campaign) string {
	bugClass := objStr(asObj(objAt(finding, "root_cause")), "class")
	if bugClass == "" {
		return ""
	}
	pb, found, err := playbooks.PlaybookForClass(bugClass)
	if err != nil || !found {
		return ""
	}
	done := map[string]bool{}
	for _, t := range executedTools(finding, campaign) {
		done[t] = true
	}
	if order := objAt(pb, "hunt_order"); order.Kind == validation.Arr {
		for _, step := range order.A {
			tool := objStr(step, "tool_id")
			if tool != "" && !done[tool] {
				return tool
			}
		}
	}
	return ""
}

// ranked is one scored candidate row: the weighted tuple, the assumption and
// tool it belongs to, and the components the reason string repeats.
type ranked struct {
	score  [4]float64
	aid    string
	tool   string
	impact int
	gate   float64
}

// NextActions is next_actions: ranked next verification steps for one finding
// — PURE, no state mutation.
func NextActions(finding validation.Value, campaign *state.Campaign,
	policy validation.Value) ([]validation.Value, error) {
	pol := policy
	if pol.Kind == validation.Null {
		var err error
		pol, err = LoadPolicy(campaign)
		if err != nil {
			return nil, err
		}
	}
	if err := ValidatePolicy(pol, "policy"); err != nil {
		return nil, err
	}
	rows, err := collectNextRows(finding, campaign, pol)
	if err != nil {
		return nil, err
	}
	// best-first on the weighted tuple, then assumption_id, then tool_id:
	// deterministic for a fixed finding + policy, no wall clock involved.
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		for k := 0; k < 4; k++ {
			if a.score[k] != b.score[k] {
				return a.score[k] > b.score[k]
			}
		}
		if a.aid != b.aid {
			return a.aid < b.aid
		}
		return a.tool < b.tool
	})
	return renderNextRows(rows, objAt(pol, "tool_evidence_tier"),
		objAt(pol, "tool_cost")), nil
}

// collectNextRows is one scored row per (blocking, unresolved assumption,
// priced tool) candidate: the assumption's verification options that the
// registry knows, or the fallback tool when it names none.
func collectNextRows(finding validation.Value, campaign *state.Campaign,
	pol validation.Value) ([]ranked, error) {
	reg := registrySet()
	rows := []ranked{}
	for _, a := range assumptions(finding) {
		if !truthy(objAt(a, "blocking")) {
			continue
		}
		if !contains(Unresolved, objStr(a, "status")) {
			continue
		}
		options := knownOptions(objAt(a, "verification_options"), reg)
		if len(options) == 0 {
			fb := fallbackTool(finding, campaign)
			if fb == "" || !reg[fb] {
				continue
			}
			// the fallback must also be priced by the policy
			if objAt(objAt(pol, "tool_evidence_tier"), fb).Kind == validation.Null ||
				objAt(objAt(pol, "tool_cost"), fb).Kind == validation.Null {
				continue
			}
			options = []string{fb}
		}
		aid := objStr(a, "id")
		impact, err := DependencyImpact(finding, aid)
		if err != nil {
			return nil, err
		}
		gate, err := GateValue(finding, aid, pol)
		if err != nil {
			return nil, err
		}
		for _, tool := range options {
			score, err := ScoreCandidate(aid, tool, finding, pol, impact, gate)
			if err != nil {
				return nil, err
			}
			rows = append(rows, ranked{score: score, aid: aid, tool: tool,
				impact: impact, gate: gate})
		}
	}
	return rows, nil
}

// knownOptions is the verification_options the tool registry actually has.
func knownOptions(opts validation.Value, reg map[string]bool) []string {
	out := []string{}
	if opts.Kind != validation.Arr {
		return out
	}
	for _, t := range opts.A {
		if t.Kind == validation.Str && reg[t.S] {
			out = append(out, t.S)
		}
	}
	return out
}

// renderNextRows is the public row shape, in the given order.
func renderNextRows(rows []ranked, tiers, costs validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, r := range rows {
		out = append(out, validation.VObj(
			validation.KV{K: "assumption_id", V: validation.VStr(r.aid)},
			validation.KV{K: "tool_id", V: validation.VStr(r.tool)},
			validation.KV{K: "score", V: validation.VArr(
				validation.VFloat(r.score[0]), validation.VFloat(r.score[1]),
				validation.VFloat(r.score[2]), validation.VFloat(r.score[3]))},
			validation.KV{K: "reason", V: validation.VStr(fmt.Sprintf(
				"dependency impact %d, tier %s, cost %s, gate %.2f", r.impact,
				scalarText(objAt(tiers, r.tool)),
				scalarText(objAt(costs, r.tool)), r.gate))}))
	}
	return out
}

// DecideNext is decide_next: the loop hook — rank NextActions for one
// finding, log the decision on the hash chain as a framework routing.decided
// event (NOT a model.* family member), and return the decision
// {"finding_id", "actions", "selected"}.
func DecideNext(campaign *state.Campaign, findingID string,
	policy validation.Value) (validation.Value, error) {
	finding, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	actions, err := NextActions(finding, campaign, policy)
	if err != nil {
		return validation.VNull(), err
	}
	var selected validation.Value = validation.VNull()
	if len(actions) > 0 {
		selected = actions[0]
	}
	ranked := []validation.Value{}
	for _, a := range actions {
		ranked = append(ranked, validation.VObj(
			validation.KV{K: "assumption_id", V: objAt(a, "assumption_id")},
			validation.KV{K: "tool_id", V: objAt(a, "tool_id")},
			validation.KV{K: "score", V: objAt(a, "score")}))
	}
	data := validation.VObj(
		validation.KV{K: "selected", V: selected},
		validation.KV{K: "ranked", V: validation.VArr(ranked...)})
	if _, err := campaign.Log("routing.decided", &findingID, &data); err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(findingID)},
		validation.KV{K: "actions", V: validation.VArr(actions...)},
		validation.KV{K: "selected", V: selected}), nil
}

// ---- small helpers --------------------------------------------------------

func assumptions(finding validation.Value) []validation.Value {
	if a := objAt(finding, "assumptions"); a.Kind == validation.Arr {
		return a.A
	}
	return nil
}

func byID(finding validation.Value, assumptionID string) (validation.Value, error) {
	for _, a := range assumptions(finding) {
		if objStr(a, "id") == assumptionID {
			return a, nil
		}
	}
	ids := []validation.Value{}
	for _, a := range assumptions(finding) {
		ids = append(ids, objAt(a, "id"))
	}
	return validation.VNull(), fmt.Errorf("%s is not an assumption of this "+
		"finding (ids: %s)", validation.PyReprStr(assumptionID),
		pyListReprVals(ids))
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

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

func asObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

func setKey(obj validation.Value, key string, val validation.Value) validation.Value {
	out := validation.VObj()
	done := false
	for _, kv := range obj.O {
		if kv.K == key {
			out.O = append(out.O, validation.KV{K: key, V: val})
			done = true
			continue
		}
		out.O = append(out.O, kv)
	}
	if !done {
		out.O = append(out.O, validation.KV{K: key, V: val})
	}
	return out
}

func copyValue(v validation.Value) validation.Value {
	switch v.Kind {
	case validation.Obj:
		out := validation.VObj()
		for _, kv := range v.O {
			out.O = append(out.O, validation.KV{K: kv.K, V: copyValue(kv.V)})
		}
		return out
	case validation.Arr:
		out := make([]validation.Value, len(v.A))
		for i := range v.A {
			out[i] = copyValue(v.A[i])
		}
		return validation.VArr(out...)
	}
	return v
}

func sortedKeysNotIn(obj validation.Value, allowed map[string]bool) []string {
	out := []string{}
	if obj.Kind != validation.Obj {
		return out
	}
	for _, kv := range obj.O {
		if !allowed[kv.K] {
			out = append(out, kv.K)
		}
	}
	sort.Strings(out)
	return out
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Bool:
		return v.B
	case validation.Null:
		return false
	case validation.Str:
		return v.S != ""
	case validation.Int:
		return v.I != 0
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return true
}

func valueEq(a, b validation.Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case validation.Str:
		return a.S == b.S
	case validation.Int:
		return a.I == b.I
	case validation.Null:
		return true
	case validation.Bool:
		return a.B == b.B
	case validation.Flt:
		return a.F == b.F
	}
	return false
}

func scalarText(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	}
	return ""
}

func pyRepr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return validation.PyReprStr(v.S)
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	}
	return validation.PyRepr(v)
}

func pyListRepr(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pyListReprVals(xs []validation.Value) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = pyRepr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
