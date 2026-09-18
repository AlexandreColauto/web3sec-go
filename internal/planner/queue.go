package planner

import (
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// DecisionRule is decision_rule: high prior + cheap validation = investigate
// now. High prior + expensive validation + weak reachability = deprioritize.
// Returns the queue slot class: 'now' | 'next' | 'batch' | 'park'. The
// reachability tail is Python's `reachability="unknown"` default.
func DecisionRule(prior float64, cost string, reachability ...string) string {
	reach := "unknown"
	if len(reachability) > 0 {
		reach = reachability[0]
	}
	if prior >= 0.75 && cost == "cheap" {
		return "now"
	}
	if prior >= 0.75 && reach == "demonstrated" {
		return "now"
	}
	if prior >= 0.6 {
		if cost != "expensive" {
			return "next"
		}
		return "batch"
	}
	if prior >= 0.4 {
		if cost == "cheap" {
			return "batch"
		}
		return "park"
	}
	return "park"
}

// PlannerHint is one learning.load_planner_hints row (kind="priority"): the
// planner only reads hint_id and content.
type PlannerHint struct {
	HintID  string
	Content string
}

// loadPlannerHintsFunc is the learning.load_planner_hints seam (learning is
// unported). Feature absent: no hints, so include_hints=True is a no-op —
// byte-identical to Python with an empty hint store.
var loadPlannerHintsFunc = func(*state.Campaign) ([]PlannerHint, error) {
	return nil, nil
}

// SetLoadPlannerHints wires learning.load_planner_hints(campaign,
// kind="priority").
func SetLoadPlannerHints(f func(*state.Campaign) ([]PlannerHint, error)) {
	if f == nil {
		panic("planner: nil planner-hint loader")
	}
	loadPlannerHintsFunc = f
}

// WorkQueue is work_queue: the ordered, bounded work list for the
// orchestrator — each priority annotated with prior risk, validation cost,
// and queue slot.
//
// includeHints folds in the reflection-derived planner hints
// (learning.planner_hint, kind='priority') — the loop closure run 1 left open:
// reflection said things, the planner never heard them. Hint rows are tagged
// `source: hint:<hint_id>` so the operator can see which queue rows came from
// the campaign's own after-action learning. The discovery COMPLETION PROOF
// calls this with the default (false): hints steer, they do not block stage
// completion.
func WorkQueue(campaign *state.Campaign, plan, model validation.Value,
	includeHints bool) ([]validation.Value, error) {
	out := []validation.Value{}
	for _, p := range listOf(plan, "priorities") {
		// Closed priorities (answered / not-applicable / deprioritized) never
		// re-enter the queue: a not-applicable row was a legitimate closing
		// disposition (planner.gates) and re-queueing it kept the discovery
		// proof permanently blocked (feedback-triage A1).
		if st := objStr(p, "status"); st == "answered" ||
			st == "not-applicable" || st == "deprioritized" {
			continue
		}
		cost := objStr(p, "budget_class")
		if cost == "" {
			cost = "standard"
		}
		risk := numAt(p, "risk")
		trajs := []string{}
		for _, t := range listOf(p, "trajectories") {
			trajs = append(trajs, enumTrajectory(pyStr(t)))
		}
		out = append(out, validation.VObj(
			kv("priority_id", objAt(p, "id")),
			kv("question", objAt(p, "question")),
			kv("risk", objAt(p, "risk")),
			kv("cost", validation.VStr(cost)),
			kv("slot", validation.VStr(DecisionRule(risk, cost))),
			kv("trajectories", strArr(trajs)),
			kv("components", keyOrEmpty(p, "components")),
			kv("invariant_ids", keyOrEmpty(p, "invariant_ids")),
			kv("required_context", keyOrEmpty(p, "required_context")),
		))
	}
	if includeHints {
		hints, err := loadPlannerHintsFunc(campaign)
		if err != nil {
			return nil, err
		}
		for _, h := range hints {
			out = append(out, validation.VObj(
				kv("priority_id", validation.VStr(h.HintID)),
				kv("question", validation.VStr("from reflection ("+h.HintID+
					"): "+h.Content)),
				kv("risk", validation.VFloat(0.7)),
				kv("cost", validation.VStr("standard")),
				kv("slot", validation.VStr(DecisionRule(0.7, "standard"))),
				kv("trajectories", strArr([]string{"code"})),
				kv("components", validation.VArr()),
				kv("invariant_ids", validation.VArr()),
				kv("required_context", validation.VArr()),
				kv("source", validation.VStr("hint:"+h.HintID)),
			))
		}
	}
	order := map[string]int{"now": 0, "next": 1, "batch": 2, "park": 3}
	ranked, err := rankQueue(campaign, model, out, order)
	if err != nil {
		return nil, err
	}
	out = ranked
	// G17 tactic batting average (policy-gated, default off): a tripped
	// lens's unstarted slots demote to park with the reason line. Flag
	// off (or nothing tripped, or nothing movable) returns the standing
	// order untouched — byte law.
	tripped, err := trippedLenses(campaign)
	if err != nil {
		return nil, err
	}
	if len(tripped) > 0 {
		applyAutoTune(out, plan, campaign, tripped)
	}
	return out, nil
}

// ---- Task 12: risk-weighted cockpit ordering ------------------------------
//
// The queue used to order by (slot, risk, plan order): inside a slot the only
// signal was the priority's own prior, so two rows with equal risk kept the
// plan's alphabetical order no matter what they worked. The cockpit therefore
// surfaced the alphabetically first file, not the risky one.
//
// The ordering weight is now ADDITIVE:
//
//	Score = (untouchedCount * W1) + (severityScore * W2) + (openQuestionCount * W3)
//
// openQuestionCount is DISTINCT QUESTIONS PER ROW, not (question, component)
// pairs: one unresolved open question that names two components of the same row
// contributes W3 once (critic round 1, F5). Summing per component inflated a
// single question into N and let a row out-rank an otherwise identical row
// purely by how many of its components that one question happened to name. The
// count-once rule can only LOWER a row's weight relative to the per-component
// sum — no row is ever promoted by it — which is the conservative direction for
// a cockpit that must not rank work on a duplicated signal.
//
// ponytail: additive, NEVER multiplicative — a product zeroes out a critical
// consensus contract the moment one factor is 0 (already swept, or no open
// question names it) and drops it below alphabetical zero-signal entries,
// which is exactly the failure the review flagged. Tune the weights here and
// nowhere else; there is no config key.
const (
	queueWeightUntouched = 1.0 // W1: per untouched contract the row works
	queueWeightSeverity  = 2.0 // W2: per severity band of those contracts
	queueWeightOpenQ     = 1.5 // W3: per open question naming them
)

// queueSeverityBands is the model's own severity vocabulary as weights:
// critical=3 / high=2 / medium=1 / low=0.
var queueSeverityBands = map[string]float64{
	"critical": 3, "high": 2, "medium": 1, "low": 0,
}

// queueScore is one row's ordering weight, in its three named parts.
type queueScore struct {
	untouched int
	severity  float64
	openQ     int // DISTINCT unresolved open questions naming this row
}

// weight is the additive score. Never a product (see the constants above).
func (s queueScore) weight() float64 {
	return float64(s.untouched)*queueWeightUntouched +
		s.severity*queueWeightSeverity +
		float64(s.openQ)*queueWeightOpenQ
}

// queueSignals is the per-campaign lookup the score reads. Every map is read
// by key and never ranged, so Go's map order cannot leak into the queue.
type queueSignals struct {
	inScope  map[string]string  // in-scope contract name/path -> coverage path
	touched  map[string]bool    // coverage path -> swept (worked at least once)
	severity map[string]float64 // contract reference -> max severity band
	invSev   map[string]float64 // invariant id -> severity band
	// openQ maps a contract reference to the ORDINALS of the unresolved open
	// questions naming it, in model declaration order. Identity — not a tally —
	// is what lets scoreRow count one question once even when it names several
	// components of the same row (F5); the slices are ordered, so nothing here
	// is map-ranged.
	openQ map[string][]int
}

// rankQueue orders the assembled rows: slot class first (the DecisionRule
// contract), then the additive score, then alphabetical by priority id and
// question. Deterministic by construction — no map is ranged.
func rankQueue(campaign *state.Campaign, model validation.Value,
	rows []validation.Value, slotOrder map[string]int) ([]validation.Value, error) {
	signals, err := buildQueueSignals(campaign, model)
	if err != nil {
		return nil, err
	}
	type ranked struct {
		row    validation.Value
		slot   int
		weight float64
		id     string
		q      string
	}
	out := make([]ranked, 0, len(rows))
	for _, row := range rows {
		out = append(out, ranked{
			row:    row,
			slot:   slotOrder[objStr(row, "slot")],
			weight: signals.scoreRow(row).weight(),
			id:     objStr(row, "priority_id"),
			q:      objStr(row, "question"),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.slot != b.slot {
			return a.slot < b.slot
		}
		if a.weight != b.weight {
			return a.weight > b.weight
		}
		if a.id != b.id {
			return a.id < b.id
		}
		return a.q < b.q
	})
	ordered := make([]validation.Value, 0, len(out))
	for _, r := range out {
		ordered = append(ordered, r.row)
	}
	return ordered, nil
}

// buildQueueSignals reads the model and the campaign's coverage ledger. A
// campaign with no ledger has swept nothing, so every in-scope contract is
// untouched; a ledger that EXISTS but cannot be read is an error (a torn
// ledger must not silently re-rank the queue as if nothing were swept).
func buildQueueSignals(campaign *state.Campaign,
	model validation.Value) (*queueSignals, error) {
	s := &queueSignals{
		inScope:  map[string]string{},
		touched:  map[string]bool{},
		severity: map[string]float64{},
		invSev:   map[string]float64{},
		openQ:    map[string][]int{},
	}
	for _, c := range listOf(model, "contracts") {
		if !pyTruthyBigNonEmpty(objAt(c, "in_scope")) {
			continue
		}
		name, path := objStr(c, "name"), objStr(c, "path")
		if name != "" {
			s.inScope[name] = path
		}
		if path != "" {
			s.inScope[path] = path
		}
	}
	for _, inv := range listOf(model, "invariants") {
		band := queueSeverityBands[objStr(inv, "severity_if_broken")]
		if id := objStr(inv, "id"); id != "" {
			s.invSev[id] = band
		}
		for _, ref := range listOf(inv, "applies_to") {
			key := pyStr(ref)
			if key == "" {
				continue
			}
			if band > s.severity[key] {
				s.severity[key] = band
			}
		}
	}
	for ord, q := range listOf(model, "open_questions") {
		if pyTruthyBigNonEmpty(objAt(q, "resolved")) {
			continue
		}
		// ord identifies the question: one model entry is one question, however
		// many of a row's components it names (F5). A repeated ref inside one
		// question is already dropped by openQuestionRefs, so no ref can carry
		// the same ordinal twice.
		for _, ref := range openQuestionRefs(q) {
			s.openQ[ref] = append(s.openQ[ref], ord)
		}
	}
	covPath := filepath.Join(campaign.ArtifactsDir, "coverage.json")
	if _, err := os.Stat(covPath); err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	// The ledger is read as the artifact it is (the `coverage` schema is
	// validated where it is written). Importing internal/coverage here would
	// close a cycle: coverage's own test binary pulls planner through
	// audit/sections -> completion, so the read stays on the document.
	cov, err := validation.ReadJson(covPath)
	if err != nil {
		return nil, err
	}
	for _, row := range listOf(cov, "contracts") {
		path := objStr(row, "path")
		if path == "" {
			continue
		}
		s.touched[path] = coverageSwept(row)
	}
	return s, nil
}

// coverageSwept is the coverage ledger's own "has this been worked" test
// (refresh_gaps): a row that is not `unknown` and carries at least one
// trajectory count has been swept. Anything else — no row, `unknown`, zero
// trajectories — is untouched.
func coverageSwept(row validation.Value) bool {
	if objStr(row, "status") == "unknown" || objStr(row, "status") == "" {
		return false
	}
	counts := objAt(row, "trajectory_counts")
	return counts.Kind == validation.Obj && len(counts.O) >= 1
}

// scoreRow is one queue row's score: untouched contracts, the worst severity
// band of the invariants that apply to them (or that the row names directly),
// and how many DISTINCT unresolved open questions name them. One question that
// names two of the row's components counts once (F5): the weight measures how
// many questions are open about the row, not how many ways one question can
// spell the row's surface.
func (s *queueSignals) scoreRow(row validation.Value) queueScore {
	out := queueScore{}
	named := map[int]bool{} // question ordinals already counted for this row
	for _, c := range listOf(row, "components") {
		ref := pyStr(c)
		path, ok := s.inScope[ref]
		if !ok {
			continue
		}
		if !s.touched[path] {
			out.untouched++
		}
		if v := s.severity[ref]; v > out.severity {
			out.severity = v
		}
		for _, ord := range s.openQ[ref] {
			named[ord] = true
		}
	}
	// len() of a set: never ranged, so no map order can reach the score.
	out.openQ = len(named)
	for _, id := range listOf(row, "invariant_ids") {
		if v := s.invSev[pyStr(id)]; v > out.severity {
			out.severity = v
		}
	}
	return out
}

// enumTrajectory is TRAJECTORY_TO_ENUM.get(t, "code").
func enumTrajectory(t string) string {
	if e, ok := TrajectoryToEnum[t]; ok {
		return e
	}
	return "code"
}

// keyOrEmpty is `p.get(key, [])` — the default applies only when the key is
// ABSENT, so an explicit null passes through (Python does the same).
func keyOrEmpty(p validation.Value, key string) validation.Value {
	got, ok := fieldAt(p, key)
	if !ok {
		return validation.VArr()
	}
	return got
}

// numAt is a numeric field as float64 (0 when absent/non-numeric).
func numAt(v validation.Value, key string) float64 {
	got := objAt(v, key)
	switch got.Kind {
	case validation.Flt:
		return got.F
	case validation.Int:
		return float64(got.I)
	}
	return 0
}
