// Package findings ports webv2.findings: the finding IR (CRUD), the evidence
// ladder (E0-E7) and the gate algebra over evidence types.
//
// Design rules enforced here, not anywhere else: CONFIRMED is structurally
// unreachable without the evidence floor for the bug class; evidence at
// level >= E4 must name the sandbox profile it was produced under; every
// status move is recorded in the finding's own history AND the campaign
// event log, with a reason (transition lands with Task 2).
package findings

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// The constants below keep the Python (webv2.findings) names verbatim so
// the two twins stay greppable side by side. The values are contractual.
var (
	// EVIDENCE_ORDER is EVIDENCE_ORDER: the TRUST axis — the E0-E7 ladder,
	// monotonic, no skipping. The order is contractual: it is the
	// '/'.join(EVIDENCE_ORDER) inside the unknown-level error text and the
	// strong-ordering key of every level comparison.
	EVIDENCE_ORDER = []string{"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7"}

	// EVIDENCE_LEVELS is EVIDENCE_LEVELS = set(EVIDENCE_ORDER).
	EVIDENCE_LEVELS = setOf(EVIDENCE_ORDER...)

	// TERMINAL is TERMINAL: statuses that absorb (no outgoing transition).
	TERMINAL = setOf("DISPROVED", "OUT_OF_SCOPE", "INFORMATIONAL", "DUPLICATE",
		"SUPERSEDED")

	// STATUS_FLOOR is STATUS_FLOOR: the evidence floor per target status.
	STATUS_FLOOR = map[string]string{
		"HYPOTHESIS": "E0", "NEEDS_RESEARCH": "E0", "PROVISIONALLY_VALID": "E1",
		"POSSIBLE": "E2", "CONFIRMED": "E5", "CHAIN": "E4",
	}

	// CLASS_CONFIRM_FLOOR is CLASS_CONFIRM_FLOOR: bug classes whose
	// CONFIRMED floor differs from the default. Classes whose
	// exploitability is fully determined by code semantics (no dependence
	// on live mainnet state) are fully provable in a local unit harness
	// (E4). Economic/oracle/bridge classes need fork reality (E5) or
	// cross-chain witnesses (E6): their impact lives in mainnet state.
	CLASS_CONFIRM_FLOOR = map[string]string{
		"access-control": "E4", "signature-replay": "E4",
		"upgrade-initializer": "E4", "authorization": "E4", "reentrancy": "E4",
		"logic-error": "E4", "dos-griefing": "E4", "token-integration": "E4",
		// Internal pricing-formula error (wrong basis in a share-price
		// equation): code semantics only. Distinct from
		// share-price-inflation (E6), whose impact lives in mainnet state.
		"share-price-accounting": "E4",
		"oracle-manipulation":    "E5",
		"flash-loan":             "E5",
		// Mechanism-design classes: the subtle failure is an UNREALISTIC
		// BENIGN-ACTOR MODEL — a single green fork run does not catch it.
		// E6 = independent reproduction, reachable on single-chain forks.
		"share-price-inflation": "E6",
		"economic-invariant":    "E6",
		"liquidation-logic":     "E5",
		"bridge-message":        "E6",
		"cross-chain-replay":    "E6",
		// Offchain families (G9): the failure lives in the dapp/offchain
		// estate, not in contract code semantics — mirror the
		// bridge-message scenario floor (E6, independent reproduction),
		// not a new floor. Deliberately absent from
		// CROSS_CHAIN_E6_CLASSES (cross-chain-witness flavor only) and
		// from ECONOMIC_CONFIRMATION_CLASSES (no three-clause gate).
		"frontend-injection": "E6",
		"infra-boundary":     "E6",
	}

	// CROSS_CHAIN_E6_CLASSES is _CROSS_CHAIN_E6_CLASSES: classes whose E6
	// flavor is a CROSS-CHAIN witness (as opposed to independent
	// reproduction on a single fork). reachability_diagnostic uses this to
	// avoid false chain-pin alarms for single-chain E6 classes.
	CROSS_CHAIN_E6_CLASSES = setOf("bridge-message", "cross-chain-replay")

	// ALLOWED_TRANSITIONS is ALLOWED_TRANSITIONS: the status state machine
	// edges. A terminal status has no outgoing edges.
	ALLOWED_TRANSITIONS = map[string]map[string]struct{}{
		"HYPOTHESIS": setOf("NEEDS_RESEARCH", "PROVISIONALLY_VALID", "POSSIBLE",
			"DISPROVED", "OUT_OF_SCOPE", "DUPLICATE", "INFORMATIONAL",
			"SUPERSEDED"),
		"NEEDS_RESEARCH": setOf("POSSIBLE", "PROVISIONALLY_VALID", "DISPROVED",
			"OUT_OF_SCOPE", "DUPLICATE", "INFORMATIONAL", "SUPERSEDED"),
		"PROVISIONALLY_VALID": setOf("POSSIBLE", "NEEDS_RESEARCH", "DISPROVED",
			"OUT_OF_SCOPE", "DUPLICATE", "INFORMATIONAL", "SUPERSEDED"),
		"POSSIBLE": setOf("CONFIRMED", "NEEDS_RESEARCH", "DISPROVED", "OUT_OF_SCOPE",
			"DUPLICATE", "INFORMATIONAL", "SUPERSEDED"),
		"CONFIRMED": setOf("DISPROVED", "DUPLICATE", "CHAIN", "OUT_OF_SCOPE",
			"INFORMATIONAL", "SUPERSEDED"),
		"CHAIN":         setOf("CONFIRMED", "DISPROVED", "SUPERSEDED"),
		"DISPROVED":     setOf(),
		"DUPLICATE":     setOf(),
		"OUT_OF_SCOPE":  setOf(),
		"INFORMATIONAL": setOf(),
		"SUPERSEDED":    setOf(),
	}

	// EVIDENCE_TYPE_GROUPS is EVIDENCE_TYPE_GROUPS: the COMPLEMENTARY axis
	// of the gate — what kind of knowledge a piece of evidence carries.
	// A gate clause is "at least one evidence item of a type in S at level
	// >= L"; ten E7 items of the wrong type satisfy zero clauses.
	EVIDENCE_TYPE_GROUPS = map[string]map[string]struct{}{
		"static":            setOf("reasoning", "static-analysis"),
		"reachability":      setOf("reachability"),
		"invariant":         setOf("invariant-test", "symbolic-witness"),
		"local-poc":         setOf("unit-test", "foundry-test", "fuzz"),
		"fork-poc":          setOf("fork-test", "trace", "balance-delta"),
		"independent-repro": setOf("differential", "historical-analog", "manual"),
		"economic":          setOf("balance-delta", "manual"),
	}

	// ECONOMIC_CONFIRMATION_CLASSES is ECONOMIC_CONFIRMATION_CLASSES:
	// classes whose impact lives in live economic state. Their CONFIRMED
	// gate is the full three-stage requirement: local proof the logic
	// fires, live-state proof it fires against real data (fork OR
	// independent repro — alternatives, one clause), and an economic
	// quantification.
	ECONOMIC_CONFIRMATION_CLASSES = setOf("oracle-manipulation", "flash-loan",
		"share-price-inflation", "economic-invariant", "liquidation-logic")
)

// setOf builds a set-as-map from its members (an empty, non-nil set when
// called with no members).
func setOf(items ...string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, it := range items {
		s[it] = struct{}{}
	}
	return s
}

// effectiveFloorFunc is the floors.effective_floor seam: the campaign-aware
// instance-level floor override. Until floors is ported the built-in
// class/status default applies.
var effectiveFloorFunc = func(c *state.Campaign, status string, bugClass string) string {
	return RequiredLevelFor(status, bugClass)
}

// SetEffectiveFloor installs the campaign-aware floor resolver
// (floors.effective_floor); a nil f restores the built-in default.
// floors.go (P1 Task 3) wires this.
func SetEffectiveFloor(f func(*state.Campaign, string, string) string) {
	if f == nil {
		effectiveFloorFunc = func(c *state.Campaign, status string, bugClass string) string {
			return RequiredLevelFor(status, bugClass)
		}
		return
	}
	effectiveFloorFunc = f
}

// RequiredLevelFor is required_level_for: the floor for a target status,
// with the class-aware CONFIRMED override.
func RequiredLevelFor(status, bugClass string) string {
	if status == "CONFIRMED" && bugClass != "" {
		if f, ok := CLASS_CONFIRM_FLOOR[bugClass]; ok {
			return f
		}
		return STATUS_FLOOR["CONFIRMED"]
	}
	if f, ok := STATUS_FLOOR[status]; ok {
		return f
	}
	return "E0"
}

// RequiredLevelForCampaign is required_level_for_campaign: the evidence
// floor that applies IN THIS CAMPAIGN — the instance-level override when
// the operator set one (floors.set_floor_policy: data, actor, written
// reason, logged event), else the built-in CLASS_CONFIRM_FLOOR /
// STATUS_FLOOR default. Without a campaign, the built-in default.
func RequiredLevelForCampaign(campaign *state.Campaign, status, bugClass string) string {
	if campaign == nil {
		return RequiredLevelFor(status, bugClass)
	}
	return effectiveFloorFunc(campaign, status, bugClass)
}

// TransitionAllowed reports whether ALLOWED_TRANSITIONS carries the edge.
func TransitionAllowed(from, to string) bool {
	dst, ok := ALLOWED_TRANSITIONS[from]
	if !ok {
		return false
	}
	_, ok = dst[to]
	return ok
}

// LevelIndex is level_index: the ladder position, or a ValueError with the
// ladder enumerated when the level is unknown.
func LevelIndex(level string) (int, error) {
	for i, e := range EVIDENCE_ORDER {
		if e == level {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown evidence level %s; the ladder is %s",
		validation.PyReprStr(level), strings.Join(EVIDENCE_ORDER, "/"))
}

// GateRequirement is one gate requirement: a set of satisfying evidence types
// (nil — any type) and a minimum level. Decision names a NAMED DECISION that
// stands in for the clause's evidence ("unpriceable": some economic impacts
// cannot honestly be priced, so inventing a number to satisfy the gate is the
// failure mode — round-7 D3, risk.RecordUnpriceable).
type GateRequirement struct {
	Types    map[string]struct{}
	MinLevel string
	Decision string
}

// GateRequirements is gate_requirements: the gate for *status* as a
// conjunction of evidence clauses.
//
// Each clause is satisfied when the finding holds at least one evidence
// item whose type is in the clause (any type when nil) at level >=
// MinLevel. The default — a single any-type clause at the class floor — is
// the legacy ladder-only behavior, so every pre-existing gate is unchanged.
// Economic classes upgrade to the three-clause gate.
//
// Invariant: evidence may accumulate monotonically, but no evidence can
// substitute for a missing clause — a clause is satisfied only by an item
// of one of its types at or above its level, regardless of how much or how
// strong the finding's other evidence is.
func GateRequirements(status, bugClass string, campaign *state.Campaign) []GateRequirement {
	floor := RequiredLevelForCampaign(campaign, status, bugClass)
	if status == "CONFIRMED" && bugClass != "" && inSet(ECONOMIC_CONFIRMATION_CLASSES, bugClass) {
		return []GateRequirement{
			{Types: copySet(EVIDENCE_TYPE_GROUPS["local-poc"]), MinLevel: "E4"},
			{Types: mergeSets(EVIDENCE_TYPE_GROUPS["fork-poc"],
				EVIDENCE_TYPE_GROUPS["independent-repro"]), MinLevel: floor},
			// the quantification clause accepts a NAMED DECISION in place of
			// the artifact: some impacts cannot honestly be priced, and
			// inventing a number to satisfy the gate is the failure mode
			// (round-7 D3). See risk.record_unpriceable.
			{Types: copySet(EVIDENCE_TYPE_GROUPS["economic"]), MinLevel: "E7",
				Decision: "unpriceable"},
		}
	}
	return []GateRequirement{{Types: nil, MinLevel: floor}}
}

// UnpriceableDecision is unpriceable_decision: the finding's recorded
// UNPRICEABLE decision, or nil.
//
// economic_impact.priceable ABSENT means priceable — every finding written
// before this field existed keeps its behaviour — so only an explicit false
// counts, and only when the decision carries the ceiling basis it was made
// against (a bare flag is not a decision). risk.RecordUnpriceable is the
// sole writer; audit cross-checks the projection against the
// finding.unpriceable log event, so this read stays as cheap as
// floors.floor_override.
func UnpriceableDecision(finding validation.Value) *validation.Value {
	imp := asDict(objAt(finding, "economic_impact"))
	p := objAt(imp, "priceable")
	if p.Kind != validation.Bool || p.B {
		return nil
	}
	ceiling := objAt(imp, "ceiling")
	if ceiling.Kind != validation.Str || strings.TrimSpace(ceiling.S) == "" {
		return nil
	}
	out := validation.VObj(
		validation.KV{K: "priceable", V: validation.VBool(false)},
		validation.KV{K: "ceiling", V: ceiling},
	)
	return &out
}

// ClauseMet is _clause_met: does the finding hold an evidence item of one
// of the clause's types at or above its min level? A level-less or
// unknown-level item satisfies nothing.
func ClauseMet(finding validation.Value, clause GateRequirement) bool {
	// A clause may name a NAMED DECISION that stands in for its evidence
	// (the economic-class E7 quantification is impossible for some
	// findings). The decision is recorded state, not a bypass: absent it,
	// the clause is unmet exactly as before.
	if clause.Decision == "unpriceable" &&
		UnpriceableDecision(finding) != nil {
		return true
	}
	need, err := LevelIndex(clause.MinLevel)
	if err != nil {
		return false
	}
	for _, e := range objAt(finding, "evidence").A {
		lvl, err := LevelIndex(objStr(e, "level"))
		if err != nil {
			continue
		}
		if lvl < need {
			continue
		}
		if clause.Types == nil {
			return true
		}
		if _, ok := clause.Types[objStr(e, "type")]; ok {
			return true
		}
	}
	return false
}

// FindingLevel is finding_level: the highest evidence level, or "E0" when
// the finding holds no (parseable) evidence.
func FindingLevel(finding validation.Value) (string, error) {
	best := 0
	for _, e := range objAt(finding, "evidence").A {
		lvl, err := LevelIndex(objStr(e, "level"))
		if err != nil {
			continue
		}
		if lvl > best {
			best = lvl
		}
	}
	return EVIDENCE_ORDER[best], nil
}

// IsExecutionLevel is is_execution_level: EXECUTION evidence (E4/E5/E6)
// must trace to an EXEC record in this campaign's ledger. E7 is ANALYSIS
// evidence (economic impact quantified) — it needs an artifact reference,
// not a sandbox run. This single predicate is the level set BOTH the
// add_evidence path and the ingest path enforce, so the two can never
// drift apart.
func IsExecutionLevel(level string) (bool, error) {
	lvl, err := LevelIndex(level)
	if err != nil {
		return false, err
	}
	base, _ := LevelIndex("E4")
	return lvl >= base && level != "E7", nil
}

// EvidenceDeficit is evidence_deficit: a human-readable description of
// which gate clauses are unmet for *status*, or nil when the whole gate is
// met.
func EvidenceDeficit(finding validation.Value, status string, campaign *state.Campaign) *string {
	bugClass := objStr(objAt(finding, "root_cause"), "class")
	clauses := GateRequirements(status, bugClass, campaign)
	if len(clauses) == 1 && clauses[0].Types == nil {
		have, err := FindingLevel(finding)
		if err != nil {
			return nil
		}
		need := clauses[0].MinLevel
		h, _ := LevelIndex(have)
		n, _ := LevelIndex(need)
		if h >= n {
			return nil
		}
		out := fmt.Sprintf("evidence level %s < required %s for %s", have, need, status)
		return &out
	}
	var missing []string
	for _, cl := range clauses {
		if ClauseMet(finding, cl) {
			continue
		}
		types := "(any)"
		if cl.Types != nil {
			names := keysOf(cl.Types)
			sort.Strings(names)
			types = listRepr(names)
		}
		msg := fmt.Sprintf("no evidence of type %s at level >= %s", types,
			cl.MinLevel)
		if cl.Decision == "unpriceable" {
			// the sanctioned alternative is part of the message: the silent
			// "no evidence" is what pushed operators into invented numbers.
			// A nil or id-less campaign (library callers) has no id to
			// name, so the catalog's own metavariable stands in — the same
			// text NameCampaign leaves when the id is empty.
			cid := campaignPlaceholder
			if campaign != nil && campaign.CampaignID != "" {
				cid = campaign.CampaignID
			}
			msg += " and no unpriceable decision recorded (`webv2 impact " +
				cid + " <finding> --unpriceable --ceiling '<capacity " +
				"basis>' --reason <why no figure is defensible> --actor <you>`)"
		}
		missing = append(missing, msg)
	}
	if len(missing) == 0 {
		return nil
	}
	out := strings.Join(missing, "; ")
	return &out
}

func inSet(s map[string]struct{}, key string) bool {
	_, ok := s[key]
	return ok
}

// copySet is frozenset(s): a fresh set, so a clause never aliases (and so a
// caller can never mutate) a shared EVIDENCE_TYPE_GROUPS entry.
func copySet(s map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for k := range s {
		out[k] = struct{}{}
	}
	return out
}

// mergeSets is set union (the disjunction INSIDE one clause's type set).
func mergeSets(a, b map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

// keysOf returns the key set of a type set (unsorted).
func keysOf(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

// listRepr renders a sorted list in Python's list-literal form.
func listRepr(names []string) string {
	parts := make([]string, len(names))
	for i, s := range names {
		parts[i] = validation.PyReprStr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// objAt is the findings-local dict lookup: the value for key, or Null when
// the key is absent (or the receiver is not an object).
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

// objStr is the string flavor of objAt ("" when absent or not a string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	return ""
}
