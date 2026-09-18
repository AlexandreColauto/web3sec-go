// gate.go: the CONFIRMED gate as STRUCTURED failures —
// reachability_diagnostic / confirmation_gate_detail / _confirmation_gates
// (webv2.findings). Every failure is {check_id, message, remediation};
// check_id is stable (the report and `webv2 gate explain` key on it) and
// remediation is the exact command that clears the check. The checks inspect
// live state (code), the answers are on the record (data) — and no failure is
// a dead end.
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// campaignPlaceholder is the campaign metavariable the remediation catalogs
// carry where the command must name the campaign. It is left in the exported
// maps because they are also the campaign-less catalog `webv2 gate --explain`
// prints; every operator-facing site that holds a campaign renders through
// NameCampaign, so the line it prints is copyable.
const campaignPlaceholder = "<campaign>"

// NameCampaign renders a remediation catalog entry for the campaign id in
// hand: the id replaces every <campaign> metavariable. An empty id (a caller
// that genuinely has no campaign) leaves the entry as the catalog wrote it —
// never an empty command.
func NameCampaign(entry, campaignID string) string {
	if campaignID == "" {
		return entry
	}
	return strings.ReplaceAll(entry, campaignPlaceholder, campaignID)
}

// GATE_REMEDIATION is GATE_REMEDIATION: the exact command that clears each
// check. Values are contractual; a value carrying <campaign> is a template
// rendered by NameCampaign (the gate holds the campaign, so its printed
// remediation names it; the campaign-less `webv2 gate --explain` shows the
// template).
var GATE_REMEDIATION = map[string]string{
	"critic-verdict": "webv2 verdict <campaign> <fid> --verdict confirmed " +
		"--reason '<reasoning>'",
	"memory-check": "webv2 recall <campaign> --finding <fid>   (records a " +
		"graph-memory consultation)",
	"reproduction-reproduced": "webv2 mint <fid> --exec <EXEC-ID>   (a " +
		"reproduced attempt, sandboxed)",
	"evidence-floor": "webv2 mint <fid> --exec <EXEC-ID>   (or, for a NAMED " +
		"decision: webv2 floors set — an override, logged, never a silent " +
		"edit). Economic-class E7: when no USD figure is defensible, record " +
		"the decision instead — webv2 impact <campaign> <fid> --unpriceable " +
		"--ceiling '<capacity basis>' --reason '<why>' --actor <you>",
	"evidence-floor-unreachable": "webv2 snap / export FORK_RPC_URL   (make " +
		"the evidence reachable) — or webv2 floors set to record the override " +
		"as a decision",
	"snapshot-compatible": "webv2 snap   (re-pin the target and re-verify the " +
		"finding against it)",
	"shield-adjudication": "webv2 shield <fid> --extraction --reason '<why the " +
		"effect is still extraction despite being documented as intended>' " +
		"--actor <you>",
	"claim-drift": "make the claim and the measurement agree: fix the title, " +
		"or re-run the PoC and re-measure extraction_ratio",
	"reproduction-tier": "webv2 mint <campaign> <fid> --exec <fork exec> " +
		"--description '...' --tier T3   (record the fork-tier attempt the " +
		"evidence is based on)",
	"invariant-unverified": "webv2 invariant-verify <campaign> <INV-ID> " +
		"--artifact <ART-ID>   (check the statement against code; the artifact " +
		"must be registered)",
	"sequence-coverage": "webv2 sequence run <spec-file> --finding <fid>   " +
		"(a T4 sequence PoC covering the declared exploit_sequence)",
}

// ---- seams into modules that land later (invariants: Task 8; reproduction /
// ---- sequence_poc / planner / taxonomy: their own tasks). The defaults are
// ---- the safe no-ops; Set* wires the real implementation.

// normalizeInvIDFunc is invariants.normalize_inv_id (INV-001 -> INV-1). The
// default is the Python semantics verbatim — every gate comparison keys on
// the canonical spelling, so an identity default would silently split
// INV-005 from INV-5. SetNormalizeInvID re-wires it to the invariants module.
var invIDRe = regexp.MustCompile(`^INV-([0-9]+)$`)

var normalizeInvIDFunc = func(iid string) string {
	m := invIDRe.FindStringSubmatch(iid)
	if m == nil {
		return iid
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return iid
	}
	return "INV-" + strconv.FormatInt(n, 10)
}

// SetNormalizeInvID wires invariants.normalize_inv_id (Task 8).
func SetNormalizeInvID(f func(string) string) {
	if f == nil {
		panic("findings: nil normalize_inv_id")
	}
	normalizeInvIDFunc = f
}

// loadInvariantLinksFunc is invariants.load_links: the registry document
// ({"invariants": {...}}).
var loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
	return validation.VObj(), nil
}

// SetLoadInvariantLinks wires invariants.load_links (Task 8).
func SetLoadInvariantLinks(f func(*state.Campaign) (validation.Value, error)) {
	if f == nil {
		panic("findings: nil invariant links loader")
	}
	loadInvariantLinksFunc = f
}

// documentedInvariantsFunc is invariants.documented_invariants: the ids the
// target documents about itself (keyed by canonical id).
var documentedInvariantsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
	return map[string]validation.Value{}, nil
}

// SetDocumentedInvariants wires invariants.documented_invariants (Task 8).
func SetDocumentedInvariants(f func(*state.Campaign) (map[string]validation.Value, error)) {
	if f == nil {
		panic("findings: nil documented-invariants loader")
	}
	documentedInvariantsFunc = f
}

// invariantVerifiedFunc is invariants._is_verified: the log-anchored verdict.
var invariantVerifiedFunc = func(entry validation.Value, c *state.Campaign,
	iid string, events []validation.Value) bool {
	return false
}

// SetInvariantVerified wires invariants._is_verified (Task 8).
func SetInvariantVerified(f func(validation.Value, *state.Campaign, string,
	[]validation.Value) bool) {
	if f == nil {
		panic("findings: nil invariant verifier")
	}
	invariantVerifiedFunc = f
}

// intentClaimsFunc is invariants.intent_claims: documented invariants whose
// text carries intent language, keyed by canonical id.
var intentClaimsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
	return map[string]validation.Value{}, nil
}

// SetIntentClaims wires invariants.intent_claims (Task 8).
func SetIntentClaims(f func(*state.Campaign) (map[string]validation.Value, error)) {
	if f == nil {
		panic("findings: nil intent-claims loader")
	}
	intentClaimsFunc = f
}

// reproductionTierOrderFunc is reproduction.TIER_ORDER. The default is the
// Python constant verbatim; a wiring agent may override it.
var reproductionTierOrderFunc = func() []string {
	return []string{"none", "T0", "T1", "T2", "T3", "T4"}
}

// SetReproductionTierOrder wires reproduction.TIER_ORDER.
func SetReproductionTierOrder(f func() []string) {
	if f == nil {
		panic("findings: nil tier order")
	}
	reproductionTierOrderFunc = f
}

// onchainSequenceRequiredFunc is sequence_poc.onchain_sequence_required.
var onchainSequenceRequiredFunc = func(*state.Campaign, validation.Value) bool {
	return false
}

// SetOnchainSequenceRequired wires sequence_poc.onchain_sequence_required.
func SetOnchainSequenceRequired(f func(*state.Campaign, validation.Value) bool) {
	if f == nil {
		panic("findings: nil sequence-required predicate")
	}
	onchainSequenceRequiredFunc = f
}

// verifySequenceCoverageFunc is sequence_poc.verify_sequence_coverage:
// (covered, reasons).
var verifySequenceCoverageFunc = func(*state.Campaign, validation.Value,
	validation.Value) (bool, []string) {
	return false, nil
}

// SetVerifySequenceCoverage wires sequence_poc.verify_sequence_coverage.
func SetVerifySequenceCoverage(f func(*state.Campaign, validation.Value,
	validation.Value) (bool, []string)) {
	if f == nil {
		panic("findings: nil sequence coverage verifier")
	}
	verifySequenceCoverageFunc = f
}

// GateFailure is one structured CONFIRMED-gate failure. The field order is
// the Python dict order; Value renders that dict.
type GateFailure struct {
	CheckID     string
	Message     string
	Remediation string
}

// Value renders the failure as the Python {check_id, message, remediation}.
func (g GateFailure) Value() validation.Value {
	return validation.VObj(
		validation.KV{K: "check_id", V: validation.VStr(g.CheckID)},
		validation.KV{K: "message", V: validation.VStr(g.Message)},
		validation.KV{K: "remediation", V: validation.VStr(g.Remediation)},
	)
}

// Clause is one live CONFIRMED-gate clause with its verdict
// (confirmation_gate_clauses' dict). Subject is Python's optional "subject"
// key: a clause that is ONE of several sharing a check id (an invariant id)
// carries it, so the checklist and the delta can tell them apart.
type Clause struct {
	CheckID     string
	OK          bool
	Message     string
	Remediation string
	Subject     *string
}

// Value renders the clause as the Python dict in key order:
// {check_id, ok, message, remediation} (+ subject when truthy).
func (cl Clause) Value() validation.Value {
	out := validation.VObj(
		validation.KV{K: "check_id", V: validation.VStr(cl.CheckID)},
		validation.KV{K: "ok", V: validation.VBool(cl.OK)},
		validation.KV{K: "message", V: validation.VStr(cl.Message)},
		validation.KV{K: "remediation", V: validation.VStr(cl.Remediation)},
	)
	if cl.Subject != nil && *cl.Subject != "" {
		out.O = append(out.O, validation.KV{K: "subject",
			V: validation.VStr(*cl.Subject)})
	}
	return out
}

// ID is findings.clause_id: the check id, qualified by its subject.
func (cl Clause) ID() string {
	if cl.Subject != nil && *cl.Subject != "" {
		return cl.CheckID + "[" + *cl.Subject + "]"
	}
	return cl.CheckID
}

// ClauseID is findings.clause_id for a clause value.
func ClauseID(cl Clause) string { return cl.ID() }

// FailingCheckIDs is _failing_check_ids: the failing clause ids, first
// appearance order, de-duplicated — what a refused CONFIRMED transition
// records so the next dry run can show the delta.
func FailingCheckIDs(clauses []Clause) []string {
	seen := []string{}
	for _, cl := range clauses {
		cid := cl.ID()
		if !cl.OK && !slices.Contains(seen, cid) {
			seen = append(seen, cid)
		}
	}
	return seen
}

// EconomicClausePresent is economic_clause_present: this finding's CONFIRMED
// gate HAS an economic-class clause — the E7 quantification a recorded
// UNPRICEABLE decision can satisfy (identified by its own `decision` marker
// in gate_requirements, the same live logic the gate uses).
func EconomicClausePresent(campaign *state.Campaign, finding validation.Value) bool {
	cls := ""
	if v := validation.ObjAt(asDict(validation.ObjAt(finding, "root_cause")), "class"); v.Kind ==
		validation.Str {
		cls = v.S
	}
	for _, cl := range GateRequirements("CONFIRMED", cls, campaign) {
		if cl.Decision == "unpriceable" {
			return true
		}
	}
	return false
}

// asDict is _as_dict: fail-closed normalization for unvalidated on-disk
// blocks — a non-dict block behaves as an absent block so gate checks fail
// closed instead of raising AttributeError (the load path does not validate).
func asDict(v validation.Value) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VObj()
	}
	return v
}

// sortedSetKeys is sorted(set): the members in ascending order.
func sortedSetKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// firstRunes is Python's s[:n] (code-point slicing).
func firstRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// activeForkTargetPin reads the ACTIVE snapshot's pin manifest — the same
// FILE sequencepoc reads for snapshot_has_fork_target, in the immutable tree,
// never the state mirror.
//
// The triple is (pin, present, err). present=false with err=nil is the FACT
// that there is no active snapshot or no pin manifest at all (ENOENT). Any
// other stat/read failure is a REFUSAL naming the path and the errno: a pin
// the tool could not read must never be folded into "no deployment/chain pin"
// (r45b — the r44 pinnedCompiler shape).
func activeForkTargetPin(campaign *state.Campaign) (validation.Value, bool, error) {
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), false, err
	}
	if sid == nil || *sid == "" {
		return validation.VNull(), false, nil
	}
	pinPath := filepath.Join(campaign.Dir, "snapshots", *sid, "snapshot.json")
	if st, serr := os.Stat(pinPath); serr != nil {
		if os.IsNotExist(serr) {
			return validation.VNull(), false, nil
		}
		return validation.VNull(), false, fmt.Errorf(
			"the active snapshot's pin manifest %s cannot be read: %v",
			pinPath, serr)
	} else if st.IsDir() {
		return validation.VNull(), false, fmt.Errorf(
			"the active snapshot's pin manifest %s is a directory", pinPath)
	}
	pin, rerr := validation.ReadJson(pinPath)
	if rerr != nil {
		return validation.VNull(), false, fmt.Errorf(
			"the active snapshot's pin manifest %s cannot be read: %v",
			pinPath, rerr)
	}
	return pin, true, nil
}

// ReachabilityDiagnostic is reachability_diagnostic: the structural
// prerequisites for reaching *minLevel* IN THIS CAMPAIGN. E5/E6 evidence is
// not a matter of effort but of infrastructure. bugClass nil is Python's
// None (conservative: every class is treated as cross-chain).
func ReachabilityDiagnostic(campaign *state.Campaign, minLevel string,
	bugClass *string) ([]string, error) {
	li, err := LevelIndex(minLevel)
	if err != nil {
		return nil, err
	}
	e5 := levelIndexValue("E5")
	if li < e5 {
		return []string{}, nil
	}
	missing := []string{}
	// the state mirror carries only the lean registry row (id/pass/pinned);
	// the pins themselves live in the snapshot FILE inside the immutable
	// tree — read the file, not the mirror.
	pin, present, err := activeForkTargetPin(campaign)
	if err != nil {
		return nil, err
	}
	hasDep, hasChain := false, false
	if present {
		hasDep = validation.PyTruthy(validation.ObjAt(pin, "deployment"))
		hasChain = validation.PyTruthy(validation.ObjAt(pin, "chain"))
	}
	if !(hasDep || hasChain) {
		missing = append(missing,
			"no deployment/chain pin on the active snapshot — fork evidence "+
				"(E5+) has no fork target, for single-call PoCs and multi-tx "+
				"sequence PoCs (`webv2 sequence run`) alike; pin one "+
				"(`webv2 snap`) or record a floor override (`webv2 floors set`)")
	}
	e6 := levelIndexValue("E6")
	if li >= e6 && !hasChain {
		// Class-aware: the cross-chain-witness requirement applies only to
		// classes whose E6 flavor IS a cross-chain witness. Campaign-level
		// calls (bug_class=None) keep the conservative warning.
		if bugClass == nil || inSet(CROSS_CHAIN_E6_CLASSES, *bugClass) {
			missing = append(missing, "no chain pin on the active snapshot — "+
				"cross-chain witnesses (E6) need one")
		}
	}
	if os.Getenv("FORK_RPC_URL") == "" {
		missing = append(missing, "FORK_RPC_URL is not set — the fork-runner "+
			"profile cannot reach a chain")
	}
	return missing, nil
}

// invariantIDs is _invariant_ids: every invariant id a finding hangs off
// (singular + structured list), in canonical form so zero-padded citations
// match the registry regardless of spelling.
func invariantIDs(finding validation.Value) []string {
	var ids []string
	if iid := validation.ObjAt(asDict(validation.ObjAt(finding, "invariant")), "id"); validation.PyTruthy(iid) &&
		iid.Kind == validation.Str {
		ids = append(ids, normalizeInvIDFunc(iid.S))
	}
	sec := validation.ObjAt(finding, "security_invariants")
	if !validation.PyTruthy(sec) || sec.Kind != validation.Arr {
		return ids
	}
	for _, s := range sec.A {
		if s.Kind != validation.Obj {
			continue
		}
		id := validation.ObjAt(s, "id")
		if !validation.PyTruthy(id) || id.Kind != validation.Str {
			continue
		}
		nid := normalizeInvIDFunc(id.S)
		if nid != "" && !slices.Contains(ids, nid) {
			ids = append(ids, nid)
		}
	}
	return ids
}

// bugClassPtr is _as_dict(...).get("class") as Python's None-vs-str: nil for
// an absent/null class, else the string.
func bugClassPtr(v validation.Value) *string {
	if v.Kind != validation.Str {
		return nil
	}
	s := v.S
	return &s
}

// tierBelowT3 is (tier not in TIER_ORDER or index(tier) < index("T3")).
func tierBelowT3(tier validation.Value, order []string) bool {
	if tier.Kind != validation.Str {
		return true
	}
	i, j := indexOfStr(order, tier.S), indexOfStr(order, "T3")
	if i < 0 {
		return true
	}
	return i < j
}

func indexOfStr(items []string, want string) int {
	for i, it := range items {
		if it == want {
			return i
		}
	}
	return -1
}

// ConfirmationGateClauses is confirmation_gate_clauses: the CONFIRMED gate
// as EVERY live clause with its verdict, in gate order. This is the single
// source of the clause set — ConfirmationGateDetail is the failing-only view
// built from it, ConfirmationGates renders those failures for the transition
// error message, and `gate --dry-run` prints the whole checklist. A clause
// appears only when it APPLIES to this finding (the invariant shield clause,
// the on-chain sequence clause) — the live set the transition itself uses,
// never a hand-maintained list.
func ConfirmationGateClauses(campaign *state.Campaign,
	finding validation.Value) ([]Clause, error) {
	g := &gateRun{campaign: campaign, finding: finding, out: []Clause{}}
	ver := asDict(validation.ObjAt(finding, "verification"))
	repro := asDict(validation.ObjAt(ver, "reproduction"))
	g.criticVerdict(ver)
	if err := g.memoryCheck(finding); err != nil {
		return nil, err
	}
	g.reproduction(repro)
	floor, err := g.evidenceFloor(finding)
	if err != nil {
		return nil, err
	}
	g.reproductionTier(repro, floor)
	if err := g.sequenceCoverage(repro); err != nil {
		return nil, err
	}
	g.snapshotCompatible()
	if err := g.shield(ver); err != nil {
		return nil, err
	}
	if err := g.invariants(finding); err != nil {
		return nil, err
	}
	return g.claimDrift(finding)
}

// ConfirmationGateDetail is confirmation_gate_detail: the CONFIRMED gate as
// structured failures, in the contractual check order — the failing-only view
// of ConfirmationGateClauses.
func ConfirmationGateDetail(campaign *state.Campaign,
	finding validation.Value) ([]GateFailure, error) {
	clauses, err := ConfirmationGateClauses(campaign, finding)
	if err != nil {
		return nil, err
	}
	out := []GateFailure{}
	for _, cl := range clauses {
		if cl.OK {
			continue
		}
		out = append(out, GateFailure{CheckID: cl.CheckID, Message: cl.Message,
			Remediation: cl.Remediation})
	}
	return out, nil
}

// gateRun carries the gate state across the per-check helpers so each stays
// well under the length limit.
type gateRun struct {
	campaign *state.Campaign
	finding  validation.Value
	out      []Clause
}

// remediation renders the catalog entry for checkID with the campaign id the
// run holds, so a printed fix line is a command the operator can copy.
func (g *gateRun) remediation(checkID string) string {
	cid := ""
	if g.campaign != nil {
		cid = g.campaign.CampaignID
	}
	return NameCampaign(GATE_REMEDIATION[checkID], cid)
}

func (g *gateRun) fail(checkID, message string, subject *string) {
	g.out = append(g.out, Clause{CheckID: checkID, OK: false, Message: message,
		Remediation: g.remediation(checkID), Subject: subject})
}

func (g *gateRun) satisfied(checkID string, subject *string) {
	g.out = append(g.out, Clause{CheckID: checkID, OK: true,
		Remediation: g.remediation(checkID), Subject: subject})
}

func (g *gateRun) criticVerdict(ver validation.Value) {
	v := validation.ObjAt(ver, "critic_verdict")
	if v.Kind != validation.Str || v.S != "confirmed" {
		g.fail("critic-verdict", "hostile critic verdict is "+
			validation.PyRepr(v)+", need 'confirmed'", nil)
		return
	}
	g.satisfied("critic-verdict", nil)
}

func (g *gateRun) memoryCheck(finding validation.Value) error {
	msg, err := MemoryCheckFails(g.campaign, validation.ObjStr(finding, "finding_id"))
	if err != nil {
		return err
	}
	if msg != nil {
		g.fail("memory-check", *msg, nil)
		return nil
	}
	g.satisfied("memory-check", nil)
	return nil
}

func (g *gateRun) reproduction(repro validation.Value) {
	if s := validation.ObjAt(repro, "status"); s.Kind != validation.Str ||
		s.S != "reproduced" {
		g.fail("reproduction-reproduced", "reproduction status is "+
			validation.PyRepr(s)+", need 'reproduced'", nil)
		return
	}
	g.satisfied("reproduction-reproduced", nil)
}

// evidenceFloor appends evidence-floor (and the unreachable diagnostic) and
// returns the class floor the later tier check keys on.
func (g *gateRun) evidenceFloor(finding validation.Value) (string, error) {
	classV := validation.ObjAt(asDict(validation.ObjAt(finding, "root_cause")), "class")
	bugClass := ""
	if classV.Kind == validation.Str {
		bugClass = classV.S
	}
	floor := RequiredLevelForCampaign(g.campaign, "CONFIRMED", bugClass)
	deficit := EvidenceDeficit(finding, "CONFIRMED", g.campaign)
	if deficit == nil {
		g.satisfied("evidence-floor", nil)
		return floor, nil
	}
	g.fail("evidence-floor", *deficit, nil)
	fi, err := LevelIndex(floor)
	if err != nil {
		return floor, err
	}
	e5 := levelIndexValue("E5")
	if fi < e5 {
		return floor, nil
	}
	diag, err := ReachabilityDiagnostic(g.campaign, floor, bugClassPtr(classV))
	if err != nil {
		return floor, err
	}
	if len(diag) > 0 {
		g.fail("evidence-floor-unreachable",
			"structurally unreachable in this campaign: "+
				strings.Join(diag, "; ")+" — if the target truly cannot produce "+
				"that evidence, record the decision with `webv2 floors set` "+
				"instead of editing the framework's floor table", nil)
	}
	return floor, nil
}

func (g *gateRun) reproductionTier(repro validation.Value, floor string) {
	fi, err := LevelIndex(floor)
	if err != nil {
		return
	}
	e5 := levelIndexValue("E5")
	if fi < e5 {
		return
	}
	tier := validation.ObjAt(repro, "tier_reached")
	if _, ok := fieldAt(repro, "tier_reached"); !ok {
		tier = validation.VStr("none")
	}
	if !tierBelowT3(tier, reproductionTierOrderFunc()) {
		g.satisfied("reproduction-tier", nil)
		return
	}
	g.fail("reproduction-tier", fmt.Sprintf("evidence floor %s demands a "+
		"fork-level reproduction (T3+), but tier_reached is %s — record the "+
		"fork-tier attempt (record_attempt / attempt_and_mint) before "+
		"confirming", floor, validation.PyRepr(tier)), nil)
}

func (g *gateRun) sequenceCoverage(repro validation.Value) error {
	if !onchainSequenceRequiredFunc(g.campaign, g.finding) {
		return nil
	}
	// r45b: the predicate is fail-closed on a pin the tool could not read
	// (it answers "required", never "not required"). Read the pin here as
	// well: when THAT read fails, the clause cannot be judged, so the gate
	// refuses with the path and the errno instead of reporting missing
	// sequence coverage the operator cannot act on. A genuinely absent pin
	// (ENOENT) is a fact and falls through to the normal clause.
	if _, _, err := activeForkTargetPin(g.campaign); err != nil {
		return err
	}
	execs, err := state.AllExecs(g.campaign)
	if err != nil {
		return err
	}
	byID := make(map[string]validation.Value, len(execs))
	for _, r := range execs {
		if id := validation.ObjStr(r, "exec_id"); id != "" {
			byID[id] = r
		}
	}
	attempts := validation.ObjAt(repro, "attempts")
	if attempts.Kind != validation.Arr {
		attempts = validation.VArr()
	}
	for _, a := range attempts.A {
		if a.Kind != validation.Obj {
			continue
		}
		rec, ok := byID[validation.ObjStr(a, "artifact_id")]
		if !ok {
			continue
		}
		if covered, _ := verifySequenceCoverageFunc(g.campaign, g.finding,
			rec); covered {
			g.satisfied("sequence-coverage", nil)
			return nil
		}
	}
	g.fail("sequence-coverage", "declared exploit_sequence needs a multi-tx "+
		"PoC — no recorded attempt traces to an exec with verified sequence "+
		"coverage (single-call PoCs cannot cover it)", nil)
	return nil
}

func (g *gateRun) snapshotCompatible() {
	// Python calls assert_snapshot_compatible(campaign, finding) with its
	// strict default (True) and folds the mismatch into a gate failure.
	if _, err := snapshot.AssertSnapshotCompatible(g.campaign, g.finding,
		true); err != nil {
		g.fail("snapshot-compatible", err.Error(), nil)
		return
	}
	g.satisfied("snapshot-compatible", nil)
}

func (g *gateRun) shield(ver validation.Value) error {
	iid := validation.ObjAt(asDict(validation.ObjAt(g.finding, "invariant")), "id")
	if !validation.PyTruthy(iid) || iid.Kind != validation.Str {
		return nil
	}
	claims, err := intentClaimsFunc(g.campaign)
	if err != nil {
		return err
	}
	claim, ok := claims[normalizeInvIDFunc(iid.S)]
	if !ok || !validation.PyTruthy(claim) {
		return nil
	}
	if validation.PyTruthy(validation.ObjAt(ver, "shield_adjudication")) {
		g.satisfied("shield-adjudication", nil)
		return nil
	}
	g.fail("shield-adjudication", fmt.Sprintf("invariant %s is documented as "+
		"intended (%s) — record the extraction adjudication before CONFIRMED",
		iid.S, firstRunes(validation.ObjStr(claim, "intent_line"), 100)), nil)
	return nil
}

func (g *gateRun) invariants(finding validation.Value) error {
	links, err := loadInvariantLinksFunc(g.campaign)
	if err != nil {
		return err
	}
	reg := asDict(validation.ObjAt(links, "invariants"))
	normReg := make(map[string]validation.Value, len(reg.O))
	for _, kv := range reg.O {
		if kv.V.Kind == validation.Obj {
			normReg[normalizeInvIDFunc(kv.K)] = kv.V
		}
	}
	doc, err := documentedInvariantsFunc(g.campaign)
	if err != nil {
		return err
	}
	events, err := g.campaign.Events()
	if err != nil {
		return err
	}
	for _, iid := range invariantIDs(finding) {
		subj := iid
		e, ok := normReg[iid]
		if !ok {
			g.fail("invariant-unverified", "invariant-unverified: "+iid+
				" not in registry — seed it or correct the id", &subj)
			continue
		}
		if _, isDoc := doc[iid]; isDoc || validation.ObjStr(e, "source") == "documented" {
			g.satisfied("invariant-unverified", &subj)
			continue
		}
		if !invariantVerifiedFunc(e, g.campaign, iid, events) {
			g.fail("invariant-unverified", fmt.Sprintf("invariant %s has "+
				"status %s — verify it against code before CONFIRMED", iid,
				validation.PyRepr(validation.ObjAt(e, "status"))), &subj)
			continue
		}
		g.satisfied("invariant-unverified", &subj)
	}
	return nil
}

func (g *gateRun) claimDrift(finding validation.Value) ([]Clause, error) {
	problems, err := ClaimDriftProblems(finding)
	if err != nil {
		return nil, err
	}
	for _, p := range problems {
		g.fail("claim-drift", p, nil)
	}
	if len(problems) == 0 {
		g.satisfied("claim-drift", nil)
	}
	return g.out, nil
}

// ConfirmationGates is _confirmation_gates: the failed gates rendered as
// "<check_id>: <message>" strings (the transition error message).
func ConfirmationGates(campaign *state.Campaign,
	finding validation.Value) ([]string, error) {
	detail, err := ConfirmationGateDetail(campaign, finding)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(detail))
	for i, c := range detail {
		out[i] = c.CheckID + ": " + c.Message
	}
	return out, nil
}
