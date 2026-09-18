package findings

import (
	"slices"
	"sort"
	"strings"

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
