// Package trajectory is the port of webv2/trajectory.py: the typed model-event
// family + its integrity report.
//
// The campaign event log is hash-chained; the model boundary writes the
// model.* events into it directly. What the chain alone cannot see is DRIFT
// inside an event: a hand-written model.request without its context_hash
// chains perfectly well. This module closes that gap — record_model_event
// validates the payload against the event's definition in
// trajectory.schema.json BEFORE logging, record_outcome carries the gold
// outcome with the same posture, model_trajectory projects the log, and
// verify_trajectory reports (never raises).
package trajectory

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// TRAJECTORY_SCHEMA_VERSION is TRAJECTORY_SCHEMA_VERSION.
const TRAJECTORY_SCHEMA_VERSION = 2

// ModelEventTypes maps a model.* event type to its definition name in
// trajectory.schema.json. "outcome" is NOT model traffic — it is the
// harness-written training-metadata carrier — but it is registered in the
// same map so model_trajectory() projects it (role: null) and
// verify_trajectory validates it with the same machinery.
var ModelEventTypes = []struct{ Event, Definition string }{
	{"model.request", "model_request"},
	{"model.rejected", "model_rejected"},
	{"model.response", "model_response"},
	{"model.plan_received", "model_plan_received"},
	{"model.reproducer_request", "model_reproducer_request"},
	{"outcome", "outcome"},
}

var eventDefinition = func() map[string]string {
	m := map[string]string{}
	for _, e := range ModelEventTypes {
		m[e.Event] = e.Definition
	}
	return m
}()

// ModelEventTypeNames is sorted(MODEL_EVENT_TYPES) — the error-message order.
func ModelEventTypeNames() []string {
	out := make([]string, 0, len(ModelEventTypes))
	for _, e := range ModelEventTypes {
		out = append(out, e.Event)
	}
	sort.Strings(out)
	return out
}

// OutcomeValues is OUTCOME_VALUES: the gold outcome vocabulary.
var OutcomeValues = []string{
	"confirmed-exploitable", "confirmed-not-exploitable", "disproved",
	"out-of-scope", "duplicate", "economic-no-go", "unfinished",
}

// FindingStatuses is FINDING_STATUSES = frozenset(ALLOWED_TRANSITIONS).
func FindingStatuses() []string {
	out := make([]string, 0, len(findings.ALLOWED_TRANSITIONS))
	for k := range findings.ALLOWED_TRANSITIONS {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// UnreadableCaseReason is UNREADABLE_CASE_REASON: the fail-closed
// exclude_reason when a linked case's partition cannot be read.
const UnreadableCaseReason = "case partition unreadable (fail closed)"

// EvalStore is the eval_store seam (a parallel-wave deliverable). When it is
// absent every case-linked derivation fails CLOSED; a row with no case_id
// stays visible. Tests install a stub to exercise every branch.
type EvalStore interface {
	LoadCase(caseID string) (validation.Value, error)
}

var evalStore EvalStore

// SetEvalStore installs the eval store (nil restores the absent default).
func SetEvalStore(s EvalStore) { evalStore = s }

// contractFailures is _contract_failures.
func contractFailures(data validation.Value, definition string) ([]string, error) {
	return validation.ValidateDefinitionFailures(data, "trajectory", definition)
}

// RecordModelEvent is record_model_event: validate the payload against its
// trajectory definition, then append it to the hash-chained log. Unknown
// event type or contract failure raises and logs NOTHING.
func RecordModelEvent(campaign *state.Campaign, eventType string,
	data validation.Value, ref *string) (validation.Value, error) {
	definition, ok := eventDefinition[eventType]
	if !ok {
		return validation.VNull(), fmt.Errorf(
			"unknown model event type %s; known: %s",
			validation.PyReprStr(eventType), validation.PyListRepr(ModelEventTypeNames()))
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf(
			"%s data must be a JSON object, got %s", eventType, pyTypeName(data))
	}
	failures, err := contractFailures(data, definition)
	if err != nil {
		return validation.VNull(), err
	}
	if len(failures) > 0 {
		n := len(failures)
		if n > 5 {
			n = 5
		}
		return validation.VNull(), fmt.Errorf(
			"%s trajectory contract failure: %s", eventType,
			strings.Join(failures[:n], "; "))
	}
	d := data
	return campaign.Log(eventType, ref, &d)
}

// casePartition is _case_partition: the linked case's partition, or Null when
// it cannot be read — the sentinel record_outcome treats as fail-closed.
func casePartition(caseID string) validation.Value {
	if evalStore == nil {
		return validation.VNull()
	}
	loaded, err := loadCaseSafely(caseID)
	if err != nil || loaded.Kind != validation.Obj {
		return validation.VNull()
	}
	p := validation.ObjAt(loaded, "partition")
	if p.Kind == validation.Str {
		return p
	}
	return validation.VNull()
}

// loadCaseSafely contains a panicking/erroring store loader (Python's
// `except Exception`).
func loadCaseSafely(caseID string) (out validation.Value, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = validation.VNull(), fmt.Errorf("store panic")
		}
	}()
	return evalStore.LoadCase(caseID)
}

// DeriveTraining is _derive_training: the training-usability decision.
func DeriveTraining(caseID validation.Value, excluded bool,
	excludeReason validation.Value) validation.Value {
	if excluded || excludeReason.Kind != validation.Null {
		vis := "visible"
		if excluded {
			vis = "hidden"
		}
		return validation.VObj(
			validation.KV{K: "visibility", V: validation.VStr(vis)},
			validation.KV{K: "excluded", V: validation.VBool(excluded)},
			validation.KV{K: "exclude_reason", V: excludeReason})
	}
	if caseID.Kind == validation.Null {
		return visibleTraining()
	}
	partition := casePartition(caseID.S)
	if partition.Kind == validation.Str && partition.S == "dev" {
		return visibleTraining()
	}
	if partition.Kind == validation.Str &&
		(partition.S == "held-out" || partition.S == "training") {
		return excludedTraining(fmt.Sprintf("case partition %s — leakage guard",
			validation.PyReprStr(partition.S)))
	}
	if partition.Kind == validation.Null {
		return excludedTraining(UnreadableCaseReason)
	}
	return excludedTraining(fmt.Sprintf("case partition %s unrecognized "+
		"(fail closed)", validation.PyReprStr(partition.S)))
}

func visibleTraining() validation.Value {
	return validation.VObj(
		validation.KV{K: "visibility", V: validation.VStr("visible")},
		validation.KV{K: "excluded", V: validation.VBool(false)},
		validation.KV{K: "exclude_reason", V: validation.VNull()})
}

func excludedTraining(reason string) validation.Value {
	return validation.VObj(
		validation.KV{K: "visibility", V: validation.VStr("hidden")},
		validation.KV{K: "excluded", V: validation.VBool(true)},
		validation.KV{K: "exclude_reason", V: validation.VStr(reason)})
}

// OutcomeOpts carries record_outcome's keyword arguments.
type OutcomeOpts struct {
	FinalStatus       string
	FinalEvidenceTier string
	CaseID            *string
	Excluded          bool
	ExcludeReason     *string
}

// RecordOutcome is record_outcome: write the outcome event (the
// training-metadata carrier) with the validate-before-write posture.
func RecordOutcome(campaign *state.Campaign, findingID, outcome string,
	o OutcomeOpts) (validation.Value, error) {
	if !slices.Contains(OutcomeValues, outcome) {
		return validation.VNull(), fmt.Errorf("unknown outcome %s; known: %s",
			validation.PyReprStr(outcome), validation.PyListRepr(OutcomeValues))
	}
	if !slices.Contains(findings.EVIDENCE_ORDER, o.FinalEvidenceTier) {
		return validation.VNull(), fmt.Errorf(
			"unknown evidence tier %s; the ladder is %s",
			validation.PyReprStr(o.FinalEvidenceTier),
			validation.PyListRepr(findings.EVIDENCE_ORDER))
	}
	statuses := FindingStatuses()
	if !slices.Contains(statuses, o.FinalStatus) {
		return validation.VNull(), fmt.Errorf(
			"unknown final_status %s; the finding status vocabulary is %s",
			validation.PyReprStr(o.FinalStatus), validation.PyListRepr(statuses))
	}
	if o.Excluded && (o.ExcludeReason == nil ||
		strings.TrimSpace(*o.ExcludeReason) == "") {
		return validation.VNull(), fmt.Errorf("exclude_reason is required when " +
			"excluded — an exclusion is a written decision, never a silent drop")
	}
	if _, err := findings.LoadFinding(campaign, findingID); err != nil {
		return validation.VNull(), fmt.Errorf(
			"outcome names finding %s, which does not exist in campaign %s",
			validation.PyReprStr(findingID), campaign.CampaignID)
	}
	caseID := validation.VNull()
	if o.CaseID != nil {
		caseID = validation.VStr(*o.CaseID)
	}
	reason := validation.VNull()
	if o.ExcludeReason != nil {
		reason = validation.VStr(*o.ExcludeReason)
	}
	data := validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(campaign.CampaignID)},
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "final_status", V: validation.VStr(o.FinalStatus)},
		validation.KV{K: "final_evidence_tier", V: validation.VStr(o.FinalEvidenceTier)},
		validation.KV{K: "finding_id", V: validation.VStr(findingID)},
		validation.KV{K: "case_id", V: caseID},
		validation.KV{K: "training", V: DeriveTraining(caseID, o.Excluded, reason)},
		validation.KV{K: "at", V: validation.VStr(state.NowIso())},
	)
	ref := findingID
	return RecordModelEvent(campaign, "outcome", data, &ref)
}

// ModelTrajectory is model_trajectory: the model.* projection of the log, in
// seq order.
func ModelTrajectory(campaign *state.Campaign) ([]validation.Value, error) {
	events, err := campaign.Events()
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, e := range events {
		etype := validation.ObjAt(e, "type")
		if etype.Kind != validation.Str {
			continue
		}
		if _, ok := eventDefinition[etype.S]; !ok {
			continue
		}
		data := validation.ObjAt(e, "data")
		role := validation.VNull()
		if data.Kind == validation.Obj {
			if r := validation.ObjAt(data, "role"); r.Kind == validation.Str {
				role = r
			}
		}
		out = append(out, validation.VObj(
			validation.KV{K: "seq", V: validation.ObjAt(e, "seq")},
			validation.KV{K: "at", V: validation.ObjAt(e, "at")},
			validation.KV{K: "type", V: etype},
			validation.KV{K: "role", V: role},
			validation.KV{K: "ref", V: validation.ObjAt(e, "ref")},
			validation.KV{K: "data", V: data},
			validation.KV{K: "event_hash", V: validation.ObjAt(e, "event_hash")},
		))
	}
	return out, nil
}

// VerifyTrajectory is verify_trajectory: the integrity report. A reporter,
// never a raiser.
func VerifyTrajectory(campaign *state.Campaign) (validation.Value, error) {
	problems := []string{}
	logReport, err := campaign.VerifyLog()
	if err != nil {
		return validation.VNull(), err
	}
	if !logReport.OK {
		problems = append(problems, logReport.Problems...)
		return validation.VObj(
			validation.KV{K: "ok", V: validation.VBool(false)},
			validation.KV{K: "events", V: validation.VInt(0)},
			validation.KV{K: "problems", V: validation.VArr(strsToVals(problems)...)},
		), nil
	}
	events, err := campaign.Events()
	if err != nil {
		return validation.VNull(), err
	}
	modelEvents := []validation.Value{}
	for _, e := range events {
		etype := validation.ObjAt(e, "type")
		if etype.Kind == validation.Str {
			if _, ok := eventDefinition[etype.S]; ok {
				modelEvents = append(modelEvents, e)
			}
		}
	}
	for _, e := range modelEvents {
		found, err := eventProblems(campaign, e)
		if err != nil {
			return validation.VNull(), err
		}
		problems = append(problems, found...)
	}
	n := len(problems)
	if n > 10 {
		n = 10
	}
	return validation.VObj(
		validation.KV{K: "ok", V: validation.VBool(len(problems) == 0)},
		validation.KV{K: "events", V: validation.VInt(int64(len(modelEvents)))},
		validation.KV{K: "problems",
			V: validation.VArr(strsToVals(problems[:n])...)},
	), nil
}

// eventProblems is the per-event integrity check: the data contract, plus
// every `ref`/`data.finding_id` that names an F- finding must resolve to
// readable finding JSON. A malformed event reports; an unreadable contract
// is a real error and is returned.
//
// The finding probe keeps its three cases apart, like every other reader of
// the findings store (r43b/P3-2): ENOENT is absence and is reported as such;
// any other stat failure is a read failure, reported by naming the path and
// the error, never as an absent finding; a file that stats but does not
// parse is reported as unreadable JSON.
func eventProblems(campaign *state.Campaign,
	e validation.Value) ([]string, error) {
	problems := []string{}
	seq := scalarText(validation.ObjAt(e, "seq"))
	etype := validation.ObjAt(e, "type").S
	data := validation.ObjAt(e, "data")
	if data.Kind != validation.Obj {
		return append(problems, fmt.Sprintf(
			"seq %s (%s): data is not a JSON object", seq, etype)), nil
	}
	failures, err := contractFailures(data, eventDefinition[etype])
	if err != nil {
		return nil, err
	}
	if len(failures) > 0 {
		problems = append(problems, fmt.Sprintf(
			"seq %s (%s): data fails its contract: %s", seq, etype,
			failures[0]))
	}
	for _, pair := range []struct {
		where string
		val   validation.Value
	}{
		{"ref", validation.ObjAt(e, "ref")},
		{"data.finding_id", validation.ObjAt(data, "finding_id")},
	} {
		fid := pair.val
		if fid.Kind != validation.Str || !strings.HasPrefix(fid.S, "F-") {
			continue
		}
		path := findings.FindingPath(campaign, fid.S)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				problems = append(problems, fmt.Sprintf(
					"seq %s (%s): %s %s names a finding that does not exist",
					seq, etype, pair.where, fid.S))
			} else {
				// r43b (P3-2): only ENOENT is evidence of absence. Any
				// other stat failure (EACCES, ENAMETOOLONG, EIO) means the
				// probe could not examine the path at all — it has no
				// evidence about the finding, so it names the read failure
				// and the path and judges nothing else. Fail-closed either
				// way: both are problems.
				problems = append(problems, fmt.Sprintf(
					"seq %s (%s): %s %s cannot be read: %s: %v",
					seq, etype, pair.where, fid.S, path, err))
			}
		} else if _, err := findings.LoadFinding(campaign, fid.S); err != nil {
			problems = append(problems, fmt.Sprintf(
				"seq %s (%s): %s %s is not readable JSON: %v", seq, etype,
				pair.where, fid.S, err))
		}
	}
	return problems, nil
}

func strsToVals(xs []string) []validation.Value {
	out := make([]validation.Value, len(xs))
	for i, x := range xs {
		out[i] = validation.VStr(x)
	}
	return out
}

func pyTypeName(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return "str"
	case validation.Arr:
		return "list"
	case validation.Int:
		return "int"
	case validation.Flt:
		return "float"
	case validation.Bool:
		return "bool"
	case validation.Null:
		return "NoneType"
	}
	return "dict"
}

// scalarText renders a scalar like Python's str() in an f-string.
func scalarText(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Null:
		return "None"
	}
	return ""
}
