// Package floors ports webv2.floors: instance-level evidence floor policy —
// operator-stated DATA, never code.
//
// findings.CLASS_CONFIRM_FLOOR is the framework's DEFAULT judgment about what
// each bug class needs to reach CONFIRMED. A single campaign may legitimately
// disagree with that default: an undeployed playground cannot produce fork
// evidence no matter how hard the operator works, and the right response is a
// campaign-level DECISION — recorded as data, named actor, written reason,
// one log event — not an edit of the framework's source.
//
// Design rules, enforced here:
//
//   - The built-in table is never mutated by an override. CLASS_CONFIRM_FLOOR
//     stays the framework default; overrides live in state["floor_policy"] and
//     are consulted only through EffectiveFloor /
//     findings.RequiredLevelForCampaign.
//   - Every override entry names its actor and a reason (schema-enforced), and
//     every set/clear is one hash-chained floor_policy.set /
//     floor_policy.cleared event. The audit cross-checks the state projection
//     against those events, so a hand-edited policy file is caught exactly
//     like a hand-edited artifact hash.
//   - A per-campaign floor POLICY FILE can seed the overrides at init time, so
//     a no-deployment target declares its ceiling up front instead of
//     discovering the gap at the gate.
//
// Floors are per-finding evidence sufficiency; campaign convergence is gated
// by plan diversity + lenses (the divergence gate). Never lower a floor to
// make a workflow pass.
package floors

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// classRe is _CLASS_RE. Python's re.match is anchored with $, and Python's $
// also matches just before a trailing newline, so the RE2 transcription adds
// the optional "\n" to keep the two regexes exactly equivalent ("abc\n"
// matches in both; "abc\n\n" in neither).
var classRe = regexp.MustCompile(`^[a-z0-9-]{3,64}\n?$`)

// nowIsoFunc is state.now_iso (unexported in the state twin): the timestamp
// stamped on every override entry. The default is byte-identical to the state
// twin, including the WEBV2_NOW golden-suite pin.
var nowIsoFunc = defaultNowIso

// SetNowIso installs the state clock; nil restores the built-in default.
func SetNowIso(f func() string) {
	if f == nil {
		nowIsoFunc = defaultNowIso
		return
	}
	nowIsoFunc = f
}

// defaultNowIso is state.now_iso: UTC with exactly 6-digit microseconds and a
// +00:00 offset (never "Z"), pinned verbatim by WEBV2_NOW.
func defaultNowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// saveStateFunc is campaign._save (unexported in the state twin): bump
// updated_at in place and re-write the projection with schema validation.
var saveStateFunc = defaultSaveState

// SetSaveState installs the state writer; nil restores the built-in default
// (a faithful twin of campaign._save).
func SetSaveState(f func(*state.Campaign, validation.Value) error) {
	if f == nil {
		saveStateFunc = defaultSaveState
		return
	}
	saveStateFunc = f
}

// defaultSaveState is campaign._save: updated_at is replaced in place (key
// position kept) and the state is re-written under the campaign_state schema.
func defaultSaveState(c *state.Campaign, st validation.Value) error {
	for i, kv := range st.O {
		if kv.K == "updated_at" {
			st.O[i].V = validation.VStr(nowIsoFunc())
			break
		}
	}
	return validation.WriteJson(c.StatePath, st, "campaign_state")
}

// init wires the campaign-aware floor resolver into findings (findings cannot
// import floors: cycle).
func init() {
	findings.SetEffectiveFloor(EffectiveFloor)
}

// SetFloorPolicy is set_floor_policy: record (or replace) the instance-level
// floor for one bug class.
//
// This is the sanctioned alternative to editing CLASS_CONFIRM_FLOOR: the
// decision is data, attributed, reasoned and logged. Re-setting a class
// replaces its previous entry — the superseded entry's event stays in the log,
// so the full decision history is recoverable.
func SetFloorPolicy(campaign *state.Campaign, bugClass, floor, actor,
	reason string) (validation.Value, error) {
	if !classRe.MatchString(bugClass) {
		// the class namespace is kebab-case ("access-control"), not
		// snake_case — the message must say what the regex accepts
		return validation.VNull(), fmt.Errorf(
			"bug class must be kebab-case (a-z 0-9 -), got %s",
			validation.PyReprStr(bugClass))
	}
	if !inEvidenceOrder(floor) {
		return validation.VNull(), fmt.Errorf("floor must be one of %s, got %s",
			strings.Join(findings.EVIDENCE_ORDER, "/"), validation.PyReprStr(floor))
	}
	if strings.TrimSpace(actor) == "" {
		return validation.VNull(), errors.New(
			"floor overrides must name their actor (who decided this)")
	}
	if strings.TrimSpace(reason) == "" || utf8.RuneCountInString(reason) < 10 {
		return validation.VNull(), errors.New("floor overrides require a " +
			"written reason (>= 10 chars) — an unnamed preference is not a policy")
	}
	entry := validation.VObj(
		kv("class", validation.VStr(bugClass)),
		kv("floor", validation.VStr(floor)),
		kv("actor", validation.VStr(actor)),
		kv("reason", validation.VStr(reason)),
		kv("at", validation.VStr(nowIsoFunc())),
	)
	// schema-validated by campaign._save (campaign_state covers floor_policy)
	st, err := campaign.State()
	if err != nil {
		return validation.VNull(), err
	}
	policy := objAt(st, "floor_policy")
	var remaining []validation.Value
	replaced := false
	for _, e := range policy.A {
		if objStr(e, "class") == bugClass {
			replaced = true
			continue
		}
		remaining = append(remaining, e)
	}
	st.O = validation.SetOrAppend(st.O, "floor_policy",
		validation.VArr(append(remaining, entry)...))
	if err := saveStateFunc(campaign, st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("floor", validation.VStr(floor)),
		kv("actor", validation.VStr(actor)),
		kv("reason", validation.VStr(reason)),
		kv("replaced", validation.VBool(replaced)),
	)
	if _, err := campaign.Log("floor_policy.set", &bugClass, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// ClearFloorPolicy is clear_floor_policy: remove the override for one class
// (falls back to the built-in table). A class with no override yields an error
// whose twin is Python's KeyError — errors.Is(err, ErrNoFloorOverride).
func ClearFloorPolicy(campaign *state.Campaign, bugClass, actor, reason string) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("clearing a floor override must name its actor")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("clearing a floor override requires a written reason")
	}
	st, err := campaign.State()
	if err != nil {
		return err
	}
	policy := objAt(st, "floor_policy")
	remaining := make([]validation.Value, 0, len(policy.A))
	for _, e := range policy.A {
		if objStr(e, "class") == bugClass {
			continue
		}
		remaining = append(remaining, e)
	}
	if len(remaining) == len(policy.A) {
		return &KeyError{Msg: fmt.Sprintf(
			"no floor override for class %s in this campaign",
			validation.PyReprStr(bugClass))}
	}
	st.O = validation.SetOrAppend(st.O, "floor_policy", validation.VArr(remaining...))
	if err := saveStateFunc(campaign, st); err != nil {
		return err
	}
	data := validation.VObj(
		kv("actor", validation.VStr(actor)),
		kv("reason", validation.VStr(reason)),
	)
	_, err = campaign.Log("floor_policy.cleared", &bugClass, &data)
	return err
}

// ErrNoFloorOverride is the sentinel behind ClearFloorPolicy's KeyError twin.
var ErrNoFloorOverride = errors.New("no floor override")

// KeyError is the twin of Python's KeyError: the message is the exception's
// argument, and errors.Is(err, ErrNoFloorOverride) reports true.
type KeyError struct{ Msg string }

func (e *KeyError) Error() string { return e.Msg }

// Is makes errors.Is(err, ErrNoFloorOverride) true.
func (e *KeyError) Is(target error) bool { return target == ErrNoFloorOverride }

// FloorOverride is floor_override: the instance-level floor for bugClass, or
// nil for the default (the last matching entry wins, as in Python).
func FloorOverride(campaign *state.Campaign, bugClass string) (*string, error) {
	policy, err := policyOf(campaign)
	if err != nil {
		return nil, err
	}
	for i := len(policy) - 1; i >= 0; i-- {
		if objStr(policy[i], "class") == bugClass {
			out := objStr(policy[i], "floor")
			return &out, nil
		}
	}
	return nil, nil
}

// EffectiveFloor is effective_floor: the floor the CONFIRMED gate actually
// applies in THIS campaign — the instance override when one exists, else the
// built-in default.
//
// It is the findings.SetEffectiveFloor seam target, so it cannot return an
// error: an unreadable state file falls back to the built-in default rather
// than taking down every gate call.
func EffectiveFloor(campaign *state.Campaign, status, bugClass string) string {
	if campaign != nil && status == "CONFIRMED" && bugClass != "" {
		ov, err := FloorOverride(campaign, bugClass)
		if err == nil && ov != nil {
			return *ov
		}
	}
	return findings.RequiredLevelFor(status, bugClass)
}

// FloorTableReport is floor_table_report: the full floor table as it applies
// to this campaign — every known class with its default floor and any instance
// override. The taxonomy the operator was forced to reverse-engineer, now
// readable.
func FloorTableReport(campaign *state.Campaign) (validation.Value, error) {
	policy, err := policyOf(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	overrides := map[string]validation.Value{}
	for _, e := range policy {
		overrides[objStr(e, "class")] = e
	}
	classes := map[string]struct{}{}
	for cls := range taxonomy.KnownClasses() {
		classes[cls] = struct{}{}
	}
	for cls := range findings.CLASS_CONFIRM_FLOOR {
		classes[cls] = struct{}{}
	}
	rows := make([]validation.Value, 0, len(classes))
	for _, cls := range sortedKeys(classes) {
		defaultFloor := validation.VNull()
		if f, ok := findings.CLASS_CONFIRM_FLOOR[cls]; ok {
			defaultFloor = validation.VStr(f)
		}
		ov, hasOv := overrides[cls]
		effective := defaultFloor
		var override validation.Value = validation.VNull()
		if hasOv {
			effective = validation.VStr(objStr(ov, "floor"))
			override = validation.VObj(
				kv("actor", validation.VStr(objStr(ov, "actor"))),
				kv("reason", validation.VStr(objStr(ov, "reason"))),
				kv("at", validation.VStr(objStr(ov, "at"))),
			)
		}
		rows = append(rows, validation.VObj(
			kv("class", validation.VStr(cls)),
			kv("default_floor", defaultFloor),
			kv("effective_floor", effective),
			kv("override", override),
		))
	}
	return validation.VObj(
		kv("default_note", validation.VStr("classes without a listed floor "+
			"default to the STATUS_FLOOR CONFIRMED level (E5) — the most "+
			"conservative assumption for unknown classes")),
		kv("rows", validation.VArr(rows...)),
	), nil
}

// LoadPolicyFile is load_policy_file: read a per-campaign floor policy file,
// {"overrides": [{"class": ..., "floor": ..., "reason": ...}]}.
func LoadPolicyFile(path string) ([]validation.Value, error) {
	p := filepath.Clean(path)
	doc, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	overrides := objAt(doc, "overrides")
	if doc.Kind != validation.Obj || overrides.Kind != validation.Arr {
		return nil, fmt.Errorf("floor policy file %s must be "+
			`{"overrides": [{"class", "floor", "reason"}]}`, p)
	}
	for _, ov := range overrides.A {
		if ov.Kind != validation.Obj || !hasKey(ov, "class") || !hasKey(ov, "floor") {
			return nil, fmt.Errorf(
				"each floor override needs 'class' and 'floor': %s",
				validation.PyRepr(ov))
		}
	}
	return overrides.A, nil
}

// ApplyPolicyFile is apply_policy_file: seed the campaign's floor policy from
// a file at init time. Each override goes through SetFloorPolicy, so every
// entry is actor-attributed (actor = "campaign-init") and logged exactly like
// a runtime decision.
func ApplyPolicyFile(campaign *state.Campaign, path string) ([]validation.Value, error) {
	overrides, err := LoadPolicyFile(path)
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(overrides))
	for _, ov := range overrides {
		entry, err := setFloorFromValues(campaign, objAt(ov, "class"),
			objAt(ov, "floor"), policyReason(ov, path))
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// setFloorFromValues is set_floor_policy's isinstance contract for values that
// arrive from JSON: a non-string class or floor fails the same kebab-case /
// EVIDENCE_ORDER check, with CPython's repr in the message ("got 5",
// "got ['E4']", "got None"). The class check runs first, as in Python.
func setFloorFromValues(campaign *state.Campaign, classV, floorV validation.Value,
	reason string) (validation.Value, error) {
	class, ok := valueStr(classV)
	if !ok {
		return validation.VNull(), fmt.Errorf(
			"bug class must be kebab-case (a-z 0-9 -), got %s",
			validation.PyRepr(classV))
	}
	floor, ok := valueStr(floorV)
	if !ok {
		return validation.VNull(), fmt.Errorf("floor must be one of %s, got %s",
			strings.Join(findings.EVIDENCE_ORDER, "/"), validation.PyRepr(floorV))
	}
	return SetFloorPolicy(campaign, class, floor, "campaign-init", reason)
}

// policyReason is `ov.get("reason") or f"declared in floor policy file {name}"`:
// a falsy value (null/false/0/""/[]/{}) takes the fallback, while a truthy
// non-string becomes str(value) and must then satisfy the >= 10 char rule.
func policyReason(ov validation.Value, path string) string {
	reason := objAt(ov, "reason")
	if reason.Kind == validation.Str && reason.S != "" {
		return reason.S
	}
	if !pyTruthy(reason) {
		return "declared in floor policy file " + filepath.Base(path)
	}
	return validation.PyRepr(reason)
}

// valueStr is isinstance(v, str): only a JSON string is a string.
func valueStr(v validation.Value) (string, bool) {
	if v.Kind == validation.Str {
		return v.S, true
	}
	return "", false
}

// pyTruthy is CPython truthiness over a Value: null/False/0/""/[]/{} are
// false, everything else true.
func pyTruthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		if v.Big != "" {
			return v.Big != "0"
		}
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// ---- local helpers -------------------------------------------------------

// policyOf is _policy: the campaign's floor_policy list (nil when unset).
func policyOf(campaign *state.Campaign) ([]validation.Value, error) {
	st, err := campaign.State()
	if err != nil {
		return nil, err
	}
	return objAt(st, "floor_policy").A, nil
}

// inEvidenceOrder is `floor in EVIDENCE_ORDER`.
func inEvidenceOrder(floor string) bool {
	for _, e := range findings.EVIDENCE_ORDER {
		if e == floor {
			return true
		}
	}
	return false
}

// hasKey is Python's `key in dict` (distinct from a present-but-null value).
func hasKey(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// objAt is the dict lookup: the value for key, or Null when absent.
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

// kv is the keyed KV constructor (non-test code cannot use a test helper).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// sortedKeys returns a set's keys in Python's sorted() order.
func sortedKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
