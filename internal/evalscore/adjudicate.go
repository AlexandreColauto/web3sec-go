// Package evalscore — non-gold adjudication.
//
// The precision join in evalscore.go treats every live finding that anchors
// no gold case as a false positive. That single bucket conflates three
// different states of the world:
//
//   - the finding is WRONG (a genuine false positive);
//   - the finding is RIGHT but the gold dataset does not contain it (a real
//     audit finding outside the benchmark's answer key);
//   - the finding RESTS ON AN ASSUMPTION the campaign could not discharge
//     (neither confirmed nor refuted — a separate epistemic state).
//
// Calling all three "false positive" makes precision a measure of agreement
// with the dataset rather than of correctness. This file adds the third
// verdict as DATA: one row per live finding, with the basis for the decision
// and the actor who made it, so the scorecard can subtract what was judged
// true and keep what was judged wrong.
//
// This is the same posture as probes.SetBlank: a decision that moves a score
// is written down, attributed, reasoned, and logged — never an unstated
// adjustment.
package evalscore

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// Verdicts is the adjudication verdict vocabulary, in fixed reporting order.
var Verdicts = []string{"additional-true-positive", "false-positive", "assumption-gated"}

// Bases is the evidence basis vocabulary, in fixed reporting order.
var Bases = []string{"dataset-cross-check", "author-review", "reproduction", "code-argument"}

// Severities is the severity vocabulary, in fixed reporting order. It is the
// campaign-wide severity ladder; "tbd" is the honest default for an
// adjudication that does not re-rate the finding.
var Severities = []string{"tbd", "low", "medium", "high", "critical"}

// The three verdicts, named once so the store and the scorer cannot drift.
const (
	verdictAdditional    = "additional-true-positive"
	verdictFalsePositive = "false-positive"
	verdictGated         = "assumption-gated"
)

// AdjudicationReasonMin is the minimum written reason, matching the schema's
// minLength. A verdict with no stated reason is an opinion, not a datum.
const AdjudicationReasonMin = 10

// Adjudication is one non-gold verdict on one live finding. Assumption is
// set iff Verdict == assumption-gated (Validate enforces both directions).
type Adjudication struct {
	Finding    string // the live finding id
	Verdict    string // additional-true-positive | false-positive | assumption-gated
	Severity   string
	Basis      string // dataset-cross-check | author-review | reproduction | code-argument
	Assumption string // set iff Verdict == assumption-gated
	Exec       string
	Reason     string
	Actor      string
	At         string
}

// kv is the keyed KV constructor (unkeyed cross-package literals are
// rejected by go vet).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// keyFields pairs a state-doc field with the struct field it fills, so Load
// and Record cannot disagree about the row's shape.
type keyField struct {
	key string
	ptr *string
}

// fields is the row's field list in schema order.
func (a *Adjudication) fields() []keyField {
	return []keyField{
		{"finding", &a.Finding},
		{"verdict", &a.Verdict},
		{"severity", &a.Severity},
		{"basis", &a.Basis},
		{"assumption", &a.Assumption},
		{"exec", &a.Exec},
		{"reason", &a.Reason},
		{"actor", &a.Actor},
		{"at", &a.At},
	}
}

// Load reads the campaign state key "eval_adjudications". Pure read: an
// absent, null, or empty key all mean "no rows". A row whose fields are not
// strings is skipped, never guessed at — half-read evidence is worse than
// none.
//
// The raw projection is read rather than (*state.Campaign).State: the schema
// types the key as an array, so a null/absent key is a legacy or hand-edited
// doc that this advisory key must tolerate, not a corruption worth failing
// the score over.
func Load(c *state.Campaign) ([]Adjudication, error) {
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		return nil, err
	}
	v := obj(st, "eval_adjudications")
	if v.Kind != validation.Arr {
		return nil, nil
	}
	out := []Adjudication{}
	for _, item := range v.A {
		if item.Kind != validation.Obj {
			continue
		}
		a, ok := adjudicationOf(item)
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// adjudicationOf reads one state row, ok=false when any present field is not
// a string (the row is skipped, not partially trusted).
func adjudicationOf(v validation.Value) (Adjudication, bool) {
	var a Adjudication
	for _, f := range a.fields() {
		for _, kv := range v.O {
			if kv.K != f.key {
				continue
			}
			if kv.V.Kind != validation.Str {
				return Adjudication{}, false
			}
			*f.ptr = kv.V.S
			break
		}
	}
	return a, true
}

// Index keys rows by finding id, the join key every consumer uses. A later
// row for the same finding wins (Record replaces, so this is a safety net
// for hand-edited state, not the store's contract). The key is the BARE
// finding id, so in a multi-program suite roll-up one row adjudicates that
// id in every program — unreachable through the production single-program
// Score, but a real property of this map.
func Index(adjs []Adjudication) map[string]Adjudication {
	out := make(map[string]Adjudication, len(adjs))
	for _, a := range adjs {
		out[a.Finding] = a
	}
	return out
}

// scoreableRows decides what the scorer may treat as an adjudication, and is
// the SCORE-path twin of Record's write-path gate: Validate runs here too,
// because Load trusts whatever the (hand-editable) state file holds. It
// returns the rows that survive — at most one per finding id, the last row
// winning, the same shadowing order Index assigns — plus the count of rows
// refused. A refused row is not an adjudication at all: the caller reports
// it and lets its finding score as unadjudicated, so garbage in the state
// file can neither move the precision number nor disappear without a trace.
//
// The drop happens BEFORE the dedupe on purpose: an unreadable row must not
// shadow a readable one that names the same finding.
func scoreableRows(adjs []Adjudication) ([]Adjudication, int) {
	valid := make([]Adjudication, 0, len(adjs))
	invalid := 0
	for _, a := range adjs {
		if err := Validate(a); err != nil {
			invalid++
			continue
		}
		valid = append(valid, a)
	}
	kept := make([]Adjudication, 0, len(valid))
	at := make(map[string]int, len(valid))
	for _, a := range valid {
		if i, seen := at[a.Finding]; seen {
			kept[i] = a // last row for a finding wins
			continue
		}
		at[a.Finding] = len(kept)
		kept = append(kept, a)
	}
	return kept, invalid
}

// oneOf reports membership in a fixed vocabulary.
func oneOf(v string, allowed []string) bool {
	for _, s := range allowed {
		if v == s {
			return true
		}
	}
	return false
}

// Validate checks one row on its own terms and returns the first problem as
// an error. Fail-loud on every way the decision could be unfalsifiable; this
// is the same posture as probes.SetBlank.
func Validate(a Adjudication) error {
	if strings.TrimSpace(a.Finding) == "" {
		return fmt.Errorf("an adjudication must name the finding it " +
			"adjudicates (finding id F-...)")
	}
	if !oneOf(a.Verdict, Verdicts) {
		return fmt.Errorf("adjudication verdict %s is not one of %s",
			validation.PyReprStr(a.Verdict), strings.Join(Verdicts, ", "))
	}
	if !oneOf(a.Basis, Bases) {
		return fmt.Errorf("adjudication basis %s is not one of %s",
			validation.PyReprStr(a.Basis), strings.Join(Bases, ", "))
	}
	if a.Severity != "" && !oneOf(a.Severity, Severities) {
		return fmt.Errorf("adjudication severity %s is not one of %s "+
			"(or empty for unchanged)", validation.PyReprStr(a.Severity),
			strings.Join(Severities, ", "))
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(a.Reason)); n < AdjudicationReasonMin {
		return fmt.Errorf("an adjudication requires a written reason "+
			"(>= %d chars), got %s (%d chars)", AdjudicationReasonMin,
			validation.PyReprStr(a.Reason), n)
	}
	if strings.TrimSpace(a.Actor) == "" {
		return fmt.Errorf("an adjudication must name its actor (who judged " +
			"the finding)")
	}
	if a.Verdict == verdictGated && strings.TrimSpace(a.Assumption) == "" {
		return fmt.Errorf("verdict %s requires the assumption that must "+
			"hold: the assumption IS the whole content of a gated verdict",
			verdictGated)
	}
	if a.Verdict != verdictGated && strings.TrimSpace(a.Assumption) != "" {
		return fmt.Errorf("an assumption is only meaningful with the %s "+
			"verdict; for verdict %s it is an argument for the verdict and "+
			"belongs in reason", verdictGated,
			validation.PyReprStr(a.Verdict))
	}
	return nil
}

// adjudicationValue projects a validated Adjudication into the state row:
// required fields always, optional ones only when set (the schema's enums
// have no empty member).
func adjudicationValue(a Adjudication) validation.Value {
	kvs := []validation.KV{}
	for _, f := range a.fields() {
		switch f.key {
		case "severity", "assumption", "exec":
			if *f.ptr == "" {
				continue
			}
		}
		kvs = append(kvs, kv(f.key, validation.VStr(*f.ptr)))
	}
	return validation.VObj(kvs...)
}

// saveState is campaign._save (unexported in the state twin): bump updated_at
// in place and re-write the projection under the campaign_state schema.
func saveState(c *state.Campaign, st validation.Value) error {
	// r14: this local _save re-implementation bypassed the campaign
	// lock (unlocked read-modify-write racing another process). The
	// twin body now lives in exactly one place: state.SaveState.
	return c.SaveState(st)
}

// Record validates, refuses a finding id that is not in the campaign's LIVE
// finding set, replaces any prior row for the same finding id, writes the
// state file, and appends the "eval.adjudicated" event. Mirrors
// probes.SetBlank's read-modify-write + Log shape.
//
// A row for a finding that is not live is refused because an adjudication is
// a claim about a finding that exists: accepting it would let the score be
// moved by a typo.
func Record(c *state.Campaign, a Adjudication) (Adjudication, error) {
	if err := Validate(a); err != nil {
		return Adjudication{}, err
	}
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		return Adjudication{}, err
	}
	if !LiveIDs(live)[a.Finding] {
		return Adjudication{}, fmt.Errorf("no live finding %s in campaign "+
			"%s: an adjudication is a claim about a finding that exists",
			validation.PyReprStr(a.Finding), c.CampaignID)
	}
	a.At = state.NowIso()
	entry := adjudicationValue(a)
	// r14: load->save of adjudications is one read-modify-write unit —
	// racing `verdict` calls used to drop an adjudication silently.
	if err := c.LockProcess(); err != nil {
		return Adjudication{}, err
	}
	defer c.UnlockProcess()
	st, err := c.State()
	if err != nil {
		return Adjudication{}, err
	}
	prior := obj(st, "eval_adjudications")
	kept := []validation.Value{}
	replaced := false
	for _, e := range prior.A {
		if field(e, "finding") == a.Finding {
			replaced = true
			continue
		}
		kept = append(kept, e)
	}
	st.O = validation.SetOrAppend(st.O, "eval_adjudications",
		validation.VArr(append(kept, entry)...))
	// r18 P2 (evalscore site): the adjudication row entered campaign_state
	// BEFORE its event; a refused log left the scorer's authority row —
	// the thing scoring TRUSTS — updated while eval.adjudicated never
	// existed, and the retry's `replaced: true` hid the burn. Floor
	// law (floors.go): snapshot state bytes pre-write, unwind on refusal.
	prevRaw, hadRaw := c.RawState()
	if err := saveState(c, st); err != nil {
		return Adjudication{}, err
	}
	data := validation.VObj(
		kv("finding", validation.VStr(a.Finding)),
		kv("verdict", validation.VStr(a.Verdict)),
		kv("basis", validation.VStr(a.Basis)),
		kv("reason", validation.VStr(a.Reason)),
		kv("actor", validation.VStr(a.Actor)),
		kv("replaced", validation.VBool(replaced)),
	)
	if a.Severity != "" {
		data.O = append(data.O, kv("severity", validation.VStr(a.Severity)))
	}
	if a.Assumption != "" {
		data.O = append(data.O, kv("assumption", validation.VStr(a.Assumption)))
	}
	if a.Exec != "" {
		data.O = append(data.O, kv("exec", validation.VStr(a.Exec)))
	}
	if _, err := c.Log("eval.adjudicated", &a.Finding, &data); err != nil {
		if uerr := c.UnwindState(prevRaw, hadRaw); uerr != nil {
			return Adjudication{}, fmt.Errorf("%w (UNWIND ALSO FAILED: %v "+
				"— state holds an adjudication with no event; repair by "+
				"hand)", err, uerr)
		}
		return Adjudication{}, err
	}
	return a, nil
}

// LiveIDs returns the ids of a live finding set, the membership test Record
// applies. VERIFIED against internal/findings/storage.go (
// SaveFinding/objStr "finding_id") and the finding schema's required list:
// the id key is "finding_id", not "id".
func LiveIDs(live []validation.Value) map[string]bool {
	out := make(map[string]bool, len(live))
	for _, f := range live {
		if id := field(f, "finding_id"); id != "" {
			out[id] = true
		}
	}
	return out
}
