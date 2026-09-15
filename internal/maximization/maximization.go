// Package maximization is the variant ladder (base -> amplified -> maximal):
// a 1:1 port of webv2/maximization.py (port-era provenance; twin retired 2026-09-09).
//
// Chaining composes ACROSS confirmed findings; this module searches WITHIN
// one, along five fixed axes. Integrity rules: a rung above base counts only
// when REPRODUCED (its own EXEC, E4+ profile, real evidence); a rung can be
// DISPROVED with a written reason and is queued as negative memory; the
// ladder closes with a disposition (complete or waived), never silently open;
// the finding's claim pins to the maximal reproduced rung.
package maximization

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// Axes is AXES: the five fixed-order maximization axes.
var Axes = []string{"capital-minimization", "precondition-removal",
	"role-conflation", "ordering-permutation", "cap-saturation"}

// AxeChecklist is AXE_CHECKLIST: the verbatim operator prompts per axis.
var AxeChecklist = map[string]string{
	"capital-minimization": "What is the TRUE minimum attacker capital? " +
		"Dust the pool with the smallest unit the code accepts (1 wei?). " +
		"Was the $ figure in the base PoC a protocol requirement or the " +
		"analyst's convenience?",
	"precondition-removal": "Which base preconditions does the CODE " +
		"actually enforce? For each: can the exploit run WITHOUT it (victim " +
		"only deposits, never stakes)? A precondition nobody asserted is a " +
		"rung waiting to happen.",
	"role-conflation": "Can the attacker occupy the victim's seat? First " +
		"staker, first depositor, last withdrawer — is any 'victim' role " +
		"open to anyone, including the attacker?",
	"ordering-permutation": "Does entry ORDER change the economics? " +
		"Front-run the donation, sandwich the update, drain before the " +
		"accounting catches up.",
	"cap-saturation": "Is there a payout cap per call/per block/per actor? " +
		"Can repeated timed calls saturate it to 100%? Does the cap bind " +
		"BEFORE full extraction — and can timing defeat it?",
}

// ---- learning seam (P3, unported) -----------------------------------------

// MemoryRequest is one learning.queue_memory call.
type MemoryRequest struct {
	Kind            string
	Status          string
	Pattern         string
	FindingID       *string
	BugClass        *string
	EvidenceSummary string
	Negative        *validation.Value
}

// queueMemory is learning.queue_memory. Unported module: the safe default is
// a no-op (Python's absent-data behavior — the disproof is still recorded on
// the ladder and the log, only the negative-memory row is missing).
var queueMemory = func(*state.Campaign, MemoryRequest) (validation.Value, error) {
	return validation.VNull(), nil
}

// SetQueueMemory installs learning.queue_memory; nil restores the no-op.
func SetQueueMemory(f func(*state.Campaign, MemoryRequest) (validation.Value, error)) {
	if f == nil {
		f = func(*state.Campaign, MemoryRequest) (validation.Value, error) {
			return validation.VNull(), nil
		}
	}
	queueMemory = f
}

// ---- helpers --------------------------------------------------------------

func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
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
	if f := objAt(v, key); f.Kind == validation.Str {
		return f.S
	}
	return ""
}

// asObj is `d.get(key) or {}`.
func asObj(v validation.Value) validation.Value {
	if v.Kind == validation.Obj {
		return v
	}
	return validation.VObj()
}

func listOf(v validation.Value, key string) validation.Value {
	if f := objAt(v, key); f.Kind == validation.Arr {
		return f
	}
	return validation.VArr()
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.VArr(out...)
}

// pyListRepr is Python's repr() of a list of strings.
func pyListRepr(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// pyTupleRepr is Python's repr() of a tuple of strings.
func pyTupleRepr(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, validation.PyReprStr(s))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// noneText is Python's f"{finding_id}" for a possibly-absent CLI positional:
// the empty string stands in for None (ids are never empty in the model).
func noneText(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

// idRepr is Python's {id!r} for a possibly-absent CLI positional.
func idRepr(s string) string {
	if s == "" {
		return "None"
	}
	return validation.PyReprStr(s)
}

func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00", now.Format("2006-01-02T15:04:05"),
		now.Nanosecond()/1000)
}

// ladderPath is _ladder_path: campaign.dir / "ladders" / f"{finding_id}.json".
func ladderPath(c *state.Campaign, findingID string) string {
	return filepath.Join(c.Dir, "ladders", findingID+".json")
}

// LoadLadder is load_ladder: the ladder artifact, or nil when absent. A
// stored ladder is validated against variant_ladder (Python does the same).
func LoadLadder(c *state.Campaign, findingID string) (*validation.Value, error) {
	p := ladderPath(c, findingID)
	if _, err := os.Stat(p); err != nil {
		return nil, nil
	}
	lad, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	if err := validation.Validate(lad, "variant_ladder", 1); err != nil {
		return nil, err
	}
	return &lad, nil
}

// SaveLadder is save_ladder: stamp updated_at, validate, write.
func SaveLadder(c *state.Campaign, ladder *validation.Value) (string, error) {
	ladder.O = validation.SetOrAppend(ladder.O, "updated_at", validation.VStr(nowIso()))
	if err := validation.Validate(*ladder, "variant_ladder", 1); err != nil {
		return "", err
	}
	p := ladderPath(c, objStr(*ladder, "finding_id"))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := validation.WriteJson(p, *ladder, ""); err != nil {
		return "", err
	}
	return p, nil
}

// newRung is _new_rung (Python's keyword defaults).
func newRung(name, description string, axes []string, capitalUSD,
	extractionRatio *float64, removed, added []string, status string,
	execID, evidenceID *string, reason string) validation.Value {
	if axes == nil {
		axes = []string{}
	}
	if removed == nil {
		removed = []string{}
	}
	if added == nil {
		added = []string{}
	}
	if status == "" {
		status = "assumed"
	}
	capV := validation.VNull()
	if capitalUSD != nil {
		capV = validation.VFloat(*capitalUSD)
	}
	extV := validation.VNull()
	if extractionRatio != nil {
		extV = validation.VFloat(*extractionRatio)
	}
	execV, evV := validation.VNull(), validation.VNull()
	if execID != nil {
		execV = validation.VStr(*execID)
	}
	if evidenceID != nil {
		evV = validation.VStr(*evidenceID)
	}
	return validation.VObj(
		kvOf("rung_id", validation.VStr("R-"+tailOf(state.NewID("x", 6)))),
		kvOf("name", validation.VStr(name)),
		kvOf("description", validation.VStr(description)),
		kvOf("axes", strArr(axes)),
		kvOf("capital_usd", capV),
		kvOf("extraction_ratio", extV),
		kvOf("removed_preconditions", strArr(removed)),
		kvOf("added_preconditions", strArr(added)),
		kvOf("status", validation.VStr(status)),
		kvOf("exec_id", execV),
		kvOf("evidence_id", evV),
		kvOf("reason", validation.VStr(reason)),
		kvOf("created_at", validation.VStr(nowIso())),
		kvOf("reproduced_at", validation.VNull()),
	)
}

func tailOf(id string) string {
	for i := 0; i < len(id); i++ {
		if id[i] == '-' {
			return id[i+1:]
		}
	}
	return id
}

// StartLadder is start_ladder: open the ladder with rung 0 = the base as
// currently claimed. Idempotent: returns the existing ladder when one exists.
func StartLadder(c *state.Campaign, findingID string) (validation.Value, error) {
	existing, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if existing != nil {
		return *existing, nil
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	base := baseRung(f)
	lad := validation.VObj(
		kvOf("ladder_id", validation.VStr("LAD-"+tailOf(state.NewID("x", 8)))),
		kvOf("finding_id", validation.VStr(findingID)),
		kvOf("campaign_id", validation.VStr(c.CampaignID)),
		kvOf("created_at", validation.VStr(nowIso())),
		kvOf("updated_at", validation.VStr(nowIso())),
		kvOf("axes_explored", validation.VArr()),
		kvOf("axis_notes", validation.VObj()),
		kvOf("variants", validation.VArr(base)),
		kvOf("maximal_rung_id", validation.VNull()),
		kvOf("disposition", validation.VObj(
			kvOf("state", validation.VStr("open")),
			kvOf("reason", validation.VNull()),
			kvOf("actor", validation.VNull()),
			kvOf("at", validation.VNull()))),
		kvOf("history", validation.VArr()),
	)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// r19 P1 #4: SaveLadder's own write is atomic (temp+rename), but
		// a partial-visibility error (ENOSPC mid-rename on some mounts)
		// must not leave a doc the retry will early-return over. Remove
		// any bytes it may have produced (start ran on an absent ladder
		// — the early-return above proves it).
		if rmErr := os.Remove(ladderPath(c, findingID)); rmErr != nil &&
			!os.IsNotExist(rmErr) {
			return validation.VNull(), fmt.Errorf(
				"%w (AND the orphan ladder doc could NOT be removed: %v — "+
					"the retry's early-return would print 'started' without "+
					"an event; remove ladders/%s.json by hand)", err, rmErr,
				findingID)
		}
		return validation.VNull(), err
	}
	mx := asObj(objAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "ladder_id", objAt(lad, "ladder_id"))
	if !hasKey(mx, "disposition") {
		mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("open"))
	}
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r19 P1 #4 (the live-repro'd burn): a finding write that fails
		// AFTER the ladder doc landed left an ORPHAN ladder — the retry
		// takes the idempotent early-return (the doc exists), prints
		// "started", exit 0, and ladder.started can NEVER be emitted;
		// audit stays PASS over the orphan. The doc is this verb's
		// creation: unwinding means REMOVING it, restoring the finding
		// to its (untouched) bytes.
		if rmErr := os.Remove(ladderPath(c, findingID)); rmErr != nil &&
			!os.IsNotExist(rmErr) {
			restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
			return validation.VNull(), fmt.Errorf(
				"%w (AND the orphan ladder doc survived removal: %v — "+
					"delete ladders/%s.json by hand before retrying)", err,
				rmErr, findingID)
		}
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	data := validation.VObj(
		kvOf("ladder_id", objAt(lad, "ladder_id")),
		kvOf("base_rung", objAt(base, "rung_id")))
	if _, err := c.Log("ladder.started", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return lad, nil
}

// baseRung is rung 0: the finding's current claim, its capital and ratio
// carried over, status "reproduced" only when reproduction says so, and the
// first cited EXEC evidence id.
func baseRung(f validation.Value) validation.Value {
	impact := asObj(objAt(f, "economic_impact"))
	repro := asObj(objAt(asObj(objAt(f, "verification")), "reproduction"))
	status := "assumed"
	if objStr(repro, "status") == "reproduced" {
		status = "reproduced"
	}
	var capitalPtr, ratioPtr *float64
	if v := objAt(asObj(objAt(f, "attacker")), "required_capital_usd"); v.Kind !=
		validation.Null {
		if fv, ok := numOf(v); ok {
			capitalPtr = &fv
		}
	}
	if v := objAt(impact, "extraction_ratio"); v.Kind != validation.Null {
		if fv, ok := numOf(v); ok {
			ratioPtr = &fv
		}
	}
	base := newRung("base", "as claimed at reproduction: "+objStr(f, "title"),
		nil, capitalPtr, ratioPtr, nil, nil, status, nil, nil, "")
	cited := []string{}
	for _, e := range listOf(f, "evidence").A {
		if strings.HasPrefix(objStr(e, "artifact_id"), "EXEC-") {
			cited = append(cited, objStr(e, "artifact_id"))
		}
	}
	if len(cited) > 0 {
		base.O = validation.SetOrAppend(base.O, "exec_id", validation.VStr(cited[0]))
	}
	return base
}

// hasKey is `key in d`.
func hasKey(v validation.Value, key string) bool {
	if v.Kind != validation.Obj {
		return false
	}
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// numOf is float(v) for the int/float/bool shapes JSON carries.
func numOf(v validation.Value) (float64, bool) {
	switch v.Kind {
	case validation.Int:
		return float64(v.I), true
	case validation.Flt:
		return v.F, true
	case validation.Bool:
		if v.B {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// requireOpen is _require_open: only a COMPLETE ladder refuses mutation (a
// waived ladder is re-openable by adding work).
func requireOpen(lad validation.Value) error {
	if objStr(asObj(objAt(lad, "disposition")), "state") == "complete" {
		return fmt.Errorf("ladder disposition is complete; reopen it with an " +
			"explicit reason before adding work (webv2 ladder reopen)")
	}
	return nil
}

// AddVariant is add_variant: record a candidate rung. It is ASSUMED until
// reproduced or DISPROVED with a reason — an assumed rung never moves the
// claim.
func AddVariant(c *state.Campaign, findingID, name, description string,
	axes []string, capitalUSD, extractionRatio *float64, removed,
	added []string) (validation.Value, error) {
	for _, a := range axes {
		if !containsStr(Axes, a) {
			return validation.VNull(), fmt.Errorf(
				"unknown axis %s; the axes are %s", validation.PyReprStr(a),
				pyTupleRepr(Axes))
		}
	}
	if len(axes) == 0 {
		return validation.VNull(), fmt.Errorf("a variant must name the axis " +
			"(axes) it exploits — that is what makes the search auditable")
	}
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf(
			"no ladder for %s; webv2 ladder start %s first", noneText(findingID),
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	rung := newRung(name, description, axes, capitalUSD, extractionRatio,
		removed, added, "", nil, nil, "")
	variants := listOf(lad, "variants")
	variants.A = append(variants.A, rung)
	lad.O = validation.SetOrAppend(lad.O, "variants", variants)
	explored := listOf(lad, "axes_explored")
	for _, a := range axes {
		if !containsStr(listStrings(explored), a) {
			explored.A = append(explored.A, validation.VStr(a))
		}
	}
	lad.O = validation.SetOrAppend(lad.O, "axes_explored", explored)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the SaveLadder-error arm was the one return after this
		// verb's first write that skipped the unwind (SetMaximal,
		// WaiveLadder, ReopenLadder and StartLadder all restore here).
		// WriteJson is atomic, but a partial-visibility failure can still
		// leave the doc ahead of the ledger; restore the pair.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	data := validation.VObj(
		kvOf("rung_id", objAt(rung, "rung_id")),
		kvOf("axes", strArr(axes)),
		kvOf("name", validation.VStr(name)))
	if _, err := c.Log("ladder.variant_added", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return rung, nil
}

// listStrings renders an array value as Go strings.
func listStrings(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, it := range v.A {
		if it.Kind == validation.Str {
			out = append(out, it.S)
		}
	}
	return out
}

func containsStr(items []string, want string) bool {
	for _, s := range items {
		if s == want {
			return true
		}
	}
	return false
}

// ExploreAxis is explore_axis: mark an axis explored WITHOUT a rung — when
// the honest answer is 'considered, not applicable', the note is the artifact.
func ExploreAxis(c *state.Campaign, findingID, axis, note string) (validation.Value, error) {
	if !containsStr(Axes, axis) {
		return validation.VNull(), fmt.Errorf("unknown axis %s; the axes are %s",
			idRepr(axis), pyTupleRepr(Axes))
	}
	if utf8.RuneCountInString(strings.TrimSpace(note)) < 10 {
		return validation.VNull(), fmt.Errorf("an axis marked not-applicable " +
			"needs a written reason (>=10 chars) — otherwise it is unexplored")
	}
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	notes := asObj(objAt(lad, "axis_notes"))
	notes.O = validation.SetOrAppend(notes.O, axis, validation.VStr(strings.TrimSpace(note)))
	lad.O = validation.SetOrAppend(lad.O, "axis_notes", notes)
	explored := listOf(lad, "axes_explored")
	if !containsStr(listStrings(explored), axis) {
		explored.A = append(explored.A, validation.VStr(axis))
	}
	lad.O = validation.SetOrAppend(lad.O, "axes_explored", explored)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: same arm as AddVariant's — the first write's own refusal
		// returned without the unwind.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	data := validation.VObj(
		kvOf("axis", validation.VStr(axis)),
		kvOf("note", validation.VStr(truncate(strings.TrimSpace(note), 200))))
	if _, err := c.Log("ladder.axis_explored", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return lad, nil
}

// truncate is Python's s[:n] over code points.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ReproduceRung is reproduce_rung: a rung counts when it runs. The mint
// enforces profile/exit/output/idempotence and writes the evidence item; the
// rung is bound to it afterwards.
func ReproduceRung(c *state.Campaign, findingID, rungID, execID string,
	evidenceType *string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	rungPtr, err := findRung(lad, rungID)
	if err != nil {
		return validation.VNull(), err
	}
	rung := *rungPtr
	desc := fmt.Sprintf("variant rung %s: %s", objStr(rung, "name"),
		objStr(rung, "description"))
	// r41 P1: MintReproEvidence writes the FINDING first —
	// findings.AddEvidence saves the evidence item and only THEN appends
	// finding.evidence_added, with no unwind of its own — so a refused
	// ledger returns from the mint with the item already ON the finding and
	// no event behind it. These baselines used to be captured AFTER the
	// mint (:638-639), which left that half-land outside this verb's unwind
	// window: a refused ladder.rung_reproduced kept the minted evidence and
	// its updated_at stamp, with zero events anywhere. Capture BOTH files
	// BEFORE the mint; a refused mint restores them.
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	preMintFPrev, preMintFHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := reproduction.MintReproEvidence(c, findingID, execID, desc,
		nil, evidenceType); err != nil {
		restoreLadderPair(c, findingID, ladPrev, ladHad, preMintFPrev,
			preMintFHad)
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// The mint wrote this file moments ago, so this refusal means the
		// finding went missing under it: unwind the mint's half-land.
		restoreLadderPair(c, findingID, ladPrev, ladHad, preMintFPrev,
			preMintFHad)
		return validation.VNull(), err
	}
	evID := ""
	for _, e := range listOf(f, "evidence").A {
		if objStr(e, "artifact_id") == execID {
			evID = objStr(e, "evidence_id")
			break
		}
	}
	rung.O = validation.SetOrAppend(rung.O, "status", validation.VStr("reproduced"))
	rung.O = validation.SetOrAppend(rung.O, "exec_id", validation.VStr(execID))
	if evID == "" {
		rung.O = validation.SetOrAppend(rung.O, "evidence_id", validation.VNull())
	} else {
		rung.O = validation.SetOrAppend(rung.O, "evidence_id", validation.VStr(evID))
	}
	rung.O = validation.SetOrAppend(rung.O, "reproduced_at", validation.VStr(nowIso()))
	if err := replaceRung(&lad, rung); err != nil {
		// Nothing to unwind: the ladder is still only in memory here, and
		// the mint's own finding file + finding.evidence_added pair is
		// already complete (see the window note below). Unreachable anyway
		// — findRung just proved the rung id exists.
		return validation.VNull(), err
	}
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(nowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("reproduced")),
		kvOf("exec_id", validation.VStr(execID))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// Re-capture the FINDING now that the mint's own finding.evidence_added
	// event has landed (the mint returns success only once both halves are
	// written): the item is then an authoritative file+event pair, and
	// restoring the file alone would orphan that event. The LADDER snapshot
	// above stands — nothing has written the ladder since it was captured.
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: this arm returned without the unwind too.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	data := validation.VObj(
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("exec_id", validation.VStr(execID)))
	if _, err := c.Log("ladder.rung_reproduced", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return rung, nil
}

// findRung is _find_rung. The KeyError text is Python's: the CLI renders
// str(KeyError(msg)) — repr of the message — so the message is wrapped here.
func findRung(lad validation.Value, rungID string) (*validation.Value, error) {
	ids := []string{}
	for _, r := range listOf(lad, "variants").A {
		if objStr(r, "rung_id") == rungID {
			out := r
			return &out, nil
		}
		ids = append(ids, objStr(r, "rung_id"))
	}
	msg := fmt.Sprintf("unknown rung %s; rungs: %s", idRepr(rungID),
		pyListRepr(ids))
	return nil, &keyError{msg: validation.PyReprStr(msg)}
}

// keyError is Python's KeyError: str(e) is repr(message).
type keyError struct{ msg string }

func (e *keyError) Error() string { return e.msg }

// replaceRung swaps the rung with the same rung_id back into variants.
func replaceRung(lad *validation.Value, rung validation.Value) error {
	variants := listOf(*lad, "variants")
	for i, r := range variants.A {
		if objStr(r, "rung_id") == objStr(rung, "rung_id") {
			variants.A[i] = rung
			lad.O = validation.SetOrAppend(lad.O, "variants", variants)
			return nil
		}
	}
	return fmt.Errorf("unknown rung %s", validation.PyReprStr(objStr(rung, "rung_id")))
}

// DisproveRung is disprove_rung: a dead-end rung with a written reason is
// NEGATIVE KNOWLEDGE, queued as memory so the next campaign does not re-spend
// a PoC cycle on it.
func DisproveRung(c *state.Campaign, findingID, rungID, reason string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	if utf8.RuneCountInString(strings.TrimSpace(reason)) < 10 {
		return validation.VNull(), fmt.Errorf("a disproof needs a written " +
			"reason — 'didn't work' is not knowledge")
	}
	rungPtr, err := findRung(lad, rungID)
	if err != nil {
		return validation.VNull(), err
	}
	rung := *rungPtr
	if objStr(rung, "status") == "reproduced" {
		return validation.VNull(), fmt.Errorf("rung %s is reproduced; a "+
			"reproduced rung cannot be disproved — mint a fresh exec for the "+
			"corrected claim or open a new rung", rungID)
	}
	rung.O = validation.SetOrAppend(rung.O, "status", validation.VStr("disproved"))
	rung.O = validation.SetOrAppend(rung.O, "reason", validation.VStr(strings.TrimSpace(reason)))
	if err := replaceRung(&lad, rung); err != nil {
		return validation.VNull(), err
	}
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(nowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("disproved"))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the first write's own refusal skipped the unwind.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	fid := findingID
	negative := validation.VObj(kvOf("why_safe", validation.VStr(strings.TrimSpace(reason))))
	if _, err := queueMemory(c, MemoryRequest{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "maximal-exploitation dead end: " + objStr(rung, "name") +
			" — " + objStr(rung, "description"),
		FindingID:       &fid,
		EvidenceSummary: strings.TrimSpace(reason),
		Negative:        &negative,
	}); err != nil {
		// r41 P1: the ladder doc was ALREADY saved above reading
		// "disproved" (plus a history row), and the memory row is its own
		// file+event pair (learning.QueueMemory unwinds itself, r40), so
		// THIS refusal must not leave the ladder ahead of the ledger:
		// without the restore the ladder showed a disproof with zero
		// ladder.rung_disproved events and the retry re-stamped it.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	data := validation.VObj(kvOf("rung_id", validation.VStr(rungID)))
	if _, err := c.Log("ladder.rung_disproved", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return rung, nil
}

// SetMaximal is set_maximal: pin the finding's claim to a REPRODUCED rung.
func SetMaximal(c *state.Campaign, findingID, rungID string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if err := requireOpen(lad); err != nil {
		return validation.VNull(), err
	}
	rungPtr, err := findRung(lad, rungID)
	if err != nil {
		return validation.VNull(), err
	}
	rung := *rungPtr
	if objStr(rung, "status") != "reproduced" {
		return validation.VNull(), fmt.Errorf("rung %s is %s; the claim may "+
			"only pin to a REPRODUCED rung — an assumed rung is a hypothesis "+
			"about bigger impact, not a claim of it", rungID,
			validation.PyReprStr(objStr(rung, "status")))
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	lad.O = validation.SetOrAppend(lad.O, "maximal_rung_id", validation.VStr(rungID))
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(nowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("claim_pinned"))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	mx := asObj(objAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "maximal_rung_id", validation.VStr(rungID))
	mx.O = validation.SetOrAppend(mx.O, "claim_from", validation.VStr(rungID))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if v := objAt(rung, "capital_usd"); v.Kind != validation.Null {
		attacker := asObj(objAt(f, "attacker"))
		attacker.O = validation.SetOrAppend(attacker.O, "required_capital_usd", v)
		f.O = validation.SetOrAppend(f.O, "attacker", attacker)
	}
	if v := objAt(rung, "extraction_ratio"); v.Kind != validation.Null {
		impact := asObj(objAt(f, "economic_impact"))
		impact.O = validation.SetOrAppend(impact.O, "extraction_ratio", v)
		f.O = validation.SetOrAppend(f.O, "economic_impact", impact)
	}
	if err := findings.SaveFinding(c, &f); err != nil {
		// r41 P2: the ladder save above STANDS and the finding stamp did
		// not, so this refusal left the ladder doc pinning max R and the
		// finding's maximization block untouched, with no ladder.claim_pinned
		// event anywhere — a pin the ledger never heard of (the retry can
		// still record it, so the unlogged pin, not a burn, is the damage).
		// Restore the pair before returning, exactly like CompleteLadder's
		// r40 arm.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	data := validation.VObj(
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("capital_usd", objAt(rung, "capital_usd")),
		kvOf("extraction_ratio", objAt(rung, "extraction_ratio")))
	if _, err := c.Log("ladder.claim_pinned", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return f, nil
}

// CompleteLadder is complete_ladder: close the search — every axis explored,
// maximal rung set and reproduced.
func CompleteLadder(c *state.Campaign, findingID, actor string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	explored := listStrings(listOf(lad, "axes_explored"))
	unexplored := []string{}
	for _, a := range Axes {
		if !containsStr(explored, a) {
			unexplored = append(unexplored, a)
		}
	}
	if len(unexplored) > 0 {
		return validation.VNull(), fmt.Errorf("ladder not complete: "+
			"unexplored axes %s — add a rung or mark each with a written "+
			"not-applicable note (webv2 ladder explore)", pyListRepr(unexplored))
	}
	maxID := objStr(lad, "maximal_rung_id")
	if maxID == "" {
		return validation.VNull(), fmt.Errorf("no maximal rung pinned: "+
			"webv2 ladder set-maximal %s <rung_id> (must be a reproduced rung)",
			findingID)
	}
	rungPtr, err := findRung(lad, maxID)
	if err != nil {
		return validation.VNull(), err
	}
	if objStr(*rungPtr, "status") != "reproduced" {
		return validation.VNull(), fmt.Errorf("maximal rung is not reproduced " +
			"— pin the claim to a reproduced rung or disprove the open rungs")
	}
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("complete")),
		kvOf("reason", validation.VNull()),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(nowIso()))))
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the r40 follow-up closed this verb's LoadFinding and
		// SaveFinding arms but not this one — the first write's own refusal
		// returned with the doc possibly ahead of the ledger.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// r40 follow-up: the ladder was ALREADY saved above, so this
		// refusal left it reading complete with no ledger event and no
		// stamped finding — the same gate-completes-with-zero-events burn
		// the WaiveLadder fix closed, one call site over. Restore the pair
		// before returning, like the ledger-refusal arm below.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	mx := asObj(objAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("complete"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r40 follow-up: same shape — the ladder save stands, the finding
		// stamp did not, and no event was ever appended. Restore, so a
		// failed completion cannot leave a gate reading DONE.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	data := validation.VObj(kvOf("actor", validation.VStr(actor)))
	if _, err := c.Log("ladder.complete", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return lad, nil
}

// WaiveLadder is waive_ladder: explicit, attributed, logged — the honest
// escape hatch. It also records a completion waiver for the finding id.
func WaiveLadder(c *state.Campaign, findingID, reason, actor string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("waived")),
		kvOf("reason", validation.VStr(strings.TrimSpace(reason))),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(nowIso()))))
	// r40 P1: WaiveLadder was the NINTH ladder write site and the only one
	// without the r18 unwind. It saved the ladder, stamped the finding and
	// only THEN called completion.Waive, so EVERY refusal of that call —
	// the >=10-char reason rule, an empty actor, or the ledger refusing
	// the completion.waived append — returned with both files already
	// rewritten: a ladder reading {"state":"waived"} that no ledger event
	// anchors, no waiver row (waivers.jsonl absent), and verify/audit
	// green over it. The refusal can land AFTER the pair is touched (the
	// rule lives in completion.Waive, which runs last by design — hoisting
	// it here would duplicate completion's validation and its Python
	// strip/len semantics), so the door is the class-wide one: snapshot
	// BOTH files before the first write and restore them on any refusal.
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	mx := asObj(objAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("waived"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	if _, err := completion.Waive(c, "maximal-exploitation", findingID,
		reason, actor); err != nil {
		// r40 P1: the ledger refused the completion.waived append (its own
		// waiver row is unwound by state.AppendJsonlThenLog) or the
		// reason/actor rule fired before that append wrote anything. Either
		// way the ladder doc and the finding are already rewritten and must
		// come back: a refused waive must not leave a gate-completing state
		// anywhere (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	return lad, nil
}

// ReopenLadder is reopen_ladder: un-close a closed (complete or waived)
// ladder so more work can be added. requireOpen refuses mutation of a
// COMPLETE ladder and points here; reopening is reasoned, attributed and
// logged. An already-open ladder needs no reopening. (B2: the escape hatch
// the requireOpen error message always advertised but never existed.)
func ReopenLadder(c *state.Campaign, findingID, reason, actor string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		return validation.VNull(), fmt.Errorf("no ladder for %s",
			noneText(findingID))
	}
	lad := *ladPtr
	if objStr(asObj(objAt(lad, "disposition")), "state") == "open" {
		return validation.VNull(), fmt.Errorf("ladder is already open — " +
			"nothing to reopen")
	}
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return validation.VNull(), fmt.Errorf("reopening a closed ladder " +
			"needs a written reason (the audit trail, not a bypass)")
	}
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("open")),
		kvOf("reason", validation.VStr(trimmed)),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(nowIso()))))
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair).
	ladPrev, ladHad := prevFile(ladderPath(c, findingID))
	fPrev, fHad := prevFile(findings.FindingPath(c, findingID))
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// r41 P2: the ladder was ALREADY saved above, so this refusal left
		// it reading "open" with no ladder.reopen event and no finding
		// stamp — the shape CompleteLadder closed at r40, one call site
		// over, and the retry's already-open early-return makes the missing
		// event unemittable forever. Restore the pair first.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	mx := asObj(objAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("open"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r41 P2: the ladder save above STANDS, the finding stamp did not,
		// and no event was ever appended. The ladder now reads "open", so
		// the retry hits the already-open early-return: the reopen, its
		// reason and its actor would be permanently unrecorded. Restore the
		// pair (see restoreLadderPair) so the retry is a REAL reopen.
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)
		return validation.VNull(), err
	}
	data := validation.VObj(
		kvOf("reason", validation.VStr(trimmed)),
		kvOf("actor", validation.VStr(actor)))
	if _, err := c.Log("ladder.reopen", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		restoreLadderPair(c, findingID, ladPrev, ladHad, fPrev, fHad)

		return validation.VNull(), err
	}
	return lad, nil
}

// LadderReport is ladder_report: the ladder with claim-vs-measured deltas.
func LadderReport(c *state.Campaign, findingID string) (validation.Value, error) {
	ladPtr, err := LoadLadder(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if ladPtr == nil {
		fid := validation.VStr(findingID)
		if findingID == "" {
			fid = validation.VNull()
		}
		return validation.VObj(kvOf("finding_id", fid),
			kvOf("ladder", validation.VNull())), nil
	}
	lad := *ladPtr
	variants := listOf(lad, "variants").A
	base := variants[0]
	rungs := []validation.Value{}
	for _, r := range variants {
		row := validation.Value{Kind: validation.Obj,
			O: append([]validation.KV(nil), r.O...)}
		if b, ok := numAt(base, "capital_usd"); ok {
			if v, ok := numAt(r, "capital_usd"); ok {
				row.O = validation.SetOrAppend(row.O, "capital_delta_usd",
					validation.VFloat(v-b))
			}
		}
		if b, ok := numAt(base, "extraction_ratio"); ok {
			if v, ok := numAt(r, "extraction_ratio"); ok {
				row.O = validation.SetOrAppend(row.O, "extraction_delta",
					validation.VFloat(v-b))
			}
		}
		rungs = append(rungs, row)
	}
	maxID := objStr(lad, "maximal_rung_id")
	var maximal validation.Value = validation.VNull()
	for _, r := range variants {
		if maxID != "" && objStr(r, "rung_id") == maxID {
			maximal = r
			break
		}
	}
	explored := listStrings(listOf(lad, "axes_explored"))
	unexplored := []string{}
	for _, a := range Axes {
		if !containsStr(explored, a) {
			unexplored = append(unexplored, a)
		}
	}
	return validation.VObj(
		kvOf("finding_id", validation.VStr(findingID)),
		kvOf("ladder_id", objAt(lad, "ladder_id")),
		kvOf("disposition", objAt(lad, "disposition")),
		kvOf("axes_explored", objAt(lad, "axes_explored")),
		kvOf("unexplored_axes", strArr(unexplored)),
		kvOf("rungs", validation.VArr(rungs...)),
		kvOf("maximal", maximal),
	), nil
}

// numAt is `v.get(key) is not None` + float(v).
func numAt(v validation.Value, key string) (float64, bool) {
	x := objAt(v, key)
	if x.Kind == validation.Null {
		return 0, false
	}
	return numOf(x)
}

// SortAxes is a helper for deterministic diagnostics.
func SortAxes(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}

// r18 P1-2: the LADDER class — StartLadder wrote the ladder doc and the
// finding's maximization block BEFORE logging; a refused Log left the
// projection rows standing, the event absent, and the retry path takes
// the idempotent early-return (finding already has ladder_id) so the
// missing ladder.started can NEVER be emitted — the r9 PinSnapshot
// permanent-burn shape reborn, with `verify` GREEN throughout. Same
// discipline, generalized: capture BOTH file bytes before the first
// write of a verb; restore them together when the ledger refuses.
func prevFile(path string) ([]byte, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// restoreLadderPair undoes one verb's writes. A failed restore is
// swallowed silently ONLY because the caller already returns the ledger
// error — the damage it describes (state ahead of event) is exactly
// what verify's projection hunt burns red, so it is never hidden.
func restoreLadderPair(c *state.Campaign, findingID string,
	ladPrev []byte, ladHad bool, fPrev []byte, fHad bool) {
	lp := ladderPath(c, findingID)
	fp := findings.FindingPath(c, findingID)
	if !ladHad {
		os.Remove(lp)
	} else {
		os.WriteFile(lp, ladPrev, 0o644)
	}
	if !fHad {
		os.Remove(fp)
	} else {
		os.WriteFile(fp, fPrev, 0o644)
	}
}
