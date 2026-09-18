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
	"slices"
	"sort"
	"strings"

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

// asObj is `d.get(key) or {}`.

func listOf(v validation.Value, key string) validation.Value {
	if f := validation.ObjAt(v, key); f.Kind == validation.Arr {
		return f
	}
	return validation.VArr()
}

// pyListRepr is Python's repr() of a list of strings.

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
	ladder.O = validation.SetOrAppend(ladder.O, "updated_at", validation.VStr(state.NowIso()))
	if err := validation.Validate(*ladder, "variant_ladder", 1); err != nil {
		return "", err
	}
	p := ladderPath(c, validation.ObjStr(*ladder, "finding_id"))
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
		kvOf("axes", validation.StrArr(axes)),
		kvOf("capital_usd", capV),
		kvOf("extraction_ratio", extV),
		kvOf("removed_preconditions", validation.StrArr(removed)),
		kvOf("added_preconditions", validation.StrArr(added)),
		kvOf("status", validation.VStr(status)),
		kvOf("exec_id", execV),
		kvOf("evidence_id", evV),
		kvOf("reason", validation.VStr(reason)),
		kvOf("created_at", validation.VStr(state.NowIso())),
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
		kvOf("created_at", validation.VStr(state.NowIso())),
		kvOf("updated_at", validation.VStr(state.NowIso())),
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
	// refused event restores them (restoreLadderPair). r42: the snapshot
	// itself REFUSES the verb when either file exists but cannot be read,
	// BEFORE this first write, so nothing needs unwinding.
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r19 P1 #4: SaveLadder's own write is atomic (temp+rename), but
		// a partial-visibility error (ENOSPC mid-rename on some mounts)
		// must not leave a doc the retry will early-return over. Remove
		// any bytes it may have produced (start ran on an absent ladder
		// — the early-return above proves it).
		if rmErr := os.Remove(ladderPath(c, findingID)); rmErr != nil &&
			!os.IsNotExist(rmErr) {
			orphan := fmt.Errorf(
				"%w (AND the orphan ladder doc could NOT be removed: %v — "+
					"the retry's early-return would print 'started' without "+
					"an event; remove ladders/%s.json by hand)", err, rmErr,
				findingID)
			return validation.VNull(), unwindLadderPair(pair, orphan)
		}
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "ladder_id", validation.ObjAt(lad, "ladder_id"))
	if !validation.HasKey(mx, "disposition") {
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
			return validation.VNull(), unwindLadderPair(pair, fmt.Errorf(
				"%w (AND the orphan ladder doc survived removal: %v — "+
					"delete ladders/%s.json by hand before retrying)", err,
				rmErr, findingID))
		}
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("ladder_id", validation.ObjAt(lad, "ladder_id")),
		kvOf("base_rung", validation.ObjAt(base, "rung_id")))
	if _, err := c.Log("ladder.started", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	return lad, nil
}

// baseRung is rung 0: the finding's current claim, its capital and ratio
// carried over, status "reproduced" only when reproduction says so, and the
// first cited EXEC evidence id.
func baseRung(f validation.Value) validation.Value {
	impact := validation.AsObj(validation.ObjAt(f, "economic_impact"))
	repro := validation.AsObj(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "verification")), "reproduction"))
	status := "assumed"
	if validation.ObjStr(repro, "status") == "reproduced" {
		status = "reproduced"
	}
	var capitalPtr, ratioPtr *float64
	if v := validation.ObjAt(validation.AsObj(validation.ObjAt(f, "attacker")), "required_capital_usd"); v.Kind !=
		validation.Null {
		if fv, ok := numOf(v); ok {
			capitalPtr = &fv
		}
	}
	if v := validation.ObjAt(impact, "extraction_ratio"); v.Kind != validation.Null {
		if fv, ok := numOf(v); ok {
			ratioPtr = &fv
		}
	}
	base := newRung("base", "as claimed at reproduction: "+validation.ObjStr(f, "title"),
		nil, capitalPtr, ratioPtr, nil, nil, status, nil, nil, "")
	cited := []string{}
	for _, e := range listOf(f, "evidence").A {
		if strings.HasPrefix(validation.ObjStr(e, "artifact_id"), "EXEC-") {
			cited = append(cited, validation.ObjStr(e, "artifact_id"))
		}
	}
	if len(cited) > 0 {
		base.O = validation.SetOrAppend(base.O, "exec_id", validation.VStr(cited[0]))
	}
	return base
}

// hasKey is `key in d`.

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
	if validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "disposition")), "state") == "complete" {
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
		if !slices.Contains(Axes, a) {
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
		if !slices.Contains(listStrings(explored), a) {
			explored.A = append(explored.A, validation.VStr(a))
		}
	}
	lad.O = validation.SetOrAppend(lad.O, "axes_explored", explored)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the SaveLadder-error arm was the one return after this
		// verb's first write that skipped the unwind (SetMaximal,
		// WaiveLadder, ReopenLadder and StartLadder all restore here).
		// WriteJson is atomic, but a partial-visibility failure can still
		// leave the doc ahead of the ledger; restore the pair.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("rung_id", validation.ObjAt(rung, "rung_id")),
		kvOf("axes", validation.StrArr(axes)),
		kvOf("name", validation.VStr(name)))
	if _, err := c.Log("ladder.variant_added", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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

// ExploreAxis is explore_axis: mark an axis explored WITHOUT a rung — when
// the honest answer is 'considered, not applicable', the note is the artifact.
func ExploreAxis(c *state.Campaign, findingID, axis, note string) (validation.Value, error) {
	if !slices.Contains(Axes, axis) {
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
	notes := validation.AsObj(validation.ObjAt(lad, "axis_notes"))
	notes.O = validation.SetOrAppend(notes.O, axis, validation.VStr(strings.TrimSpace(note)))
	lad.O = validation.SetOrAppend(lad.O, "axis_notes", notes)
	explored := listOf(lad, "axes_explored")
	if !slices.Contains(listStrings(explored), axis) {
		explored.A = append(explored.A, validation.VStr(axis))
	}
	lad.O = validation.SetOrAppend(lad.O, "axes_explored", explored)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: same arm as AddVariant's — the first write's own refusal
		// returned without the unwind.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("axis", validation.VStr(axis)),
		kvOf("note", validation.VStr(truncate(strings.TrimSpace(note), 200))))
	if _, err := c.Log("ladder.axis_explored", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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
	desc := fmt.Sprintf("variant rung %s: %s", validation.ObjStr(rung, "name"),
		validation.ObjStr(rung, "description"))
	// r41 P1: MintReproEvidence writes the FINDING first —
	// findings.AddEvidence saves the evidence item and only THEN appends
	// finding.evidence_added, with no unwind of its own — so a refused
	// ledger returns from the mint with the item already ON the finding and
	// no event behind it. These baselines used to be captured AFTER the
	// mint (:638-639), which left that half-land outside this verb's unwind
	// window: a refused ladder.rung_reproduced kept the minted evidence and
	// its updated_at stamp, with zero events anywhere. Capture BOTH files
	// BEFORE the mint; a refused mint restores them.
	preMint, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := reproduction.MintReproEvidence(c, findingID, execID, desc,
		nil, evidenceType); err != nil {
		return validation.VNull(), unwindLadderPair(preMint, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// The mint wrote this file moments ago, so this refusal means the
		// finding went missing under it: unwind the mint's half-land.
		return validation.VNull(), unwindLadderPair(preMint, err)
	}
	evID := ""
	for _, e := range listOf(f, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			evID = validation.ObjStr(e, "evidence_id")
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
	rung.O = validation.SetOrAppend(rung.O, "reproduced_at", validation.VStr(state.NowIso()))
	if err := replaceRung(&lad, rung); err != nil {
		// Nothing to unwind: the ladder is still only in memory here, and
		// the mint's own finding file + finding.evidence_added pair is
		// already complete (see the window note below). Unreachable anyway
		// — findRung just proved the rung id exists.
		return validation.VNull(), err
	}
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(state.NowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("reproduced")),
		kvOf("exec_id", validation.VStr(execID))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// Re-capture the FINDING now that the mint's own finding.evidence_added
	// event has landed (the mint returns success only once both halves are
	// written): the item is then an authoritative file+event pair, and
	// restoring the file alone would orphan that event. The LADDER snapshot
	// above stands — nothing has written the ladder since it was captured.
	// An unreadable re-capture refuses here, before the ladder write.
	postMint := preMint
	postMint.fnd = prevFile(findings.FindingPath(c, findingID))
	if postMint.fnd.unreadable {
		return validation.VNull(), ladderSnapshotRefusal("finding", findingID,
			postMint.fnd)
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: this arm returned without the unwind too.
		return validation.VNull(), unwindLadderPair(postMint, err)
	}
	data := validation.VObj(
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("exec_id", validation.VStr(execID)))
	if _, err := c.Log("ladder.rung_reproduced", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(postMint, err)
	}
	return rung, nil
}

// findRung is _find_rung. The KeyError text is Python's: the CLI renders
// str(KeyError(msg)) — repr of the message — so the message is wrapped here.
func findRung(lad validation.Value, rungID string) (*validation.Value, error) {
	ids := []string{}
	for _, r := range listOf(lad, "variants").A {
		if validation.ObjStr(r, "rung_id") == rungID {
			out := r
			return &out, nil
		}
		ids = append(ids, validation.ObjStr(r, "rung_id"))
	}
	msg := fmt.Sprintf("unknown rung %s; rungs: %s", idRepr(rungID),
		validation.PyListRepr(ids))
	return nil, &keyError{msg: validation.PyReprStr(msg)}
}

// keyError is Python's KeyError: str(e) is repr(message).
type keyError struct{ msg string }

func (e *keyError) Error() string { return e.msg }

// replaceRung swaps the rung with the same rung_id back into variants.
func replaceRung(lad *validation.Value, rung validation.Value) error {
	variants := listOf(*lad, "variants")
	for i, r := range variants.A {
		if validation.ObjStr(r, "rung_id") == validation.ObjStr(rung, "rung_id") {
			variants.A[i] = rung
			lad.O = validation.SetOrAppend(lad.O, "variants", variants)
			return nil
		}
	}
	return fmt.Errorf("unknown rung %s", validation.PyReprStr(validation.ObjStr(rung, "rung_id")))
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
	if validation.ObjStr(rung, "status") == "reproduced" {
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
		kvOf("at", validation.VStr(state.NowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("disproved"))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the first write's own refusal skipped the unwind.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	fid := findingID
	negative := validation.VObj(kvOf("why_safe", validation.VStr(strings.TrimSpace(reason))))
	if _, err := queueMemory(c, MemoryRequest{
		Kind: "disproved", Status: "DISPROVED",
		Pattern: "maximal-exploitation dead end: " + validation.ObjStr(rung, "name") +
			" — " + validation.ObjStr(rung, "description"),
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
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(kvOf("rung_id", validation.VStr(rungID)))
	if _, err := c.Log("ladder.rung_disproved", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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
	if validation.ObjStr(rung, "status") != "reproduced" {
		return validation.VNull(), fmt.Errorf("rung %s is %s; the claim may "+
			"only pin to a REPRODUCED rung — an assumed rung is a hypothesis "+
			"about bigger impact, not a claim of it", rungID,
			validation.PyReprStr(validation.ObjStr(rung, "status")))
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	lad.O = validation.SetOrAppend(lad.O, "maximal_rung_id", validation.VStr(rungID))
	hist := listOf(lad, "history")
	hist.A = append(hist.A, validation.VObj(
		kvOf("at", validation.VStr(state.NowIso())),
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("event", validation.VStr("claim_pinned"))))
	lad.O = validation.SetOrAppend(lad.O, "history", hist)
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "maximal_rung_id", validation.VStr(rungID))
	mx.O = validation.SetOrAppend(mx.O, "claim_from", validation.VStr(rungID))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if v := validation.ObjAt(rung, "capital_usd"); v.Kind != validation.Null {
		attacker := validation.AsObj(validation.ObjAt(f, "attacker"))
		attacker.O = validation.SetOrAppend(attacker.O, "required_capital_usd", v)
		f.O = validation.SetOrAppend(f.O, "attacker", attacker)
	}
	if v := validation.ObjAt(rung, "extraction_ratio"); v.Kind != validation.Null {
		impact := validation.AsObj(validation.ObjAt(f, "economic_impact"))
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
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("rung_id", validation.VStr(rungID)),
		kvOf("capital_usd", validation.ObjAt(rung, "capital_usd")),
		kvOf("extraction_ratio", validation.ObjAt(rung, "extraction_ratio")))
	if _, err := c.Log("ladder.claim_pinned", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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
		if !slices.Contains(explored, a) {
			unexplored = append(unexplored, a)
		}
	}
	if len(unexplored) > 0 {
		return validation.VNull(), fmt.Errorf("ladder not complete: "+
			"unexplored axes %s — add a rung or mark each with a written "+
			"not-applicable note (webv2 ladder explore)", validation.PyListRepr(unexplored))
	}
	maxID := validation.ObjStr(lad, "maximal_rung_id")
	if maxID == "" {
		return validation.VNull(), fmt.Errorf("no maximal rung pinned: "+
			"webv2 ladder set-maximal %s <rung_id> (must be a reproduced rung)",
			findingID)
	}
	rungPtr, err := findRung(lad, maxID)
	if err != nil {
		return validation.VNull(), err
	}
	if validation.ObjStr(*rungPtr, "status") != "reproduced" {
		return validation.VNull(), fmt.Errorf("maximal rung is not reproduced " +
			"— pin the claim to a reproduced rung or disprove the open rungs")
	}
	lad.O = validation.SetOrAppend(lad.O, "disposition", validation.VObj(
		kvOf("state", validation.VStr("complete")),
		kvOf("reason", validation.VNull()),
		kvOf("actor", validation.VStr(actor)),
		kvOf("at", validation.VStr(state.NowIso()))))
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// r41 P2: the r40 follow-up closed this verb's LoadFinding and
		// SaveFinding arms but not this one — the first write's own refusal
		// returned with the doc possibly ahead of the ledger.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// r40 follow-up: the ladder was ALREADY saved above, so this
		// refusal left it reading complete with no ledger event and no
		// stamped finding — the same gate-completes-with-zero-events burn
		// the WaiveLadder fix closed, one call site over. Restore the pair
		// before returning, like the ledger-refusal arm below.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("complete"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r40 follow-up: same shape — the ladder save stands, the finding
		// stamp did not, and no event was ever appended. Restore, so a
		// failed completion cannot leave a gate reading DONE.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(kvOf("actor", validation.VStr(actor)))
	if _, err := c.Log("ladder.complete", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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
		kvOf("at", validation.VStr(state.NowIso()))))
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
	// r42: the snapshot ABORTS here, before that first write, when either
	// file exists but cannot be read (the door that used to DELETE it).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("waived"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	if _, err := completion.Waive(c, "maximal-exploitation", findingID,
		reason, actor); err != nil {
		// r40 P1: the ledger refused the completion.waived append (its own
		// waiver row is unwound by state.AppendJsonlThenLog) or the
		// reason/actor rule fired before that append wrote anything. Either
		// way the ladder doc and the finding are already rewritten and must
		// come back: a refused waive must not leave a gate-completing state
		// anywhere (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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
	if validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "disposition")), "state") == "open" {
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
		kvOf("at", validation.VStr(state.NowIso()))))
	// r18: capture BOTH files before the first write; a
	// refused event restores them (restoreLadderPair). r42: an unreadable
	// file refuses the verb before any write (see snapshotLadderFiles).
	pair, err := snapshotLadderFiles(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveLadder(c, &lad); err != nil {
		// A refused or short write can still have put bytes on disk
		// (temp+rename that failed after the rename, ENOSPC mid-write).
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		// r41 P2: the ladder was ALREADY saved above, so this refusal left
		// it reading "open" with no ladder.reopen event and no finding
		// stamp — the shape CompleteLadder closed at r40, one call site
		// over, and the retry's already-open early-return makes the missing
		// event unemittable forever. Restore the pair first.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	mx := validation.AsObj(validation.ObjAt(f, "maximization"))
	mx.O = validation.SetOrAppend(mx.O, "disposition", validation.VStr("open"))
	f.O = validation.SetOrAppend(f.O, "maximization", mx)
	if err := findings.SaveFinding(c, &f); err != nil {
		// r41 P2: the ladder save above STANDS, the finding stamp did not,
		// and no event was ever appended. The ladder now reads "open", so
		// the retry hits the already-open early-return: the reopen, its
		// reason and its actor would be permanently unrecorded. Restore the
		// pair (see restoreLadderPair) so the retry is a REAL reopen.
		return validation.VNull(), unwindLadderPair(pair, err)
	}
	data := validation.VObj(
		kvOf("reason", validation.VStr(trimmed)),
		kvOf("actor", validation.VStr(actor)))
	if _, err := c.Log("ladder.reopen", &findingID, &data); err != nil {
		// r18: the ledger refused — restore BOTH the ladder
		// doc and the finding (see restoreLadderPair).
		return validation.VNull(), unwindLadderPair(pair, err)
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
	maxID := validation.ObjStr(lad, "maximal_rung_id")
	var maximal validation.Value = validation.VNull()
	for _, r := range variants {
		if maxID != "" && validation.ObjStr(r, "rung_id") == maxID {
			maximal = r
			break
		}
	}
	explored := listStrings(listOf(lad, "axes_explored"))
	unexplored := []string{}
	for _, a := range Axes {
		if !slices.Contains(explored, a) {
			unexplored = append(unexplored, a)
		}
	}
	return validation.VObj(
		kvOf("finding_id", validation.VStr(findingID)),
		kvOf("ladder_id", validation.ObjAt(lad, "ladder_id")),
		kvOf("disposition", validation.ObjAt(lad, "disposition")),
		kvOf("axes_explored", validation.ObjAt(lad, "axes_explored")),
		kvOf("unexplored_axes", validation.StrArr(unexplored)),
		kvOf("rungs", validation.VArr(rungs...)),
		kvOf("maximal", maximal),
	), nil
}

// numAt is `v.get(key) is not None` + float(v).
func numAt(v validation.Value, key string) (float64, bool) {
	x := validation.ObjAt(v, key)
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
//
// r42 P1: that snapshot used to collapse EVERY read error into "the file
// did not exist" and the restore honored the lie with os.Remove — so an
// existing-but-UNREADABLE finding was DELETED by the very unwind that
// exists to protect it. The message ('open ...: permission denied') never
// said the tool had done the deleting, the ladder was left pointing at a
// record that no longer existed, and verify/audit stayed GREEN over the
// loss. Three pre-call states, never two:
//
//	absent     — ReadFile said ENOENT: the restore removes what this verb
//	             may have created, and only that.
//	readable   — the exact pre-call bytes are in raw: the restore puts them
//	             back byte for byte.
//	unreadable — the file is there (or a read failure leaves its absence
//	             UNPROVEN) and its bytes are unknown: the restore must not
//	             touch it, and must SAY SO.
type ladderFileSnap struct {
	path       string
	raw        []byte
	had        bool  // ReadFile succeeded: raw holds the exact pre-call bytes
	unreadable bool  // present (or absence unproven) and NOT readable
	rerr       error // why the bytes are unknown, when unreadable
}

// prevFile is the ladder family's only reader. It returns the read error
// UNCOLLAPSED — os.IsNotExist(err) is the one "the file was absent"
// signal — and classifies the path into the three states above, the same
// three-state discipline findings.prevBytes and state.appendJsonlThenLog
// follow. A caller that sees unreadable must ABORT the verb BEFORE its
// first write; that abort is what keeps the r42 deletion unreachable.
func prevFile(path string) ladderFileSnap {
	raw, err := os.ReadFile(path)
	if err == nil {
		return ladderFileSnap{path: path, raw: raw, had: true}
	}
	if os.IsNotExist(err) {
		// Genuinely absent: the verb may create it, and the unwind may
		// remove what the verb created. Nothing to guess at.
		return ladderFileSnap{path: path}
	}
	// Not "absent": the file is there and unreadable, or a read failure
	// leaves its absence UNPROVEN (absence is inconclusive). Either way
	// its bytes are unknown, so no restore may conclude they were gone.
	_, serr := os.Stat(path)
	return ladderFileSnap{path: path, had: serr == nil, unreadable: true,
		rerr: err}
}

// ladderPair is the two files one ladder verb may touch, both captured
// before its first write.
type ladderPair struct {
	lad ladderFileSnap
	fnd ladderFileSnap
}

// snapshotLadderFiles is the ONE snapshot door of the ladder family: read
// BOTH files before the verb's first write and REFUSE the verb when either
// one exists but cannot be read. A verb that never starts writing has
// nothing to unwind, so the r42 deletion becomes unreachable — and the
// restore refuses the unreadable state on its own too (see restore).
func snapshotLadderFiles(c *state.Campaign, findingID string) (ladderPair, error) {
	lad := prevFile(ladderPath(c, findingID))
	if lad.unreadable {
		return ladderPair{}, ladderSnapshotRefusal("ladder", findingID, lad)
	}
	fnd := prevFile(findings.FindingPath(c, findingID))
	if fnd.unreadable {
		return ladderPair{}, ladderSnapshotRefusal("finding", findingID, fnd)
	}
	return ladderPair{lad: lad, fnd: fnd}, nil
}

// ladderSnapshotRefusal names the read failure, the file and the choice:
// the verb stops BEFORE any write, so nothing was changed and nothing
// needs unwinding. The retry after the file is readable is a real verb —
// not the "no finding in campaign" the old deletion answered with.
func ladderSnapshotRefusal(kind, findingID string, s ladderFileSnap) error {
	why := "is present but unreadable"
	if !s.had {
		why = "cannot be read and its absence cannot be proven"
	}
	return fmt.Errorf("cannot snapshot the %s %s before writing (%w): it %s — "+
		"refusing before any write, so its bytes are neither overwritten nor "+
		"removed; make it readable and retry", kind, findingID, s.rerr, why)
}

// restore puts this file back exactly as it was, or REPORTS that it could
// not — a failed restore is never swallowed again (restoreLadderPair used
// to return void while every other door in the tree names its failures).
func (s ladderFileSnap) restore() error {
	if s.unreadable {
		// The pre-call bytes were never readable: removing would be the
		// r42 bug (deleting a record we never saw), writing would invent
		// them. Leave the file ALONE and say so.
		return fmt.Errorf("the pre-call bytes were never readable (%v), so "+
			"%s could not be restored and was NOT touched", s.rerr,
			filepath.Base(s.path))
	}
	if !s.had {
		if rerr := os.Remove(s.path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	return os.WriteFile(s.path, s.raw, 0o644)
}

// restoreLadderPair undoes one verb's writes, file by file, and NAMES every
// file it could not put back (the same voice as findings.SaveThenLog,
// sandbox's execDirTxn.fail and the link/JSONL siblings). A silent failed
// restore is the half-land this law exists to prevent: state ahead of event
// is exactly what verify's projection hunt burns red over.
func restoreLadderPair(p ladderPair) error {
	var failed []string
	for _, s := range []ladderFileSnap{p.lad, p.fnd} {
		if rerr := s.restore(); rerr != nil {
			failed = append(failed, fmt.Sprintf("%s: %v",
				filepath.Base(s.path), rerr))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not restore %s", strings.Join(failed, "; "))
	}
	return nil
}

// unwindLadderPair restores the pair and returns the verb's refusal, naming
// BOTH failures when the restore itself failed — the same wording as
// findings.SaveThenLog's '(UNWIND ALSO FAILED: ...)'.
func unwindLadderPair(p ladderPair, refused error) error {
	if rerr := restoreLadderPair(p); rerr != nil {
		return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the ladder pair may "+
			"hold post-write bytes with no event; repair the named file(s) "+
			"by hand before continuing)", refused, rerr)
	}
	return refused
}
