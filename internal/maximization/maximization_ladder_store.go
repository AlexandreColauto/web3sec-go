// Ladder store: the ladder artifact path, load/save, rung construction, the base rung and ladder start.
package maximization

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

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
