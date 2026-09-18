package planner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// TrajectoryContracts is TRAJECTORY_CONTRACTS (insertion order is the plan's
// trajectory_matrix order).
var TrajectoryContracts = []validation.KV{
	kv("A-code", validation.VStr("implementation-centric: find bugs in the "+
		"code as written")),
	kv("B-economic", validation.VStr("economic attacker: assume the protocol "+
		"is economically exploitable and find the imbalance")),
	kv("C-state-machine", validation.VStr("state-machine attacker: find "+
		"dangerous call/state sequences and illegal transitions")),
	kv("D-attacker", validation.VStr("privileged actor: assume the attacker "+
		"holds each realistic role and abuse it")),
	kv("E-historical", validation.VStr("historical analog: find variants of "+
		"known exploits, patches and disclosures")),
	kv("F-integration", validation.VStr("adversarial integrator: assume every "+
		"external contract/token behaves unexpectedly")),
	kv("G-drift", validation.VStr("spec drift: spec vs implementation vs "+
		"deployment vs config divergence")),
	kv("H-lifecycle", validation.VStr("consensus/lifecycle game: model the "+
		"full commit→challenge→finalize (or propose→vote→execute) game and "+
		"the adversary WINNING it — a valid transition proven from an "+
		"invalid claimed root, a challenge that never fires, a finalization "+
		"that can be blocked")),
}

// TrajectoryToEnum is TRAJECTORY_TO_ENUM.
var TrajectoryToEnum = map[string]string{
	"A-code": "code", "B-economic": "economic", "C-state-machine": "state-machine",
	"D-attacker": "attacker", "E-historical": "historical",
	"F-integration": "integration", "G-drift": "drift",
	"H-lifecycle": "lifecycle",
}

// LoadPlan is load_plan: read + validate + keep the artifact registration
// current + log the load.
func LoadPlan(campaign *state.Campaign,
	path string) (validation.Value, error) {
	plan, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		return validation.VNull(), err
	}
	n := len(listOf(plan, "priorities"))
	note := "campaign plan, " + itoa(n) + " priorities"
	if _, err := campaign.RegisterOrRefresh("plan", path, note, nil,
		"plan re-loaded (content may have changed)"); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(kv("priorities", validation.VInt(int64(n))))
	if _, err := campaign.Log("plan.loaded", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// ValidatePlan is validate_plan: the plan's write-time checks WITHOUT touching
// disk — seed the canonical lens entries, reject non-canonical bug classes,
// validate against the schema. Split out of SavePlan so a rebuild can prove
// the incoming plan is writable BEFORE it archives the outgoing one (a failed
// rebuild must not retire a live contract).
func ValidatePlan(campaign *state.Campaign,
	plan validation.Value) (validation.Value, error) {
	_, plan = SeedLenses(plan, ModelOrEmpty(campaign))
	bad := nonCanonicalClasses(plan)
	if len(bad) > 0 {
		return validation.VNull(), errValue("priorities " + strings.Join(bad, ", ") +
			" declare non-canonical bug_class; the canonical class list is " +
			"what `webv2 floors " + campaign.CampaignID + "` prints (one row per class, with " +
			"its CONFIRMED floor) — use a listed class or drop the " +
			"bug_class key")
	}
	if err := validation.Validate(plan, "campaign_plan", 1); err != nil {
		return validation.VNull(), err
	}
	return plan, nil
}

// SavePlan is save_plan: write the plan and keep its artifact registration
// current. The plan is a LIVING document (mark_answered rewrites it in
// place); the registry follows the content via a logged refresh instead of
// accumulating ghost rows.
//
// This is the LIVING-document writer, deliberately without a "does a plan
// already exist?" guard: `mark_answered`, `--emit`, lens closures and every
// other sanctioned in-place rewrite go through here. The no-clobber guard for
// REGENERATION lives in `Orchestrator.plan` (B1) — put it here and the living
// document freezes. An empty path is Python's `path=None`.
//
// The write->register window is the r40e UNWIND-ON-REFUSAL site for every
// planner verb that ends in SavePlan (mark_answered, sibling_rescan,
// mark_lens, probes emit, the rebuild corridor): the plan file is written,
// and then the artifact registration APPENDS its ledger event
// (artifact.registered / artifact.refreshed — the refresh pins the new
// bytes' sha256 in the event). A refused append (torn ledger, mirror lag or
// hole, held lock, unreadable ledger) used to leave the new plan file on
// disk while the registration's own unwind reverted the registry row to the
// OLD sha — audit section 2 then burns "content hash mismatch (stored
// <old>..., actual <new>...)" on a plan whose decision the ledger never
// recorded, and the retry after the heal rewrites it twice. So the file's
// bytes are snapshotted before the write, and ANY refusal in the window
// restores those exact bytes (or removes a file that did not exist yet) —
// the same snapshot -> write -> append -> restore dance as
// state.AppendJsonlThenLog, applied to a whole-file artifact, under the
// campaign process lock the inner append re-enters by depth.
func SavePlan(campaign *state.Campaign, plan validation.Value,
	path ...string) (string, error) {
	plan, err := ValidatePlan(campaign, plan)
	if err != nil {
		return "", err
	}
	target := planPath(campaign)
	if len(path) > 0 && path[0] != "" {
		target = path[0]
	}
	n := len(listOf(plan, "priorities"))
	note := "campaign plan, " + itoa(n) + " priorities"
	reason := "plan saved (" + itoa(n) + " priorities)"
	if err := planWindow(campaign, target,
		func() error { return validation.WriteJson(target, plan, "") },
		func() error {
			_, lerr := campaign.RegisterOrRefresh("plan", target, note,
				nil, reason)
			return lerr
		}); err != nil {
		return "", err
	}
	return target, nil
}

// planPath is the campaign plan artifact: artifacts/campaign_plan.json.
func planPath(campaign *state.Campaign) string {
	return filepath.Join(campaign.ArtifactsDir, "campaign_plan.json")
}

// planWindow is the planner's ONE unwind-on-refusal door: snapshot the plan
// file's bytes, hold the campaign process lock across the whole
// snapshot -> write -> append -> restore window (the inner Log/register
// re-enters the lock by depth), run the write, run the ledger append, and
// on ANY refusal restore the exact pre-write bytes — or remove a file that
// did not exist yet, never creating an empty one. A FAILED restore means
// the plan bytes are still AHEAD of the refused event — the exact
// half-land this helper exists to prevent; name both failures so no caller
// can report a clean unwind that never happened.
//
// Two callers share it: SavePlan runs the write + the artifact-registration
// append; planThenLog wraps the whole SavePlan + semantic-event pair (the
// semantic append itself — plan.priority_status / plan.sibling_priority /
// plan.lens_status — is the same law at one level up: a status flip the
// ledger never recorded is a decision the gates read as truth, so its
// refusal must also put the plan bytes back).
func planWindow(campaign *state.Campaign, target string,
	write func() error, log func() error) error {
	if err := campaign.LockProcess(); err != nil {
		return err
	}
	defer campaign.UnlockProcess()
	prevRaw, perr := os.ReadFile(target)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	restore := func() error {
		if had {
			return os.WriteFile(target, prevRaw, 0o644)
		}
		if rerr := os.Remove(target); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	fail := func(err error) error {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s holds "+
				"post-write bytes with no event; repair by hand before "+
				"continuing)", err, rerr, filepath.Base(target))
		}
		return err
	}
	if err := write(); err != nil {
		// A failed or short write can still have put bytes on disk
		// (a non-atomic writer, a failing fsync): the plan file would be
		// there with the error returned — the same half-land as a refused
		// append.
		return fail(err)
	}
	if err := log(); err != nil {
		return fail(err)
	}
	return nil
}

// planThenLog is the r40e door for the named SavePlan->Log pairings
// (mark_answered, sibling_rescan, mark_lens): snapshot the plan file, save
// the plan (SavePlan's own window restores on ITS refusal), append the
// semantic event, and on ITS refusal restore the pre-write bytes exactly.
// The restore is the loud shape on purpose: when the semantic append is the
// refused one, the artifact registration ahead of it has already refreshed
// the registry row to the post-write bytes (its event pins them), so a
// restored file and an advanced row disagree — audit section 2 names the
// mismatch, with `webv2 artifact-reconcile` as the sanctioned repair — while
// the alternative (leaving the flipped status in place) is the silent
// half-land no audit direction sees.
func planThenLog(campaign *state.Campaign, plan validation.Value,
	log func() error) error {
	target := planPath(campaign)
	return planWindow(campaign, target,
		func() error {
			_, werr := SavePlan(campaign, plan)
			return werr
		}, log)
}

// isCanonicalClass reports whether cls is in the canonical bug-class vocabulary
// SavePlan hard-validates against (taxonomy.KnownClasses — the same set the
// findings transitions seam wires). One classifier for the validator, the plan
// builder and the divergence gate's findings reader, so a class one of them
// accepts can never be one the others reject.
func isCanonicalClass(cls string) bool {
	_, ok := taxonomy.KnownClasses()[cls]
	return ok
}

// nonCanonicalClasses is the bug_class hard-validation list.
func nonCanonicalClasses(plan validation.Value) []string {
	bad := []string{}
	for _, p := range listOf(plan, "priorities") {
		bc := validation.ObjAt(p, "bug_class")
		if !pyTruthyBigNonEmpty(bc) {
			continue
		}
		if bc.Kind != validation.Str || !isCanonicalClass(bc.S) {
			bad = append(bad, validation.ObjStr(p, "id")+" (bug_class "+
				validation.PyRepr(bc)+")")
		}
	}
	return bad
}
