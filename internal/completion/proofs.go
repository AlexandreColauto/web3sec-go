// proofs.go: the proof builders, in PROOFS order. Each returns
// {"done": bool, "missing": [str], "note": str} — deterministic, read-only,
// total: a missing file means NOT done, never a crash (the halt must be
// reportable, not an exception).
package completion

import (
	"fmt"
	"path/filepath"
	"strings"

	"websec/internal/invariants"
	"websec/internal/planner"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// seams into modules that are not ported yet (rule 5)
// ---------------------------------------------------------------------------

// MaximizationAPI is the maximization.load_ladder seam: the finding's variant
// ladder, or Null when none exists (Python's None).
type MaximizationAPI interface {
	LoadLadder(c *state.Campaign, findingID string) (validation.Value, error)
}

type noLadders struct{}

func (noLadders) LoadLadder(*state.Campaign, string) (validation.Value, error) {
	return validation.VNull(), nil
}

var maximizationImpl MaximizationAPI = noLadders{}

// SetMaximization installs maximization.load_ladder; nil restores the
// default (no ladder artifact = Python's absent-file answer).
func SetMaximization(m MaximizationAPI) {
	if m == nil {
		m = noLadders{}
	}
	maximizationImpl = m
}

// ForkPocAPI is the fork_poc.fork_poc_evidence seam. Evidence returns the
// proven evidence item (Null = not proven) plus the missing[] reason; the
// item itself is unused by the proof, only its presence is.
type ForkPocAPI interface {
	ForkPocEvidence(c *state.Campaign,
		finding validation.Value) (validation.Value, *string, error)
}

type noForkPoc struct{}

// ForkPocEvidence is the "fork_poc not wired" default, byte-identical to the
// Python twin for the campaigns whose proof cannot hold: a finding with no
// fork-level (E5/E6) evidence gets Python's first reason literal; one that
// CLAIMS fork-level evidence gets the "not traced to a SUCCEEDED
// fork-runner exec" literal. The sequence-coverage branch (a campaign with a
// fork target and a multi-step finding) belongs to sequence_poc and is not
// reproduced here — see the seam report.
func (noForkPoc) ForkPocEvidence(_ *state.Campaign,
	finding validation.Value) (validation.Value, *string, error) {
	reason := "no fork-level evidence (E5/E6) — run the PoC on the " +
		"pinned mainnet fork (webv2 exec --profile fork-runner) and mint it " +
		"(webv2 mint --type fork-test)"
	for _, e := range listAt(finding, "evidence") {
		if e.Kind != validation.Obj {
			continue
		}
		lvl := objStr(e, "level")
		if lvl == "E5" || lvl == "E6" {
			reason = "evidence claims fork-level but no E5/E6 item traces to a " +
				"SUCCEEDED fork-runner exec in the ledger — unit-harness " +
				"evidence (E4) proves semantics, not mainnet"
			break
		}
	}
	return validation.VNull(), &reason, nil
}

var forkPocImpl ForkPocAPI = noForkPoc{}

// SetForkPocEvidence installs fork_poc.fork_poc_evidence; nil restores the
// default (nothing can be proven).
func SetForkPocEvidence(f ForkPocAPI) {
	if f == nil {
		f = noForkPoc{}
	}
	forkPocImpl = f
}

// ---------------------------------------------------------------------------
// protocol-model … reproduction
// ---------------------------------------------------------------------------

// proofProtocolModel is _proof_protocol_model. The artifact alone is NOT the
// proof: every invariant the model declares must be in the seeded registry.
func proofProtocolModel(c *state.Campaign) (validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if !fileExists(p) {
		return proofResult(false, []string{"artifacts/protocol_model.json — run the " +
			"protocol-model stage and load the model"}, "model not loaded"), nil
	}
	model, err := validation.ReadJson(p)
	if err != nil {
		return proofResult(false, []string{"protocol model is unreadable/invalid — re-run " +
			"`webv2 model <campaign> model.json`"}, "protocol model artifact unreadable"), nil
	}
	modelIDs := []string{}
	for _, inv := range listAt(model, "invariants") {
		if inv.Kind != validation.Obj {
			continue
		}
		if id := objStr(inv, "id"); id != "" {
			modelIDs = append(modelIDs, id)
		}
	}
	if len(modelIDs) == 0 {
		return proofResult(false, []string{"the protocol model declares no invariants — a " +
			"protocol without invariants is not auditable; refine the model (the invariant seed step has " +
			"nothing to seed)"}, "protocol model has no invariants"), nil
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := objAt(links, "invariants")
	// Python guards `isinstance(k, str)`; a JSON object key is always a
	// string, so every key counts.
	normReg := map[string]bool{}
	for _, k := range reg.O {
		normReg[invariants.NormalizeInvID(k.K)] = true
	}
	unseeded := []string{}
	for _, id := range modelIDs {
		if !normReg[invariants.NormalizeInvID(id)] {
			unseeded = append(unseeded, id)
		}
	}
	if len(unseeded) > 0 {
		head := unseeded
		if len(head) > 5 {
			head = head[:5]
		}
		tail := ""
		if len(unseeded) > 5 {
			tail = "..."
		}
		msg := fmt.Sprintf("invariant registry missing %d model invariant(s) "+
			"(%s %s) — seeding did not run; re-run `webv2 model <campaign> "+
			"model.json`", len(unseeded), strings.Join(head, ", "), tail)
		note := fmt.Sprintf("protocol model loaded but %d invariant(s) unseeded",
			len(unseeded))
		return proofResult(false, []string{msg}, note), nil
	}
	note := fmt.Sprintf("protocol model loaded, %d invariant(s) seeded in the registry",
		len(modelIDs))
	return proofResult(true, []string{}, note), nil
}

// loadPlan is _load_plan: the campaign plan, read-only. found=false is
// Python's FileNotFoundError branch; an error is any other load failure.
func loadPlan(c *state.Campaign) (validation.Value, bool, error) {
	p := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	if !fileExists(p) {
		return validation.VNull(), false, nil
	}
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		return validation.VNull(), true, err
	}
	return plan, true, nil
}

// proofCampaignPlanning is _proof_campaign_planning.
func proofCampaignPlanning(c *state.Campaign) (validation.Value, error) {
	plan, found, err := loadPlan(c)
	if err != nil {
		return validation.VNull(), err
	}
	if !found {
		return proofResult(false, []string{"campaign plan — orchestrator.plan()"},
			"no plan"), nil
	}
	priorities := listAt(plan, "priorities")
	if !pyTruthy(objAt(plan, "priorities")) {
		return proofResult(false, []string{"plan has zero priorities"},
			"empty plan"), nil
	}
	return proofResult(true, []string{},
		fmt.Sprintf("%d priorities", len(priorities))), nil
}

// proofDiscovery is _proof_discovery: draining the work queue is necessary,
// not sufficient — the divergence gate must close too.
func proofDiscovery(c *state.Campaign) (validation.Value, error) {
	plan, found, err := loadPlan(c)
	if err != nil {
		return validation.VNull(), err
	}
	if !found {
		return proofResult(false,
			[]string{"campaign plan (discovery consumes its queue)"},
			"no plan"), nil
	}
	queue, err := planner.WorkQueue(c, plan, validation.VObj(), false)
	if err != nil {
		return validation.VNull(), err
	}
	items := make([]proofItem, 0, len(queue))
	for _, w := range queue {
		items = append(items, proofItem{objStr(w, "priority_id"),
			headRunes(objStr(w, "question"), 60)})
	}
	divergence, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		return validation.VNull(), err
	}
	divMissing := listAt(divergence, "missing")
	for _, m := range divMissing {
		items = append(items, proofItem{objStr(m, "subject"), objStr(m, "what")})
	}
	wmap, err := waiverMap(c, "discovery")
	if err != nil {
		return validation.VNull(), err
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "work queue drained; divergence gate closed"
	if len(queue) > 0 {
		note = fmt.Sprintf("%d queued priorities remain", len(queue))
	} else if len(divMissing) > 0 {
		note = "work queue drained but the divergence gate is open"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofDedup is _proof_dedup (advisory): the deterministic sweep runs in the
// builtin; what it cannot do is adjudicate the near-duplicate CANDIDATES.
func proofDedup(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "dedup")
	if err != nil {
		return validation.VNull(), err
	}
	unresolved := []proofItem{}
	live, err := liveFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range live {
		fid := objStr(f, "finding_id")
		dd := orEmpty(objAt(f, "dedup"))
		verdicts := orEmpty(objAt(dd, "candidate_verdicts"))
		for _, other := range listAt(dd, "possible_duplicate_of") {
			// Python: verdicts.get(other) — a list/dict entry is
			// unhashable and raises TypeError, which proof_status reports
			// as "proof error: unhashable type: 'list'".
			if other.Kind == validation.Arr || other.Kind == validation.Obj {
				return validation.VNull(), fmt.Errorf("unhashable type: %s",
					validation.PyReprStr(kindName(other)))
			}
			v := objAt(verdicts, other.S)
			if v.Kind == validation.Str && (v.S == "same" || v.S == "distinct") {
				continue
			}
			unresolved = append(unresolved, proofItem{fid + "~" + pyStrAny(other),
				"no normalization verdict"})
		}
	}
	missing := unwaived(unresolved, wmap, func(s, m string) string {
		return "candidate pair " + s + ": " + m
	})
	note := "all candidate pairs adjudicated"
	if len(missing) > 0 {
		note = "unresolved near-duplicate candidates"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofHostileReview is _proof_hostile_review.
func proofHostileReview(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "hostile-review")
	if err != nil {
		return validation.VNull(), err
	}
	open, err := findingsWith(c, OpenStatuses)
	if err != nil {
		return validation.VNull(), err
	}
	openItems := []proofItem{}
	for _, f := range open {
		verdict, ok := fieldAt(orEmpty(objAt(f, "verification")), "critic_verdict")
		if !ok || verdict.Kind == validation.Null ||
			(verdict.Kind == validation.Str && verdict.S == "pending") {
			openItems = append(openItems, proofItem{objStr(f, "finding_id"),
				"no critic verdict"})
		}
	}
	missing := unwaived(openItems, wmap, func(s, m string) string { return s + ": " + m })
	note := "every open finding reviewed"
	if len(openItems) > 0 {
		note = fmt.Sprintf("%d open findings await review", len(openItems))
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// proofReproduction is _proof_reproduction (advisory): POSSIBLE findings
// whose critic CONFIRMED them must have at least one honest reproduction
// ATTEMPT recorded (attempts include failures — the attempt is the work).
func proofReproduction(c *state.Campaign) (validation.Value, error) {
	wmap, err := waiverMap(c, "reproduction")
	if err != nil {
		return validation.VNull(), err
	}
	possible, err := findingsWith(c, []string{"POSSIBLE"})
	if err != nil {
		return validation.VNull(), err
	}
	items := []proofItem{}
	for _, f := range possible {
		ver := orEmpty(objAt(f, "verification"))
		if objStr(ver, "critic_verdict") != "confirmed" {
			continue
		}
		repro := orEmpty(objAt(ver, "reproduction"))
		if objStr(repro, "status") != "reproduced" &&
			!pyTruthy(objAt(repro, "attempts")) {
			items = append(items, proofItem{objStr(f, "finding_id"),
				"no reproduction attempt recorded"})
		}
	}
	missing := unwaived(items, wmap, func(s, m string) string { return s + ": " + m })
	note := "repro attempts recorded for all candidates"
	if len(missing) > 0 {
		note = "critic-confirmed candidates without a repro attempt"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}
