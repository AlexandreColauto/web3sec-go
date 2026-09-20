// proofs.go: the proof builders, in PROOFS order. Each returns
// {"done": bool, "missing": [str], "note": str} — deterministic, read-only,
// total: a missing file means NOT done, never a crash (the halt must be
// reportable, not an exception).
package completion

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"websec/internal/findings"
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
		lvl := validation.ObjStr(e, "level")
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
	cid := c.CampaignID
	if cid == "" {
		// A campaign in hand without an id keeps the documented metavariable
		// rather than rendering a command with an empty hole.
		cid = "<campaign>"
	}
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if !fileExists(p) {
		return proofResult(false, []string{"artifacts/protocol_model.json — run the " +
			"protocol-model stage and load the model"}, "model not loaded"), nil
	}
	model, err := validation.ReadJson(p)
	if err != nil {
		return proofResult(false, []string{"protocol model is unreadable/invalid — re-run " +
			"`webv2 model " + cid + " model.json`"}, "protocol model artifact unreadable"), nil
	}
	modelIDs := []string{}
	for _, inv := range listAt(model, "invariants") {
		if inv.Kind != validation.Obj {
			continue
		}
		if id := validation.ObjStr(inv, "id"); id != "" {
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
	reg := validation.ObjAt(links, "invariants")
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
			"(%s %s) — seeding did not run; re-run `webv2 model %s "+
			"model.json`", len(unseeded), strings.Join(head, ", "), tail,
			cid)
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
	if !pyTruthyBigNonEmpty(validation.ObjAt(plan, "priorities")) {
		return proofResult(false, []string{"plan has zero priorities"},
			"empty plan"), nil
	}
	return proofResult(true, []string{},
		fmt.Sprintf("%d priorities", len(priorities))), nil
}

// livenessOwedStatuses are the statuses under which a liveness finding owes
// its adversarial_game clause at the discovery exit: the open statuses (the
// claims discovery files and the divergence gate closes over) and
// CONFIRMED/CHAIN (a finding confirmed before discovery closed must still
// answer before the gate exits). Dead terminal dispositions (DISPROVED,
// DUPLICATE, OUT_OF_SCOPE, INFORMATIONAL, SUPERSEDED) no longer claim a live
// freeze, so they owe nothing.
var livenessOwedStatuses = append(append([]string{}, OpenStatuses...),
	confirmedStatuses...)

// proofDiscovery is _proof_discovery: draining the work queue is necessary,
// not sufficient — the divergence gate must close too, and a live liveness
// finding must carry its adversarial_game clause (who profits from the
// freeze, how, and why the challenge path does not undo it) before the
// divergence gate closes. The trigger is findings.IsLivenessFinding — the
// same shared predicate the bounty-gate check15 fires on (a root_cause.class
// in LivenessClasses, or economic_impact.kind == "liveness", or a granted
// liveness-terminal capability) — no prose heuristics. It only refuses the
// exit; recording stays the setter's job, so no event is duplicated.
// proofDiscoveryState carries one proofDiscovery evaluation's shared context:
// the collected missing[] items, the liveness clause items with their waiver
// map, and the counts the final note is chosen from.
type proofDiscoveryState struct {
	campaign   *state.Campaign
	items      []proofItem
	queueN     int
	divMissing []validation.Value
	agItems    []proofItem
	agWaived   map[string]validation.Value
}

func proofDiscovery(c *state.Campaign) (validation.Value, error) {
	plan, found, err := loadPlan(c)
	if err != nil {
		return validation.VNull(), err
	}
	if !found {
		return proofDiscoveryNoPlan(c)
	}
	s := &proofDiscoveryState{campaign: c}
	if err := s.proofDiscoveryCollect(plan); err != nil {
		return validation.VNull(), err
	}
	cid := c.CampaignID
	if cid == "" {
		// Same metavariable rule as proofProtocolModel: no command with an
		// empty hole where the campaign belongs.
		cid = "<campaign>"
	}
	if err := s.proofDiscoveryLiveness(cid); err != nil {
		return validation.VNull(), err
	}
	return s.proofDiscoveryFinish()
}

// proofDiscoveryNoPlan is the absent-plan branch: the r12 waiver consult
// comes before the refusal, so a recorded waiver can satisfy the deficit.
func proofDiscoveryNoPlan(c *state.Campaign) (validation.Value, error) {
	// r12: a waiver is a recorded disposition, and it must be able to
	// waive THIS deficit — the early return used to precede the
	// waiverMap read, so `waive discovery --subject '*'` printed
	// "waived" and then the proof refused anyway: an inert waiver
	// that silently satisfied nothing. The waiver consult comes
	// before the refusal, stage-wide or a plan-subject row.
	wmap, werr := waiverMap(c, "discovery")
	if werr != nil {
		return validation.VNull(), werr
	}
	if _, ok := wmap["*"]; !ok {
		if _, ok := wmap["campaign plan (discovery consumes its queue)"]; !ok {
			return proofResult(false,
				[]string{"campaign plan (discovery consumes its queue)"},
				"no plan"), nil
		}
	}
	actor := "operator"
	if w, ok := wmap["*"]; ok {
		actor = validation.ObjStr(w, "actor")
	} else if w, ok := wmap["campaign plan (discovery consumes "+
		"its queue)"]; ok {
		actor = validation.ObjStr(w, "actor")
	}
	return proofResult(true, []string{},
		"no plan — waived by "+actor), nil
}

// proofDiscoveryCollect gathers the queue's remaining priorities and the
// divergence gate's missing rows into the item list.
func (s *proofDiscoveryState) proofDiscoveryCollect(plan validation.Value) error {
	queue, err := planner.WorkQueue(s.campaign, plan, validation.VObj(), false)
	if err != nil {
		return err
	}
	s.queueN = len(queue)
	s.items = make([]proofItem, 0, len(queue))
	for _, w := range queue {
		s.items = append(s.items, proofItem{validation.ObjStr(w, "priority_id"),
			headRunes(validation.ObjStr(w, "question"), 60)})
	}
	divergence, err := planner.DivergenceStatusFor(s.campaign, plan, nil)
	if err != nil {
		return err
	}
	s.divMissing = listAt(divergence, "missing")
	for _, m := range s.divMissing {
		s.items = append(s.items, proofItem{validation.ObjStr(m, "subject"), validation.ObjStr(m, "what")})
	}
	return nil
}

// proofDiscoveryLiveness collects the live liveness findings that owe their
// adversarial_game clause, with the adversarial-game waiver map.
func (s *proofDiscoveryState) proofDiscoveryLiveness(cid string) error {
	live, err := findingsWith(s.campaign, livenessOwedStatuses)
	if err != nil {
		return err
	}
	agWaived, err := waiverMap(s.campaign, "adversarial-game")
	if err != nil {
		return err
	}
	s.agWaived = agWaived
	s.agItems = []proofItem{}
	for _, f := range live {
		if !findings.IsLivenessFinding(f) {
			continue
		}
		deficits := findings.AdversarialGameDeficits(f)
		if len(deficits) == 0 {
			continue
		}
		s.agItems = append(s.agItems, proofItem{validation.ObjStr(f, "finding_id"),
			livenessClauseWhat(cid, validation.ObjStr(f, "finding_id"), deficits)})
	}
	return nil
}

// proofDiscoveryFinish applies both waiver maps and renders the final
// proof result and note.
func (s *proofDiscoveryState) proofDiscoveryFinish() (validation.Value, error) {
	wmap, err := waiverMap(s.campaign, "discovery")
	if err != nil {
		return validation.VNull(), err
	}
	missing := unwaived(s.items, wmap, func(s, m string) string { return s + ": " + m })
	clauseMissing := unwaived(s.agItems, s.agWaived,
		func(s, m string) string { return s + ": " + m })
	missing = append(missing, clauseMissing...)
	note := "work queue drained; divergence gate closed"
	if s.queueN > 0 {
		note = fmt.Sprintf("%d queued priorities remain", s.queueN)
	} else if len(s.divMissing) > 0 {
		note = "work queue drained but the divergence gate is open"
	} else if len(clauseMissing) > 0 {
		note = "work queue drained, divergence gate closed — a live liveness " +
			"finding owes its adversarial_game clause"
	}
	return proofResult(len(missing) == 0, missing, note), nil
}

// livenessClauseWhat is the missing[] text for one liveness finding without
// its clause: the exact deficit (bounty-gate check15's detail) and the exact
// next step — the same command the bounty gate's remediation names, because
// the clause is one artifact, not two.
func livenessClauseWhat(cid, fid string, deficits []string) string {
	var clause string
	if len(deficits) == 1 && deficits[0] == "missing" {
		clause = "the adversarial_game clause (who profits from the freeze)"
	} else {
		clause = "adversarial_game " + strings.Join(deficits, ", ") +
			" missing or too short (each >= " +
			strconv.Itoa(findings.AdversarialGameFieldMin) + " chars)"
	}
	cmd := "webv2 adversarial-game " + cid + " " + fid +
		" --who-profit 'who profits from the freeze' --mechanism 'how the " +
		"profit works' --interplay 'why the challenge path does not undo it'" +
		" --strongest-attacker 'does a proof-valid bad batch still win the " +
		"challenge?'"
	waive := "webv2 waive " + cid + " adversarial-game --subject " + fid +
		" --reason '...' if the incentive argument lives elsewhere, e.g. the " +
		"chain narrative"
	return "liveness finding lacks " + clause + " — " + cmd +
		"   (or: " + waive + ")"
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
		fid := validation.ObjStr(f, "finding_id")
		dd := orEmpty(validation.ObjAt(f, "dedup"))
		verdicts := orEmpty(validation.ObjAt(dd, "candidate_verdicts"))
		for _, other := range listAt(dd, "possible_duplicate_of") {
			// Python: verdicts.get(other) — a list/dict entry is
			// unhashable and raises TypeError, which proof_status reports
			// as "proof error: unhashable type: 'list'".
			if other.Kind == validation.Arr || other.Kind == validation.Obj {
				return validation.VNull(), fmt.Errorf("unhashable type: %s",
					validation.PyReprStr(kindName(other)))
			}
			v := validation.ObjAt(verdicts, other.S)
			if v.Kind == validation.Str && (v.S == "same" || v.S == "distinct") {
				continue
			}
			unresolved = append(unresolved, proofItem{fid + "~" + validation.PyStr(other),
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
		verdict, ok := fieldAt(orEmpty(validation.ObjAt(f, "verification")), "critic_verdict")
		if !ok || verdict.Kind == validation.Null ||
			(verdict.Kind == validation.Str && verdict.S == "pending") {
			openItems = append(openItems, proofItem{validation.ObjStr(f, "finding_id"),
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
		ver := orEmpty(validation.ObjAt(f, "verification"))
		if validation.ObjStr(ver, "critic_verdict") != "confirmed" {
			continue
		}
		repro := orEmpty(validation.ObjAt(ver, "reproduction"))
		if validation.ObjStr(repro, "status") != "reproduced" &&
			!pyTruthyBigNonEmpty(validation.ObjAt(repro, "attempts")) {
			items = append(items, proofItem{validation.ObjStr(f, "finding_id"),
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
