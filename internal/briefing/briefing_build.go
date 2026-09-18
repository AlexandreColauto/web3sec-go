// Build-brief internals: build_brief's former single body, split into the
// phase helpers BuildBrief drives in the original order. Pure structural
// move — every block below is the original code, unchanged.
package briefing

import (
	"sort"
	"time"

	"websec/internal/chainengine"
	"websec/internal/costs"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/relations"
	"websec/internal/risk"
	"websec/internal/roles"
	"websec/internal/state"
	"websec/internal/validation"
)

// briefViews is the bundle of standalone views build_brief loads once, in
// the original order.
type briefViews struct {
	chains       []validation.Value
	terminal     validation.Value
	bountyView   validation.Value
	deficits     []validation.Value
	reach        []validation.Value
	memPending   []string
	corpusRecall validation.Value
	pendingMem   []validation.Value
	relView      validation.Value
	relCheck     validation.Value
	yieldRep     validation.Value
	advice       []validation.Value
	budget       validation.Value
}

// briefHunt is the critical-hunt section bundle build_brief assembles.
type briefHunt struct {
	prescreen  *validation.Value
	forkDiff   *validation.Value
	recency    []validation.Value
	amplifiers validation.Value
	toolFlags  validation.Value
	invSection validation.Value
	stale      []validation.Value
}

// briefCtx carries build_brief's shared state across the phase helpers
// below; BuildBrief drives them in the original body's order.
type briefCtx struct {
	campaign      *state.Campaign
	deepAudit     bool
	generatedAt   string
	st            validation.Value
	all           []validation.Value
	counts        []validation.KV
	e6            validation.Value
	views         *briefViews
	huntProblems  []string
	readProblems  []string
	problems      []string
	stagesDone    int64
	elapsedOut    validation.Value
	terminals     []validation.Value
	pmOut         []validation.Value
	byKind        []validation.KV
	campaignBlock validation.Value
	plan          validation.Value
	planErr       error
}

// briefLoadBase runs build_brief's preamble: the state read, generated_at,
// the finding tally, the independent-verification queue and the standalone
// views — each failure aborting the brief, in the original order.
func briefLoadBase(campaign *state.Campaign, deepAudit bool,
	now *string) (*briefCtx, error) {
	b := &briefCtx{campaign: campaign, deepAudit: deepAudit}
	st, err := campaign.State()
	if err != nil {
		return nil, err
	}
	b.st = st
	b.generatedAt = state.NowIso()
	if now != nil {
		b.generatedAt = *now
	}
	if b.all, b.counts, err = briefFindingCounts(campaign); err != nil {
		return nil, err
	}
	if b.e6, err = briefE6Queue(campaign, b.all); err != nil {
		return nil, err
	}
	if b.views, err = briefLoadViews(campaign); err != nil {
		return nil, err
	}
	return b, nil
}

// briefFindingCounts loads every finding and tallies it by status
// (build_brief's counts block).
func briefFindingCounts(campaign *state.Campaign) ([]validation.Value, []validation.KV, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, nil, err
	}
	counts := []validation.KV{}
	index := map[string]int{}
	for _, f := range all {
		s := validation.ObjStr(f, "status")
		if i, ok := index[s]; ok {
			counts[i].V = validation.VInt(counts[i].V.I + 1)
		} else {
			index[s] = len(counts)
			counts = append(counts, validation.KV{K: s,
				V: validation.VInt(1)})
		}
	}
	return all, counts, nil
}

// e6key orders the independent-verification queue: mandatory rows first,
// each group by the canonical work-order key.
type e6key struct {
	mandatory bool
	key       risk.WorkOrderKey
}

// briefE6Queue is build_brief's independent_verification_queue block.
func briefE6Queue(campaign *state.Campaign,
	all []validation.Value) (validation.Value, error) {
	o := orchestrator.New(campaign)
	e6, err := o.IndependentVerificationQueue()
	if err != nil {
		return validation.VNull(), err
	}
	byID := map[string]validation.Value{}
	for _, f := range all {
		byID[validation.ObjStr(f, "finding_id")] = f
	}
	e6List := append([]validation.Value{}, e6.A...)
	keys := make([]e6key, len(e6List))
	for i, q := range e6List {
		f, ok := byID[validation.ObjStr(q, "finding_id")]
		if !ok {
			f = validation.VObj(kv("finding_id", validation.ObjAt(q, "finding_id")))
		}
		k, err := risk.WorkOrderKeyFor(f)
		if err != nil {
			return validation.VNull(), err
		}
		keys[i] = e6key{pyTruthyInt64Only(validation.ObjAt(q, "mandatory")), k}
	}
	sort.SliceStable(e6List, func(i, j int) bool {
		if keys[i].mandatory != keys[j].mandatory {
			return keys[i].mandatory
		}
		return keys[i].key.Less(keys[j].key)
	})
	return validation.VArr(e6List...), nil
}

// briefLoadViews loads the standalone views build_brief folds in — chains,
// terminals, bounty, deficits, reachability, memory, relations, economics —
// in the original order, each failure aborting the brief.
func briefLoadViews(campaign *state.Campaign) (*briefViews, error) {
	v := &briefViews{}
	var err error
	if v.chains, err = Materializable(campaign); err != nil {
		return nil, err
	}
	if v.terminal, err = chainengine.TerminalReport(campaign, nil); err != nil {
		return nil, err
	}
	if v.bountyView, err = Bounty(campaign); err != nil {
		return nil, err
	}
	if v.deficits, err = GateDeficits(campaign); err != nil {
		return nil, err
	}
	if v.reach, err = Reachability(campaign); err != nil {
		return nil, err
	}
	if v.memPending, err = MemoryRecallHints(campaign); err != nil {
		return nil, err
	}
	if v.corpusRecall, err = findings.CorpusRecallGaps(campaign); err != nil {
		return nil, err
	}
	if v.pendingMem, err = learning.PendingMemory(campaign); err != nil {
		return nil, err
	}
	if v.relView, err = relations.GraphView(campaign); err != nil {
		return nil, err
	}
	if v.relCheck, err = relations.VerifyRelations(campaign); err != nil {
		return nil, err
	}
	if v.yieldRep, err = costs.YieldReport(campaign); err != nil {
		return nil, err
	}
	if v.advice, err = costs.AllocationAdvice(campaign); err != nil {
		return nil, err
	}
	if v.budget, err = costs.BudgetStatus(campaign); err != nil {
		return nil, err
	}
	return v, nil
}

// collectProblems seeds the hunt/read problem sinks, computes the stage
// progress and elapsed hours, and opens the top-level problems block with
// the never-written-graph disclosure.
func (b *briefCtx) collectProblems() {
	b.huntProblems = []string{}

	// r45a: read failures get their own sink. huntProblems keeps its existing
	// semantics (Python's critical_hunt.problems: malformed-input notes only),
	// while readProblems is folded into the top-level problems block — the one
	// diagnostic list the cockpit prints — so a section that is omitted
	// because its input could not be READ is disclosed instead of rendering
	// as a section that is legitimately empty.
	b.readProblems = []string{}

	// feedback-triage A5: the stage ledger also carries sub-stage rows the
	// orchestrator emits per pass (discovery-specialist,
	// hypothesis-triage, dedup-normalization, independent-reproduction,
	// ...). Those are not among the canonical pipeline stages, so counting
	// every done row let the cockpit report "stages 19/17". The denominator
	// is len(pipeline.StageIDs), so the numerator must count the same
	// top-level set.
	topLevel := make(map[string]bool, len(pipeline.StageIDs))
	for _, id := range pipeline.StageIDs {
		topLevel[id] = true
	}
	stages := validation.AsObj(validation.ObjAt(b.st, "stages"))
	stagesDone := int64(0)
	for _, s := range stages.O {
		if topLevel[s.K] && validation.ObjStr(s.V, "status") == "done" {
			stagesDone++
		}
	}
	b.stagesDone = stagesDone
	var elapsedOut validation.Value = validation.VNull()
	if created := validation.ObjStr(b.st, "created_at"); created != "" {
		if t0 := ParseISO(created); t0 != nil {
			elapsedOut = validation.VFloat(validation.PythonRound(
				time.Since(*t0).Seconds()/3600, 1))
		}
	}
	b.elapsedOut = elapsedOut

	b.problems = []string{}
	liveFindings := []validation.Value{}
	for _, f := range b.all {
		if !junkStatuses[validation.ObjStr(f, "status")] {
			liveFindings = append(liveFindings, f)
		}
	}
	if len(liveFindings) > 0 && intField(b.views.relView, "edge_count") == 0 &&
		validation.ObjStr(b.st, "phase") != "COMPLETE" {
		b.problems = append(b.problems, "the graph was never written — mint its "+
			"deterministic edges: webv2 relations "+
			b.campaign.CampaignID+" --rebuild")
	}
}

// huntSections runs the critical-hunt sections in the original order, then
// folds readProblems into the top-level problems list before stale
// artifacts are loaded.
func (b *briefCtx) huntSections() (briefHunt, error) {
	h := briefHunt{}
	var err error
	if h.prescreen, err = ChPrescreen(b.campaign, &b.huntProblems,
		&b.readProblems); err != nil {
		return h, err
	}
	if h.forkDiff, err = ChForkdiff(b.campaign, &b.huntProblems,
		&b.readProblems); err != nil {
		return h, err
	}
	if h.recency, err = ChRecency(b.campaign, &b.huntProblems,
		&b.readProblems); err != nil {
		return h, err
	}
	h.amplifiers = ChAmplifiers(b.campaign, &b.huntProblems, &b.readProblems)
	h.toolFlags = ChToolFlags(b.campaign, &b.huntProblems)
	h.invSection = ChInvariants(b.campaign, &b.huntProblems)
	// r45a: the artifacts above exist but could not be read — say so in the
	// cockpit-visible problems list instead of letting the sections vanish.
	for _, msg := range b.readProblems {
		b.problems = noteProblem(b.problems, msg)
	}
	if h.stale, err = roles.StaleArtifacts(b.campaign); err != nil {
		return h, err
	}
	return h, nil
}

// buildCampaignBlock is build_brief's campaign section: the terminal rows, the
// pending-memory rows, the relation counts, the active snapshot and the
// identity/phase/budget object itself.
func (b *briefCtx) buildCampaignBlock() validation.Value {
	terminals := []validation.Value{}
	for _, p := range listAt(b.views.terminal, "shortest_by_terminal") {
		terminals = append(terminals, validation.VObj(
			kv("path", validation.ObjAt(p, "path")),
			kv("terminal_capability", validation.ObjAt(p, "terminal_capability")),
			kv("capital_usd", validation.ObjAt(p, "total_capital_required_usd"))))
	}
	pmOut := []validation.Value{}
	for _, m := range b.views.pendingMem {
		pmOut = append(pmOut, validation.VObj(
			kv("memory_id", validation.ObjAt(m, "memory_id")),
			kv("kind", validation.ObjAt(m, "kind")),
			kv("status", validation.ObjAt(m, "status")),
			kv("pattern", validation.ObjAt(m, "pattern")),
			kv("finding_id", validation.ObjAt(m, "finding_id"))))
	}
	byKind := []validation.KV{}
	for _, k := range validation.AsObj(validation.ObjAt(b.views.relView, "by_kind")).O {
		n := 0
		if k.V.Kind == validation.Arr {
			n = len(k.V.A)
		}
		byKind = append(byKind, validation.KV{K: k.K, V: validation.VInt(int64(n))})
	}
	var snapshotOut validation.Value = validation.VNull()
	if sid, err := b.campaign.ActiveSnapshotIDOrNone(); err == nil && sid != nil {
		snapshotOut = validation.VStr(*sid)
	}
	b.terminals, b.pmOut, b.byKind = terminals, pmOut, byKind
	b.campaignBlock = validation.VObj(
		kv("campaign_id", validation.VStr(b.campaign.CampaignID)),
		kv("program", validation.ObjAt(b.st, "program")),
		kv("phase", validation.ObjAt(b.st, "phase")),
		kv("closed", validation.VBool(validation.ObjStr(b.st, "phase") == "COMPLETE")),
		kv("completed_by", validation.ObjAt(b.st, "completed_by")),
		kv("completed_reason", validation.ObjAt(b.st, "completed_reason")),
		kv("pass", validation.ObjAt(validation.ObjAt(b.st, "budget"), "pass")),
		kv("discovery_slots_left", validation.VInt(
			intField(validation.ObjAt(b.st, "budget"), "max_discovery_findings")-
				intField(validation.ObjAt(b.st, "budget"), "discovery_findings_so_far"))),
		kv("active_snapshot", snapshotOut),
		kv("stages_done", validation.VInt(b.stagesDone)),
		kv("stages_total", validation.VInt(int64(len(pipeline.StageIDs)))),
		kv("elapsed_hours", b.elapsedOut))
	return b.campaignBlock
}

// findingsBlock is build_brief's findings section.
func (b *briefCtx) findingsBlock() validation.Value {
	return validation.VObj(
		kv("total", validation.VInt(int64(len(b.all)))),
		kv("by_status", validation.VObj(b.counts...)),
		kv("materializable_chains", validation.VArr(b.views.chains...)),
		kv("gate_deficits", validation.VArr(b.views.deficits...)),
		kv("structurally_unreachable", validation.VArr(b.views.reach...)),
		kv("memory_recall_pending", validation.StrArr(b.views.memPending)))
}

// huntBlock is build_brief's critical_hunt section. G1 tool flags: the
// advisory block is attached only when it has content (validation.Null means
// no finding carries detector provenance), so a campaign without detector
// findings keeps byte-identical brief output — the additive convention.
func (b *briefCtx) huntBlock(h briefHunt) validation.Value {
	block := validation.VObj(
		kv("prescreen", ptrOrNull(h.prescreen)),
		kv("fork_diff", ptrOrNull(h.forkDiff)),
		kv("recency_top", validation.VArr(h.recency...)),
		kv("amplifiers", h.amplifiers),
		kv("invariant_verification", h.invSection),
		kv("stale_artifacts", validation.VArr(h.stale...)),
		kv("problems", validation.StrArr(b.huntProblems)))
	if h.toolFlags.Kind != validation.Null {
		setKey(&block, "tool_flags", h.toolFlags)
	}
	return block
}

// assembleBrief mints the brief object itself — the key order below IS the
// output order — then attaches the presence-gated lens-yield block.
func (b *briefCtx) assembleBrief(h briefHunt) (validation.Value, error) {
	brief := validation.VObj(
		kv("generated_at", validation.VStr(b.generatedAt)),
		kv("campaign", b.buildCampaignBlock()),
		kv("findings", b.findingsBlock()),
		kv("corpus_recall", b.views.corpusRecall),
		kv("terminals", validation.VArr(b.terminals...)),
		kv("independent_verification_queue", b.e6),
		kv("bounty", b.views.bountyView),
		kv("pending_memory", validation.VArr(b.pmOut...)),
		kv("relations", validation.VObj(
			kv("edge_count", validation.ObjAt(b.views.relView, "edge_count")),
			kv("by_kind", validation.VObj(b.byKind...)),
			kv("drift_problems", validation.ObjAt(b.views.relCheck, "problems")))),
		kv("problems", validation.StrArr(b.problems)),
		kv("economics", validation.VObj(
			kv("totals", validation.ObjAt(b.views.yieldRep, "totals")),
			kv("budget", b.views.budget),
			kv("allocation_advice", validation.VArr(b.views.advice...)),
			kv("note", validation.VStr("advisory only — never gates a "+
				"status (the cost ceiling halts the pipeline, it does not "+
				"gate findings)")))),
		kv("critical_hunt", b.huntBlock(h)))

	// G13 cost attribution, presence-gated (the additive convention): a
	// campaign with zero lens-carrying cost rows and no plan lens data
	// keeps byte-identical brief output — no lens_yield key at all.
	if lensYield, err := costs.LensYield(b.campaign); err != nil {
		return validation.VNull(), err
	} else if len(lensYield) > 0 {
		econ := validation.ObjAt(brief, "economics")
		setKey(&econ, "lens_yield", validation.VArr(lensYield...))
		setKey(&brief, "economics", econ)
	}
	return brief, nil
}

// setDivergence attaches the divergence-gate state, tolerating a missing
// plan (the key is then null). The plan — or its load error — is kept on
// the context for the disposition and criticality phases below.
func (b *briefCtx) setDivergence(brief *validation.Value) error {
	b.plan, b.planErr = planner.LoadPlanReadonly(b.campaign)
	if b.planErr != nil {
		setKey(brief, "divergence", validation.VNull())
		return nil
	}
	div, err := planner.DivergenceStatusFor(b.campaign, b.plan, nil)
	if err != nil {
		return err
	}
	setKey(brief, "divergence", div)
	return nil
}

// setProbeSurface attaches the mechanical candidate surface (A4).
func (b *briefCtx) setProbeSurface(brief *validation.Value) {
	summary, err := probes.SurfaceSummary(b.campaign, nil)
	if err != nil || summary == nil {
		setKey(brief, "probe_surface", validation.VNull())
	} else {
		setKey(brief, "probe_surface", *summary)
	}
}

// setSurfaceLines attaches the two presence-gated surface-line blocks.
func (b *briefCtx) setSurfaceLines(brief *validation.Value) {
	// G9 opaque surfaces (Task 6): the model's tracked-but-opaque
	// component surfaces, one display line per component. Presence-gated
	// (the additive convention): a campaign whose model carries no
	// components gains no key at all.
	if surfaces := TrackedSurfaces(b.campaign); len(surfaces) > 0 {
		setKey(brief, "tracked_surfaces", validation.StrArr(surfaces))
	}

	// G10 assumption table (Task 4): the model's per-hop declared table
	// plus ASSUMPTION GAP lines, one display line per row/gap. Presence-
	// gated (the additive convention): a chains-only legacy campaign
	// gains no key at all.
	if lines := ChainAssumptions(b.campaign); len(lines) > 0 {
		setKey(brief, "chain_assumption_lines", validation.StrArr(lines))
	}
}

// setDispositionReview attaches the B4 disposition-review block: high-risk
// rows (tier 0 / gap >= 3) dismissed with dismissal vocabulary — the
// closures the operator should re-check. Presence-gated (the additive
// convention): the key exists only when something is flagged, so a clean
// campaign's brief bytes are unchanged (the print layer also gates on
// non-empty). A plan-load failure suppresses the block, as before.
func (b *briefCtx) setDispositionReview(brief *validation.Value) {
	flags, derr := planner.DispositionReview(b.campaign, b.plan)
	if derr != nil || len(flags) == 0 {
		return
	}
	rev := validation.VArr()
	for _, f := range flags {
		phrases := validation.VArr()
		for _, ph := range f.Phrases {
			phrases.A = append(phrases.A, validation.VStr(ph))
		}
		rev.A = append(rev.A, validation.VObj(
			kv("priority", validation.VStr(f.Priority)),
			kv("row_id", validation.VStr(f.RowID)),
			kv("tier", validation.VInt(f.Tier)),
			kv("assertion_gap", validation.VInt(f.Gap)),
			kv("reason", validation.VStr(f.Reason)),
			kv("phrases", phrases)))
	}
	setKey(brief, "disposition_review", rev)
}

// setCriticality attaches the criticality coverage section, naming an
// unread model/index in the problems block.
func (b *briefCtx) setCriticality(brief *validation.Value) error {
	// criticality coverage (task 8)
	//
	// r45a: criticalityBlock answers "the section is omitted, as when the
	// model is absent" for a model or structural index that EXISTS but could
	// not be read. It now hands that failure back as an `unreadable`
	// disclosure instead of (model) silently dropping the section or (index)
	// ranking criticality against a fabricated empty index; the message goes
	// into the problems block, and the section itself stays unset.
	crit, critOK, critErr := criticalityBlock(b.campaign, b.all, b.plan, b.planErr)
	if critErr != nil {
		return critErr
	}
	if msg := validation.ObjStr(crit, "unreadable"); msg != "" {
		b.problems = noteProblem(b.problems, msg)
		// The problems key was captured when `brief` was built, above; this
		// disclosure is discovered after that, so the block is re-set (key
		// position kept — the key already exists) rather than lost.
		setKey(brief, "problems", validation.StrArr(b.problems))
	}
	if critOK {
		setKey(brief, "criticality", crit)
	}
	return nil
}

// setAttention attaches the attention ledger, aged against the brief's own
// generated_at.
func (b *briefCtx) setAttention(brief *validation.Value) error {
	att, err := AttentionLedger(b.campaign, b.generatedAt,
		&b.campaign.CampaignID,
		pyTruthyInt64Only(validation.ObjAt(b.campaignBlock, "closed")))
	if err != nil {
		return err
	}
	setKey(brief, "attention", att)
	return nil
}

// setNextActions attaches the concrete prioritized command list.
func (b *briefCtx) setNextActions(brief *validation.Value) error {
	actions, err := NextActions(*brief, b.campaign)
	if err != nil {
		return err
	}
	setKey(brief, "next_actions", validation.StrArr(actions))
	return nil
}
