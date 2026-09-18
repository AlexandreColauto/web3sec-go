package briefing

import (
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- next actions ----------------------------------------------------------

func integrityDetail(integ validation.Value) string {
	probs := validation.ObjAt(integ, "problems")
	if probs.Kind == validation.Obj {
		parts := []string{}
		for _, kvp := range probs.O {
			parts = append(parts, kvp.K+": "+validation.PyRepr(kvp.V))
		}
		out := ""
		for i, s := range parts {
			if i > 0 {
				out += "; "
			}
			out += s
		}
		return out
	}
	parts := []string{}
	for _, p := range probs.A {
		if p.Kind == validation.Str {
			parts = append(parts, p.S)
		} else {
			parts = append(parts, validation.PyRepr(p))
		}
	}
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// webv2Action renders one copyable next action: the command first, the
// reason as a shell comment. Task 7's law is render-boundary-wide (review
// round 1, I-2): every line briefing.go mints must be pasteable, so prose
// rides the `# reason` suffix instead of leading the line.
func webv2Action(command, reason string) string {
	if reason == "" {
		return command
	}
	return command + "  # " + noParens(reason)
}

// noParens keeps interpolated prose inside a `# reason` comment from
// tripping the no-parenthesis law — the plan's own test regex is `\(` and
// it reads the whole line; brackets carry the same meaning to an operator.
func noParens(s string) string {
	return strings.NewReplacer("(", "[", ")", "]").Replace(s)
}

// boxLocalCap is the box's E-cap for the reachability line: E4 — the local
// execution ceiling the environment records. envgo's profileMaxLevel gives
// every isolated container profile E4 and the doctor's e4_capable list names
// exactly those profiles; E5+ is a fork run, which is what the line's "fork
// required" clause names. Read, not probed: `docker info` inside a pure view
// would turn the cockpit host-dependent and hang it for up to the probe's
// 20s timeout on a wedged daemon — `webv2 env doctor` is the probe.
//
// ponytail: constant, not a live probe; wire envgo's e4_capable in when the
// brief gains a cached environment block (the value only moves on a box that
// cannot run containers at all, which `env doctor` already reports).
const boxLocalCap = "E4"

// openFindingClasses is the set of bug classes the campaign's open findings
// carry: the classes a CONFIRMED move could still target. findings.IsTerminal
// is the shared dead-row predicate, so a disproved or superseded row is not
// open work. The read is not fail-soft — the brief already fails on the same
// store (Reachability).
func openFindingClasses(campaign *state.Campaign) ([]string, error) {
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	classes := []string{}
	for _, f := range all {
		if findings.IsTerminal(validation.ObjStr(f, "status")) {
			continue
		}
		cls := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
		if cls == "" || seen[cls] {
			continue
		}
		seen[cls] = true
		classes = append(classes, cls)
	}
	return classes, nil
}

// ReachabilityLine renders the evidence-reachability advisory: which of the
// campaign's open bug classes can reach CONFIRMED on this box (floor at or
// below cap) and which need a fork. Reachable classes lead, fork-required
// classes follow, each group alphabetized, one class per clause with its own
// floor. An empty class list renders nothing. Pure prose, advisory only: no
// gate, proof or phase transition reads it.
func ReachabilityLine(classes []string, cap string) string {
	reachable, forked := []string{}, []string{}
	for _, c := range classes {
		if findings.ReachableLocally(c, cap) {
			reachable = append(reachable, c)
		} else {
			forked = append(forked, c)
		}
	}
	sort.Strings(reachable)
	sort.Strings(forked)
	clauses := make([]string, 0, len(classes))
	for _, c := range reachable {
		clauses = append(clauses, "CONFIRMED locally reachable for "+c+
			" (floor "+findings.ClassConfirmFloor(c)+")")
	}
	for _, c := range forked {
		clauses = append(clauses, "fork required for "+c+
			" (floor "+findings.ClassConfirmFloor(c)+" > "+cap+")")
	}
	if len(clauses) == 0 {
		return ""
	}
	return "evidence reachability: " + strings.Join(clauses, "; ")
}

// NextActions is _next_actions: the prioritized, concrete work list.
// nextActionsCtx carries the shared context of the NextActions split: the
// brief being rendered, the campaign, the two brief sub-objects the sections
// read, the resolved campaign id used by the open-branch mints, and the
// action list being accumulated plus the two identity sets the attention
// sections populate and the generic filter consumes.
type nextActionsCtx struct {
	brief    validation.Value
	campaign *state.Campaign
	cb       validation.Value
	integ    validation.Value
	cid      string
	actions  []string
	// the attention ledger leads the queue
	attentionLead map[string]bool
	// the attention-minted lines themselves: the generic filter must not
	// count them as "something else to do" (they carry no `# reason` — the
	// ledger block already renders the prose beside the command)
	attentionLines map[string]bool
}

// NextActions is webv2.briefing next_actions: the concrete prioritized
// command list. Each section below is one cohesive block of the original
// body, in the original order.
func NextActions(brief validation.Value, campaign *state.Campaign) ([]string, error) {
	nx := &nextActionsCtx{
		brief:          brief,
		campaign:       campaign,
		cb:             validation.AsObj(validation.ObjAt(brief, "campaign")),
		integ:          validation.AsObj(validation.ObjAt(brief, "integrity")),
		actions:        []string{},
		attentionLead:  map[string]bool{},
		attentionLines: map[string]bool{},
	}
	closed, err := nx.nextActionsClosed()
	if err != nil {
		return nil, err
	}
	if closed {
		return nx.actions, nil
	}

	// cid for every open-branch mint: the campaign pointer may be nil
	// (hand-built briefs), the brief's own campaign_id is the fallback.
	nx.cid = lensActionCampaign(brief, campaign)

	nx.nextActionsColdProbe()
	if err := nx.nextActionsReachability(); err != nil {
		return nil, err
	}
	nx.nextActionsProbeRows()
	nx.nextActionsLensRouting()
	nx.nextActionsSkew()
	nx.nextActionsCriticality()
	nx.nextActionsPlanPriorities()
	nx.nextActionsAttention()
	nx.nextActionsDivergenceGate()
	nx.nextActionsInvariantDebt()
	nx.nextActionsIntegrity()
	nx.nextActionsCostCeiling()
	nx.nextActionsChains()
	nx.nextActionsE6Queue()
	nx.nextActionsMemoryRecall()
	nx.nextActionsCorpusRecall()
	nx.nextActionsUnreachable()
	nx.nextActionsBountyGate()
	nx.nextActionsGateDeficits()
	nx.nextActionsPendingMemory()
	nx.nextActionsTerminals()
	if err := nx.nextActionsGenericFallback(); err != nil {
		return nil, err
	}
	nx.nextActionsLensYield()
	return nx.actions, nil
}
