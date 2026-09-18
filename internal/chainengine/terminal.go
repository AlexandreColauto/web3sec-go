// terminal.go: reachable economic terminal states (chain_engine.py's
// ATTACKER_BASELINE, CAPITAL_FIELDS, find_terminal_chains, terminal_report).
package chainengine

import (
	"slices"
	"sort"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// AttackerBaseline is ATTACKER_BASELINE: the default attacker, an
// unprivileged EOA. It can call public entry points; it holds no role, no
// token position, no private state. Capital is deliberately NOT a
// capability: it is a cost, annotated per path.
var AttackerBaseline = []string{"call_any_entry_point"}

// CapitalFields is CAPITAL_FIELDS: the reported breakdown of what an exploit
// path costs. None means "not known" and is carried as 0 in aggregation.
var CapitalFields = []string{"required_usd", "recoverable_usd",
	"irrecoverable_cost_usd", "atomic_usd", "borrowable_usd"}

// capital is one node's reported capital (the five ordered fields).
type capital struct {
	required      float64
	recoverable   float64
	irrecoverable float64
	atomic        float64
	borrowable    float64
}

// value renders the five fields in CAPITAL_FIELDS order; withNet appends the
// derived net_at_risk_usd (required - recoverable).
func (k capital) value(withNet bool) validation.Value {
	out := []validation.KV{
		kvOf("required_usd", validation.VFloat(k.required)),
		kvOf("recoverable_usd", validation.VFloat(k.recoverable)),
		kvOf("irrecoverable_cost_usd", validation.VFloat(k.irrecoverable)),
		kvOf("atomic_usd", validation.VFloat(k.atomic)),
		kvOf("borrowable_usd", validation.VFloat(k.borrowable)),
	}
	if withNet {
		out = append(out, kvOf("net_at_risk_usd",
			validation.VFloat(k.required-k.recoverable)))
	}
	return validation.VObj(out...)
}

// add is _add_capital: field-wise sum (None carried as 0).
func addCapital(a, b capital) capital {
	return capital{
		required:      a.required + b.required,
		recoverable:   a.recoverable + b.recoverable,
		irrecoverable: a.irrecoverable + b.irrecoverable,
		atomic:        a.atomic + b.atomic,
		borrowable:    a.borrowable + b.borrowable,
	}
}

// capitalNode is _capital_node: one finding's reported capital, falling back
// to the legacy flat attacker.required_capital_usd.
func capitalNode(f validation.Value) capital {
	att := validation.AsObj(validation.ObjAt(f, "attacker"))
	prof := validation.AsObj(validation.ObjAt(att, "capital_profile"))
	get := func(key string) float64 {
		v := validation.ObjAt(prof, key)
		if v.Kind == validation.Null && key == "required_usd" {
			v = validation.ObjAt(att, "required_capital_usd")
		}
		if v.Kind == validation.Null {
			return 0.0
		}
		if fv, ok := pyFloat(v); ok {
			return fv
		}
		return 0.0
	}
	return capital{
		required:      get("required_usd"),
		recoverable:   get("recoverable_usd"),
		irrecoverable: get("irrecoverable_cost_usd"),
		atomic:        get("atomic_usd"),
		borrowable:    get("borrowable_usd"),
	}
}

// findingNode is _finding_node.
type findingNode struct {
	fid      string
	title    string
	granted  map[string]struct{}
	required map[string]struct{}
	cap      capital
}

func newFindingNode(f validation.Value) findingNode {
	caps := validation.AsObj(validation.ObjAt(f, "capabilities"))
	return findingNode{
		fid:      validation.ObjStr(f, "finding_id"),
		title:    validation.ObjStr(f, "title"),
		granted:  setOf(norm(capInput(validation.ObjAt(caps, "granted")))),
		required: setOf(norm(capInput(validation.ObjAt(caps, "required")))),
		cap:      capitalNode(f),
	}
}

// baseOf is `set(baseline) if baseline is not None else set(ATTACKER_BASELINE)`.
func baseOf(baseline *[]string) map[string]struct{} {
	if baseline == nil {
		return setOf(AttackerBaseline)
	}
	return setOf(*baseline)
}

// terminalNodes is the CONFIRMED/CHAIN finding table, in load order.
func terminalNodes(c *state.Campaign) ([]findingNode, error) {
	return terminalNodesMode(c, false)
}

// terminalNodesMode is the node table for the terminal search. Default mode
// is the CONFIRMED/CHAIN table; includeHypothesis (the B1/B3 mode) also
// admits every non-terminal status — HYPOTHESIS through POSSIBLE — so an
// unproven liveness finding can still end a search path (the callers that
// expose that mode say so explicitly).
func terminalNodesMode(c *state.Campaign, includeHypothesis bool) ([]findingNode, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	out := []findingNode{}
	for _, f := range all {
		st := validation.ObjStr(f, "status")
		_, absorbed := findings.TERMINAL[st]
		if st == "CONFIRMED" || st == "CHAIN" ||
			(includeHypothesis && !absorbed) {
			out = append(out, newFindingNode(f))
		}
	}
	return out, nil
}

// nodeAt finds a node by finding id.
func nodeAt(nodes []findingNode, fid string) findingNode {
	for _, n := range nodes {
		if n.fid == fid {
			return n
		}
	}
	return findingNode{}
}

// terminalFrame is one DFS frame: current finding, path, held caps, capital.
type terminalFrame struct {
	cur     string
	path    []string
	held    map[string]struct{}
	capital capital
}

// FindTerminalChains is find_terminal_chains(): search for REACHABLE
// TERMINAL STATES (economic, or liveness since IMPROVEMENTS B1) over
// CONFIRMED (or CHAIN) findings. A nil baseline means ATTACKER_BASELINE; a
// non-nil pointer (even to an empty slice) is the explicit baseline.
func FindTerminalChains(c *state.Campaign, baseline *[]string, maxDepth,
	minLength int) ([]validation.Value, error) {
	return FindTerminalChainsMode(c, baseline, maxDepth, minLength, false)
}

// FindTerminalChainsMode is the B1/B3 search mode: with includeHypothesis
// true, unconfirmed findings (HYPOTHESIS .. POSSIBLE) are admitted as nodes,
// so a chain can reach a liveness terminal that has not been proven yet.
// Every row is still a REACHABLE path in the capability graph; the rows do
// not claim confirmation — materialization remains CONFIRMED-only
// (MaterializeChain's hard gate).
func FindTerminalChainsMode(c *state.Campaign, baseline *[]string, maxDepth,
	minLength int, includeHypothesis bool) ([]validation.Value, error) {
	base := baseOf(baseline)
	nodes, err := terminalNodesMode(c, includeHypothesis)
	if err != nil {
		return nil, err
	}
	paths := []validation.Value{}
	seen := map[string]struct{}{}
	for _, start := range nodes {
		if !subsetOf(start.required, base) {
			continue
		}
		stack := []terminalFrame{{cur: start.fid, path: []string{start.fid},
			held: unionSets(base, start.granted), capital: start.cap}}
		for len(stack) > 0 {
			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			node := nodeAt(nodes, frame.cur)
			if p, ok := terminalPathDoc(frame, node, seen, minLength); ok {
				paths = append(paths, p)
			}
			if len(frame.path) >= maxDepth {
				continue
			}
			for _, nxt := range nodes {
				if slices.Contains(frame.path, nxt.fid) {
					continue
				}
				if !subsetOf(nxt.required, frame.held) {
					continue
				}
				path := append(append([]string{}, frame.path...), nxt.fid)
				stack = append(stack, terminalFrame{cur: nxt.fid, path: path,
					held:    unionSets(frame.held, nxt.granted),
					capital: addCapital(frame.capital, nxt.cap)})
			}
		}
	}
	sort.SliceStable(paths, func(i, j int) bool {
		li, lj := len(listOf(paths[i], "path").A), len(listOf(paths[j], "path").A)
		if li != lj {
			return li < lj
		}
		return pyFloatAt(paths[i], "total_capital_required_usd") <
			pyFloatAt(paths[j], "total_capital_required_usd")
	})
	if len(paths) > MaxProposals {
		paths = paths[:MaxProposals]
	}
	return paths, nil
}

// terminalPathDoc is one terminal path row: emitted only when the path is
// long enough, new, and ends on a node that grants a terminal capability.
func terminalPathDoc(frame terminalFrame, node findingNode,
	seen map[string]struct{}, minLength int) (validation.Value, bool) {
	if len(frame.path) < minLength {
		return validation.VNull(), false
	}
	key := joinPipe(frame.path)
	if _, ok := seen[key]; ok {
		return validation.VNull(), false
	}
	terminals := []string{}
	for _, cap := range setKeys(node.granted) {
		if capabilities.IsTerminal(cap) {
			terminals = append(terminals, cap)
		}
	}
	if len(terminals) == 0 {
		return validation.VNull(), false
	}
	seen[key] = struct{}{}
	return validation.VObj(
		kvOf("path", validation.StrArr(frame.path)),
		kvOf("terminal_capability", validation.VStr(terminals[0])),
		kvOf("terminal_capabilities", validation.StrArr(terminals)),
		kvOf("terminal_finding", validation.VStr(frame.cur)),
		kvOf("total_capital_required_usd",
			validation.VFloat(frame.capital.required)),
		kvOf("capital_breakdown", frame.capital.value(true)),
	), true
}

// pyFloatAt reads a float field (0 when absent).
func pyFloatAt(v validation.Value, key string) float64 {
	f, _ := pyFloat(validation.ObjAt(v, key))
	return f
}

// containsStr is Python's `x in list`.

// TerminalReport is terminal_report(): direct drains, multi-step terminal
// chains, the shortest path per terminal capability, and materialized chains
// with a terminal annotation.
func TerminalReport(c *state.Campaign, baseline *[]string) (validation.Value, error) {
	base := setKeys(baseOf(baseline))
	paths, err := FindTerminalChains(c, baseline, 5, 1)
	if err != nil {
		return validation.VNull(), err
	}
	direct := []validation.Value{}
	chains := []validation.Value{}
	for _, p := range paths {
		if len(listOf(p, "path").A) == 1 {
			direct = append(direct, p)
		} else {
			chains = append(chains, p)
		}
	}
	bestOrder := []string{}
	best := map[string]validation.Value{}
	for _, p := range paths {
		k := validation.ObjStr(p, "terminal_capability")
		cur, ok := best[k]
		if !ok || len(listOf(p, "path").A) < len(listOf(cur, "path").A) {
			if !ok {
				bestOrder = append(bestOrder, k)
			}
			best[k] = p
		}
	}
	sort.Strings(bestOrder)
	shortest := []validation.Value{}
	for _, k := range bestOrder {
		shortest = append(shortest, best[k])
	}
	materialized, err := chainDocs(c, true)
	if err != nil {
		return validation.VNull(), err
	}
	// Presence-gated (the additive convention): the liveness sentence appears
	// only when a liveness terminal actually surfaced, so a campaign without
	// one keeps its exact note bytes.
	note := "terminal paths search CONFIRMED findings only; terminal = " +
		"asset-kind capability granted by the last finding"
	for _, p := range paths {
		if capabilities.IsLivenessTerminal(validation.ObjStr(p, "terminal_capability")) {
			note += "; liveness terminal (B1) = liveness_loss granted by the " +
				"last finding — non-economic: the freeze itself is the impact"
			break
		}
	}
	return validation.VObj(
		kvOf("baseline", validation.StrArr(base)),
		kvOf("note", validation.VStr(note)),
		kvOf("direct", valueArr(direct)),
		kvOf("terminal_chains", valueArr(chains)),
		kvOf("shortest_by_terminal", valueArr(shortest)),
		kvOf("materialized_terminal_chains", valueArr(materialized)),
	), nil
}
