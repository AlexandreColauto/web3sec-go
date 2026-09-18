// Package chainengine is the Exploit Capability Graph: a 1:1 port of
// webv2/chain_engine.py (port-era provenance; twin retired 2026-09-09). A finding is "capability X exists";
// chains are discovered by graph search over granted→required edges and
// materialized only when every constituent is independently CONFIRMED.
package chainengine

import (
	"fmt"
	"os"
	"sort"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ChainReportNote is chain_report's note.
const ChainReportNote = "proposals become chains only when every member is CONFIRMED"

// MaxProposals is MAX_PROPOSALS: the enumeration guard. Proposals are leads
// for humans, not a deliverable — past this the report stops.
const MaxProposals = 500

// ChainSignature is chain_signature(): an order-invariant hash of a member
// set (ported from attempt v2).
func ChainSignature(signatures []string) string {
	items := []string{}
	for _, s := range signatures {
		if s != "" {
			items = append(items, s)
		}
	}
	sort.Strings(items)
	return findings.TextSignature("chain|" + joinPipe(items))
}

func joinPipe(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "|"
		}
		out += s
	}
	return out
}

// norm is _norm(): canonical capability labels via the shared vocabulary.
func norm(caps []string) []string {
	return capabilities.NormalizeLabels(caps)
}

// nonDuplicate is the status filter shared by both sweeps. r12: it was a
// hand-copied three-status list {DUPLICATE, OUT_OF_SCOPE, INFORMATIONAL}
// while the sibling sweep (terminals) already used the framework's own
// TERMINAL law — so capability links were rendered FROM superseded rows
// and chains proposed through them, the exact r5 drift class this repo
// declared closed. Terminal rows (DISPROVED, OUT_OF_SCOPE, INFORMATIONAL,
// DUPLICATE, SUPERSEDED) answer a question; a sweep chains ANSWERS to
// nothing. Live rows — including CONFIRMED — still participate.
func nonDuplicate(f validation.Value) bool {
	return !findings.IsTerminal(validation.ObjStr(f, "status"))
}

// capBlock is `f.get("capabilities") or {}` normalized into granted/required.
func capBlock(f validation.Value) ([]string, []string) {
	caps := asObj(validation.ObjAt(f, "capabilities"))
	return norm(capInput(validation.ObjAt(caps, "granted"))),
		norm(capInput(validation.ObjAt(caps, "required")))
}

// BuildCapabilityIndex is build_capability_index(): granted -> [finding_ids],
// required -> [finding_ids], over all non-duplicate findings. Both maps are
// returned as ordered objects (Python dict insertion order = load order).
func BuildCapabilityIndex(c *state.Campaign) (validation.Value, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	granted := []validation.KV{}
	required := []validation.KV{}
	for _, f := range all {
		if !nonDuplicate(f) {
			continue
		}
		fid := validation.ObjStr(f, "finding_id")
		g, r := capBlock(f)
		for _, cap := range g {
			granted = appendID(granted, cap, fid)
		}
		for _, cap := range r {
			required = appendID(required, cap, fid)
		}
	}
	return validation.VObj(
		kvOf("granted", validation.VObj(granted...)),
		kvOf("required", validation.VObj(required...)),
	), nil
}

// appendID is `granted.setdefault(c, []).append(fid)`.
func appendID(list []validation.KV, cap, fid string) []validation.KV {
	for i := range list {
		if list[i].K == cap {
			list[i].V.A = append(list[i].V.A, validation.VStr(fid))
			return list
		}
	}
	return append(list, kvOf(cap, validation.VArr(validation.VStr(fid))))
}

// idsOf is `index[list].get(cap, [])` as Go strings.
func idsOf(list []validation.KV, cap string) []string {
	for _, kv := range list {
		if kv.K == cap {
			out := make([]string, 0, len(kv.V.A))
			for _, id := range kv.V.A {
				out = append(out, pyStr(id))
			}
			return out
		}
	}
	return nil
}

// FindLinks is find_links(): all granted→required matches between distinct
// findings.
func FindLinks(c *state.Campaign) ([]validation.Value, error) {
	idx, err := BuildCapabilityIndex(c)
	if err != nil {
		return nil, err
	}
	granted := validation.ObjAt(idx, "granted").O
	required := validation.ObjAt(idx, "required").O
	links := []validation.Value{}
	for _, needKV := range required {
		for _, grantFid := range idsOf(granted, needKV.K) {
			for _, needFid := range idsOf(required, needKV.K) {
				if grantFid == needFid {
					continue
				}
				links = append(links, validation.VObj(
					kvOf("from", validation.VStr(grantFid)),
					kvOf("to", validation.VStr(needFid)),
					kvOf("capability", validation.VStr(needKV.K)),
				))
			}
		}
	}
	return links, nil
}

// chainNode is one finding's normalized capability sets.
type chainNode struct {
	fid   string
	grant map[string]struct{}
	need  map[string]struct{}
}

// chainFindings is the ordered (load order) non-duplicate finding table.
func chainFindings(c *state.Campaign) ([]chainNode, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	out := []chainNode{}
	for _, f := range all {
		if !nonDuplicate(f) {
			continue
		}
		g, r := capBlock(f)
		out = append(out, chainNode{fid: validation.ObjStr(f, "finding_id"),
			grant: setOf(g), need: setOf(r)})
	}
	return out, nil
}

// needsOf returns the finding ids requiring cap, in load order.
func needsOf(nodes []chainNode, cap string) []string {
	out := []string{}
	for _, n := range nodes {
		if _, ok := n.need[cap]; ok {
			out = append(out, n.fid)
		}
	}
	return out
}

// chainState is one DFS frame.
type chainState struct {
	cur   string
	visit map[string]struct{}
	path  []string
	held  map[string]struct{}
}

// FindChains is find_chains(): enumerate simple capability chains up to depth
// 5, deduped by member set and capped at MAX_PROPOSALS.
//
// DEVIATION (declared, inherited from the orchestrator's faithful default):
// Python iterates `caps_held` and `needs[cap]` as SETS, whose string
// iteration order varies with PYTHONHASHSEED — the proposal ORDER is not
// reproducible across Python processes either. This port sorts both
// neighbor sets, so it is deterministic; where each capability is declared
// by one finding the orders coincide exactly.
func FindChains(c *state.Campaign, minLength int) ([]validation.Value, error) {
	nodes, err := chainFindings(c)
	if err != nil {
		return nil, err
	}
	chains := []validation.Value{}
	seen := map[string]struct{}{}
	for _, start := range nodes {
		if len(seen) >= MaxProposals {
			break
		}
		stack := []chainState{{cur: start.fid,
			visit: map[string]struct{}{start.fid: {}},
			path:  []string{start.fid}, held: map[string]struct{}{}}}
		for len(stack) > 0 {
			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			var node chainNode
			for _, n := range nodes {
				if n.fid == frame.cur {
					node = n
					break
				}
			}
			held := unionSets(frame.held, node.grant)
			if len(frame.path) >= minLength {
				key := memberKey(frame.path)
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					chains = append(chains, validation.VObj(
						kvOf("members", validation.StrArr(frame.path)),
						kvOf("capabilities", validation.StrArr(setKeys(held)))))
				}
			}
			// find_chains: once the cap is reached the enumeration BREAKS
			// (the guard, not a post-hoc trim, bounds memory); the depth
			// limit only prunes this branch.
			if len(seen) >= MaxProposals {
				break
			}
			if len(frame.path) >= 5 {
				continue
			}
			for _, cap := range setKeys(held) {
				for _, nxt := range needsOf(nodes, cap) {
					if _, ok := frame.visit[nxt]; ok {
						continue
					}
					visit := map[string]struct{}{}
					for k := range frame.visit {
						visit[k] = struct{}{}
					}
					visit[nxt] = struct{}{}
					path := append(append([]string{}, frame.path...), nxt)
					stack = append(stack, chainState{cur: nxt, visit: visit,
						path: path, held: held})
				}
			}
		}
	}
	return chains, nil
}

// memberKey is tuple(sorted(path)) flattened into a map key.
func memberKey(path []string) string {
	sorted := append([]string{}, path...)
	sort.Strings(sorted)
	return joinPipe(sorted)
}

// ChainReport is chain_report(): links, proposals, materialized chains read
// off disk (a materialized chain is a file, not a computation).
func ChainReport(c *state.Campaign) (validation.Value, error) {
	links, err := FindLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	proposals, err := FindChains(c, 2)
	if err != nil {
		return validation.VNull(), err
	}
	materialized, err := chainDocs(c, false)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kvOf("capability_links", valueArr(links)),
		kvOf("proposals", valueArr(proposals)),
		kvOf("materialized", valueArr(materialized)),
		kvOf("note", validation.VStr(ChainReportNote)),
	), nil
}

// chainDocs reads chains/CHAIN-*.json in sorted path order; onlyTerminal
// keeps the docs carrying a truthy `terminal` (terminal_report's filter).
//
// r43a: an absent chains/ directory is an empty campaign; a chains/ directory
// that cannot be listed refuses (a proof/finding built on "zero chains" must
// not stand when the chain store was unreadable). The per-row os.Stat is
// honest about its own three cases too: a row that vanished is the layout
// filter, anything else means the row cannot be examined at all.
func chainDocs(c *state.Campaign, onlyTerminal bool) ([]validation.Value, error) {
	matches, err := validation.ListPrefixedOptional(c.ChainsDir, "CHAIN-",
		".json")
	if err != nil {
		return nil, fmt.Errorf("the chain store %s cannot be listed: %v",
			c.ChainsDir, err)
	}
	out := []validation.Value{}
	for _, p := range matches {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("the chain %s cannot be examined: %v", p, err)
		}
		doc, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		if onlyTerminal && !truthy(validation.ObjAt(doc, "terminal")) {
			continue
		}
		out = append(out, doc)
	}
	return out, nil
}

// truthy is Python's bool().
func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}
