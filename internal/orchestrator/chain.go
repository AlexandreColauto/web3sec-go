// chain.go: the seam to webv2.chain_engine (P2, unported).
//
// chain_report is the only function the orchestrator calls, and it is built
// from two pure functions over data the Go twin already owns (findings +
// capabilities), so the default here is a faithful port — the seam exists so
// P2 can install the materialization-aware module (materialize_chain,
// terminal_report) without touching the facade.
//
// DEVIATION (declared): Python iterates `caps_held` and `needs[cap]` as SETS,
// whose iteration order for strings varies with PYTHONHASHSEED — the proposal
// ORDER is therefore not reproducible across Python processes either. The Go
// port sorts both neighbor sets, so it is deterministic; for fixtures where
// each capability is declared by one finding the orders coincide exactly.
package orchestrator

import (
	"os"
	"sort"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ChainReportNote is chain_engine.chain_report's note.
const ChainReportNote = "proposals become chains only when every member is CONFIRMED"

// MaxProposals is chain_engine.MAX_PROPOSALS: the enumeration guard. Proposals
// are leads for humans, not a deliverable — past this the report stops.
const MaxProposals = 500

// ChainEngineAPI is the chain_engine.py seam. ChainReport is the only function
// the orchestrator calls.
type ChainEngineAPI struct {
	ChainReport func(c *state.Campaign) (validation.Value, error)
}

// nonDuplicate is the status filter shared by both sweeps.
func nonDuplicate(f validation.Value) bool {
	switch strAt(f, "status") {
	case "DUPLICATE", "OUT_OF_SCOPE", "INFORMATIONAL":
		return false
	}
	return true
}

// capList is `_norm(caps.get("granted"))`'s input conversion. The schema says
// array-of-string, but Python's normalize_labels() iterates whatever it is
// handed, so a bare string collapses to its characters and an object to its
// keys; a non-iterable raises there, and is treated as empty here.
func capList(v validation.Value) []string {
	switch v.Kind {
	case validation.Arr:
		out := make([]string, 0, len(v.A))
		for _, item := range v.A {
			out = append(out, pyStr(item))
		}
		return out
	case validation.Str:
		out := []string{}
		for _, r := range v.S {
			out = append(out, string(r))
		}
		return out
	case validation.Obj:
		out := make([]string, 0, len(v.O))
		for _, kv := range v.O {
			out = append(out, kv.K)
		}
		return out
	}
	return nil
}

// capBlock is `f.get("capabilities") or {}` normalized into granted/required.
func capBlock(f validation.Value) ([]string, []string) {
	caps := asDict(objAt(f, "capabilities"))
	return capabilities.NormalizeLabels(capList(objAt(caps, "granted"))),
		capabilities.NormalizeLabels(capList(objAt(caps, "required")))
}

// capabilityIndex is build_capability_index(): granted -> [finding_ids],
// required -> [finding_ids], in load order (Python dict insertion order).
type capabilityIndex struct {
	granted  []validation.KV
	required []validation.KV
}

func (ix *capabilityIndex) ids(list []validation.KV, cap string) []string {
	for _, kv := range list {
		if kv.K == cap {
			out := make([]string, 0, len(kv.V.A))
			for _, id := range kv.V.A {
				out = append(out, id.S)
			}
			return out
		}
	}
	return nil
}

func (ix *capabilityIndex) appendTo(list *[]validation.KV, cap, fid string) {
	for i, kv := range *list {
		if kv.K == cap {
			(*list)[i].V.A = append((*list)[i].V.A, validation.VStr(fid))
			return
		}
	}
	*list = append(*list, kvOf(cap, validation.VArr(validation.VStr(fid))))
}

// buildCapabilityIndex is build_capability_index().
func buildCapabilityIndex(c *state.Campaign) (*capabilityIndex, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	ix := &capabilityIndex{}
	for _, f := range all {
		if !nonDuplicate(f) {
			continue
		}
		fid := strAt(f, "finding_id")
		granted, required := capBlock(f)
		for _, cap := range granted {
			ix.appendTo(&ix.granted, cap, fid)
		}
		for _, cap := range required {
			ix.appendTo(&ix.required, cap, fid)
		}
	}
	return ix, nil
}

// findLinks is find_links(): all granted -> required matches between distinct
// findings.
func findLinks(c *state.Campaign) ([]validation.Value, error) {
	ix, err := buildCapabilityIndex(c)
	if err != nil {
		return nil, err
	}
	links := []validation.Value{}
	for _, needKV := range ix.required {
		for _, grantFid := range ix.ids(ix.granted, needKV.K) {
			for _, needFid := range ix.ids(ix.required, needKV.K) {
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
		granted, required := capBlock(f)
		node := chainNode{fid: strAt(f, "finding_id"),
			grant: map[string]struct{}{}, need: map[string]struct{}{}}
		for _, cap := range granted {
			node.grant[cap] = struct{}{}
		}
		for _, cap := range required {
			node.need[cap] = struct{}{}
		}
		out = append(out, node)
	}
	return out, nil
}

// needsOf returns the finding ids requiring cap, sorted (see file header).
func needsOf(nodes []chainNode, cap string) []string {
	out := []string{}
	for _, n := range nodes {
		if _, ok := n.need[cap]; ok {
			out = append(out, n.fid)
		}
	}
	sort.Strings(out)
	return out
}

// capsHeld returns the sorted capability keys (see file header).
func capsHeld(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// chainState is one DFS frame: the current finding, the visited set, the path
// and the capabilities held on arrival.
type chainState struct {
	cur   string
	visit map[string]struct{}
	path  []string
	held  map[string]struct{}
}

// findChains is find_chains(): enumerate simple capability chains up to depth
// 5, deduped by member set and capped at MAX_PROPOSALS.
func findChains(c *state.Campaign) ([]validation.Value, error) {
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
			held := map[string]struct{}{}
			for k := range frame.held {
				held[k] = struct{}{}
			}
			for k := range node.grant {
				held[k] = struct{}{}
			}
			if len(frame.path) >= 2 {
				key := memberKey(frame.path)
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					chains = append(chains, validation.VObj(
						kvOf("members", strArr(frame.path)),
						kvOf("capabilities", strArr(capsHeld(held)))))
				}
			}
			if len(seen) >= MaxProposals || len(frame.path) >= 5 {
				continue
			}
			for _, cap := range capsHeld(held) {
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
	key := ""
	for _, s := range sorted {
		key += s + "|"
	}
	return key
}

// defaultChainReport is chain_report(): links, proposals, materialized chains
// read off disk (a materialized chain is a file, not a computation).
func defaultChainReport(c *state.Campaign) (validation.Value, error) {
	links, err := findLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	proposals, err := findChains(c)
	if err != nil {
		return validation.VNull(), err
	}
	matches := validation.ListPrefixed(c.ChainsDir, "CHAIN-", ".json")
	materialized := []validation.Value{}
	for _, p := range matches {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		doc, err := validation.ReadJson(p)
		if err != nil {
			return validation.VNull(), err
		}
		materialized = append(materialized, doc)
	}
	return validation.VObj(
		kvOf("capability_links", valueArr(links)),
		kvOf("proposals", valueArr(proposals)),
		kvOf("materialized", valueArr(materialized)),
		kvOf("note", validation.VStr(ChainReportNote)),
	), nil
}

var ceAPI = ChainEngineAPI{ChainReport: defaultChainReport}

// SetChainEngine installs the chain_engine implementation (P2 wires this). A
// nil argument — or a nil field — restores the default.
func SetChainEngine(api ChainEngineAPI) {
	if api.ChainReport == nil {
		api.ChainReport = defaultChainReport
	}
	ceAPI = api
}
