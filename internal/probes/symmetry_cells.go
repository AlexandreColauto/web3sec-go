package probes

import (
	"sort"
	"strings"

	"websec/internal/validation"
)

// ---- cells ----------------------------------------------------------------

// symCell is one (direction, asset, primitive) performed by one function.
type symCell struct {
	Direction string
	Asset     string
	Primitive string
	Contract  string
	Function  string
	Line      int
}

// symMemberIsTestDouble reports whether a family member contract node is a
// test double (its declaring file classifies as one). Test harnesses are not
// custody members: their mint/burn cells are fixture noise that fills the
// per-axis emit quota ahead of real pairings. Reuses srcclass via
// IsTestDoublePath — the same rule collapse.go already applies when folding.
func symMemberIsTestDouble(cnode validation.Value) bool {
	return IsTestDoublePath(vStr(cnode, "path"))
}

// symAssetOf refines the asset label from a call's receiver: the verb table
// above collapses every token call to "erc20", which made an ERC-1155/721
// gateway disagree with an ERC-20 gateway over the same verb. Receiver-name
// matching is deliberately shallow — the indexed call string already carries
// the interface name.
// ponytail: receiver substring (1155/721); a per-interface kind table only if
// a mislabeled receiver ever shows up in a campaign.
func symAssetOf(call, def string) string {
	recv := call
	if i := lastIndexByte(recv, '.'); i >= 0 {
		recv = recv[:i]
	}
	rl := lower(recv)
	switch {
	case strings.Contains(rl, "1155"):
		return "erc1155"
	case strings.Contains(rl, "721"):
		return "erc721"
	}
	return def
}

// symmetryCells reads the custody primitives of one function node into
// (direction, asset, primitive) cells. The verb table is shared with
// probe_custody.go (mintCalls/burnCalls/payCalls/inCalls); the `direction`
// comes from the function name and the asset class from the primitive itself.
func symmetryCells(contract, function string, line int, node validation.Value) []symCell {
	type hit struct {
		primitive string
		asset     string
	}
	hits := []hit{}
	for _, call := range vStrList(node, "calls_internal") {
		low := lower(call)
		switch {
		case inSet(mintCalls, low):
			hits = append(hits, hit{"mint", "share"})
		case inSet(burnCalls, low):
			hits = append(hits, hit{"burn", "share"})
		}
	}
	for _, call := range vStrList(node, "calls_external") {
		low := lower(call)
		method := low
		if i := lastIndexByte(low, '.'); i >= 0 {
			method = low[i+1:]
		}
		switch {
		case inSet(mintCalls, method):
			hits = append(hits, hit{"mint", symAssetOf(low, "erc20")})
		case inSet(burnCalls, method):
			hits = append(hits, hit{"burn", symAssetOf(low, "erc20")})
		case hasPrefix(low, "low-level."), method == "sendvalue", method == "transfereth":
			hits = append(hits, hit{"send-native", "native"})
		case inSet(payCalls, method):
			hits = append(hits, hit{"transfer-out", symAssetOf(low, "erc20")})
		case inSet(inCalls, method):
			hits = append(hits, hit{"transfer-in", symAssetOf(low, "erc20")})
		}
	}
	seen := map[string]struct{}{}
	out := []symCell{}
	direction := symmetryDirectionOf(function)
	for _, h := range hits {
		key := direction + "\x00" + h.asset + "\x00" + h.primitive + "\x00" + contract
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, symCell{Direction: direction, Asset: h.asset,
			Primitive: h.primitive, Contract: contract, Function: function,
			Line: line})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return symCellKey(out[i]) < symCellKey(out[j])
	})
	return out
}

// dedupeSymCells folds the copies of one defining function that each member's
// closure re-lists (an inherited function must not count once per inheritor).
func dedupeSymCells(cells []symCell) []symCell {
	seen := map[string]struct{}{}
	out := []symCell{}
	for _, c := range cells {
		key := symCellKey(c)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return symCellKey(out[i]) < symCellKey(out[j]) })
	return out
}

// symCellKey is the total order over cells used everywhere (determinism).
func symCellKey(c symCell) string {
	return strings.Join([]string{c.Direction, c.Asset, c.Primitive, c.Contract,
		c.Function, itoa(c.Line)}, "\x00")
}
