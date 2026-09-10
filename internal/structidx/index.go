// index.go: the campaign-bound artifact lifecycle — index_snapshot,
// save_index and the K3 freshness chain (ensure_fresh_index). Every derived
// report (value flow, prescreen, recency, fork-diff) is built through
// EnsureFreshIndex, so a report can only ever carry the ACTIVE pin's
// snapshot_id.
package structidx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// StructuralIndexFile is the root artifact every derived report copies its
// snapshot_id from.
const StructuralIndexFile = "structural_index.json"

// ValueFlowFile is the backward-slice artifact.
const ValueFlowFile = "value_flow.json"

// StaleIndexError is a structural index that predates the current parse
// version. Reading it as v3 would report "no guards" for every function — a
// lie, not an empty surface — so callers must reject it and rebuild.
type StaleIndexError struct{ Msg string }

func (e *StaleIndexError) Error() string { return e.Msg }

// RequireParseVersion is require_parse_version: fail loud on a pre-v3 index,
// naming the exact rebuild command.
func RequireParseVersion(index validation.Value, source string) error {
	got := validation.VNull()
	if index.Kind == validation.Obj {
		got = objAt(index, "parse_version")
	}
	if got.Kind == validation.Str && got.S == ParseVersion {
		return nil
	}
	// The stale index still carries the campaign it belongs to, so the
	// rebuild command names it. An index with no campaign_id at all (a
	// hand-built value, as in the direct unit test) keeps the documented
	// metavariable rather than an empty hole.
	rebuild := IndexRebuildCommand
	if cid := objStr(index, "campaign_id"); cid != "" {
		rebuild = strings.Replace(rebuild, CampaignPlaceholder, cid, 1)
	}
	return &StaleIndexError{Msg: fmt.Sprintf(
		"%s has parse_version=%s, need %s — rebuild it: `%s`",
		source, validation.PyRepr(got), validation.PyRepr(validation.VStr(ParseVersion)),
		rebuild)}
}

func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	return state.NowIso()
}

// IndexTreeValue is _index_tree's return dict: nodes deduped, closures
// attached, in the exact Python key order.
func IndexTreeValue(root string) (validation.Value, error) {
	tree, err := IndexTree(root)
	if err != nil {
		return validation.VNull(), err
	}
	nodes := dedupeNodes(tree.nodes)
	attachClosures(nodes, tree.edges)
	nodeVals := make([]validation.Value, 0, len(nodes))
	for _, n := range nodes {
		nodeVals = append(nodeVals, n.toValue())
	}
	edgeVals := make([]validation.Value, 0, len(tree.edges))
	for _, e := range tree.edges {
		edgeVals = append(edgeVals, validation.VObj(
			validation.KV{K: "from", V: validation.VStr(e.from)},
			validation.KV{K: "rel", V: validation.VStr(e.rel)},
			validation.KV{K: "to", V: validation.VStr(e.to)},
		))
	}
	return validation.VObj(
		validation.KV{K: "nodes", V: validation.VArr(nodeVals...)},
		validation.KV{K: "edges", V: validation.VArr(edgeVals...)},
		validation.KV{K: "parse_version", V: validation.VStr(ParseVersion)},
		validation.KV{K: "solidity_files", V: validation.VInt(tree.solidityFiles)},
		validation.KV{K: "other_files_listed", V: validation.VInt(tree.otherFiles)},
	), nil
}

// IndexSnapshot is index_snapshot: parse the tree, stamp campaign identity,
// the active pin (or "unpinned"), the backend and the clock.
func IndexSnapshot(c *state.Campaign, root, backend string) (validation.Value, error) {
	tree, err := IndexTreeValue(root)
	if err != nil {
		return validation.VNull(), err
	}
	nodeVals := objList(objAt(tree, "nodes"))
	edgeVals := objList(objAt(tree, "edges"))
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	snapID := "unpinned"
	if snap != nil {
		snapID = *snap
	}
	externalEdges := int64(0)
	for _, e := range edgeVals {
		if hasPrefix2(objStr(e, "to"), "*#") {
			externalEdges++
		}
	}
	var contracts, functions, stateVars, entryPoints int64
	for _, n := range nodeVals {
		switch objStr(n, "kind") {
		case "contract", "interface", "library":
			contracts++
		case "function":
			functions++
			if b := objAt(n, "is_entry_point"); b.Kind == validation.Bool && b.B {
				entryPoints++
			}
		case "state-variable":
			stateVars++
		}
	}
	stats := validation.VObj(
		validation.KV{K: "solidity_files", V: objAt(tree, "solidity_files")},
		validation.KV{K: "other_files_listed", V: objAt(tree, "other_files_listed")},
		validation.KV{K: "contracts", V: validation.VInt(contracts)},
		validation.KV{K: "functions", V: validation.VInt(functions)},
		validation.KV{K: "state_variables", V: validation.VInt(stateVars)},
		validation.KV{K: "entry_points", V: validation.VInt(entryPoints)},
		validation.KV{K: "external_call_edges", V: validation.VInt(externalEdges)},
	)
	return validation.VObj(
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "snapshot_id", V: validation.VStr(snapID)},
		validation.KV{K: "backend", V: validation.VStr(backend)},
		validation.KV{K: "parse_version", V: validation.VStr(ParseVersion)},
		validation.KV{K: "created_at", V: validation.VStr(nowIso())},
		validation.KV{K: "entry_count", V: validation.VInt(
			int64(len(nodeVals) + len(edgeVals)))},
		validation.KV{K: "nodes", V: objAt(tree, "nodes")},
		validation.KV{K: "edges", V: objAt(tree, "edges")},
		validation.KV{K: "stats", V: stats},
	), nil
}

// IndexPath is campaign.artifacts_dir / "structural_index.json".
func IndexPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, StructuralIndexFile)
}

// SaveIndex is save_index: require v3, validate against the schema, write.
func SaveIndex(c *state.Campaign, index validation.Value) (string, error) {
	if err := RequireParseVersion(index, "structural index"); err != nil {
		return "", err
	}
	if err := validation.Validate(index, "structural_index", 1); err != nil {
		return "", err
	}
	out := IndexPath(c)
	if err := validation.WriteJson(out, index, ""); err != nil {
		return "", err
	}
	return out, nil
}

// EnsureFreshIndex is ensure_fresh_index: the stored index is reused ONLY
// while its snapshot_id still matches the active pin AND its parse_version is
// current; otherwise it is rebuilt from the snapshot tree and saved.
func EnsureFreshIndex(c *state.Campaign, root string) (validation.Value, error) {
	p := IndexPath(c)
	if _, err := os.Stat(p); err == nil {
		idx, rerr := validation.ReadJson(p)
		if rerr == nil && idx.Kind == validation.Obj {
			active, aerr := c.ActiveSnapshotIDOrNone()
			if aerr != nil {
				return validation.VNull(), aerr
			}
			stored := objAt(idx, "snapshot_id")
			if sameActive(stored, active) &&
				objStr(idx, "parse_version") == ParseVersion {
				return idx, nil
			}
		}
	}
	idx, err := IndexSnapshot(c, root, "regex")
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := SaveIndex(c, idx); err != nil {
		return validation.VNull(), err
	}
	return idx, nil
}

// sameActive compares a stored snapshot_id against the active pin the way
// Python's `==` does (None only equals None).
func sameActive(stored validation.Value, active *string) bool {
	if active == nil {
		return stored.Kind == validation.Null
	}
	return stored.Kind == validation.Str && stored.S == *active
}

// objAt is v.get(key) with a missing key reading as None.
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}
