// coverage_init.go: init_from_index — building the initial ledger from the
// structural index and the model (contract rows, entry-point/function
// counts, invariant links, surface totals).
package coverage

import (
	"strings"

	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

// InitFromIndex is init_from_index: every in-scope contract starts as
// `unknown`, every entry point as unreviewed.
func InitFromIndex(c *state.Campaign, index, model validation.Value) (validation.Value, error) {
	// Python also builds an in_scope name set here and never reads it; the
	// dead local is omitted (no observable difference for a schema-valid
	// model, where contracts[].name is required).
	contracts, err := contractRows(index, model)
	if err != nil {
		return validation.VNull(), err
	}
	surfaces, err := surfaceCounts(index, model)
	if err != nil {
		return validation.VNull(), err
	}
	cov := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("snapshot_id", getOr(index, "snapshot_id", validation.VStr("unpinned"))),
		kv("updated_at", validation.VStr(state.NowIso())),
		kv("contracts", validation.VArr(contracts...)),
		kv("surfaces", surfaces),
		kv("funnel", validation.VObj()),
		kv("gaps", validation.VArr()),
		kv("summary", validation.VObj()),
	)
	if _, err := Save(c, &cov); err != nil {
		return validation.VNull(), err
	}
	return cov, nil
}

// contractRows builds one ledger row per contract/interface/library node, in
// index order, de-duplicated by name. The index is an external document, so
// every read is dict[key] with Python's KeyError text.
func contractRows(index, model validation.Value) ([]validation.Value, error) {
	nodes, err := reqKey(index, "nodes")
	if err != nil {
		return nil, err
	}
	surface := siAPI.ExternalSurface(index)
	contracts := make([]validation.Value, 0, len(nodes.A))
	seen := map[string]struct{}{}
	for _, n := range nodes.A {
		kind, err := reqKey(n, "kind")
		if err != nil {
			return nil, err
		}
		if kind.S != "contract" && kind.S != "interface" && kind.S != "library" {
			continue
		}
		name, err := reqKey(n, "name")
		if err != nil {
			return nil, err
		}
		if _, dup := seen[name.S]; dup {
			continue
		}
		seen[name.S] = struct{}{}
		eps, err := countEntryPoints(n, surface)
		if err != nil {
			return nil, err
		}
		path, err := reqKey(n, "path")
		if err != nil {
			return nil, err
		}
		fns, err := countFunctions(n, nodes.A)
		if err != nil {
			return nil, err
		}
		invIDs, err := invariantIDs(model, name.S)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, validation.VObj(
			kv("path", validation.VStr(path.S)),
			kv("status", validation.VStr("unknown")),
			kv("trajectory_counts", validation.VObj()),
			kv("entry_points_total", validation.VInt(eps)),
			kv("entry_points_reviewed", validation.VInt(0)),
			kv("functions_total", validation.VInt(fns)),
			kv("functions_reviewed", validation.VInt(0)),
			kv("invariant_ids", invIDs),
			kv("findings_ids", validation.VArr()),
			kv("thoroughness", validation.VNull()),
		))
	}
	return contracts, nil
}

// countEntryPoints is len([f for f in external_surface(index)
// if f["id"].startswith(n["id"] + ".")]).
func countEntryPoints(n validation.Value, surface []validation.Value) (int64, error) {
	eps := int64(0)
	for _, f := range surface {
		fid, err := reqKey(f, "id")
		if err != nil {
			return 0, err
		}
		id, err := reqKey(n, "id")
		if err != nil {
			return 0, err
		}
		if strings.HasPrefix(fid.S, id.S+".") {
			eps++
		}
	}
	return eps, nil
}

// countFunctions is the functions_total comprehension over the index nodes.
func countFunctions(n validation.Value, nodes []validation.Value) (int64, error) {
	fns := int64(0)
	for _, f := range nodes {
		fkind, err := reqKey(f, "kind")
		if err != nil {
			return 0, err
		}
		if fkind.S != "function" {
			continue
		}
		fid, err := reqKey(f, "id")
		if err != nil {
			return 0, err
		}
		id, err := reqKey(n, "id")
		if err != nil {
			return 0, err
		}
		if strings.HasPrefix(fid.S, id.S+".") {
			fns++
		}
	}
	return fns, nil
}

// invariantIDs is the model.invariants filter: every invariant whose
// applies_to mentions the contract name (substring, Python's `name in a`).
func invariantIDs(model validation.Value, name string) (validation.Value, error) {
	ids := []validation.Value{}
	for _, inv := range listField(model, "invariants") {
		for _, a := range listField(inv, "applies_to") {
			if strings.Contains(a.S, name) {
				id, err := reqKey(inv, "id")
				if err != nil {
					return validation.VNull(), err
				}
				ids = append(ids, validation.VStr(id.S))
				break
			}
		}
	}
	return validation.VArr(ids...), nil
}

// surfaceCounts is the initial surfaces block: every total from the model and
// the index, every reviewed count zero.
func surfaceCounts(index, model validation.Value) (validation.Value, error) {
	cross, err := crossContractPaths(index)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kv("privilege_paths", surfaceRow(int64(len(protocolgraph.PrivilegeSurface(model))))),
		kv("oracle_surfaces", surfaceRow(int64(len(protocolgraph.OracleChain(model))))),
		kv("upgrade_paths", surfaceRow(int64(len(listField(model, "upgrade_paths"))))),
		kv("cross_contract_paths", surfaceRow(cross)),
		kv("external_call_sites", surfaceRow(int64(len(siAPI.ExternalCallSites(index))))),
		kv("state_machines", surfaceRow(int64(len(protocolgraph.StateMachines(model))))),
	), nil
}

// surfaceRow is one {"total": n, "reviewed": 0} row.
func surfaceRow(total int64) validation.Value {
	return validation.VObj(
		kv("total", validation.VInt(total)),
		kv("reviewed", validation.VInt(0)),
	)
}

// crossContractPaths counts call edges into a "*#" pseudo-node that is not
// the "*#low-level" bucket.
func crossContractPaths(index validation.Value) (int64, error) {
	edges, err := reqKey(index, "edges")
	if err != nil {
		return 0, err
	}
	n := int64(0)
	for _, e := range edges.A {
		rel, err := reqKey(e, "rel")
		if err != nil {
			return 0, err
		}
		if rel.S != "calls" {
			continue
		}
		to, err := reqKey(e, "to")
		if err != nil {
			return 0, err
		}
		if strings.HasPrefix(to.S, "*#") && !strings.HasPrefix(to.S, "*#low-level") {
			n++
		}
	}
	return n, nil
}
