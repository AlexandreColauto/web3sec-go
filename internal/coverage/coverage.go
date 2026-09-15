// Package coverage ports webv2.coverage: coverage accounting with UNKNOWN as
// a first-class status.
//
// At any moment the campaign can answer: what has been swept, from which
// trajectory, with what density — and what is explicitly UNKNOWN. "Not
// analyzed" must never silently become "secure": unswept contracts are
// enumerated with status `unknown` in every summary and report.
//
// Structural index seam: coverage calls structural_index.external_surface and
// structural_index.external_call_sites. That module is a later task, so both
// reads go through StructuralIndexAPI / SetStructuralIndex. The default is
// the absent-module behavior (no entry points, no external call sites), which
// is byte-identical to Python only when the index has none either.
//
// Deviations (all documented at the call site):
//   - Errors carry Python's str(exception): a KeyError is rendered as the repr
//     of its message, which is what the CLI prints.
//   - A non-object trajectory_counts / verification / snapshot document is
//     treated as empty where Python would raise AttributeError; no valid
//     ledger can contain one.
//   - init_from_index's dead `in_scope` local is omitted, and the seam's
//     external_surface is called once instead of once per contract node.
package coverage

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

// SweepOpts mirrors record_sweep's keyword defaults.
type SweepOpts struct {
	EntryPointsReviewed int64
	FunctionsReviewed   int64
	Complete            bool
}

// StructuralIndexAPI is the seam to webv2.structural_index (P3, unported).
// Both fields receive the parsed index document and return the matching
// function nodes: ExternalSurface is external_surface (entry points),
// ExternalCallSites is external_call_sites (calls_external / delegatecalls).
type StructuralIndexAPI struct {
	ExternalSurface   func(index validation.Value) []validation.Value
	ExternalCallSites func(index validation.Value) []validation.Value
}

// emptyNodes is the absent-module default: no nodes at all.
func emptyNodes(validation.Value) []validation.Value { return nil }

var siAPI = StructuralIndexAPI{ExternalSurface: emptyNodes, ExternalCallSites: emptyNodes}

// SetStructuralIndex installs the structural_index implementation (P3 wires
// this). A nil argument — or a nil field — restores the absent-module default.
func SetStructuralIndex(api StructuralIndexAPI) {
	if api.ExternalSurface == nil {
		api.ExternalSurface = emptyNodes
	}
	if api.ExternalCallSites == nil {
		api.ExternalCallSites = emptyNodes
	}
	siAPI = api
}

// Path is _path: the coverage ledger under the campaign's artifacts dir.
func Path(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "coverage.json")
}

// Load is load: the ledger document as written (key order preserved).
func Load(c *state.Campaign) (validation.Value, error) {
	return validation.ReadJson(Path(c))
}

// Save is save: stamp updated_at, validate against the coverage schema, write
// with json.dumps(indent=2), and return the path. The caller's Value is
// mutated in place, as Python mutates the dict it was handed.
func Save(c *state.Campaign, cov *validation.Value) (string, error) {
	cov.O = validation.SetOrAppend(cov.O, "updated_at", validation.VStr(nowIso()))
	if err := validation.Validate(*cov, "coverage", 1); err != nil {
		return "", err
	}
	if err := validation.WriteJson(Path(c), *cov, ""); err != nil {
		return "", err
	}
	return Path(c), nil
}

// saveThenLog is the coverage package's r40e UNWIND-ON-REFUSAL door — the
// sibling of state.AppendJsonlThenLog / findings.SaveThenLog for the
// coverage ledger, which is a whole-file artifact rather than an
// append-only row. coverage.json is campaign TRUTH: the uncovered-critical
// gates, the funnel/UNKNOWN accounting and the reports all read it, so a
// sweep row that lands while its coverage.sweep event is REFUSED (torn
// ledger, mirror lag or hole, held lock, unreadable ledger) is a
// disposition the ledger never recorded — and the retry after the heal
// writes a SECOND row for the one event. So the file's bytes are
// snapshotted before the write, the whole snapshot -> write -> append ->
// restore window is held under the campaign process lock the inner Log
// re-enters by depth, and a refused append restores those exact bytes — or
// removes a file that did not exist yet, never creating an empty one. A
// FAILED restore means the row bytes are still AHEAD of the refused event;
// name both failures so no caller can report a clean unwind that never
// happened.
func saveThenLog(c *state.Campaign, cov *validation.Value,
	log func() error) error {
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	path := Path(c)
	prevRaw, perr := os.ReadFile(path)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	restore := func() error {
		if had {
			return os.WriteFile(path, prevRaw, 0o644)
		}
		if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	fail := func(err error) error {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the coverage "+
				"ledger holds post-write bytes with no event; repair by "+
				"hand before continuing)", err, rerr)
		}
		return err
	}
	if _, err := Save(c, cov); err != nil {
		return fail(err)
	}
	if err := log(); err != nil {
		return fail(err)
	}
	return nil
}

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
		kv("updated_at", validation.VStr(nowIso())),
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

// RecordSweep is record_sweep: record one specialist pass over a contract
// from one trajectory and return the updated contract row.
func RecordSweep(c *state.Campaign, contract, trajectory string,
	opts SweepOpts) (validation.Value, error) {
	cov, err := Load(c)
	if err != nil {
		return validation.VNull(), err
	}
	rows, err := reqKey(cov, "contracts")
	if err != nil {
		return validation.VNull(), err
	}
	for i := range rows.A {
		path, err := reqKey(rows.A[i], "path")
		if err != nil {
			return validation.VNull(), err
		}
		if !matchesContract(path.S, contract) {
			continue
		}
		row, err := sweepRow(rows.A[i], trajectory, opts)
		if err != nil {
			return validation.VNull(), err
		}
		rows.A[i] = row
		cov.O = validation.SetOrAppend(cov.O, "contracts", rows)
		data := validation.VObj(
			kv("contract", validation.VStr(contract)),
			kv("trajectory", validation.VStr(trajectory)),
			kv("complete", validation.VBool(opts.Complete)),
		)
		// r40e: the sweep row without its coverage.sweep event is a
		// disposition no later reader can see; unwind the ledger write on a
		// refused append.
		if err := saveThenLog(c, &cov, func() error {
			_, lerr := c.Log("coverage.sweep", nil, &data)
			return lerr
		}); err != nil {
			return validation.VNull(), err
		}
		return row, nil
	}
	inner := fmt.Sprintf("unknown contract %s in coverage ledger",
		validation.PyReprStr(contract))
	return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(inner))
}

// matchesContract is record_sweep's path predicate (the endswith("/"+contract)
// clause is subsumed by the plain endswith).
func matchesContract(path, contract string) bool {
	return strings.HasSuffix(path, contract) || path == contract ||
		strings.Contains(path, contract)
}

// sweepRow applies one sweep to a contract row. The min() cap keeps the
// Python quirk: a falsy entry_points_total caps at the ARGUMENT, not at 0.
func sweepRow(row validation.Value, trajectory string, opts SweepOpts) (validation.Value, error) {
	counts, err := reqKey(row, "trajectory_counts")
	if err != nil {
		return validation.VNull(), err
	}
	if counts.Kind != validation.Obj {
		counts = validation.VObj()
	}
	n := numOrZero(objAt(counts, trajectory)).addInt(1)
	counts.O = validation.SetOrAppend(counts.O, trajectory, n.value())
	row.O = validation.SetOrAppend(row.O, "trajectory_counts", counts)

	epr := numOrZero(objAt(row, "entry_points_reviewed")).addInt(opts.EntryPointsReviewed)
	eprCap := numInt(opts.EntryPointsReviewed)
	if validation.PyTruthy(objAt(row, "entry_points_total")) {
		eprCap = numOf(objAt(row, "entry_points_total"))
	}
	row.O = validation.SetOrAppend(row.O, "entry_points_reviewed", epr.min(eprCap).value())

	fr := numOrZero(objAt(row, "functions_reviewed")).addInt(opts.FunctionsReviewed)
	frCap := numInt(opts.FunctionsReviewed)
	if validation.PyTruthy(objAt(row, "functions_total")) {
		frCap = numOf(objAt(row, "functions_total"))
	}
	row.O = validation.SetOrAppend(row.O, "functions_reviewed", fr.min(frCap).value())

	if opts.Complete {
		row.O = validation.SetOrAppend(row.O, "status", validation.VStr("swept"))
	} else {
		status, err := reqKey(row, "status")
		if err != nil {
			return validation.VNull(), err
		}
		if status.S == "unknown" {
			row.O = validation.SetOrAppend(row.O, "status", validation.VStr("in-progress"))
		}
	}
	row.O = validation.SetOrAppend(row.O, "thoroughness", thoroughness(objAt(row, "entry_points_reviewed"),
		objAt(row, "entry_points_total")))
	return row, nil
}

// thoroughness is the row's density: round(reviewed/total, 3), or null when
// the total is falsy.
func thoroughness(reviewed, total validation.Value) validation.Value {
	if !validation.PyTruthy(total) {
		return validation.VNull()
	}
	return validation.VFloat(validation.PythonRound(numOrZero(reviewed).div(total), 3))
}

// RecordSurface is record_surface: set one cross-cutting surface's reviewed
// count, clamped to its total.
func RecordSurface(c *state.Campaign, surface string, reviewed int64) error {
	cov, err := Load(c)
	if err != nil {
		return err
	}
	surfaces, err := reqKey(cov, "surfaces")
	if err != nil {
		return err
	}
	row, ok := lookup(surfaces, surface)
	if !ok {
		return fmt.Errorf("%s", validation.PyReprStr(
			fmt.Sprintf("unknown surface %s", validation.PyReprStr(surface))))
	}
	total, err := reqKey(row, "total")
	if err != nil {
		return err
	}
	row.O = validation.SetOrAppend(row.O, "reviewed", numInt(reviewed).min(numOf(total)).value())
	surfaces.O = validation.SetOrAppend(surfaces.O, surface, row)
	cov.O = validation.SetOrAppend(cov.O, "surfaces", surfaces)
	_, err = Save(c, &cov)
	return err
}

// ThinCoverage is thin_coverage: contracts swept by fewer than N trajectories
// — the planner re-points a different angle at exactly these.
func ThinCoverage(c *state.Campaign, minTrajectories int64) ([]validation.Value, error) {
	cov, err := Load(c)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	contracts, err := reqKey(cov, "contracts")
	if err != nil {
		return nil, err
	}
	for _, row := range contracts.A {
		status, err := reqKey(row, "status")
		if err != nil {
			return nil, err
		}
		if status.S == "excluded" {
			continue
		}
		counts, err := reqKey(row, "trajectory_counts")
		if err != nil {
			return nil, err
		}
		if status.S != "unknown" && int64(len(counts.O)) >= minTrajectories {
			continue
		}
		path, err := reqKey(row, "path")
		if err != nil {
			return nil, err
		}
		out = append(out, validation.VObj(
			kv("path", validation.VStr(path.S)),
			kv("status", status),
			kv("trajectories", sortedKeys(counts)),
			kv("thoroughness", objAt(row, "thoroughness")),
		))
	}
	return out, nil
}

// sortedKeys is sorted(dict): the keys in code-point order.
func sortedKeys(v validation.Value) validation.Value {
	keys := make([]string, 0, len(v.O))
	for _, pair := range v.O {
		keys = append(keys, pair.K)
	}
	sort.Strings(keys)
	out := make([]validation.Value, len(keys))
	for i, k := range keys {
		out[i] = validation.VStr(k)
	}
	return validation.VArr(out...)
}

// RefreshGaps is refresh_gaps: recompute explicit gaps — unswept contracts,
// thin trajectories, unverified deployments, open questions.
func RefreshGaps(c *state.Campaign, model validation.Value) ([]validation.Value, error) {
	cov, err := Load(c)
	if err != nil {
		return nil, err
	}
	gaps := []validation.Value{}
	contracts, err := reqKey(cov, "contracts")
	if err != nil {
		return nil, err
	}
	for _, row := range contracts.A {
		status, err := reqKey(row, "status")
		if err != nil {
			return nil, err
		}
		counts, err := reqKey(row, "trajectory_counts")
		if err != nil {
			return nil, err
		}
		path, err := reqKey(row, "path")
		if err != nil {
			return nil, err
		}
		switch {
		case status.S == "unknown":
			priority := 0.5
			if validation.PyTruthy(objAt(row, "entry_points_total")) {
				priority = 0.9
			}
			gaps = append(gaps, gapRow(path.S+" has never been swept",
				"unswept-contract", validation.VStr(path.S), priority))
		case len(counts.O) < 2 && status.S != "excluded":
			gaps = append(gaps, gapRow(fmt.Sprintf("%s swept from only %d trajectory(ies)",
				path.S, len(counts.O)), "thin-trajectory", validation.VStr(path.S), 0.6))
		}
	}
	dep, err := activeDeployment(c)
	if err != nil {
		return nil, err
	}
	if validation.PyTruthy(dep) {
		if unverified := unverifiedContracts(dep); unverified > 0 {
			gaps = append(gaps, gapRow(fmt.Sprintf("%d deployed contracts have unverified source",
				unverified), "unverified-deployment", objAt(dep, "network"), 0.8))
		}
	}
	for _, q := range listField(model, "open_questions") {
		if validation.PyTruthy(objAt(q, "resolved")) {
			continue
		}
		question, err := reqKey(q, "question")
		if err != nil {
			return nil, err
		}
		gaps = append(gaps, gapRow("open question: "+question.S, "open-question",
			validation.VStr(joinBlocks(objAt(q, "blocks"))), 0.4))
	}
	cov.O = validation.SetOrAppend(cov.O, "gaps", validation.VArr(gaps...))
	if _, err := Save(c, &cov); err != nil {
		return nil, err
	}
	return gaps, nil
}

// gapRow is one gap entry, in the Python literal's key order.
func gapRow(description, kind string, component validation.Value,
	priority float64) validation.Value {
	return validation.VObj(
		kv("description", validation.VStr(description)),
		kv("kind", validation.VStr(kind)),
		kv("component", component),
		kv("priority", validation.VFloat(priority)),
	)
}

// unverifiedContracts counts deployed contracts whose source_match is
// "unverified".
func unverifiedContracts(dep validation.Value) int {
	n := 0
	for _, k := range listField(dep, "contracts") {
		if objStr(k, "source_match") == "unverified" {
			n++
		}
	}
	return n
}

// joinBlocks is "; ".join(q.get("blocks", [])).
func joinBlocks(blocks validation.Value) string {
	parts := make([]string, 0, len(blocks.A))
	for _, b := range blocks.A {
		parts = append(parts, b.S)
	}
	return strings.Join(parts, "; ")
}

// activeDeployment is _active_deployment: the pinned snapshot's deployment
// block, or null when there is no active snapshot / no snapshot file.
func activeDeployment(c *state.Campaign) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	sid := objAt(st, "active_snapshot_id")
	if !validation.PyTruthy(sid) {
		return validation.VNull(), nil
	}
	p := filepath.Join(c.Dir, "snapshots", sid.S, "snapshot.json")
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(), nil
	}
	doc, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), err
	}
	if !validation.PyTruthy(doc) {
		doc = validation.VObj()
	}
	return objAt(doc, "deployment"), nil
}

// UpdateFunnel is update_funnel: project the candidate funnel from findings +
// event log.
func UpdateFunnel(c *state.Campaign) (validation.Value, error) {
	found, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range found {
		if _, ok := lookup(f, "status"); !ok {
			// Python's f["status"] raises KeyError before any counter runs.
			return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr("status"))
		}
	}
	funnel := validation.VObj(
		kv("hypotheses_generated", validation.VInt(int64(len(found)))),
		kv("after_dedupe", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return objStr(f, "status") != "DUPLICATE"
		}))),
		kv("after_review", validation.VInt(countFindings(found, func(f validation.Value) bool {
			switch objStr(f, "status") {
			case "POSSIBLE", "CONFIRMED", "CHAIN":
				return true
			}
			return false
		}))),
		kv("reproduced", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return reproductionStatus(f) == "reproduced"
		}))),
		kv("confirmed", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return objStr(f, "status") == "CONFIRMED"
		}))),
		kv("disproved", validation.VInt(countFindings(found, func(f validation.Value) bool {
			return objStr(f, "status") == "DISPROVED"
		}))),
		kv("submission_ready", validation.VInt(countFindings(found,
			func(f validation.Value) bool {
				return validation.PyTruthy(objAt(objAt(f, "bounty"), "submission_ready"))
			}))),
	)
	cov, err := Load(c)
	if err != nil {
		return validation.VNull(), err
	}
	cov.O = validation.SetOrAppend(cov.O, "funnel", funnel)
	if _, err := Save(c, &cov); err != nil {
		return validation.VNull(), err
	}
	return funnel, nil
}

// countFindings is sum(1 for f in findings if pred(f)).
func countFindings(found []validation.Value, pred func(validation.Value) bool) int64 {
	n := int64(0)
	for _, f := range found {
		if pred(f) {
			n++
		}
	}
	return n
}

// reproductionStatus is (f.get("verification") or {}).get("reproduction",
// {}).get("status"): "" when any link is absent or falsy.
func reproductionStatus(f validation.Value) string {
	verification := objAt(f, "verification")
	if !validation.PyTruthy(verification) {
		return ""
	}
	repro, ok := lookup(verification, "reproduction")
	if !ok || repro.Kind != validation.Obj {
		return ""
	}
	return objStr(repro, "status")
}

// BuildSummary is build_summary: the one-glance numbers, stamped into the
// ledger. index is accepted for signature parity; Python never reads it.
func BuildSummary(c *state.Campaign, index, model validation.Value) (validation.Value, error) {
	_ = index
	cov, err := Load(c)
	if err != nil {
		return validation.VNull(), err
	}
	invCov, err := invariants.Coverage(c)
	if err != nil {
		return validation.VNull(), err
	}
	rows, err := reqKey(cov, "contracts")
	if err != nil {
		return validation.VNull(), err
	}
	analyzed, unknown, err := summaryStatusCounts(rows.A)
	if err != nil {
		return validation.VNull(), err
	}
	invText, invRatio, err := invariantText(invCov)
	if err != nil {
		return validation.VNull(), err
	}
	priv, err := surfaceText(cov, "privilege_paths")
	if err != nil {
		return validation.VNull(), err
	}
	oracle, err := surfaceText(cov, "oracle_surfaces")
	if err != nil {
		return validation.VNull(), err
	}
	summary := validation.VObj(
		kv("contracts_analyzed", validation.VStr(
			strconv.Itoa(analyzed)+"/"+strconv.Itoa(len(rows.A)))),
		kv("contracts_unknown", validation.VInt(int64(unknown))),
		kv("entry_points", validation.VStr(sumField(rows.A, "entry_points_reviewed").text()+
			"/"+sumField(rows.A, "entry_points_total").text())),
		kv("functions", validation.VStr(sumField(rows.A, "functions_reviewed").text()+
			"/"+sumField(rows.A, "functions_total").text())),
		kv("invariants", validation.VStr(invText)),
		kv("invariant_coverage_ratio", invRatio),
		kv("privilege_paths", validation.VStr(priv)),
		kv("oracle_surfaces", validation.VStr(oracle)),
		kv("unknown_note", validation.VStr(
			"contracts with status 'unknown' are NOT secure — they are unexamined")),
	)
	cov.O = validation.SetOrAppend(cov.O, "summary", summary)
	if _, err := Save(c, &cov); err != nil {
		return validation.VNull(), err
	}
	return summary, nil
}

// summaryStatusCounts is contracts_analyzed / contracts_unknown.
func summaryStatusCounts(rows []validation.Value) (int, int, error) {
	analyzed, unknown := 0, 0
	for _, row := range rows {
		status, err := reqKey(row, "status")
		if err != nil {
			return 0, 0, err
		}
		switch status.S {
		case "swept", "in-progress":
			analyzed++
		case "unknown":
			unknown++
		}
	}
	return analyzed, unknown, nil
}

// invariantText is f"{statuses['held'] + statuses['violated']}/{total}" plus
// the test coverage ratio from the invariants module.
func invariantText(invCov validation.Value) (string, validation.Value, error) {
	statuses, err := reqKey(invCov, "statuses")
	if err != nil {
		return "", validation.VNull(), err
	}
	held, err := reqKey(statuses, "held")
	if err != nil {
		return "", validation.VNull(), err
	}
	violated, err := reqKey(statuses, "violated")
	if err != nil {
		return "", validation.VNull(), err
	}
	total, err := reqKey(invCov, "total")
	if err != nil {
		return "", validation.VNull(), err
	}
	ratio, err := reqKey(invCov, "test_coverage_ratio")
	if err != nil {
		return "", validation.VNull(), err
	}
	done := numOrZero(held).add(numOrZero(violated)).text()
	return done + "/" + numOrZero(total).text(), ratio, nil
}

// sumField is sum(c.get(k, 0) or 0 for c in contracts), keeping Python's
// int/float result type.
func sumField(rows []validation.Value, key string) pynum {
	acc := numInt(0)
	for _, row := range rows {
		acc = acc.add(numOrZero(objAt(row, key)))
	}
	return acc
}

// surfaceText is f"{surfaces[s]['reviewed']}/{surfaces[s]['total']}".
func surfaceText(cov validation.Value, surface string) (string, error) {
	surfaces, err := reqKey(cov, "surfaces")
	if err != nil {
		return "", err
	}
	row, err := reqKey(surfaces, surface)
	if err != nil {
		return "", err
	}
	reviewed, err := reqKey(row, "reviewed")
	if err != nil {
		return "", err
	}
	total, err := reqKey(row, "total")
	if err != nil {
		return "", err
	}
	return numOrZero(reviewed).text() + "/" + numOrZero(total).text(), nil
}

// nowIso is now_iso (mirrors state.nowIso, unexported there). WEBV2_NOW pins
// the clock for the golden suite; unset = real clock.
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00", now.Format("2006-01-02T15:04:05"),
		now.Nanosecond()/1000)
}

// ---- Python value helpers ------------------------------------------------

// kv is the vet-clean keyed KV constructor.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// objAt is dict.get(key): the value for key, or Null when absent (or the
// receiver is not an object).
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V
		}
	}
	return validation.VNull()
}

// lookup is the `key in dict` + indexing pair: found reports whether the key
// is PRESENT (a present null is not the same as an absent key).
func lookup(v validation.Value, key string) (validation.Value, bool) {
	if v.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, pair := range v.O {
		if pair.K == key {
			return pair.V, true
		}
	}
	return validation.VNull(), false
}

// reqKey is dict[key]: the value, or Python's str(KeyError(key)) when the key
// is absent (the repr of the key name — what the CLI prints).
func reqKey(v validation.Value, key string) (validation.Value, error) {
	val, ok := lookup(v, key)
	if !ok {
		return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(key))
	}
	return val, nil
}

// objStr returns a string field's value ("" when absent/non-string).
func objStr(v validation.Value, key string) string {
	return objAt(v, key).S
}

// listField is dict.get(key, []): the array's elements, empty when the key is
// absent or the value is not an array.
func listField(v validation.Value, key string) []validation.Value {
	return objAt(v, key).A
}

// getOr is dict.get(key, default): the default only when the key is ABSENT.
func getOr(v validation.Value, key string, def validation.Value) validation.Value {
	if val, ok := lookup(v, key); ok {
		return val
	}
	return def
}

// ---- Python number arithmetic --------------------------------------------

// pynum is a Python number for the ledger arithmetic: an exact rational plus
// the int/float distinction Python carries through +, min and str().
type pynum struct {
	rat     *big.Rat
	isFloat bool
}

// numInt is a Python int literal.
func numInt(n int64) pynum {
	return pynum{rat: new(big.Rat).SetInt64(n)}
}

// numOf is the numeric value of a Value: bool -> 0/1, int exact, float as the
// exact binary value. Non-numbers are 0 (Python would raise TypeError; the
// ledger only ever holds numbers).
func numOf(v validation.Value) pynum {
	switch v.Kind {
	case validation.Bool:
		if v.B {
			return numInt(1)
		}
		return numInt(0)
	case validation.Int:
		if r, ok := new(big.Rat).SetString(validation.IntText(v)); ok {
			return pynum{rat: r}
		}
	case validation.Flt:
		if r := new(big.Rat).SetFloat64(v.F); r != nil {
			return pynum{rat: r, isFloat: true}
		}
		return pynum{rat: new(big.Rat), isFloat: true}
	}
	return numInt(0)
}

// numOrZero is Python's `x or 0`: a falsy value (including a missing key) is
// the int 0.
func numOrZero(v validation.Value) pynum {
	if !validation.PyTruthy(v) {
		return numInt(0)
	}
	return numOf(v)
}

// add is Python's +: the result is a float when either side is.
func (a pynum) add(b pynum) pynum {
	return pynum{rat: new(big.Rat).Add(a.rat, b.rat), isFloat: a.isFloat || b.isFloat}
}

// addInt is + an int literal.
func (a pynum) addInt(n int64) pynum { return a.add(numInt(n)) }

// min is Python's min: the smaller operand, keeping its own int/float type.
func (a pynum) min(b pynum) pynum {
	if a.rat.Cmp(b.rat) <= 0 {
		return a
	}
	return b
}

// div is Python's true division: always a float.
func (a pynum) div(b validation.Value) float64 {
	x, _ := a.rat.Float64()
	y, _ := numOf(b).rat.Float64()
	return x / y
}

// text is str(number): int digits, or the float repr.
func (a pynum) text() string {
	if !a.isFloat && a.rat.IsInt() {
		return a.rat.Num().String()
	}
	f, _ := a.rat.Float64()
	return validation.PythonFloat(f)
}

// value is the JSON Value for the number (int when integral and not a float).
func (a pynum) value() validation.Value {
	if !a.isFloat && a.rat.IsInt() {
		n := a.rat.Num()
		if n.IsInt64() {
			return validation.VInt(n.Int64())
		}
		return validation.VBigInt(n.String())
	}
	f, _ := a.rat.Float64()
	return validation.VFloat(f)
}
