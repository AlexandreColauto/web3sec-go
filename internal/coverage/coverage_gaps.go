// coverage_gaps.go: refresh_gaps / thin_coverage — the explicit UNKNOWN
// accounting: unswept contracts, thin trajectories, unverified deployments,
// open questions.
package coverage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

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
			kv("thoroughness", validation.ObjAt(row, "thoroughness")),
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
			if validation.PyTruthy(validation.ObjAt(row, "entry_points_total")) {
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
				unverified), "unverified-deployment", validation.ObjAt(dep, "network"), 0.8))
		}
	}
	for _, q := range listField(model, "open_questions") {
		if validation.PyTruthy(validation.ObjAt(q, "resolved")) {
			continue
		}
		question, err := reqKey(q, "question")
		if err != nil {
			return nil, err
		}
		gaps = append(gaps, gapRow("open question: "+question.S, "open-question",
			validation.VStr(joinBlocks(validation.ObjAt(q, "blocks"))), 0.4))
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
		if validation.ObjStr(k, "source_match") == "unverified" {
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
	sid := validation.ObjAt(st, "active_snapshot_id")
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
	return validation.ObjAt(doc, "deployment"), nil
}
