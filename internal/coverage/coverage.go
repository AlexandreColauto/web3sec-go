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
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

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
	cov.O = validation.SetOrAppend(cov.O, "updated_at", validation.VStr(state.NowIso()))
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
