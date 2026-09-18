// model.go: phase 4 (PROTOCOL_INTELLIGENCE) — load the protocol model, seed
// the invariant registry, reconcile it against the protocol's own documented
// invariants, build the economic equations and seed/refresh the coverage
// ledger.
package orchestrator

import (
	"path/filepath"

	"websec/internal/coverage"
	"websec/internal/economics"
	"websec/internal/invariants"
	"websec/internal/protocolgraph"
	"websec/internal/validation"
)

// LoadProtocolModel is load_protocol_model().
func (o *Orchestrator) LoadProtocolModel(model validation.Value) (validation.Value, error) {
	p, err := protocolgraph.SaveModel(o.C, model, "")
	if err != nil {
		return validation.VNull(), err
	}
	loaded, err := protocolgraph.LoadModel(o.C, p)
	if err != nil {
		return validation.VNull(), err
	}
	links, err := invariants.SeedFromModel(o.C, loaded)
	if err != nil {
		return validation.VNull(), err
	}
	seeded := pyLen(validation.ObjAt(loaded, "invariants"))
	// Fail loud on a partial/empty seed: run-2 saved the artifact and logged
	// protocol_model.loaded while the registry silently stayed empty, and the
	// stage auto-completed on the file alone — the gap only surfaced 40
	// minutes later at mint time. A load that seeds nothing must say so, in
	// the record AND on the console.
	if seeded == 0 {
		data := validation.VObj(kvOf("reason", validation.VStr(
			"protocol model declares no invariants — nothing was seeded; the "+
				"guardrail registry is empty")))
		if _, err := o.C.Log("invariants.seed_empty", nil, &data); err != nil {
			return validation.VNull(), err
		}
	}
	reg := validation.ObjAt(links, "invariants")
	// does the model point at the protocol's OWN documented invariants?
	// divergence is surfaced (and logged), never hidden.
	recon, err := invariants.Reconcile(o.C, loaded)
	if err != nil {
		return validation.VNull(), err
	}
	eqs := economics.BuildEquations(loaded)
	// seed/refresh the coverage ledger against the index + model
	idxPath := filepath.Join(o.C.ArtifactsDir, "structural_index.json")
	if fileExists(idxPath) {
		index, err := validation.ReadJson(idxPath)
		if err != nil {
			return validation.VNull(), err
		}
		covPath := filepath.Join(o.C.ArtifactsDir, "coverage.json")
		if !fileExists(covPath) {
			if _, err := coverage.InitFromIndex(o.C, index, loaded); err != nil {
				return validation.VNull(), err
			}
		} else if _, err := coverage.RefreshGaps(o.C, loaded); err != nil {
			return validation.VNull(), err
		}
	}
	note := "model loaded; " + itoa(seeded) + " invariant(s) seeded"
	if err := o.C.SetStage("protocol-model", "needs-model",
		validation.VStr(note), nil); err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kvOf("model", loaded),
		kvOf("equations", valueArr(eqs)),
		kvOf("invariant_reconciliation", recon),
		kvOf("invariants_seeded", validation.VInt(int64(seeded))),
		kvOf("invariants_registered", validation.VInt(int64(pyLen(reg)))),
		kvOf("transforms", valueArr(economics.GenerateTransforms(loaded))),
	), nil
}
