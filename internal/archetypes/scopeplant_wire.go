// scopeplant_wire.go: installs the Task 9 plant-check surface.
//
// reproduction cannot import archetypes (structidx→reproduction is a real
// edge — structidx/wire.go — so the reverse would cycle), and structidx
// cannot import archetypes either (archetypes→structidx). This package sits
// below both edges' target, so the installer lives here: WireScopePlant
// hands reproduction the real structidx indexer, the real archetype pack
// and the real EvaluatePrecondition. Called from the CLI's ensureSeams and
// cmd/webv2's init, beside structidx.Wire().
package archetypes

import (
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// WireScopePlant installs the Task 9 (G11 scope) plant-check surface on
// reproduction. Idempotent; the setter simply replaces the seam target.
//
// The index builder is IndexSnapshot, not EnsureFreshIndex: prescreen's
// freshness wrapper persists the campaign's structural_index.json, but the
// plant check runs over an arbitrary NEW snapshot tree and must not stomp
// the campaign's active index — advisory reads stay write-free.
func WireScopePlant() {
	reproduction.SetScopePlantAPI(reproduction.ScopePlantAPI{
		BuildIndex: func(c *state.Campaign,
			root string) (validation.Value, error) {
			return structidx.IndexSnapshot(c, root, structidx.DefaultBackend)
		},
		ArchetypeIDs:  AvailableArchetypes,
		LoadArchetype: LoadArchetypeByName,
		EvalCheck:     EvaluatePrecondition,
	})
}
