// Package datasets mirrors webv2.datasets.__init__: the adapter registry.
//
// WHY (verbatim intent): each public dataset (ScaBench, DeFiHackLabs, FORGE)
// speaks its own record dialect — nested findings, incident explorers, curated
// corpora — but the framework side (webv2.ingest) accepts exactly one common
// shape. One submodule per dataset owns that dialect; this registry re-exports
// them so later dataset tasks never need to edit the registry. Python guards
// each import so a missing sibling never breaks an installed one; Go has no
// guarded dynamic import, so the registry is static and a missing sibling is a
// compile error instead of None (the stronger contract).
package datasets

import (
	"websec/internal/datasets/defihacklabs"
	"websec/internal/datasets/forge"
	"websec/internal/datasets/scabench"
	"websec/internal/validation"
)

// Adapter is one registered dataset adapter. LoadRecords reads the adapter's
// source into common-shape records (the DeFiHackLabs pair takes the explorer
// dir + PoC root; the other two use the first argument as their source file or
// directory); Ingest publishes the adapter's records through ingest.
type Adapter struct {
	Name        string
	LoadRecords func(explorerDir, pocRoot *string) ([]validation.Value, error)
	Ingest      func(maps *validation.Value, tier string) (validation.Value, error)
}

// DefiHackLabs is the DeFiHackLabs + Incident Explorer adapter.
var DefiHackLabs = Adapter{
	Name:        defihacklabs.Dataset,
	LoadRecords: defihacklabs.LoadRecords,
	Ingest: func(maps *validation.Value, tier string) (validation.Value, error) {
		return defihacklabs.Ingest(defihacklabs.IngestOptions{Maps: maps, Tier: tier})
	},
}

// Forge is the FORGE-Curated adapter.
var Forge = Adapter{
	Name: forge.Dataset,
	LoadRecords: func(_, source *string) ([]validation.Value, error) {
		return forge.LoadRecords(source)
	},
	Ingest: func(maps *validation.Value, tier string) (validation.Value, error) {
		return forge.Ingest(forge.IngestOptions{Maps: maps, Tier: tier})
	},
}

// Scabench is the ScaBench adapter.
var Scabench = Adapter{
	Name: scabench.Dataset,
	LoadRecords: func(_, source *string) ([]validation.Value, error) {
		return scabench.LoadRecords(source)
	},
	Ingest: func(maps *validation.Value, tier string) (validation.Value, error) {
		return scabench.Ingest(scabench.IngestOptions{Maps: maps, Tier: tier})
	},
}

// All is the registry in declaration order (__all__).
var All = []*Adapter{&Scabench, &DefiHackLabs, &Forge}
