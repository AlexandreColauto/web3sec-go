package invariants

// status_drift.go — model.json vs ledger: invariant-status drift (wave N/T3).
//
// A cheap agent wrote CONTRADICTED into the protocol model while the gate reads
// the LEDGER (invariant_links.json), where the model's claim is data and the
// verification axis stays UNVERIFIED until `invariant-verify`/`invariant-
// contradict` moves it with a log-anchored verdict (freshEntry: "the model's
// claimed status is DATA, never a verdict"). The artifact reconciler re-hashed
// files but never compared the two axes, so the disagreement stayed invisible.
//
// Detect-and-name ONLY: nothing here writes the model file (one-writer law —
// `webv2 model` owns it) or the ledger (only the verify/contradict APIs move
// the verification axis). The ledger governs; this names where the model
// disagrees with it.

import (
	"os"

	"websec/internal/state"
	"websec/internal/validation"
)

// DriftRow is one model↔ledger status disagreement: the id (normalized, the
// ledger's canonical spelling), the status the model claims and the status the
// ledger actually holds.
type DriftRow struct {
	InvariantID  string
	ModelStatus  string
	LedgerStatus string
}

// ModelStatusDrift compares every verification status the protocol model
// claims against the ledger registry and returns the rows that disagree, in
// model order.
//
// Silent by construction where there is nothing to compare:
//   - no model (an absent file is a legitimate state — the reconcile command
//     reports exactly what it reported before T3);
//   - a model invariant with no `status` key (the schema makes it optional);
//   - an id with no ledger entry: there is no ledger claim to name as the
//     governing one;
//   - every invariant whose two statuses agree.
func ModelStatusDrift(c *state.Campaign,
	model validation.Value) ([]DriftRow, error) {
	if model.Kind != validation.Obj {
		return nil, nil
	}
	ledger, err := ledgerStatuses(c)
	if err != nil {
		return nil, err
	}
	out := []DriftRow{}
	for _, inv := range validation.ObjAt(model, "invariants").A {
		if inv.Kind != validation.Obj {
			continue
		}
		idV, ok := fieldAt(inv, "id")
		if !ok {
			continue
		}
		claimed := validation.ObjStr(inv, "status")
		if claimed == "" {
			continue
		}
		id := NormalizeInvID(pyStr(idV))
		held, ok := ledger[id]
		if !ok || held == claimed {
			continue
		}
		out = append(out, DriftRow{
			InvariantID:  id,
			ModelStatus:  claimed,
			LedgerStatus: held,
		})
	}
	return out, nil
}

// ledgerStatuses is the ledger's verification axis as the GATE sees it, read
// WITHOUT the migration write LoadLinks performs: the reconciler's --dry run
// promises to change nothing, so the drift report must not be the one thing
// that rewrites the registry. A pre-structured entry (no test_status) reads as
// UNVERIFIED, which is what _migrate_legacy_entries would have made of it —
// and any consumer that ran LoadLinks already wrote that shape to disk. An
// entry with no status at all is no claim, and is left out.
func ledgerStatuses(c *state.Campaign) (map[string]string, error) {
	p := linksPath(c)
	if _, err := os.Stat(p); err != nil {
		return map[string]string{}, nil
	}
	links, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	reg := regOf(links)
	out := map[string]string{}
	for _, e := range reg.O {
		if e.V.Kind != validation.Obj {
			continue
		}
		st := validation.ObjStr(e.V, "status")
		if !hasKey(e.V, "test_status") {
			st = "UNVERIFIED"
		}
		if st != "" {
			out[NormalizeInvID(e.K)] = st
		}
	}
	return out, nil
}
