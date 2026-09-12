package planner

// recon.go — FIX-8: recon is not free. The operator's campaign never ran
// `webv2 sinks` or `webv2 prescreen`; the runbook lists them as recon tools,
// but nothing gated on them, so the G-02 payout-with-no-escrow-credit sat
// one mechanical backward slice away from being surfaced ("a backward slice
// from onDropMessage's _amount would have shown a payout with no escrow
// credit — surfaced mechanically, no reasoning required") and the operator
// took the free exit. The gate: closing the primitive-symmetry lens — the
// attestation that closes discovery over the divergence rows — demands the
// mechanical recon be ON RECORD first. Two stamps, both cheap by design:
// the prescreen artifact (which already carries its snapshot_id — reused,
// not duplicated) and the sinks run stamp the verb itself writes into the
// campaign state (state.recon.sinks). The refusal names the exact runnable
// commands; there is no escape hatch, because recon is cheap.

import (
	"path/filepath"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// prescreenFile is archetypes.PrescreenFile — a deliberate local mirror (the
// planner must not import the archetypes module graph, the same way it does
// not import the probes package).
const prescreenFile = "archetype_prescreen.json"

// checkReconStamps is the FIX-8 gate behind MarkLens: closing the
// primitive-symmetry lens attests over the divergence rows, and an
// attestation over rows the mechanical recon never saw is prose, not
// attestation. It refuses — before any mutation — when the campaign has no
// prescreen snapshot (artifacts/archetype_prescreen.json carrying a
// snapshot_id) or no recorded sinks run (state.recon.sinks), naming the
// runnable command for each missing stamp. The demand is unconditional:
// recon is cheap by design, so skipping it is never the honest exit.
func checkReconStamps(campaign *state.Campaign) error {
	var missing, commands []string
	if !prescreenSnapshotOnRecord(campaign) {
		missing = append(missing, "no archetype prescreen on record "+
			"(artifacts/"+prescreenFile+" is missing, unreadable or "+
			"carries no snapshot_id)")
		commands = append(commands,
			"webv2 prescreen "+campaign.CampaignID+" --src SRC")
	}
	sinks, err := campaign.ReconStamp("sinks")
	if err != nil {
		return err
	}
	if sinks.Kind != validation.Obj || objStr(sinks, "src") == "" ||
		objStr(sinks, "at") == "" {
		missing = append(missing, "no `webv2 sinks` run on record "+
			"(the campaign state carries no recon.sinks stamp)")
		commands = append(commands,
			"webv2 sinks "+campaign.CampaignID+" --src SRC")
	}
	if len(missing) == 0 {
		return nil
	}
	return errValue("lens L-04 attests primitive-symmetry over the " +
		"divergence rows, but this campaign has no recorded recon to " +
		"attest over — " + strings.Join(missing, "; ") + ". The gate " +
		"reads the mechanical recon, never the operator's memory, and " +
		"recon is cheap by design: run the missing recon over the " +
		"campaign's source tree, then re-attest:\n  " +
		strings.Join(commands, "\n  "))
}

// prescreenSnapshotOnRecord reports whether the prescreen artifact exists
// and carries the snapshot_id it was built from (prescreen stamps its
// snapshot in the report — reused here, never duplicated).
func prescreenSnapshotOnRecord(campaign *state.Campaign) bool {
	p := filepath.Join(campaign.ArtifactsDir, prescreenFile)
	// A missing or corrupt prescreen is not a prescreen: absence is exactly
	// the state the gate must refuse on.
	rep, err := validation.ReadJson(p)
	if err != nil {
		return false
	}
	sid := objAt(rep, "snapshot_id")
	return sid.Kind == validation.Str && sid.S != ""
}
