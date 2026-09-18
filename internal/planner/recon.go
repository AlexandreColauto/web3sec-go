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
// campaign state (state.recon.sinks). FIX-C binds the stamps to their
// evidence — the prescreen's snapshot_id against the campaign's active pin,
// each stamp's campaign id against the campaign being closed, and the two
// verbs' src against each other (one attestation, one tree) — because a
// stamp nobody binds is a stamp anybody can claim. FIX-E closes the binding
// symmetry the C round left open: the prescreen ARTIFACT now carries its
// campaign id (the verb writes it), so a prescreen copied from another
// campaign's artifacts directory is refused exactly the way a foreign sinks
// stamp is — even when no snapshot pin exists to catch it. The refusal names
// the exact runnable commands; there is no escape hatch, because recon is
// cheap.

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
// runnable command for each missing stamp. FIX-C binds the stamps to their
// evidence: a prescreen whose snapshot_id is not the campaign's active pin
// (the same staleness comparison runPrescreen itself makes) is refused — a
// stale prescreen is rows the current pin never screened; a sinks stamp that
// names a different campaign (the state file is operator-writable — these
// gates stop laziness, not forgery) or that predates the campaign binding is
// refused; and when both verbs stamped their src, the two recon runs must
// have seen the SAME tree — the attestation reconciles divergence rows the
// backward slice and the prescreen read together, so a sinks run over a
// different tree than the prescreen's is not the recon this attestation
// covers. The demand is unconditional: recon is cheap by design, so skipping
// it is never the honest exit.
// reconStampCheck carries one checkReconStamps evaluation's shared context:
// the accumulating missing[]/commands lists, the command literals, and the
// per-half verdicts the same-tree check consumes.
type reconStampCheck struct {
	campaign     *state.Campaign
	prescreenCmd string
	sinksCmd     string
	missing      []string
	commands     []string
	sid          string
	sidOK        bool
	sinksOK      bool
	sinks        validation.Value
}

func checkReconStamps(campaign *state.Campaign) error {
	chk := &reconStampCheck{
		campaign:     campaign,
		prescreenCmd: "webv2 prescreen " + campaign.CampaignID + " --src SRC",
		sinksCmd:     "webv2 sinks " + campaign.CampaignID + " --src SRC",
	}
	if err := chk.checkReconPrescreenHalf(); err != nil {
		return err
	}
	if err := chk.checkReconSinksHalf(); err != nil {
		return err
	}
	if err := chk.checkReconSameTree(); err != nil {
		return err
	}
	if len(chk.missing) == 0 {
		return nil
	}
	return errValue("lens L-04 attests primitive-symmetry over the " +
		"divergence rows, but this campaign has no recorded recon to " +
		"attest over — " + strings.Join(chk.missing, "; ") + ". The gate " +
		"reads the mechanical recon, never the operator's memory, and " +
		"recon is cheap by design: run the owed recon over the " +
		"campaign's source tree, then re-attest:\n  " +
		strings.Join(chk.commands, "\n  "))
}

// checkReconPrescreenHalf is the prescreen half: the artifact must exist,
// carry its snapshot_id, and that id must be the campaign's active pin (when
// one is pinned) — the staleness check runPrescreen itself applies.
func (chk *reconStampCheck) checkReconPrescreenHalf() error {
	sid, sidOK := prescreenSnapshotOnRecord(chk.campaign)
	active, err := chk.campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return err
	}
	if !sidOK {
		chk.missing = append(chk.missing, "no archetype prescreen on record "+
			"(artifacts/"+prescreenFile+" is missing, unreadable or "+
			"carries no snapshot_id)")
		chk.commands = append(chk.commands, chk.prescreenCmd)
	} else if active != nil && sid != *active {
		chk.missing = append(chk.missing, "the archetype prescreen on record is from "+
			"snapshot "+sid+", not the active pin "+*active+" — re-pinning "+
			"invalidated it, and an attestation over rows a stale prescreen "+
			"never saw is prose")
		chk.commands = append(chk.commands, chk.prescreenCmd)
	} else if cid := prescreenCampaignOnRecord(chk.campaign); cid != "" &&
		cid != chk.campaign.CampaignID {
		// FIX-E binding symmetry: the sinks half refuses a foreign-campaign
		// stamp; the prescreen half must do the same. The artifact carries
		// its campaign id since FIX-E (prescreen writes it); one without it
		// is a pre-binding artifact and stays accepted — the snapshot_id
		// binding above is its whole evidence — a copy from another
		// campaign's artifacts directory is not.
		chk.missing = append(chk.missing, "the archetype prescreen on record names "+
			"campaign "+cid+", not this campaign ("+chk.campaign.CampaignID+
			") — the artifact was not run here")
		chk.commands = append(chk.commands, chk.prescreenCmd)
	}
	chk.sid, chk.sidOK = sid, sidOK
	return nil
}

// checkReconSinksHalf is the sinks half: the stamp must exist, name the tree
// and the clock it ran under, and name THIS campaign — a stamp without a
// campaign binding (a pre-FIX-C stamp) or copied from another campaign's
// state is not this campaign's recon.
func (chk *reconStampCheck) checkReconSinksHalf() error {
	sinks, err := chk.campaign.ReconStamp("sinks")
	if err != nil {
		return err
	}
	chk.sinks = sinks
	switch {
	case sinks.Kind != validation.Obj || validation.ObjStr(sinks, "src") == "" ||
		validation.ObjStr(sinks, "at") == "":
		chk.missing = append(chk.missing, "no `webv2 sinks` run on record "+
			"(the campaign state carries no recon.sinks stamp)")
		chk.commands = append(chk.commands, chk.sinksCmd)
	case validation.ObjStr(sinks, "campaign_id") == "":
		chk.missing = append(chk.missing, "the `webv2 sinks` stamp on record does "+
			"not name the campaign it ran under, so it cannot be bound to "+
			"this campaign (a stamp written before the campaign binding "+
			"existed)")
		chk.commands = append(chk.commands, chk.sinksCmd)
	case validation.ObjStr(sinks, "campaign_id") != chk.campaign.CampaignID:
		chk.missing = append(chk.missing, "the `webv2 sinks` stamp on record names "+
			"campaign "+validation.ObjStr(sinks, "campaign_id")+", not this campaign ("+
			chk.campaign.CampaignID+") — the stamp was not run here")
		chk.commands = append(chk.commands, chk.sinksCmd)
	default:
		chk.sinksOK = true
	}
	return nil
}

// checkReconSameTree enforces the same-tree assumption: when a prescreen
// snapshot exists and the prescreen verb stamped its src, the sinks run must
// have seen the same tree — one attestation, one tree.
func (chk *reconStampCheck) checkReconSameTree() error {
	if !chk.sidOK || !chk.sinksOK {
		return nil
	}
	pre, err := chk.campaign.ReconStamp("prescreen")
	if err != nil {
		return err
	}
	if preSrc := validation.ObjStr(pre, "src"); preSrc != "" &&
		preSrc != validation.ObjStr(chk.sinks, "src") {
		chk.missing = append(chk.missing, "the recon runs disagree about the "+
			"tree: `webv2 sinks` ran over "+validation.ObjStr(chk.sinks, "src")+
			", the prescreen over "+preSrc+" — the L-04 attestation "+
			"reconciles divergence rows both recon runs read together")
		chk.commands = append(chk.commands, chk.prescreenCmd, chk.sinksCmd)
	}
	return nil
}

// prescreenCampaignOnRecord reads the prescreen artifact's campaign_id (the
// FIX-E binding the verb itself writes): "" when the artifact carries none —
// a pre-binding artifact, whose staleness binding above is its whole
// evidence — so absence stays accepted and only a FOREIGN id refuses.
// Comment on the limit: the artifact, like the state file, is
// operator-writable; gates stop laziness, not forgery.
func prescreenCampaignOnRecord(campaign *state.Campaign) string {
	p := filepath.Join(campaign.ArtifactsDir, prescreenFile)
	rep, err := validation.ReadJson(p)
	if err != nil {
		return ""
	}
	if cid := validation.ObjAt(rep, "campaign_id"); cid.Kind == validation.Str {
		return cid.S
	}
	return ""
}

// prescreenSnapshotOnRecord reads the prescreen artifact's snapshot_id: ""
// when the artifact is missing, unreadable or carries no snapshot_id —
// absence is exactly the state the gate must refuse on. The id itself is the
// staleness binding (prescreen stamps its snapshot in the report — reused
// here, never duplicated).
func prescreenSnapshotOnRecord(campaign *state.Campaign) (string, bool) {
	p := filepath.Join(campaign.ArtifactsDir, prescreenFile)
	rep, err := validation.ReadJson(p)
	if err != nil {
		return "", false
	}
	sid := validation.ObjAt(rep, "snapshot_id")
	if sid.Kind != validation.Str || sid.S == "" {
		return "", false
	}
	return sid.S, true
}
