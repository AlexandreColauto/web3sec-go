// campaign_recon.go: recon run stamps — one replace-on-rerun stamp per
// recon verb, read by the L-04 divergence gate.
package state

import (
	"websec/internal/validation"
)

// --- recon run stamps (FIX-8) ---------------------------------------------

// StampRecon records one recon run stamp: state.recon[verb] =
// {campaign_id, src, at}, replacing any prior row for the verb (a re-run
// REPLACES — the stamp is a light "this recon ran over this tree at this
// time" fact, never a per-file ledger, so a double run cannot duplicate it).
// Written by the recon verb itself; read by the L-04 divergence-gate close
// (planner.checkReconStamps). campaign_id (FIX-C) binds the stamp to the
// campaign it ran under — the state file is operator-writable, so a stamp
// copied from another campaign's state is refused by the gate, not by this
// writer: gates stop laziness, not forgery. Campaigns written before the key
// existed simply lack it; the schema keeps the property optional, so absence
// validates and reads as never-ran.
func (c *Campaign) StampRecon(verb, src string) error {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	st, err := c.State()
	if err != nil {
		return err
	}
	recon := validation.ObjAt(st, "recon")
	if recon.Kind != validation.Obj {
		recon = validation.VObj()
	}
	recon.O = validation.SetOrAppend(recon.O, verb, validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("src", validation.VStr(src)),
		kv("at", validation.VStr(nowIso())),
	))
	st.O = validation.SetOrAppend(st.O, "recon", recon)
	return c.save(st)
}

// ReconStamp is the stamp row for verb: Null when the verb never ran over
// this campaign (the key is absent, pre-stamp campaigns included).
func (c *Campaign) ReconStamp(verb string) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	recon := validation.ObjAt(st, "recon")
	if recon.Kind != validation.Obj {
		return validation.VNull(), nil
	}
	return validation.ObjAt(recon, verb), nil
}
