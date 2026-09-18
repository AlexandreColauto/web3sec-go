// campaign_snapshot.go: snapshot pins — PinSnapshot and the active-snapshot
// accessors, with the ledger-driven event decision and the UNWIND law that
// keeps the state projection honest when the pin event is refused.
package state

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/validation"
	"websec/internal/version"
)

// --- snapshot pins (Task 11; compat/attach layers land in Task 12) --------

// hasKey reports whether the object carries the key (Python `in`, distinct
// from a present-but-null value).

// PinSnapshot is pin_snapshot: schema-validate the snapshot, append its row
// ({snapshot_id, pass, pinned, registered_at}, exact key order) unless the
// id is already registered, set it active, save, and log snapshot.pinned on
// first registration. Returns the snapshot id.
func (c *Campaign) PinSnapshot(snap validation.Value) (string, error) {
	// r15: load->edit->write of campaign_state is one unit;
	// the campaign lock spans the WHOLE window (the entry that
	// used to lock only SaveState still lost updates racing a
	// sibling writer — the processlock law, method-level).
	if err := c.LockProcess(); err != nil {
		return "", err
	}
	defer c.UnlockProcess()
	if err := validation.Validate(snap, "snapshot", 1); err != nil {
		return "", err
	}
	p := &pinSnapCtx{c: c, snap: snap,
		sid: validation.ObjStr(snap, "snapshot_id")}
	st, err := c.State()
	if err != nil {
		return "", err
	}
	p.st = st
	if err := p.registerRow(); err != nil {
		return "", err
	}
	p.capturePrev()
	if err := p.saveActive(); err != nil {
		return "", err
	}
	logged, err := p.eventLogged()
	if err != nil {
		return "", err
	}
	if !logged {
		if err := p.emitEvent(); err != nil {
			return "", err
		}
	}
	return p.sid, nil
}

// pinSnapCtx carries the shared PinSnapshot context across its section
// helpers (row registration, pre-pin capture, active-id save, ledger
// decision, event emission).
type pinSnapCtx struct {
	c         *Campaign
	snap      validation.Value
	sid       string
	st        validation.Value
	existing  bool
	prevState []byte
	hadPrev   bool
}

// pinSnapRegisterRow finds any registered row for the id and, when absent,
// appends the pin row ({snapshot_id, pass, pinned, registered_at}, exact
// key order) into the working projection.
func (p *pinSnapCtx) registerRow() error {
	rows := validation.ObjAt(p.st, "snapshots")
	existing := false
	for _, r := range rows.A {
		if validation.ObjStr(r, "snapshot_id") == p.sid {
			existing = true
			break
		}
	}
	p.existing = existing
	if !existing {
		pass := validation.ObjAt(validation.ObjAt(p.st, "budget"), "pass")
		if validation.HasKey(p.snap, "pass") {
			pass = validation.ObjAt(p.snap, "pass")
		}
		pinned := validation.VBool(true)
		if validation.HasKey(p.snap, "pinned") {
			pinned = validation.ObjAt(p.snap, "pinned")
		}
		rows.A = append(rows.A, validation.VObj(
			kv("snapshot_id", validation.VStr(p.sid)),
			kv("pass", pass),
			kv("pinned", pinned),
			kv("registered_at", validation.VStr(nowIso())),
		))
		p.st.O = validation.SetOrAppend(p.st.O, "snapshots", rows)
	}
	return nil
}

// pinSnapCapturePrev keeps the exact pre-pin bytes for the UNWIND below.
//
// r9 (critic): save-then-log could strand a LYING projection — the
// state listed the snapshot (and made it active) while the corrupted
// ledger refused the snapshot.pinned event, and because the row then
// exists, no re-pin can ever emit the missing event: the projection
// audit burned red permanently. Reordering (log first) only moves the
// lie to the other side of the pair. The pin is atomic against the
// ledger by UNWIND: keep the exact pre-pin bytes, restore them if the
// event cannot be written.
func (p *pinSnapCtx) capturePrev() {
	prevState, hadPrev := []byte(nil), false
	if raw, rerr := os.ReadFile(p.c.StatePath); rerr == nil {
		prevState, hadPrev = raw, true
	}
	p.prevState, p.hadPrev = prevState, hadPrev
}

// pinSnapSaveActive sets the snapshot active and saves the projection.
func (p *pinSnapCtx) saveActive() error {
	p.st.O = validation.SetOrAppend(p.st.O, "active_snapshot_id", validation.VStr(p.sid))
	return p.c.save(p.st)
}

// pinSnapEventLogged consults the LEDGER for an existing snapshot.pinned
// event for this id.
//
// r11: the event decision keys on the LEDGER, not on the state row.
// The old `!existing` gate meant a re-pin of the same id could never
// re-emit a missing event — an erased snapshot.pinned left the
// projection red forever with the ONLY exit being the very hand-edit
// section 5 exists to catch. Now: no event for this id in the ledger
// ⇒ emit it (first pin, or a sanctioned heal); event already there ⇒
// truly no-op. The state row follows the same rule as before.
func (p *pinSnapCtx) eventLogged() (bool, error) {
	pinnedInLog := false
	evts, evErr := p.c.Events()
	if evErr != nil && !os.IsNotExist(evErr) {
		// The ledger cannot be read: the event decision is unknowable.
		// Fail like a refused event (same unwind law, r9) — never pin a
		// row whose event cannot be checked.
		if unwinding := p.c.unwindState(p.prevState, p.hadPrev); unwinding != nil {
			return false, fmt.Errorf("pinned-event lookup failed (%v) and "+
				"the state could not be unwound (%v): %w", evErr, unwinding,
				evErr)
		}
		return false, fmt.Errorf("snapshot %s was NOT kept — the ledger could "+
			"not be read to decide the pin event, and the state "+
			"projection was rolled back: %v — repair the events tail "+
			"(see `webv2 verify` line report) before re-pinning",
			p.sid, evErr)
	}
	if evErr == nil {
		for _, e := range evts {
			if validation.ObjStr(e, "type") == "snapshot.pinned" &&
				validation.ObjStr(e, "ref") == p.sid {
				pinnedInLog = true
				break
			}
		}
	}
	return pinnedInLog, nil
}

// pinSnapEmitEvent logs snapshot.pinned when the ledger decision said the
// event is missing.
func (p *pinSnapCtx) emitEvent() error {
	// DEFECT-2 follow-up: the pin records the framework build that
	// produced the snapshot, so a later `brief` running a different
	// binary can warn instead of silently trusting probe semantics
	// that changed between builds. Event data is free-form (the audit
	// checks the hash chain, never data keys), so old campaigns
	// without the key simply never warn — the grandfather rule.
	data := validation.VObj(
		kv("ladder", validation.ObjAt(validation.ObjAt(p.snap, "source"), "ladder")),
		kv("framework_build", validation.VStr(version.Commit())),
	)
	if p.existing {
		// A heal, disclosed as such — an operator reading the log
		// sees WHY the event lands second.
		data.O = validation.SetOrAppend(data.O, "reconciled",
			validation.VBool(true))
	}
	if _, err := p.c.Log("snapshot.pinned", &p.sid, &data); err != nil {
		if unwinding := p.c.unwindState(p.prevState, p.hadPrev); unwinding != nil {
			return fmt.Errorf("pin event failed (%v) AND the state "+
				"projection could not be unwound (%v): campaign_state "+
				"lists snapshot %s the ledger never recorded — repair "+
				"the events tail and re-pin `snap --reconcile` the "+
				"snapshot before trusting any projection",
				err, unwinding, p.sid)
		}
		return fmt.Errorf("snapshot %s was NOT kept — the state "+
			"projection was rolled back with the ledger refusing the "+
			"pin event: %w", p.sid, err)
	}
	return nil
}

// unwindState restores the pre-pin campaign_state.json (r9): same bytes
// through the same canonical writer, not a hand-rolled rewrite. The
// hadPrev=false branch (remove the state file) is defensive only —
// PinSnapshot reads the state through c.State() first, which fails closed
// on a missing file, so a pin never runs against no prior state (r10
// audit noted the reachability; the guard stays, the fact is recorded).
func (c *Campaign) unwindState(prev []byte, hadPrev bool) error {
	// r14: a rollback IS a state write — a racing process must not land
	// its update between our decision to unwind and the rename.
	if err := c.plock.lock(c.lockPath(), c.CampaignID); err != nil {
		return err
	}
	defer c.plock.unlock()
	if !hadPrev {
		return os.Remove(c.StatePath)
	}
	st, err := validation.ParseOrdered(prev)
	if err != nil {
		return err
	}
	return validation.WriteJson(c.StatePath, st, "campaign_state")
}

// ActiveSnapshot is active_snapshot: the active snapshots row, or Null when
// nothing is pinned (or the id has no row).
func (c *Campaign) ActiveSnapshot() (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	sid := validation.ObjAt(st, "active_snapshot_id")
	if sid.Kind != validation.Str || sid.S == "" {
		return validation.VNull(), nil
	}
	for _, r := range validation.ObjAt(st, "snapshots").A {
		if validation.ObjStr(r, "snapshot_id") == sid.S {
			return r, nil
		}
	}
	return validation.VNull(), nil
}

// ActiveSnapshotIDOrNone is active_snapshot_id_or_none: the active id, or
// nil when nothing is pinned.
func (c *Campaign) ActiveSnapshotIDOrNone() (*string, error) {
	st, err := c.State()
	if err != nil {
		return nil, err
	}
	sid := validation.ObjAt(st, "active_snapshot_id")
	if sid.Kind != validation.Str || sid.S == "" {
		return nil, nil
	}
	out := sid.S
	return &out, nil
}

// ActiveSnapshotContentHash is the content_hash of the ACTIVE pin as
// recorded in the immutable store: snapshots/<id>/snapshot.json carries
// source.content_hash (the state row is only an index into it — r13
// corrected that reading). ok=false when there is no active pin, the meta
// file is missing/unreadable, or no hash was recorded; callers treat that
// as "cannot claim". This is the proof side of the index stamping law —
// a tree may print a pin's id only after hashing equal to this.
func (c *Campaign) ActiveSnapshotContentHash() (string, bool) {
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		return "", false
	}
	meta, err := validation.ReadJson(
		filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json"))
	if err != nil {
		return "", false
	}
	h := validation.ObjAt(validation.ObjAt(meta, "source"), "content_hash")
	if h.Kind == validation.Str && h.S != "" {
		return h.S, true
	}
	return "", false
}
