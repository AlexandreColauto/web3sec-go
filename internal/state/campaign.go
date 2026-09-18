package state

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"websec/internal/validation"
	"websec/internal/version"
)

// Campaign is filesystem-backed campaign state under <root>/campaigns/<id>/.
// Every durable side effect is recorded as one event in events.jsonl; the
// state file is the working projection, the log is the audit trail.
type Campaign struct {
	Root         string
	CampaignID   string
	Dir          string
	StatePath    string
	FindingsDir  string
	ArtifactsDir string
	EventsPath   string
	MemoryDir    string
	ChainsDir    string
	ExecsDir     string

	// mu serializes log() and save(): a single-writer CLI, but the event
	// append (read-lines + append + state mirror) must be atomic under
	// -race.
	mu sync.Mutex
	// plock is the cross-process campaign lock handle (r13, processlock.go).
	plock processLock
}

var campaignIDRe = regexp.MustCompile(`^C-[0-9a-z]{8,16}$`)

// newCampaign is the Python ctor: validate the id, set the 8 paths.
func newCampaign(root, campaignID string) (*Campaign, error) {
	if !campaignIDRe.MatchString(campaignID) {
		return nil, fmt.Errorf("malformed campaign id: %s",
			validation.PyReprStr(campaignID))
	}
	root = filepath.Clean(root)
	c := &Campaign{
		Root:         root,
		CampaignID:   campaignID,
		Dir:          filepath.Join(root, "campaigns", campaignID),
		StatePath:    filepath.Join(root, "campaigns", campaignID, "campaign_state.json"),
		FindingsDir:  filepath.Join(root, "campaigns", campaignID, "findings"),
		ArtifactsDir: filepath.Join(root, "campaigns", campaignID, "artifacts"),
		EventsPath:   filepath.Join(root, "campaigns", campaignID, "events.jsonl"),
		MemoryDir:    filepath.Join(root, "campaigns", campaignID, "memory"),
		ChainsDir:    filepath.Join(root, "campaigns", campaignID, "chains"),
		ExecsDir:     filepath.Join(root, "campaigns", campaignID, "execs"),
	}
	return c, nil
}

// InitOpts mirrors Campaign.init's optional parameters. policy_path and
// floor_policy_path land in a later task (floors are P2).
type InitOpts struct {
	CampaignID string
	Budget     *validation.Value
}

// kv is the vet-clean keyed KV constructor (unkeyed cross-package
// literals are rejected by go vet).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// defaultBudget is DEFAULT_BUDGET in file order.
func defaultBudget() validation.Value {
	return validation.VObj(
		kv("max_discovery_findings", validation.VInt(400)),
		kv("max_repro_attempts_per_finding", validation.VInt(6)),
		kv("max_fresh_context_retries", validation.VInt(3)),
		kv("max_passes", validation.VInt(8)),
		kv("pass", validation.VInt(1)),
		kv("discovery_findings_so_far", validation.VInt(0)),
	)
}

// mergeBudget is {**DEFAULT_BUDGET, **budget}: existing keys replaced in
// place (position kept), new keys appended in override order.
func mergeBudget(budget *validation.Value) validation.Value {
	merged := defaultBudget()
	if budget == nil {
		return merged
	}
	out := make([]validation.KV, len(merged.O))
	copy(out, merged.O)
	for _, ov := range budget.O {
		replaced := false
		for i := range out {
			if out[i].K == ov.K {
				out[i].V = ov.V
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, ov)
		}
	}
	return validation.VObj(out...)
}

// Init is Campaign.init: create the layout, write the initial state
// (schema-validated), log campaign.created. An existing campaign is an
// error, never an overwrite.
func Init(root, program string, opts InitOpts) (retC *Campaign, retErr error) {
	id := opts.CampaignID
	if id == "" {
		id = newId("C", 10)
	}
	c, err := newCampaign(root, id)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(c.StatePath); err == nil {
		return nil, fmt.Errorf("campaign already exists: %s", c.Dir)
	}
	dirsMade := false
	// r14 (P2#7): a refused init used to leave an empty campaign skeleton
	// — every later `ls campaigns/` showed a ghost that ListCampaigns
	// skips and no verb can address. If Init refuses, it removes what
	// it created; only after some directory exists does the cleanup
	// apply (we never delete what this call did not make).
	defer func() {
		if !dirsMade || retErr == nil {
			return
		}
		// r15: EVERY failed Init un-creates what it made — the state
		// file's existence is not a reason to keep a half-campaign.
		// The original guard only swept stateless skeletons and left
		// the worse ghost: state written, campaign.created refused
		// (torn events.jsonl from an earlier era) — the refused init
		// still registered, `status` still worked, every write verb
		// died, and `already exists` blocked repair. If the state
		// file predates this call we would not be here: the
		// already-exists check returns before any mkdir.
		os.RemoveAll(c.Dir)
	}()
	for _, d := range []string{c.Dir, c.FindingsDir, c.ArtifactsDir,
		c.MemoryDir, c.ChainsDir, c.ExecsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		dirsMade = true
	}
	// Two separate now_iso() calls, as in Python (they may differ).
	createdAt := nowIso()
	updatedAt := nowIso()
	state := validation.VObj(
		kv("campaign_id", validation.VStr(id)),
		kv("program", validation.VStr(program)),
		kv("created_at", validation.VStr(createdAt)),
		kv("updated_at", validation.VStr(updatedAt)),
		kv("phase", validation.VStr("SCOPE")),
		kv("phase_history", validation.VArr()),
		kv("halt_reason", validation.VNull()),
		kv("budget", mergeBudget(opts.Budget)),
		kv("snapshots", validation.VArr()),
		kv("active_snapshot_id", validation.VNull()),
		kv("artifacts", validation.VArr()),
		kv("stages", validation.VObj()),
		kv("events", validation.VArr()),
		kv("policy_path", validation.VNull()),
		kv("floor_policy", validation.VArr()),
		kv("probe_blanks", validation.VArr()),
		// Last key: NON-GOLD ADJUDICATIONS (see evalscore.adjudicate). Empty
		// at init — a fresh campaign has judged nothing yet.
		kv("eval_adjudications", validation.VArr()),
	)
	if err := validation.WriteJson(c.StatePath, state, "campaign_state"); err != nil {
		return nil, err
	}
	data := validation.VObj(kv("program", validation.VStr(program)))
	if _, err := c.Log("campaign.created", &id, &data); err != nil {
		return nil, err
	}
	return c, nil
}

// Open is Campaign.open: the state file must exist.
//
// r45a: the old body folded EVERY stat error into "no such campaign", so an
// unsearchable campaign directory or campaigns/ (EACCES) told the operator
// that the campaign they are looking at does not exist — and the sentence is
// load-bearing: internal/cli keys its "you are not in the workspace" hint on
// the exact phrase, so a permission failure also produced a wrong workspace
// diagnosis. Only os.IsNotExist is absence (no campaign_state.json: a
// campaign was never made here, or a dangling symlink — a fact). Any other
// error (EACCES, ENOTDIR, EIO) is a READ failure this call could not perform
// and refuses, naming the campaign directory and the errno; it must never
// wear the absence sentence.
func Open(root, campaignID string) (*Campaign, error) {
	c, err := newCampaign(root, campaignID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(c.StatePath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no such campaign: %s", c.Dir)
		}
		return nil, fmt.Errorf("the campaign %s cannot be read: %v", c.Dir, err)
	}
	return c, nil
}

// State is campaign.state(): read + schema-validate the projection.
func (c *Campaign) State() (validation.Value, error) {
	st, err := validation.ReadJson(c.StatePath)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(st, "campaign_state", 1); err != nil {
		return validation.VNull(), err
	}
	return st, nil
}

// save is _save: bump updated_at in place (key position kept) and
// re-write with validation.
func (c *Campaign) save(st validation.Value) error { return c.SaveState(st) }

// SaveState is campaign._save — THE canonical state writer, exported
// because r14 caught four twin packages (floors, probes, evalscore,
// orchestrator's scope) re-implementing _save locally, and every private
// re-implementation had silently opted out of the cross-process lock:
// two racing `floors set` lost one another's update with both exiting 0.
// The twin body is unchanged (updated_at replaced in place, key position
// kept, campaign_state schema); the lock is the only addition. NEVER
// write StatePath from outside this function — the law in
// processlock.go: any read-modify-write of campaign_state holds the
// campaign lock for its whole duration (depth-counted re-entry; the
// per-process caveat from r13 still stands: cross-process is closed,
// goroutine-safety is not claimed).
func (c *Campaign) SaveState(st validation.Value) error {
	if err := c.plock.lock(c.lockPath(), c.CampaignID); err != nil {
		return err
	}
	defer c.plock.unlock()
	for i, kv := range st.O {
		if kv.K == "updated_at" {
			st.O[i].V = validation.VStr(nowIso())
			break
		}
	}
	return validation.WriteJson(c.StatePath, st, "campaign_state")
}

// ListCampaigns is list_campaigns: sorted ids of campaigns with a state
// file under root/campaigns.
//
// r44a: the result grew an error because the old signature could only say
// "no campaigns", and it said it for EVERY ReadDir error. Absence is a fact —
// a root with no campaigns/ directory yet has no campaigns, and an empty list
// is the honest answer — but a campaigns/ directory that cannot be LISTED
// supports no claim about which campaigns exist, and neither does one whose
// entries cannot be examined. Folding EACCES/ENOTDIR/EIO into "no campaigns"
// is how artifact-prune came to render its exit-2 "unknown artifact" refusal
// for an artifact that may well exist: the very campaign holding it was
// silently dropped from the loop. So:
//
//   - campaigns/ missing: empty list, nil error;
//   - campaigns/ unlistable: refusal naming the directory and the errno;
//   - an entry that cannot be stat'ed: refusal (its campaign-ness is
//     undecidable — only os.IsNotExist, a dangling symlink or a racing
//     deletion, is a fact and skips the row);
//   - an entry with no campaign_state.json: not a campaign, skipped (that is
//     the layout filter, and it is os.IsNotExist's job to say so).
func ListCampaigns(root string) ([]string, error) {
	cdir := filepath.Join(root, "campaigns")
	entries, err := os.ReadDir(cdir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no campaigns yet: an honest empty answer
		}
		return nil, fmt.Errorf("the campaign store %s cannot be listed: %v",
			cdir, err)
	}
	var out []string
	for _, e := range entries {
		// os.Stat (not e.IsDir): a symlinked campaign dir is a valid
		// campaign; ReadDir's entry type reports the link, not the target.
		ep := filepath.Join(cdir, e.Name())
		fi, err := os.Stat(ep)
		if err != nil {
			if os.IsNotExist(err) {
				continue // dangling link / raced deletion: no campaign here
			}
			return nil, fmt.Errorf("the campaign entry %s cannot be examined: %v",
				ep, err)
		}
		if !fi.IsDir() {
			continue
		}
		statePath := filepath.Join(ep, "campaign_state.json")
		if _, err := os.Stat(statePath); err != nil {
			if os.IsNotExist(err) {
				continue // a directory without a state file is not a campaign
			}
			return nil, fmt.Errorf("the campaign %s cannot be read: %v",
				e.Name(), err)
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

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
