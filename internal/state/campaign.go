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

// objStr returns a string field's value ("" when absent/non-string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	return ""
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
func Init(root, program string, opts InitOpts) (*Campaign, error) {
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
	for _, d := range []string{c.Dir, c.FindingsDir, c.ArtifactsDir,
		c.MemoryDir, c.ChainsDir, c.ExecsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
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
func Open(root, campaignID string) (*Campaign, error) {
	c, err := newCampaign(root, campaignID)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(c.StatePath); err != nil {
		return nil, fmt.Errorf("no such campaign: %s", c.Dir)
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
func (c *Campaign) save(st validation.Value) error {
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
func ListCampaigns(root string) []string {
	cdir := filepath.Join(root, "campaigns")
	entries, err := os.ReadDir(cdir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		// os.Stat (not e.IsDir): a symlinked campaign dir is a valid
		// campaign; ReadDir's entry type reports the link, not the target.
		fi, err := os.Stat(filepath.Join(cdir, e.Name()))
		if err != nil || !fi.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(cdir, e.Name(), "campaign_state.json")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// --- snapshot pins (Task 11; compat/attach layers land in Task 12) --------

// hasKey reports whether the object carries the key (Python `in`, distinct
// from a present-but-null value).
func hasKey(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// PinSnapshot is pin_snapshot: schema-validate the snapshot, append its row
// ({snapshot_id, pass, pinned, registered_at}, exact key order) unless the
// id is already registered, set it active, save, and log snapshot.pinned on
// first registration. Returns the snapshot id.
func (c *Campaign) PinSnapshot(snap validation.Value) (string, error) {
	if err := validation.Validate(snap, "snapshot", 1); err != nil {
		return "", err
	}
	sid := objStr(snap, "snapshot_id")
	st, err := c.State()
	if err != nil {
		return "", err
	}
	rows := objAt(st, "snapshots")
	existing := false
	for _, r := range rows.A {
		if objStr(r, "snapshot_id") == sid {
			existing = true
			break
		}
	}
	if !existing {
		pass := objAt(objAt(st, "budget"), "pass")
		if hasKey(snap, "pass") {
			pass = objAt(snap, "pass")
		}
		pinned := validation.VBool(true)
		if hasKey(snap, "pinned") {
			pinned = objAt(snap, "pinned")
		}
		rows.A = append(rows.A, validation.VObj(
			kv("snapshot_id", validation.VStr(sid)),
			kv("pass", pass),
			kv("pinned", pinned),
			kv("registered_at", validation.VStr(nowIso())),
		))
		st.O = validation.SetOrAppend(st.O, "snapshots", rows)
	}
	// r9 (critic): save-then-log could strand a LYING projection — the
	// state listed the snapshot (and made it active) while the corrupted
	// ledger refused the snapshot.pinned event, and because the row then
	// exists, no re-pin can ever emit the missing event: the projection
	// audit burned red permanently. Reordering (log first) only moves the
	// lie to the other side of the pair. The pin is atomic against the
	// ledger by UNWIND: keep the exact pre-pin bytes, restore them if the
	// event cannot be written.
	prevState, hadPrev := []byte(nil), false
	if raw, rerr := os.ReadFile(c.StatePath); rerr == nil {
		prevState, hadPrev = raw, true
	}
	st.O = validation.SetOrAppend(st.O, "active_snapshot_id", validation.VStr(sid))
	if err := c.save(st); err != nil {
		return "", err
	}
	// r11: the event decision keys on the LEDGER, not on the state row.
	// The old `!existing` gate meant a re-pin of the same id could never
	// re-emit a missing event — an erased snapshot.pinned left the
	// projection red forever with the ONLY exit being the very hand-edit
	// section 5 exists to catch. Now: no event for this id in the ledger
	// ⇒ emit it (first pin, or a sanctioned heal); event already there ⇒
	// truly no-op. The state row follows the same rule as before.
	pinnedInLog := false
	evts, evErr := c.Events()
	if evErr != nil && !os.IsNotExist(evErr) {
		// The ledger cannot be read: the event decision is unknowable.
		// Fail like a refused event (same unwind law, r9) — never pin a
		// row whose event cannot be checked.
		if unwinding := c.unwindState(prevState, hadPrev); unwinding != nil {
			return "", fmt.Errorf("pinned-event lookup failed (%v) and "+
				"the state could not be unwound (%v): %w", evErr, unwinding,
				evErr)
		}
		return "", fmt.Errorf("snapshot %s was NOT kept — the ledger could "+
			"not be read to decide the pin event, and the state "+
			"projection was rolled back: %v — repair the events tail "+
			"(see `webv2 verify` line report) before re-pinning",
			sid, evErr)
	}
	if evErr == nil {
		for _, e := range evts {
			if objStr(e, "type") == "snapshot.pinned" &&
				objStr(e, "ref") == sid {
				pinnedInLog = true
				break
			}
		}
	}
	if !pinnedInLog {
		// DEFECT-2 follow-up: the pin records the framework build that
		// produced the snapshot, so a later `brief` running a different
		// binary can warn instead of silently trusting probe semantics
		// that changed between builds. Event data is free-form (the audit
		// checks the hash chain, never data keys), so old campaigns
		// without the key simply never warn — the grandfather rule.
		data := validation.VObj(
			kv("ladder", objAt(objAt(snap, "source"), "ladder")),
			kv("framework_build", validation.VStr(version.Commit())),
		)
		if existing {
			// A heal, disclosed as such — an operator reading the log
			// sees WHY the event lands second.
			data.O = validation.SetOrAppend(data.O, "reconciled",
				validation.VBool(true))
		}
		if _, err := c.Log("snapshot.pinned", &sid, &data); err != nil {
			if unwinding := c.unwindState(prevState, hadPrev); unwinding != nil {
				return "", fmt.Errorf("pin event failed (%v) AND the state "+
					"projection could not be unwound (%v): campaign_state "+
					"lists snapshot %s the ledger never recorded — repair "+
					"the events tail and re-pin `snap --reconcile` the "+
					"snapshot before trusting any projection",
					err, unwinding, sid)
			}
			return "", fmt.Errorf("snapshot %s was NOT kept — the state "+
				"projection was rolled back with the ledger refusing the "+
				"pin event: %w", sid, err)
		}
	}
	return sid, nil
}

// unwindState restores the pre-pin campaign_state.json (r9): same bytes
// through the same canonical writer, not a hand-rolled rewrite. The
// hadPrev=false branch (remove the state file) is defensive only —
// PinSnapshot reads the state through c.State() first, which fails closed
// on a missing file, so a pin never runs against no prior state (r10
// audit noted the reachability; the guard stays, the fact is recorded).
func (c *Campaign) unwindState(prev []byte, hadPrev bool) error {
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
	sid := objAt(st, "active_snapshot_id")
	if sid.Kind != validation.Str || sid.S == "" {
		return validation.VNull(), nil
	}
	for _, r := range objAt(st, "snapshots").A {
		if objStr(r, "snapshot_id") == sid.S {
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
	sid := objAt(st, "active_snapshot_id")
	if sid.Kind != validation.Str || sid.S == "" {
		return nil, nil
	}
	out := sid.S
	return &out, nil
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
	st, err := c.State()
	if err != nil {
		return err
	}
	recon := objAt(st, "recon")
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
	recon := objAt(st, "recon")
	if recon.Kind != validation.Obj {
		return validation.VNull(), nil
	}
	return objAt(recon, verb), nil
}
