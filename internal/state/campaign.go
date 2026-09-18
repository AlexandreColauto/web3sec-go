package state

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"websec/internal/validation"
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
