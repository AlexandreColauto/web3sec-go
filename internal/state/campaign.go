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
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(cdir, e.Name(), "campaign_state.json")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
