package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestInitCreatesLayout: 6 dirs, campaign_state.json, events.jsonl with the
// campaign.created event; ListCampaigns returns the id.
func TestInitCreatesLayout(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme Immunefi", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		c.Dir, c.FindingsDir, c.ArtifactsDir, c.MemoryDir, c.ChainsDir, c.ExecsDir,
		c.StatePath, c.EventsPath,
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
		if (p == c.StatePath || p == c.EventsPath) && fi.IsDir() {
			t.Errorf("%s must be a file", p)
		}
		if strings.HasSuffix(p, "Dir") && !fi.IsDir() {
			t.Errorf("%s must be a dir", p)
		}
	}
	got := ListCampaigns(root)
	if len(got) != 1 || got[0] != c.CampaignID {
		t.Errorf("ListCampaigns: %v", got)
	}
	// state file carries the exact initial key set (order checked below)
	st := mustState(t, c)
	wantKeys := []string{"campaign_id", "program", "created_at", "updated_at",
		"phase", "phase_history", "halt_reason", "budget", "snapshots",
		"active_snapshot_id", "artifacts", "stages", "events", "policy_path",
		"floor_policy", "probe_blanks", "eval_adjudications"}
	if len(st.O) != len(wantKeys) {
		t.Fatalf("state key count: %d", len(st.O))
	}
	for i, k := range wantKeys {
		if st.O[i].K != k {
			t.Errorf("state key %d: got %q want %q", i, st.O[i].K, k)
		}
	}
	if got := objStr(st, "phase"); got != "SCOPE" {
		t.Errorf("phase: %q", got)
	}
	budget := objVal(st, "budget")
	wantBudget := []string{"max_discovery_findings", "max_repro_attempts_per_finding",
		"max_fresh_context_retries", "max_passes", "pass", "discovery_findings_so_far"}
	for i, k := range wantBudget {
		if budget.O[i].K != k {
			t.Errorf("budget key %d: got %q want %q", i, budget.O[i].K, k)
		}
	}
}

// TestInitRejectsDuplicate: exact FileExistsError message.
func TestInitRejectsDuplicate(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Init(root, "Acme", InitOpts{CampaignID: c.CampaignID})
	if err == nil {
		t.Fatal("expected duplicate error")
	}
	want := "campaign already exists: " + c.Dir
	if err.Error() != want {
		t.Errorf("duplicate message:\n got %q\nwant %q", err.Error(), want)
	}
}

// TestBadCampaignID: exact ValueError message.
func TestBadCampaignID(t *testing.T) {
	root := t.TempDir()
	_, err := Open(root, "INVALID ID")
	if err == nil {
		t.Fatal("expected malformed id error")
	}
	if got, want := err.Error(), "malformed campaign id: 'INVALID ID'"; got != want {
		t.Errorf("bad id message:\n got %q\nwant %q", got, want)
	}
}

// TestOpenNonexistent: exact FileNotFoundError message.
func TestOpenNonexistent(t *testing.T) {
	root := t.TempDir()
	_, err := Open(root, "C-abc12345")
	if err == nil {
		t.Fatal("expected missing campaign error")
	}
	want := "no such campaign: " + filepath.Join(root, "campaigns", "C-abc12345")
	if err.Error() != want {
		t.Errorf("open message:\n got %q\nwant %q", err.Error(), want)
	}
}

// TestInitBudgetOverride: {**DEFAULT, **override} semantics (order kept,
// values replaced, extras appended).
func TestInitBudgetOverride(t *testing.T) {
	root := t.TempDir()
	ov := validation.VObj(kv("pass", validation.VInt(3)),
		kv("max_passes", validation.VInt(2)))
	c, err := Init(root, "Acme", InitOpts{Budget: &ov})
	if err != nil {
		t.Fatal(err)
	}
	budget := objVal(mustState(t, c), "budget")
	want := []string{"max_discovery_findings", "max_repro_attempts_per_finding",
		"max_fresh_context_retries", "max_passes", "pass",
		"discovery_findings_so_far"}
	for i, k := range want {
		if budget.O[i].K != k {
			t.Errorf("budget key %d: %q want %q (positions kept)", i, budget.O[i].K, k)
		}
	}
	if v := objVal(budget, "max_passes"); v.Kind != validation.Int || v.I != 2 {
		t.Errorf("max_passes override: %+v", v)
	}
	if v := objVal(budget, "pass"); v.Kind != validation.Int || v.I != 3 {
		t.Errorf("pass override: %+v", v)
	}
}

// TestEventChain: genesis anchor (the campaign.created event logged by
// Init), chaining, seq contiguity, state mirror, created-ref framing.
func TestEventChain(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		d := validation.VObj(kv("i", validation.VInt(int64(i))))
		if _, err := c.Log("test.event", nil, &d); err != nil {
			t.Fatal(err)
		}
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("event count: %d", len(events))
	}
	for i, e := range events {
		if v := objVal(e, "seq"); v.Kind != validation.Int || v.I != int64(i) {
			t.Errorf("seq %d: %+v", i, v)
		}
	}
	first := events[0]
	if got := objStr(first, "prev_hash"); got != GenesisHash {
		t.Errorf("genesis prev_hash: %q", got)
	}
	if got := objStr(first, "type"); got != "campaign.created" {
		t.Errorf("first type: %q", got)
	}
	if got := eventHash(first); got != objStr(first, "event_hash") {
		t.Errorf("event_hash mismatch: %q vs %q", got, objStr(first, "event_hash"))
	}
	if v := objVal(first, "ref"); v.Kind != validation.Str || v.S != c.CampaignID {
		t.Errorf("created ref: %+v", v)
	}
	// chain: each prev_hash == prior event_hash
	prev := GenesisHash
	for _, e := range events {
		if got := objStr(e, "prev_hash"); got != prev {
			t.Fatalf("chain broken at seq %d: %q != %q", objVal(e, "seq").I, got, prev)
		}
		prev = objStr(e, "event_hash")
	}
	// state mirrors the full (here <1000) log
	st := mustState(t, c)
	if v := objVal(st, "events"); len(v.A) != 5 {
		t.Errorf("state mirror: %d events", len(v.A))
	}
	// on-disk line for the first event: sorted keys, ref = campaign id
	raw, _ := os.ReadFile(c.EventsPath)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var firstMap map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &firstMap); err != nil {
		t.Fatal(err)
	}
	if firstMap["seq"].(float64) != 0 || firstMap["type"] != "campaign.created" {
		t.Errorf("first event: %v", firstMap)
	}
	if firstMap["ref"] != c.CampaignID {
		t.Errorf("created ref on disk: %v", firstMap["ref"])
	}
}

// TestEventNonASCIIFraming: U+2028 in data is escaped on disk; the line
// stays one physical line and the hash is well-defined.
func TestEventNonASCIIFraming(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	d := validation.VObj(kv("s", validation.VStr("a\u2028b")))
	if _, err := c.Log("test.event", nil, &d); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(c.EventsPath)
	if strings.Contains(string(raw), "\u2028") {
		t.Error("raw U+2028 found on disk")
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("framing broken: %d lines", len(lines))
	}
	if !strings.Contains(lines[1], `\u2028`) {
		t.Errorf("U+2028 must be escaped: %q", lines[1])
	}
}

// TestEventLegacyAnchor: an unchained legacy first line anchors the chain
// at "legacy-seq-{seq}".
func TestEventLegacyAnchor(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// wipe the chained log, plant one legacy line (seq 0, no event_hash)
	legacy := `{"at": "2020-01-01T00:00:00.000000+00:00", "data": {}, "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000", "ref": null, "seq": 0, "type": "legacy.event"}`
	if err := os.WriteFile(c.EventsPath, []byte(legacy+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, err := c.Log("test.event", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(ev, "prev_hash"); got != "legacy-seq-0" {
		t.Errorf("legacy anchor: %q", got)
	}
	if got := objVal(ev, "seq").I; got != 1 {
		t.Errorf("seq after legacy: %d", got)
	}
}

// TestStateMirrorTail: the state mirror equals the full log while the
// log is under 1000 events (the cap itself is covered by
// TestTailEventsCap without the O(n^2) file churn).
func TestStateMirrorTail(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := c.Log("flood", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	st := mustState(t, c)
	if v := objVal(st, "events"); len(v.A) != 11 {
		t.Errorf("mirror: %d events", len(v.A))
	}
	events, _ := c.Events()
	if !arraysEq(objVal(st, "events").A, events) {
		t.Error("mirror must equal the full log under 1000")
	}
}

// TestTailEventsCap: the pure mirror rule at and past the 1000 boundary.
func TestTailEventsCap(t *testing.T) {
	mk := func(n int) []validation.Value {
		out := make([]validation.Value, n)
		for i := range out {
			out[i] = validation.VObj(kv("seq", validation.VInt(int64(i))))
		}
		return out
	}
	got := tailEvents(mk(1002), validation.VObj(kv("seq", validation.VInt(1002))))
	if len(got) != 1000 {
		t.Fatalf("cap: %d", len(got))
	}
	if v := objVal(got[0], "seq"); v.I != 3 {
		t.Errorf("head seq: %d", v.I)
	}
	if v := objVal(got[999], "seq"); v.I != 1002 {
		t.Errorf("tail seq: %d", v.I)
	}
	if got := tailEvents(mk(999), validation.VObj(kv("seq", validation.VInt(999)))); len(got) != 1000 {
		t.Errorf("999+1: %d", len(got))
	}
	if got := tailEvents(nil, validation.VObj(kv("seq", validation.VInt(0)))); len(got) != 1 {
		t.Errorf("empty: %d", len(got))
	}
}

// --- small test helpers -------------------------------------------------

func mustState(t *testing.T, c *Campaign) validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func objVal(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// TestRefusedInitLeavesNoSkeleton pins r14 issue 7: an init that dies
// on schema validation used to deposit an empty campaigns/C-xxxx/ tree
// — invisible to ListCampaigns, immortal to every verb.
func TestRefusedInitLeavesNoSkeleton(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(root, "p", InitOpts{CampaignID: "C-tooshort11"}); err == nil {
		t.Fatal("short program accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "campaigns", "C-tooshort11")); !os.IsNotExist(err) {
		t.Fatalf("refused init left a skeleton: %v", err)
	}
	// The success path is untouched: full tree + state.
	c, err := Init(root, "Lock Program", InitOpts{CampaignID: "C-keepme0000"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.StatePath); err != nil {
		t.Fatalf("good init damaged: %v", err)
	}
}
