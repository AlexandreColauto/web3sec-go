package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r40e — unwind-on-refusal for the post-pin attachment writers, pinned
// against the honest refusal an operator can always hit: grow the ledger a
// few events, then cut campaigns/<C>/events.jsonl to a shorter PREFIX so the
// state mirror is LONGER than the log — the next append refuses with
// "events.jsonl holds N event(s) but the state projection mirrors M ...
// run webv2 doctor".
//
// snapshot.json is campaign TRUTH (the trust gate, coverage's
// active-deployment read and `snap` all consume it), so a deployment/chain
// pin that lands while its snapshot.*_attached event is REFUSED is a pin the
// ledger never recorded. The door (pinThenLog) restores the pre-write bytes
// exactly.
//
// The PIN path itself needs no door: it writes into a brand-new dir behind
// the r8 half-pin rollback (pin.go:370-397), so a refused snapshot.excluded
// removes what it installed — pinned by
// TestR40EPinExcludedRefusalRollsBackTheHalfPin below.
// ---------------------------------------------------------------------------

// r40eSha is the sha256 of one file (or "absent").
func r40eSha(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// r40eEventCount counts one event type in the ledger.
func r40eEventCount(t *testing.T, c *state.Campaign, eventType string) int {
	t.Helper()
	evts, err := c.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	n := 0
	for _, e := range evts {
		if r40eStr(e, "type") == eventType {
			n++
		}
	}
	return n
}

// r40eStr is one string field of an object value.
func r40eStr(v validation.Value, key string) string {
	got := sget(v, key)
	if got.Kind != validation.Str {
		return ""
	}
	return got.S
}

// r40eCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair).
func r40eCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(validation.KV{K: "note",
			V: validation.VStr("r40e ledger growth")})
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

// r40ePinnedCamp pins one source tree and returns the campaign plus the
// snapshot's snapshot.json path.
func r40ePinnedCamp(t *testing.T, root, target, cid string) (*state.Campaign, validation.Value, string) {
	t.Helper()
	c := pinCampaign(t, root, cid)
	snap := mustPin(t, c, target, nil, nil)
	sid := strField(t, snap, "snapshot_id")
	return c, snap, filepath.Join(c.Dir, "snapshots", sid, "snapshot.json")
}

// r40eDeployment is the deployment pin payload (one contract).
func r40eDeployment() validation.Value {
	return validation.VObj(
		validation.KV{K: "network", V: validation.VStr("mainnet")},
		validation.KV{K: "contracts", V: validation.VArr(validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Vault")},
			validation.KV{K: "address", V: validation.VStr("0x1111111111111111111111111111111111111111")},
		))},
	)
}

// TestR40ERefusedDeploymentPinRestoresSnapshotBytes pins attach_deployment_pin:
// the deployment block and its snapshot.deployment_attached event land
// together or not at all.
func TestR40ERefusedDeploymentPinRestoresSnapshotBytes(t *testing.T) {
	root, target := pinTarget(t)
	c, snap, path := r40ePinnedCamp(t, root, target, "C-r40edep000001")
	sid := strField(t, snap, "snapshot_id")
	before := r40eSha(t, path)
	raw := r40eCutLedger(t, c)
	_, err := AttachDeploymentPin(c, sid, r40eDeployment())
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door attach_deployment_pin err = %v (want the "+
			"projection refusal)", err)
	}
	if got := r40eSha(t, path); got != before {
		t.Fatalf("the refused deployment pin rewrote snapshot.json:\n"+
			" before %s\n after  %s", before, got)
	}
	if got := r40eEventCount(t, c, "snapshot.deployment_attached"); got != 0 {
		t.Fatalf("snapshot.deployment_attached events = %d, want 0", got)
	}
	// The pre-write document must still read as "no deployment pinned".
	onDisk, rerr := validation.ReadJson(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !(sget(onDisk, "deployment").Kind == validation.Null) {
		t.Fatalf("the refused pin left a deployment block: %s",
			validation.CanonCompact(sget(onDisk, "deployment")))
	}
	// Repair, then the honest retry: one pin, one event.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := AttachDeploymentPin(c, sid, r40eDeployment())
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if sget(got, "deployment").Kind != validation.Obj {
		t.Fatalf("retry did not record the deployment: %s",
			validation.CanonCompact(got))
	}
	if n := r40eEventCount(t, c, "snapshot.deployment_attached"); n != 1 {
		t.Fatalf("snapshot.deployment_attached events after the retry = %d, "+
			"want 1", n)
	}
	if r40eSha(t, path) == before {
		t.Fatal("the retry did not rewrite snapshot.json")
	}
}

// TestR40ERefusedChainPinRestoresSnapshotBytes is the same pin for
// attach_chain_pin.
func TestR40ERefusedChainPinRestoresSnapshotBytes(t *testing.T) {
	root, target := pinTarget(t)
	c, snap, path := r40ePinnedCamp(t, root, target, "C-r40echain00001")
	sid := strField(t, snap, "snapshot_id")
	before := r40eSha(t, path)
	raw := r40eCutLedger(t, c)
	chain := validation.VObj(
		validation.KV{K: "network", V: validation.VStr("mainnet")},
		validation.KV{K: "chain_id", V: validation.VInt(1)},
		validation.KV{K: "fork_block", V: validation.VInt(21000000)},
	)
	_, err := AttachChainPin(c, sid, chain)
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door attach_chain_pin err = %v (want the projection "+
			"refusal)", err)
	}
	if got := r40eSha(t, path); got != before {
		t.Fatalf("the refused chain pin rewrote snapshot.json:\n"+
			" before %s\n after  %s", before, got)
	}
	if got := r40eEventCount(t, c, "snapshot.chain_attached"); got != 0 {
		t.Fatalf("snapshot.chain_attached events = %d, want 0", got)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AttachChainPin(c, sid, chain); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if n := r40eEventCount(t, c, "snapshot.chain_attached"); n != 1 {
		t.Fatalf("snapshot.chain_attached events after the retry = %d, want 1",
			n)
	}
}

// TestR40EPinExcludedRefusalRollsBackTheHalfPin documents why the PIN path
// needs no door of its own: the refused snapshot.excluded append fires inside
// the window the r8 half-pin rollback guards (pin.go:370-397), so the
// half-installed dir is removed — the store never reads a corpse, and no
// exclude event is recorded.
func TestR40EPinExcludedRefusalRollsBackTheHalfPin(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	// A data/ dir trips the bulk-default prune, so the pin logs
	// snapshot.excluded BEFORE it writes snapshot.json.
	writeFiles(t, target, map[string]string{
		"app.py":        "print('hi')\n",
		"src/vault.py":  "x = 1\n",
		"data/f000.dat": "x",
		"data/f001.dat": "x",
		"data/f002.dat": "x",
	})
	c := pinCampaign(t, root, "C-r40epin0000001")
	raw := r40eCutLedger(t, c)
	_, err := PinSourceSnapshot(c, target, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door pin err = %v (want the projection refusal)", err)
	}
	if !strings.Contains(err.Error(), "was NOT kept") {
		t.Fatalf("the refusal did not disclose the rollback: %v", err)
	}
	entries, derr := os.ReadDir(filepath.Join(c.Dir, "snapshots"))
	if derr != nil && !os.IsNotExist(derr) {
		t.Fatal(derr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "staging-") ||
			strings.HasPrefix(e.Name(), "src-content-") {
			t.Fatalf("the refused pin stranded a half-installed dir: %s",
				e.Name())
		}
	}
	if got := r40eEventCount(t, c, "snapshot.excluded"); got != 0 {
		t.Fatalf("snapshot.excluded events = %d, want 0", got)
	}
	// Repair, then the honest retry: the pin lands, exclude event included.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := PinSourceSnapshot(c, target, nil, nil)
	if err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if !strListContains(t, objField(t, snap, "source"), "excluded", "data") {
		t.Fatalf("the retry did not record the prune: %s",
			validation.CanonCompact(snap))
	}
	if n := r40eEventCount(t, c, "snapshot.excluded"); n != 1 {
		t.Fatalf("snapshot.excluded events after the retry = %d, want 1", n)
	}
}

// TestR40EHealthyAttachStillWorks is the happy-path guard.
func TestR40EHealthyAttachStillWorks(t *testing.T) {
	root, target := pinTarget(t)
	c, snap, path := r40ePinnedCamp(t, root, target, "C-r40ehappy00001")
	sid := strField(t, snap, "snapshot_id")
	if _, err := AttachDeploymentPin(c, sid, r40eDeployment()); err != nil {
		t.Fatalf("honest attach_deployment_pin refused: %v", err)
	}
	if n := r40eEventCount(t, c, "snapshot.deployment_attached"); n != 1 {
		t.Fatalf("snapshot.deployment_attached events = %d, want 1", n)
	}
	onDisk, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	if sget(onDisk, "deployment").Kind != validation.Obj {
		t.Fatalf("deployment not on disk: %s", validation.CanonCompact(onDisk))
	}
	if got := sget(onDisk, "manifest"); got.Kind != validation.Obj {
		t.Fatalf("manifest was not refreshed: %s", validation.CanonCompact(onDisk))
	}
}
