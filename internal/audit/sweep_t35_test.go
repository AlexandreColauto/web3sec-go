package audit

// T35 testmap re-triage: tests/test_design_upgrades.py — the audit's
// self-describing-manifest checks.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// pinnedWithManifest pins a source snapshot carrying a manifest (source Merkle
// root + self-anchored manifest_hash) and returns the campaign and the
// snapshot.json path.
func pinnedWithManifest(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := initCampaign(t)
	target := filepath.Join(c.Root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"V.sol":            "contract V {}",
		"requirements.txt": "web3==7.0.0\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(target, name), []byte(body),
			0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := validation.VObj(validation.KV{K: "compiler",
		V: validation.VStr("solc 0.8.28")})
	snap, err := snapshot.PinSourceSnapshot(c, target, &cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(snap, "snapshot_id")
	if sid == "" {
		t.Fatalf("no snapshot_id from pin: %v", snap)
	}
	meta := filepath.Join(c.Dir, "snapshots", sid, "snapshot.json")
	if _, err := os.Stat(meta); err != nil {
		t.Fatalf("snapshot metadata not on disk: %v", err)
	}
	return c, meta
}

// editSnapshot rewrites snapshot.json through mut.
func editSnapshot(t *testing.T, meta string,
	mut func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	mut(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meta, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAuditDetectsEditedManifest(t *testing.T) {
	c, meta := pinnedWithManifest(t)
	editSnapshot(t, meta, func(doc map[string]any) {
		man, _ := doc["manifest"].(map[string]any)
		if man == nil {
			t.Fatal("pinned snapshot has no manifest")
		}
		man["source_merkle_root"] = zeros64
	})
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	sections := validation.ObjAt(report, "sections")
	snaps := validation.ObjAt(sections, "snapshots")
	if validation.ObjAt(snaps, "ok").B {
		t.Fatalf("an edited manifest must fail the snapshots section: %v",
			problemsOf(report, "snapshots"))
	}
	found := false
	for _, p := range problemsOf(report, "snapshots") {
		if strings.Contains(p, "manifest") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no manifest problem: %v", problemsOf(report, "snapshots"))
	}
}

func TestLegacySnapshotWithoutManifestStillAuditsClean(t *testing.T) {
	c, meta := pinnedWithManifest(t)
	editSnapshot(t, meta, func(doc map[string]any) {
		delete(doc, "manifest")
	})
	report, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	snaps := validation.ObjAt(validation.ObjAt(report, "sections"), "snapshots")
	if !validation.ObjAt(snaps, "ok").B {
		t.Fatalf("a legacy pin without a manifest must audit clean: %v",
			problemsOf(report, "snapshots"))
	}
}

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"
