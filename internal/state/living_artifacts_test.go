package state

// Ported 1:1 from web3sec-final tests/test_living_artifacts.py (P0
// addendum, Task 0 of the P1 plan). The behavior is implemented in
// artifacts.go since P0; these tests lock it from the living-document
// angle (sanctioned re-registration vs ghost rows).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

const livingDefReason = "re-registered (content may have changed)"

func mustInit(t *testing.T) *Campaign {
	t.Helper()
	c, err := Init(t.TempDir(), "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func livingRow(t *testing.T, c *Campaign, aid string) validation.Value {
	t.Helper()
	rec, err := c.Artifact(aid)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func livingWritePlan(t *testing.T, c *Campaign, text string) string {
	t.Helper()
	p := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	b, err := json.Marshal(map[string]any{"plan": text})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// test_register_or_refresh_reuses_row
func TestLivingRegisterOrRefreshReusesRow(t *testing.T) {
	c := mustInit(t)
	p := livingWritePlan(t, c, "round 1")
	aid1, err := c.RegisterOrRefresh("plan", p, "", nil, livingDefReason)
	if err != nil {
		t.Fatal(err)
	}
	livingWritePlan(t, c, "round 2 — answer marked")
	aid2, err := c.RegisterOrRefresh("plan", p, "", nil, "round 2 answers recorded")
	if err != nil {
		t.Fatal(err)
	}
	if aid1 != aid2 {
		t.Fatalf("ghost row: %s then %s", aid1, aid2)
	}
	st := mustState(t, c)
	var rows []validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "artifact_id") == aid1 {
			rows = append(rows, a)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("rows for %s: %d", aid1, len(rows))
	}
	a := rows[0]
	if got := objAt(a, "refresh_count"); got.Kind != validation.Int || got.I != 1 {
		t.Errorf("refresh_count: %v", got)
	}
	if got := objStr(a, "refresh_reason"); !strings.Contains(got, "round 2") {
		t.Errorf("refresh_reason: %q", got)
	}
	if got := objStr(a, "refreshed_at"); got == "" {
		t.Error("refreshed_at empty")
	}
}

// test_register_or_refresh_updates_hash
func TestLivingRegisterOrRefreshUpdatesHash(t *testing.T) {
	c := mustInit(t)
	p := livingWritePlan(t, c, "v1")
	aid, err := c.RegisterOrRefresh("plan", p, "", nil, livingDefReason)
	if err != nil {
		t.Fatal(err)
	}
	old := objStr(livingRow(t, c, aid), "sha256")
	livingWritePlan(t, c, "v2 mutated")
	if _, err := c.RegisterOrRefresh("plan", p, "", nil, "v2"); err != nil {
		t.Fatal(err)
	}
	newSha := objStr(livingRow(t, c, aid), "sha256")
	if newSha == old {
		t.Fatalf("hash unchanged after refresh: %s", newSha)
	}
}

// test_refresh_requires_reason
func TestLivingRefreshRequiresReason(t *testing.T) {
	c := mustInit(t)
	p := livingWritePlan(t, c, "v1")
	aid, err := c.RegisterOrRefresh("plan", p, "", nil, livingDefReason)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefreshArtifact(aid, "", "op"); err == nil {
		t.Fatal("expected error for empty reason")
	} else if !strings.Contains(err.Error(), "reason") {
		t.Errorf("error does not mention reason: %q", err.Error())
	}
}

// test_log_records_old_new_hashes
func TestLivingLogRecordsOldNewHashes(t *testing.T) {
	c := mustInit(t)
	p := livingWritePlan(t, c, "before")
	aid, err := c.RegisterOrRefresh("plan", p, "", nil, livingDefReason)
	if err != nil {
		t.Fatal(err)
	}
	old := objStr(livingRow(t, c, aid), "sha256")
	livingWritePlan(t, c, "after")
	if _, err := c.RefreshArtifact(aid, "drift update", "learning"); err != nil {
		t.Fatal(err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var refreshed []validation.Value
	for _, e := range evs {
		if objStr(e, "type") == "artifact.refreshed" {
			refreshed = append(refreshed, e)
		}
	}
	if len(refreshed) != 1 {
		t.Fatalf("artifact.refreshed events: %d", len(refreshed))
	}
	d := objAt(refreshed[0], "data")
	if got := objStr(d, "old_sha256"); got != old {
		t.Errorf("old_sha256: %q", got)
	}
	if got := objStr(d, "new_sha256"); got == old {
		t.Errorf("new_sha256 still old: %q", got)
	}
	if got := objStr(d, "actor"); got != "learning" {
		t.Errorf("actor: %q", got)
	}
	if got := objAt(d, "refresh_count"); got.Kind != validation.Int || got.I != 1 {
		t.Errorf("refresh_count: %v", got)
	}
}

// test_different_kind_same_path_registers_new — DEVIATION (D3, 2026-09-10): the
// reference mints a new row when the kind differs; Go MIGRATES the row's kind
// and refreshes it, because a second row at one path is a stale hash the audit
// can never clear (see state.RegisterOrRefresh). The ported name is kept in the
// comment so the parity ledger still maps.
func TestLivingDifferentKindSamePathMigratesRow(t *testing.T) {
	c := mustInit(t)
	p := filepath.Join(c.ArtifactsDir, "impact.json")
	if err := os.WriteFile(p, []byte(`{"x": 1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	aid1, err := c.RegisterOrRefresh("economic-impact", p, "", nil, livingDefReason)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"x": 2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	aid2, err := c.RegisterOrRefresh("report", p, "", nil, livingDefReason)
	if err != nil {
		t.Fatal(err)
	}
	if aid1 != aid2 {
		t.Fatalf("different kind should migrate the row, got a new id: %s", aid2)
	}
	a, err := c.Artifact(aid1)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(a, "kind"); got != "report" {
		t.Errorf("migrated kind: %q", got)
	}
	if got := objStr(a, "sha256"); got != validation.Sha256Hex([]byte(`{"x": 2}`)) {
		t.Errorf("migrated sha256: %q", got)
	}
}
