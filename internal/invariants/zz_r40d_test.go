package invariants

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
// r40d — unwind-on-refusal pin for the INVARIANT_LINKS surface. The honest
// refusal an operator can always hit: grow the ledger, then cut events.jsonl
// to a shorter PREFIX so the state mirror is LONGER than the log — the next
// Log refuses with "events.jsonl holds N event(s) but the state projection
// mirrors M ... run webv2 doctor".
//
// Before r40 every SaveLinks->Log pair in this package saved first and logged
// after with no restore: a refused event left a violated/held/
// CHECKED_AGAINST_CODE/CONTRADICTED invariant on disk that the ledger never
// recorded — a status flip the gates (coverage, uncovered-critical, the
// verification axis) read as truth. The pin: the registry file's sha256 is
// byte-identical across the refusal, the event counts do not move, and the
// honest path still lands.
// ---------------------------------------------------------------------------

// r40dSha is the sha256 of one file (or "absent"), the byte-identity pin.
func r40dSha(t *testing.T, path string) string {
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

// r40dEventCount counts the ledger's anchors of one event type.
func r40dEventCount(t *testing.T, path, eventType string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), `"`+eventType+`"`)
}

// r40dCutLedger grows the ledger a few events, then cuts events.jsonl to a
// shorter prefix so the state mirror is LONGER than the log. Returns the
// full bytes (the sanctioned out-of-band repair: restore the cut tail).
func r40dCutLedger(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(pair("note",
			validation.VStr("r40d ledger growth")))
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

// TestR40DRefusedStatusFlipsRestoreRegistry pins the four gate-read flip
// verbs: a refused event must leave the registry byte-identical and add no
// event; the repaired-ledger retry lands the flip with its event.
func TestR40DRefusedStatusFlipsRestoreRegistry(t *testing.T) {
	c := invCamp(t)
	if _, err := SeedFromModel(c, r40dModel()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A registered artifact for verify/link_test (must exist pre-cut: the
	// registration itself logs).
	artPath := filepath.Join(c.Dir, "r40d-report.md")
	if err := os.WriteFile(artPath, []byte("# r40d"), 0o644); err != nil {
		t.Fatal(err)
	}
	artID, err := c.RegisterOrRefresh("report", artPath, "", nil,
		"r40d fixture artifact")
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	linksFile := linksPath(c)
	eventsBaseline := map[string]int{
		"invariant.linked_finding": r40dEventCount(t, c.EventsPath, "invariant.linked_finding"),
		"invariant.linked_test":    r40dEventCount(t, c.EventsPath, "invariant.linked_test"),
		"invariant.verified":       r40dEventCount(t, c.EventsPath, "invariant.verified"),
		"invariant.contradicted":   r40dEventCount(t, c.EventsPath, "invariant.contradicted"),
	}
	raw := r40dCutLedger(t, c)
	before := r40dSha(t, linksFile)

	refused := []struct {
		name string
		call func() error
	}{
		{"invariant.linked_finding", func() error {
			_, err := LinkFinding(c, "INV-1", "F-r40d", true)
			return err
		}},
		{"invariant.linked_test", func() error {
			_, err := LinkTest(c, "INV-1", artID)
			return err
		}},
		{"invariant.verified", func() error {
			_, err := VerifyInvariantStatement(c, "INV-1", artID)
			return err
		}},
		{"invariant.contradicted", func() error {
			_, err := ContradictInvariantStatement(c, "INV-1", "V.sol#L1")
			return err
		}},
	}
	for _, tc := range refused {
		err := tc.call()
		if err == nil || !strings.Contains(err.Error(),
			"state projection mirrors") {
			t.Fatalf("%s: err = %v (want the projection refusal)", tc.name, err)
		}
		if got := r40dSha(t, linksFile); got != before {
			t.Fatalf("%s: registry bytes moved across the refusal "+
				"(the flip without its event):\n before %s\n after  %s",
				tc.name, before, got)
		}
		for _, ev := range []string{"invariant.linked_finding",
			"invariant.linked_test", "invariant.verified",
			"invariant.contradicted"} {
			if got := r40dEventCount(t, c.EventsPath, ev); got != eventsBaseline[ev] {
				t.Fatalf("%s: %s events = %d, want %d (the refusal must "+
					"add none)", tc.name, ev, got, eventsBaseline[ev])
			}
		}
	}

	// Out-of-band repair (the cut tail restored — what `webv2 doctor`
	// reconstructs), then the honest retry: the flips land WITH events
	// and the gates read them from the same file.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LinkFinding(c, "INV-1", "F-r40d", true); err != nil {
		t.Fatalf("retry linked_finding: %v", err)
	}
	if _, err := VerifyInvariantStatement(c, "INV-1", artID); err != nil {
		t.Fatalf("retry verified: %v", err)
	}
	if _, err := ContradictInvariantStatement(c, "INV-1", "V.sol#L1"); err != nil {
		t.Fatalf("retry contradicted: %v", err)
	}
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	entry := objAt(regOf(links), "INV-1")
	if got := objStr(entry, "test_status"); got != "violated" {
		t.Fatalf("test_status = %q, want violated", got)
	}
	if got := objStr(entry, "status"); got != "CONTRADICTED" {
		t.Fatalf("status = %q, want CONTRADICTED", got)
	}
	if got := r40dEventCount(t, c.EventsPath, "invariant.linked_finding"); got != eventsBaseline["invariant.linked_finding"]+1 {
		t.Fatalf("linked_finding events after retry = %d, want %d",
			got, eventsBaseline["invariant.linked_finding"]+1)
	}
}

// r40dModel is a minimal model: one invariant, no state machines (so
// seedLiveness is out of the picture and the seed refusal hits the
// SaveLinks->Log door itself, not the earlier liveness event).
func r40dModel() validation.Value {
	return validation.VObj(
		pair("invariants", validation.VArr(validation.VObj(
			pair("id", validation.VStr("INV-1")),
			pair("statement", validation.VStr("the vault stays solvent")),
		))),
		pair("state_machines", validation.VArr()),
	)
}

// TestR40DRefusedSeedAndMigrateRestoreRegistryFile pins the two remaining
// SaveLinks->Log shapes: a refused invariants.seeded on a fresh registry
// must leave NO file behind, and a refused legacy migration (a destructive,
// one-shot rewrite that a retry can never re-log) must leave the legacy
// bytes exactly as they were.
func TestR40DRefusedSeedAndMigrateRestoreRegistryFile(t *testing.T) {
	c := invCamp(t)
	raw := r40dCutLedger(t, c)

	// Seed on a refused ledger: the fresh registry file must not exist.
	if _, err := SeedFromModel(c, r40dModel()); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("seed err = %v (want the projection refusal)", err)
	}
	if got := r40dSha(t, linksPath(c)); got != "absent" {
		t.Fatalf("refused seed left a registry file with no event: %s", got)
	}

	// Legacy migration on a refused ledger: the pre-migration bytes stand.
	legacy := `{"invariants": {"INV-9": {"status": "held"}}}` + "\n"
	if err := os.WriteFile(linksPath(c), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLinks(c); err == nil ||
		!strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("migrate err = %v (want the projection refusal)", err)
	}
	if got := r40dSha(t, linksPath(c)); got != r40dSha(t, linksPath(c)) ||
		func() bool {
			rawNow, rerr := os.ReadFile(linksPath(c))
			return rerr != nil || string(rawNow) != legacy
		}() {
		t.Fatalf("refused migration moved the legacy registry bytes")
	}

	// Repair, then both paths land honestly.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatalf("repaired migrate: %v", err)
	}
	entry := objAt(regOf(links), "INV-9")
	if got := objStr(entry, "test_status"); got != "held" {
		t.Fatalf("migrated test_status = %q, want held", got)
	}
	if got := r40dEventCount(t, c.EventsPath, "invariant.migrated"); got != 1 {
		t.Fatalf("invariant.migrated events = %d, want 1", got)
	}
	if _, err := SeedFromModel(c, r40dModel()); err != nil {
		t.Fatalf("repaired seed: %v", err)
	}
	if got := r40dEventCount(t, c.EventsPath, "invariants.seeded"); got != 1 {
		t.Fatalf("invariants.seeded events = %d, want 1", got)
	}
}
