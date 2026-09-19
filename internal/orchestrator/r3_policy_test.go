package orchestrator

// r3_policy_test.go: R3-2a (Morph r3 defect 2). The bounty policy decides
// what is IN SCOPE, yet at HEAD `scope --policy` registered nothing: no
// artifact row, no sha256, no ledger event — deleting five exclusions from
// the campaign's bounty_policy.json survived `audit` and `brief --deep`.
// Scope now registers the policy through the standard artifact seam
// (kind "policy" is already in the campaign_state enum), so the registry's
// re-hash law covers tampering and the ledger records every load.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func r3ScopeFixture(t *testing.T) (*Orchestrator, *state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "r3-program", state.InitOpts{CampaignID: "C-r3policy01"})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return New(c), c, root
}

func r3ArtifactRows(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(st, "artifacts").A
}

func r3LastEventTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		v, perr := validation.ParseOrdered([]byte(line))
		if perr != nil {
			t.Fatalf("parse event: %v", perr)
		}
		out = append(out, validation.ObjStr(v, "type"))
	}
	return out
}

func TestScopeRegistersBountyPolicy(t *testing.T) {
	o, c, root := r3ScopeFixture(t)
	policyFile := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyFile, []byte(portPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Scope(policyFile); err != nil {
		t.Fatalf("scope: %v", err)
	}
	rows := r3ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("artifact rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if validation.ObjStr(row, "kind") != "policy" {
		t.Errorf("kind = %q, want policy", validation.ObjStr(row, "kind"))
	}
	if !strings.HasPrefix(validation.ObjStr(row, "artifact_id"), "POL-") {
		t.Errorf("artifact_id = %q, want POL- prefix",
			validation.ObjStr(row, "artifact_id"))
	}
	saved := filepath.Join(c.Dir, "bounty_policy.json")
	sha, err := validation.Sha256File(saved)
	if err != nil {
		t.Fatalf("policy copy: %v", err)
	}
	if validation.ObjStr(row, "sha256") != sha {
		t.Errorf("row sha256 = %q, want %q (hash of the campaign copy)",
			validation.ObjStr(row, "sha256"), sha)
	}
	events := r3LastEventTypes(t, c)
	if events[len(events)-1] != "artifact.registered" {
		t.Fatalf("last event = %q, want artifact.registered",
			events[len(events)-1])
	}

	// A re-load with MUTATED bytes refreshes the SAME row (one row per
	// resolved path, D3) and re-hashes it — it never mints a ghost and
	// never leaves the stale hash behind.
	off := strings.Replace(portPolicy, `"rounding dust"`,
		`"rounding dust, second pass"`, 1)
	if off == portPolicy {
		t.Fatal("policy fixture mutation did not apply")
	}
	if err := os.WriteFile(policyFile, []byte(off), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Scope(policyFile); err != nil {
		t.Fatalf("second scope: %v", err)
	}
	rows = r3ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("artifact rows after reload = %d, want 1 (refresh, not ghost)",
			len(rows))
	}
	sha2, err := validation.Sha256File(saved)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(rows[0], "sha256") != sha2 {
		t.Errorf("sha256 after reload = %q, want %q",
			validation.ObjStr(rows[0], "sha256"), sha2)
	}

	// Scope WITHOUT a policy registers nothing (the no-policy note path
	// stays byte-identical, and so does the event stream).
	o2, c2, _ := r3ScopeFixture(t)
	if _, err := o2.Scope(""); err != nil {
		t.Fatalf("empty scope: %v", err)
	}
	if rows := r3ArtifactRows(t, c2); len(rows) != 0 {
		t.Fatalf("no-policy scope registered %d rows, want 0", len(rows))
	}
	for _, ty := range r3LastEventTypes(t, c2) {
		if ty == "artifact.registered" {
			t.Fatal("no-policy scope logged artifact.registered")
		}
	}
}
