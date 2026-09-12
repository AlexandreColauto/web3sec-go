package cli

// Task 17 (G8) CLI tests — `verify --scaffold {halmos|forge-fuzz}
// --invariant INV-id`: generation is a flag, not a verb.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// t17ScaffoldBytes re-renders the expected scaffold straight from the
// registry entry, the same record the command resolves.
func t17ScaffoldBytes(t *testing.T, c *state.Campaign, invID string,
	kind harness.Kind) []byte {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatalf("load links: %v", err)
	}
	var entry validation.Value
	found := false
	for _, kv := range objAt(links, "invariants").O {
		if kv.K == invID {
			entry, found = kv.V, true
		}
	}
	if !found {
		t.Fatalf("no registry entry for %s", invID)
	}
	inv := entry
	inv.O = validation.SetOrAppend(append([]validation.KV(nil),
		entry.O...), "id", validation.VStr(invID))
	body, err := harness.Scaffold(kind, inv)
	if err != nil {
		t.Fatalf("scaffold: %v", err)
	}
	return body
}

// t17EventsOf returns the parsed data payloads of every event of one type.
func t17EventsOf(t *testing.T, c *state.Campaign,
	typ string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	var out []map[string]any
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("parse event: %v", err)
		}
		if ev["type"] == typ {
			out = append(out, ev)
		}
	}
	return out
}

func TestVerifyScaffoldHalmos(t *testing.T) {
	c, root := t15Campaign(t, "scaffold")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	want := t17ScaffoldBytes(t, c, "INV-1", harness.Halmos)

	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "halmos", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "HARNESS-INV-1-halmos: scaffolded "+
		"artifacts/harness/INV-1/H.t.sol\n" {
		t.Fatalf("output %q", out)
	}
	got, err := os.ReadFile(filepath.Join(c.Dir, "artifacts", "harness",
		"INV-1", "H.t.sol"))
	if err != nil {
		t.Fatalf("read scaffold: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("artifact bytes differ from harness.Scaffold output:\n%s",
			string(got))
	}

	evs := t17EventsOf(t, c, "harness_scaffold")
	if len(evs) != 1 {
		t.Fatalf("harness_scaffold events = %d, want 1", len(evs))
	}
	sum := sha256.Sum256(want)
	data := evs[0]["data"].(map[string]any)
	for k, w := range map[string]string{
		"artifact_id": "HARNESS-INV-1-halmos",
		"invariant":   "INV-1",
		"kind":        "halmos",
		"sha256":      hex.EncodeToString(sum[:]),
	} {
		if data[k] != w {
			t.Errorf("event data %q = %v, want %q", k, data[k], w)
		}
	}

	// Idempotent: same bytes -> "unchanged", NO second event.
	code, out, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "halmos", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("second run exit %d: %q", code, errS)
	}
	if out != "HARNESS-INV-1-halmos: unchanged\n" {
		t.Fatalf("second output %q", out)
	}
	if evs := t17EventsOf(t, c, "harness_scaffold"); len(evs) != 1 {
		t.Fatalf("harness_scaffold events after rerun = %d, want 1",
			len(evs))
	}

	// The new flag never fires unasked: the closing integrity check still
	// passes on the scaffolded campaign.
	if code, _, errS = run(t, "--root", root, "verify",
		c.CampaignID); code != 0 {
		t.Fatalf("verify log exit %d: %q", code, errS)
	}
}

func TestVerifyScaffoldForgeFuzz(t *testing.T) {
	c, root := t15Campaign(t, "scaffold")
	t15SeedInvariant(t, c, "INV-2", "shares never exceed deposits")
	want := t17ScaffoldBytes(t, c, "INV-2", harness.ForgeFuzz)

	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold=forge-fuzz", "--invariant=INV-2")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "HARNESS-INV-2-forge-fuzz: scaffolded "+
		"artifacts/harness/INV-2/F.t.sol\n" {
		t.Fatalf("output %q", out)
	}
	got, err := os.ReadFile(filepath.Join(c.Dir, "artifacts", "harness",
		"INV-2", "F.t.sol"))
	if err != nil {
		t.Fatalf("read scaffold: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("artifact bytes differ from harness.Scaffold output")
	}
	evs := t17EventsOf(t, c, "harness_scaffold")
	if len(evs) != 1 {
		t.Fatalf("harness_scaffold events = %d, want 1", len(evs))
	}
}

func TestVerifyScaffoldUnknownInvariant(t *testing.T) {
	c, root := t15Campaign(t, "scaffold")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "halmos", "--invariant", "INV-missing")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if errS != "verify: unknown invariant 'INV-missing'\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestVerifyScaffoldBogusKind(t *testing.T) {
	c, root := t15Campaign(t, "scaffold")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "bogus", "--invariant", "INV-1")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	want := t36VerifyUsage + "webv2 verify: error: argument --scaffold: " +
		"invalid choice: 'bogus' (choose from 'halmos', 'forge-fuzz', " +
		"'minicertora')\n"
	if errS != want {
		t.Fatalf("stderr %q, want %q", errS, want)
	}
}

func TestVerifyScaffoldNeedsBothFlags(t *testing.T) {
	c, root := t15Campaign(t, "scaffold")
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "halmos")
	if code != 2 || errS !=
		"verify --scaffold needs --invariant INVARIANT\n" {
		t.Fatalf("scaffold-only: exit %d err %q", code, errS)
	}
	code, _, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--invariant", "INV-1")
	if code != 2 || errS !=
		"verify --invariant needs --scaffold {halmos|forge-fuzz|minicertora}\n" {
		t.Fatalf("invariant-only: exit %d err %q", code, errS)
	}
	// A missing value is argparse's error, not the handler's.
	code, _, errS = run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold")
	want := t36VerifyUsage + "webv2 verify: error: argument --scaffold: " +
		"expected one argument\n"
	if code != 2 || errS != want {
		t.Fatalf("bare flag: exit %d err %q, want %q", code, errS, want)
	}
}
