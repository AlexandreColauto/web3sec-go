package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestIndexArtifactIsRegisteredAndPoliced pins r11 issue 3 (f): a CLI
// `index` must register its structural_index.json like the orchestrator
// path does — an unregistered derived artifact was a trust boundary the
// audit could not see. Forging a payable withdraw node into the file and
// leaving the snapshot_id intact used to feed prescreen/sinks with a
// green `audit`; now the Artifacts section's hash check burns red.
func TestIndexArtifactIsRegisteredAndPoliced(t *testing.T) {
	c, root := t15Campaign(t, "index-trust")
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "A.sol"),
		[]byte("contract A {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errS := run(t, "--root", root, "index", c.CampaignID,
		"--src", src); code != 0 {
		t.Fatalf("index: %q %q", out, errS)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range objListAt(st, "artifacts") {
		if objStr(a, "kind") == "structural-index" {
			found = true
		}
	}
	if !found {
		t.Fatal("index must register its artifact (r11)")
	}
	// Tamper: forge a payable withdraw node into the registered file.
	artPath := filepath.Join(c.Dir, "artifacts", "structural_index.json")
	var doc map[string]any
	if err := json.Unmarshal(mustReadR11(t, artPath), &doc); err != nil {
		t.Fatal(err)
	}
	entries, _ := doc["entries"].([]any)
	doc["entries"] = append(entries, map[string]any{
		"file": "A.sol", "kind": "function", "name": "withdraw",
		"payable": true, "state_vars_written": []any{},
	})
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artPath, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = validation.VNull()
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code == 0 {
		t.Fatalf("audit must refuse a tampered registered artifact "+
			"(exit 0): %q", out)
	}
	if !strings.Contains(out+errS, "structural_index") &&
		!strings.Contains(out+errS, "artifact") {
		t.Fatalf("the refusal must name the tampered artifact: out %q "+
			"err %q", out, errS)
	}
}

func mustReadR11(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
