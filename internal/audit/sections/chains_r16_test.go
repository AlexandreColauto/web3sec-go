package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestChainProjectionBurnsBothWays pins r16 P2#5: chains/ had no audit
// direction at all — a materialized chain's doc could vanish (ledger
// still proposes it) or a doc could be planted (claims a materialization
// that never ran).
func TestChainProjectionBurnsBothWays(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Chain Ghost Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Ledger says CHAIN-abc12345 was materialized (event exists, doc
	// planted later — build the doc too for the green baseline):
	ref := "CHAIN-abcdef12"
	data := validation.VObj(
		validation.KV{K: "title", V: validation.VStr("x")})
	if _, err := c.Log("chain.materialized", &ref, &data); err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(c.ChainsDir, "CHAIN-abcdef12.json")
	if err := os.WriteFile(doc, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec, err := Projection(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(sec, "ok").B {
		t.Fatalf("matched chain must be green: %s",
			validation.DumpsOrdered(sec, false))
	}
	// Vanish the doc:
	os.Remove(doc)
	sec, _ = Projection(c)
	body := validation.DumpsOrdered(sec, false)
	if validation.ObjAt(sec, "ok").B || !strings.Contains(body, "CHAIN-abcdef12") {
		t.Fatalf("vanished chain must burn: %s", body)
	}
	// Restore + plant a second doc with no event:
	if err := os.WriteFile(doc, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.ChainsDir,
		"CHAIN-hand0001.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec, _ = Projection(c)
	body = validation.DumpsOrdered(sec, false)
	if validation.ObjAt(sec, "ok").B || !strings.Contains(body, "webv2 chains") ||
		!strings.Contains(body, "CHAIN-hand0001") {
		t.Fatalf("planted chain must burn naming the sanctioned verb: %s",
			body)
	}
}
