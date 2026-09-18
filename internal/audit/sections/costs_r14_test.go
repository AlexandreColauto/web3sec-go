package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestCostProjectionIsPoliced pins r14 issue 4: budget reads ONLY
// costs.jsonl while the ledger carries cost.recorded events — deleting
// the file (spend "vanishes", audit green) or writing a ghost row
// (spend inflates, audit green) both lied to the operator.
func TestCostProjectionIsPoliced(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Cost Truth Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Honest cost through the sanctioned writer.
	ref := "COST-aaaaaaaaaa"
	data := validation.VObj(
		validation.KV{K: "kind", V: validation.VStr("model")},
		validation.KV{K: "amount_usd", V: validation.VFloat(1.25)},
		validation.KV{K: "actor", V: validation.VStr("op")})
	if _, err := c.Log("cost.recorded", &ref, &data); err != nil {
		t.Fatal(err)
	}
	row := `{"cost_id": "COST-aaaaaaaaaa", "at": "2026-01-01T00:00:00+00:00", ` +
		`"kind": "model", "amount_usd": 1.25, "actor": "op"}`
	if err := os.WriteFile(filepath.Join(c.Dir, "costs.jsonl"),
		[]byte(row+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sec, err := Projection(c)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(sec, "ok").B {
		t.Fatalf("honest cost must be green: %s",
			validation.DumpsOrdered(sec, false))
	}
	// Delete the projection: the ledger still says spend happened.
	os.Remove(filepath.Join(c.Dir, "costs.jsonl"))
	sec, err = Projection(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(sec, false)
	if validation.ObjAt(sec, "ok").B || !strings.Contains(body, "COST-aaaaaaaaaa") {
		t.Fatalf("deleted costs.jsonl must burn red naming the cost: %s",
			body)
	}
	// Ghost row, no matching event: red too (un-gated).
	if err := os.WriteFile(filepath.Join(c.Dir, "costs.jsonl"),
		[]byte(`{"cost_id": "COST-ghostghost", "at": "2026-01-01T00:00:00+00:00", "kind": "model", "amount_usd": 999.0, "actor": "ghost"}`+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	sec, err = Projection(c)
	if err != nil {
		t.Fatal(err)
	}
	body = validation.DumpsOrdered(sec, false)
	if validation.ObjAt(sec, "ok").B || !strings.Contains(body, "COST-ghostghost") ||
		!strings.Contains(body, "webv2 cost") {
		t.Fatalf("ghost row must burn red naming the sanctioned verb: %s",
			body)
	}
}
