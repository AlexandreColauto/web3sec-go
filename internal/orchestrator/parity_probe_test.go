// parity_probe_test.go: the P1 gate parity probe's Go half. It is inert
// unless WEBV2_PARITY_PROBE names a campaign built by the Python twin; then it
// writes bounty_gate_all's JSON to WEBV2_PARITY_OUT so
// .scratch/t13/parity-probe.py can diff the two twins' gate output.
package orchestrator

import (
	"os"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestP1GateParityProbe opens a Python-built campaign and dumps the gate.
func TestP1GateParityProbe(t *testing.T) {
	dir := os.Getenv("WEBV2_PARITY_PROBE")
	if dir == "" {
		t.Skip("WEBV2_PARITY_PROBE not set")
	}
	out := os.Getenv("WEBV2_PARITY_OUT")
	if out == "" {
		t.Fatal("WEBV2_PARITY_OUT must name the JSON output path")
	}
	campaignID := os.Getenv("WEBV2_PARITY_CAMPAIGN")
	if campaignID == "" {
		t.Fatal("WEBV2_PARITY_CAMPAIGN must name the campaign id")
	}
	portWireSeams(t)
	c, err := state.Open(dir, campaignID)
	if err != nil {
		t.Fatalf("open campaign %s: %v", dir, err)
	}
	o := New(c)
	gates, err := o.BountyGateAll()
	if err != nil {
		t.Fatalf("bounty_gate_all: %v", err)
	}
	if err := os.WriteFile(out, []byte(validation.DumpIndented(gates)),
		0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
}
