package learning

import (
	"strings"
	"testing"
)

// TestMemoryApproveErrorsNameThemselves pins r7 issue 5: the bare-id error
// printed "error: M-…" and told the operator nothing.
func TestMemoryApproveErrorsNameThemselves(t *testing.T) {
	c := newCampaign(t, "approve-errors")
	if _, err := ApproveMemory(c, "M-89fe804d", "operator"); err == nil ||
		!strings.Contains(err.Error(), "not a memory id") {
		t.Fatalf("bad shape must be named: %v", err)
	}
	if _, err := ApproveMemory(c, "MEM-000000000000", "operator"); err == nil ||
		!strings.Contains(err.Error(), "not found in") {
		t.Fatalf("missing row must say not-found: %v", err)
	}
	if _, err := RejectMemory(c, "M-nope", "operator", "wrong"); err == nil ||
		!strings.Contains(err.Error(), "not a memory id") {
		t.Fatalf("reject shares the law: %v", err)
	}
}
