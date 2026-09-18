package learning

import (
	"os"
	"strings"
	"testing"
	"websec/internal/findings"
	"websec/internal/validation"
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

// TestStaleBugClassChainGoesLoud pins r9-4: a missing successor row mid-
// chain used to fail open (stale=false, silent promotion); now the drift
// surfaces as an unreadable-successor marker.
func TestStaleBugClassChainGoesLoud(t *testing.T) {
	c := newCampaign(t, "chain-loud")
	old := mintFinding(t, c, "logic-error", nil, nil, "Rounding inflation")
	fid := validation.ObjStr(old, "finding_id")
	succ := mintFinding(t, c, "access-control", nil, nil, "Same drain framed right")
	sid := validation.ObjStr(succ, "finding_id")
	data := validation.VObj(
		kv("old", validation.VStr(fid)),
		kv("new", validation.VStr(sid)),
		kv("actor", validation.VStr("test")))
	if _, err := c.Log("finding.superseded", &sid, &data); err != nil {
		t.Fatal(err)
	}
	mem, err := QueueMemory(c, QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED", Pattern: "pattern text ok",
		FindingID: &fid, BugClass: ptrStr("logic-error")})
	if err != nil {
		t.Fatal(err)
	}
	rowCls, fndCls, stale := StaleBugClass(c, mem)
	if !stale || rowCls != "logic-error" || fndCls != "access-control" {
		t.Fatalf("healthy chain: %q %q %v", rowCls, fndCls, stale)
	}
	// Delete the successor row: the chain must go LOUD, not silent.
	if err := os.Remove(findings.FindingPath(c, sid)); err != nil {
		t.Fatal(err)
	}
	_, fndCls, stale = StaleBugClass(c, mem)
	if !stale || !strings.Contains(fndCls, "unreadable") {
		t.Fatalf("broken chain must be reported: %q stale=%v", fndCls,
			stale)
	}
}

func ptrStr(s string) *string { return &s }
