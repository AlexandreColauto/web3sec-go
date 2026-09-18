package sharedmem

import (
	"testing"
	"websec/internal/validation"

	"websec/internal/learning"
)

// TestPublishCollapsesIdenticalPatterns is r8 issue 6: two campaigns of
// the SAME program that approve the SAME lesson must produce ONE shared
// row — recall used to read the pattern twice forever, and nothing
// downstream collapsed it. The collapse is disclosed on the report
// (memory_pattern_deduped), never silent, and the ledger record's key set
// stays byte-frozen.
func TestPublishCollapsesIdenticalPatterns(t *testing.T) {
	root := newRoot(t)
	a := makeCampaign(t, root, "Shared Program")
	if _, err := learning.QueueMemory(a, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "rounding inflation at conversion drains the pool"}); err != nil {
		t.Fatal(err)
	}
	rowsA, _ := learning.AllMemory(a)
	if _, err := learning.ApproveMemory(a,
		validation.ObjStr(rowsA[0], "memory_id"), "operator"); err != nil {
		t.Fatal(err)
	}
	first, err := PublishCampaign(a, "operator", false)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(first, "memory_added").I != 1 {
		t.Fatalf("A adds one: %v", validation.ObjAt(first, "memory_added").I)
	}
	b := makeCampaign(t, root, "Shared Program")
	if _, err := learning.QueueMemory(b, learning.QueueOpts{
		Kind: "confirmed", Status: "CONFIRMED",
		Pattern: "ROUNDING  inflation at conversion drains the pool"}); err != nil {
		t.Fatal(err)
	}
	rowsB, _ := learning.AllMemory(b)
	if _, err := learning.ApproveMemory(b,
		validation.ObjStr(rowsB[0], "memory_id"), "operator"); err != nil {
		t.Fatal(err)
	}
	second, err := PublishCampaign(b, "operator", false)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(second, "memory_added").I != 0 ||
		validation.ObjAt(second, "memory_pattern_deduped").I != 1 {
		t.Fatalf("B must collapse (0 added, 1 deduped), got added=%d dedup=%d",
			validation.ObjAt(second, "memory_added").I,
			validation.ObjAt(second, "memory_pattern_deduped").I)
	}
	shared, err := LoadSharedMemory(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(shared) != 1 {
		t.Fatalf("the lesson must ride the shared tier exactly once, got %d",
			len(shared))
	}
	// B's LOCAL row survives: provenance lives in the campaign, the SET
	// law governs only the shared surface.
	rowsB2, _ := learning.AllMemory(b)
	if len(rowsB2) != 1 {
		t.Fatalf("campaign-local row must stay: %d", len(rowsB2))
	}
}
