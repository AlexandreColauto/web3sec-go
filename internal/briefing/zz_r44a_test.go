package briefing

// R44A (P1): the criticality/coverage block fed exec blobs into the
// "covered vs uncovered" ranking behind `if recs, err := sandbox.AllExecs(...);
// err == nil` — a swallow that turned a refusal into "no exec evidence". The
// exec store is now the ONE state implementation, so a non-nil error can only
// mean the store could not be listed (absence is folded into an empty list
// with a nil error), and the block refuses through BuildBrief instead of
// asserting components uncovered from evidence it never read.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestR44aCriticalityRefusesUnreadableExecStore(t *testing.T) {
	c := r43aCampaign(t, "C-r44abrief1")
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir, "protocol_model.json"),
		[]byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	r43aChmod(t, c.ExecsDir)

	_, _, err := criticalityBlock(c, nil, validation.VNull(),
		errors.New("no plan"))
	if err == nil {
		t.Fatal("the coverage block swallowed an unreadable exec store")
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ExecsDir) {
		t.Fatalf("refusal must name the exec store: %v", err)
	}

	// And it reaches the caller: BuildBrief reports the refusal.
	if _, berr := BuildBrief(c, false, nil); berr == nil ||
		!strings.Contains(berr.Error(), c.ExecsDir) {
		t.Fatalf("BuildBrief did not surface the refusal: %v", berr)
	}
}

// The honest shape: no execs/ directory is an empty campaign, and the block
// reads it as "no exec evidence" without error.
func TestR44aCriticalityAcceptsAbsentExecStore(t *testing.T) {
	c := r43aCampaign(t, "C-r44abrief2")
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir, "protocol_model.json"),
		[]byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(c.ExecsDir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := criticalityBlock(c, nil, validation.VNull(),
		errors.New("no plan")); err != nil {
		t.Fatalf("an absent exec store is an empty campaign: %v", err)
	}
}
