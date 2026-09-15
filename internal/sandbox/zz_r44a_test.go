package sandbox

// R44A (P1): state.AllExecs and sandbox.AllExecs were two implementations of
// one law with OPPOSITE refusal semantics — r43a fixed this one while the
// state twin (the reader the audit's exec section uses) still folded every
// ReadDir error into an empty list. There is now ONE implementation: the
// canonical body lives in state (sandbox imports state, never the reverse)
// and this package delegates to it. These tests pin the delegation by
// identity of the refusal — same error, same text — and keep the honest
// shapes green.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
)

func TestR44aAllExecsDelegatesToTheStateImplementation(t *testing.T) {
	c := r43aCampaign(t, "C-r44adeleg")
	r43aChmod(t, c.ExecsDir)

	got, err := AllExecs(c)
	if err == nil {
		t.Fatalf("AllExecs on an unreadable store returned %v with no error", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ExecsDir) {
		t.Fatalf("refusal must name the exec store: %v", err)
	}
	want, werr := state.AllExecs(c)
	if werr == nil {
		t.Fatalf("state.AllExecs read the same store without error: %v", want)
	}
	if err.Error() != werr.Error() {
		t.Fatalf("two readers, two refusals — the delegation is not one "+
			"implementation:\n sandbox: %v\n state:   %v", err, werr)
	}
}

func TestR44aAllExecsAbsentStoreIsStillEmpty(t *testing.T) {
	c := r43aCampaign(t, "C-r44adeleg2")
	if err := os.RemoveAll(c.ExecsDir); err != nil {
		t.Fatal(err)
	}
	got, err := AllExecs(c)
	if err != nil {
		t.Fatalf("an absent exec store is an empty campaign: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}
