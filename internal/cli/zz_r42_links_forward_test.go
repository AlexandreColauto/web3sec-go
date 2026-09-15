package cli

// r42 P3-b — this package's linksThenLog used to be a byte-equivalent second
// copy of invariants.linksThenLog (same r20 F3 body, same r21 F9 lock note).
// It is now a forwarder onto the one home, and it is kept only because the
// harness rungs in cmd_verify_harness.go and the autoprove rung call it by
// name. This pin holds the forwarder to the law's behaviour so a future
// re-inlining of the body (a second implementation) cannot pass unnoticed:
// refused log -> the log's own error and the pre-write bytes exactly back;
// refused first save -> nothing left on disk; honest path -> the bytes land.
// The law itself is pinned in internal/invariants/zz_r42_linksdoor_test.go.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"websec/internal/state"
)

// TestR42CliLinksDoorForwardsToTheOneLaw drives the forwarder through all
// three shapes against a bare campaign.
func TestR42CliLinksDoorForwardsToTheOneLaw(t *testing.T) {
	c, err := state.Init(t.TempDir(), "r42-forward", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// The forwarder must read/write the SAME file the invariants home does
	// (artifacts/invariant_links.json), or the two doors would diverge while
	// looking identical at the call site.
	p := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	refused := errors.New("r42-forward: the ledger refused this event")
	saved := []byte("{\"invariants\": {}}\n")

	// 1. Absent file: write -> refused log -> nothing left behind.
	if err := linksThenLog(c,
		func() error { return os.WriteFile(p, saved, 0o644) },
		func() error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("forwarder err = %v, want the log's own error %v", err, refused)
	}
	if _, serr := os.Stat(p); !os.IsNotExist(serr) {
		t.Fatalf("a refused first save left the links file on disk (%v)", serr)
	}

	// 2. Present file: snapshot -> write -> refused log -> exact restore.
	orig := []byte("{\"invariants\": {\"INV-1\": {\"status\": \"UNVERIFIED\"}}}\n")
	if err := os.WriteFile(p, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := linksThenLog(c,
		func() error { return os.WriteFile(p, saved, 0o644) },
		func() error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("forwarder err = %v, want %v", err, refused)
	}
	if raw, rerr := os.ReadFile(p); rerr != nil || string(raw) != string(orig) {
		t.Fatalf("the forwarder did not restore the registry bytes (%v): %q",
			rerr, raw)
	}

	// 3. The honest path lands.
	if err := linksThenLog(c,
		func() error { return os.WriteFile(p, saved, 0o644) },
		func() error { return nil }); err != nil {
		t.Fatalf("honest forwarder call: %v", err)
	}
	if raw, rerr := os.ReadFile(p); rerr != nil || string(raw) != string(saved) {
		t.Fatalf("honest forwarder call did not land (%v): %q", rerr, raw)
	}
}
