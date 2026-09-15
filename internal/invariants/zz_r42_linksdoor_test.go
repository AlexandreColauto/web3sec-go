package invariants

// r42 P3-b — the INVARIANT_LINKS unwind-on-refusal law used to exist twice,
// byte-equivalent including its r21 F9 lock note: invariants.linksThenLog and
// cli.linksThenLog (internal/cli/cmd_verify_harness.go). The project's law is
// one implementation of a law, so the cli copy is now a forwarder and this
// package holds the one body. These tests pin that body directly, from the
// side that remains the home: snapshot -> write -> refused log -> restore.
//
// The pins: a refused log returns the LOG's own error (not a wrapped or
// invented one) and leaves the pre-write bytes byte-identical; a refused
// first save leaves NO file behind (nothing to restore); the honest path
// lands the saved bytes; and a door that CANNOT restore says so instead of
// reporting a clean unwind that never happened (the r18 P2 law).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r42Sha is the sha256 of one file (or "absent") — the byte-identity pin.
func r42Sha(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// TestR42LinksThenLogSnapshotsRestoresAndSaysWhenItCannot pins the one door's
// behaviour on both file states plus the honest path and the failed-restore
// disclosure.
func TestR42LinksThenLogSnapshotsRestoresAndSaysWhenItCannot(t *testing.T) {
	c := invCamp(t)
	p := linksPath(c)
	refused := errors.New("r42: the ledger refused this event")
	saved := []byte(`{"invariants": {"INV-1": {"test_status": "violated"}}}` +
		"\n")
	saveWriting := func() error { return os.WriteFile(p, saved, 0o644) }
	refusingLog := func() error { return refused }

	// 1. Present file: snapshot -> write -> refused log -> EXACT restore.
	orig := []byte(`{"invariants": {"INV-1": {"test_status": "held"}}}` + "\n")
	if err := os.WriteFile(p, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	before := r42Sha(t, p)
	err := LinksThenLog(c, saveWriting, refusingLog)
	if !errors.Is(err, refused) {
		t.Fatalf("refused log err = %v, want the log's own error %v", err,
			refused)
	}
	if got := r42Sha(t, p); got != before {
		t.Fatalf("the door did not restore the registry bytes:\n before %s\n"+
			" after  %s", before, got)
	}
	raw, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(raw) != string(orig) {
		t.Fatalf("restored bytes = %q, want %q", raw, orig)
	}

	// 2. Absent file: a refused log must leave nothing behind.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := LinksThenLog(c, saveWriting, refusingLog); !errors.Is(err,
		refused) {
		t.Fatalf("refused first save err = %v, want %v", err, refused)
	}
	if got := r42Sha(t, p); got != "absent" {
		t.Fatalf("a refused first save left a registry file with no event: %s",
			got)
	}

	// 3. The honest path: the saved bytes stand.
	if err := LinksThenLog(c, saveWriting, func() error { return nil }); err != nil {
		t.Fatalf("honest save+log: %v", err)
	}
	if raw, rerr := os.ReadFile(p); rerr != nil || string(raw) != string(saved) {
		t.Fatalf("honest save did not land (%v): %q", rerr, raw)
	}

	// 4. A restore that CANNOT happen must say so. A read-only registry file
	//    makes the snapshot restore fail (os.WriteFile, the door's own
	//    restore) — but only for an unprivileged process: probe that first,
	//    since root ignores the mode and the restore would honestly succeed.
	probe := filepath.Join(t.TempDir(), "r42-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(probe, 0o400); err != nil {
		t.Fatal(err)
	}
	privileged := os.WriteFile(probe, []byte("again"), 0o644) == nil
	if privileged {
		t.Log("running with CAP_DAC_OVERRIDE: the failed-restore arm cannot " +
			"be provoked by file mode (reported, not silently skipped by " +
			"assertion)")
		return
	}
	locked := []byte(`{"invariants": {}}` + "\n")
	if err := os.WriteFile(p, locked, 0o644); err != nil {
		t.Fatal(err)
	}
	failingRestoreSave := func() error {
		if err := os.WriteFile(p, saved, 0o644); err != nil {
			return err
		}
		return os.Chmod(p, 0o400) // the door's restore cannot rewrite it
	}
	err = LinksThenLog(c, failingRestoreSave, refusingLog)
	if err == nil || !strings.Contains(err.Error(), "UNWIND ALSO FAILED") {
		t.Fatalf("failed-restore err = %v, want the UNWIND ALSO FAILED "+
			"disclosure (a door that cannot restore must SAY SO)", err)
	}
	if !errors.Is(err, refused) {
		t.Fatalf("failed-restore err = %v, want it to carry the log's own "+
			"error %v too", err, refused)
	}
	// The disclosure names the state the operator must repair: the file is
	// ahead of the refused event, and that is exactly what is on disk.
	rawAfter, rerr := os.ReadFile(p)
	if rerr != nil || string(rawAfter) != string(saved) {
		t.Fatalf("expected the post-write bytes on disk (the restore failed); "+
			"got %v: %q", rerr, rawAfter)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}
