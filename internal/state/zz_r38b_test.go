package state

// zz_r38b_test.go — r38 P2-2: the SHARED unwind helper, pinned at its own
// level. The round's other r38 test file (zz_r38_test.go) covers the
// heal/classifier line; this one pins the JSONL-commit dance the cost and
// waiver writers now share (jsonlcommit.go), so "one implementation" is
// testable and the unwind is not asserted only through two callers.
//
// The law: a refused write restores the PRE-WRITE BYTES. "Refused" spans the
// append (a torn tail, a non-ASCII row on the ASCII logs, a failing fsync
// after bytes landed) and the log (torn ledger, mirror lag/hole, held lock).

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func p22Sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// p22Probe is a campaign plus a probe JSONL path that starts ABSENT.
func p22Probe(t *testing.T, id string) (*Campaign, string) {
	t.Helper()
	c, err := Init(t.TempDir(), "r38 P2-2 JSONL commit program",
		InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c, filepath.Join(c.Dir, "probe.jsonl")
}

// TestP22AppendJsonlThenLogUnwindsOnRefusedLog pins the reported shape: the
// row is APPENDED first and the event is refused, so without the restore the
// file holds a row with no event and the retry duplicates it.
func TestP22AppendJsonlThenLogUnwindsOnRefusedLog(t *testing.T) {
	c, path := p22Probe(t, "C-p22jsonl0001")
	refused := errors.New("ledger refused: mirror is longer than the log")

	// (a) the file did not exist: a refused write must leave it ABSENT, not
	// an empty file, not a row.
	if err := AppendJsonlThenLog(c, path, `{"row": "first"}`, func() error {
		return refused
	}); !errors.Is(err, refused) {
		t.Fatalf("refused log: err = %v, want the refusal back", err)
	}
	if raw, err := os.ReadFile(path); err == nil {
		t.Fatalf("absent file was created by a refused write: %d bytes %q",
			len(raw), raw)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat probe after refusal: %v", err)
	}

	// (b) the file existed: the restore must be the EXACT pre-write bytes.
	pre := []byte(`{"row": "kept"}` + "\n")
	if err := os.WriteFile(path, pre, 0o644); err != nil {
		t.Fatal(err)
	}
	logCalls := 0
	if err := AppendJsonlThenLog(c, path, `{"row": "second"}`, func() error {
		logCalls++
		return refused
	}); !errors.Is(err, refused) {
		t.Fatalf("refused log: err = %v, want the refusal back", err)
	}
	if logCalls != 1 {
		t.Fatalf("log called %d time(s), want 1", logCalls)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after refusal: %v", err)
	}
	if string(got) != string(pre) {
		t.Fatalf("refused write did not unwind: pre sha256 %s (%q) vs post "+
			"sha256 %s (%q)", p22Sha(pre), pre, p22Sha(got), got)
	}
	t.Logf("refused log unwound to the exact pre-write bytes: sha256 %s",
		p22Sha(got))

	// (c) the honest success: row lands once, log called once.
	if err := AppendJsonlThenLog(c, path, `{"row": "third"}`, func() error {
		logCalls++
		return nil
	}); err != nil {
		t.Fatalf("success path: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(pre) + `{"row": "third"}` + "\n"; string(got) != want {
		t.Fatalf("success path wrote %q, want %q", got, want)
	}
	if logCalls != 2 {
		t.Fatalf("log called %d time(s) over the three writes, want 2", logCalls)
	}
}

// TestP22AppendJsonlThenLogUnwindsOnRefusedAppend pins the sibling refusal:
// an append that put BYTES on disk and then failed (O_APPEND + a failing
// fsync, a short write) is the same half-land as a refused event, so it takes
// the same restore. The fake appender is the only way to reach that window.
func TestP22AppendJsonlThenLogUnwindsOnRefusedAppend(t *testing.T) {
	c, path := p22Probe(t, "C-p22jsonl0002")
	appendErr := errors.New("append refused after bytes landed")
	partial := func(p, line string) error {
		if err := os.WriteFile(p, []byte("PARTIAL"), 0o644); err != nil {
			return err
		}
		return appendErr
	}
	// File absent before: the partial bytes must be REMOVED, not kept.
	if err := appendJsonlThenLog(c, path, "x", partial, func() error {
		t.Fatal("log must not be called when the append is refused")
		return nil
	}); !errors.Is(err, appendErr) {
		t.Fatalf("refused append: err = %v, want the append error back", err)
	}
	if raw, err := os.ReadFile(path); err == nil {
		t.Fatalf("partial append left %d bytes behind: %q", len(raw), raw)
	}
	// File present before: the partial bytes must be replaced by the snapshot.
	pre := []byte("{\"row\": \"kept\"}\n")
	if err := os.WriteFile(path, pre, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := appendJsonlThenLog(c, path, "x", partial, func() error {
		t.Fatal("log must not be called when the append is refused")
		return nil
	}); !errors.Is(err, appendErr) {
		t.Fatalf("refused append: err = %v, want the append error back", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pre) {
		t.Fatalf("partial append not unwound: got %q, want %q", got, pre)
	}
	// An appender that fails BEFORE touching an absent file is a clean
	// refusal: the restore must not report UNWIND ALSO FAILED for a file
	// that was never there (the tolerated ErrNotExist branch).
	untouched := func(p, line string) error { return appendErr }
	if err := appendJsonlThenLog(c, path, "x", untouched, func() error {
		t.Fatal("log must not be called when the append is refused")
		return nil
	}); !errors.Is(err, appendErr) || strings.Contains(err.Error(), "UNWIND") {
		t.Fatalf("clean append refusal misreported: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != string(pre) {
		t.Fatalf("clean appender refusal touched the file: %q (%v)", raw, err)
	}
}

// TestP22AsciiVariantRidesTheSameWindow pins that the ASCII-only policy is
// enforced INSIDE the snapshot window (one dance, two doors): a non-ASCII row
// on the ASCII log must leave the file byte-identical and never reach the log.
func TestP22AsciiVariantRidesTheSameWindow(t *testing.T) {
	c, path := p22Probe(t, "C-p22jsonl0003")
	pre := []byte(`{"row": "kept"}` + "\n")
	if err := os.WriteFile(path, pre, 0o644); err != nil {
		t.Fatal(err)
	}
	err := AppendJsonlAsciiThenLog(c, path, `{"row": "café"}`,
		func() error {
			t.Fatal("the log must not be called for a rejected ASCII row")
			return nil
		})
	if err == nil {
		t.Fatal("AppendJsonlAsciiThenLog accepted a non-ASCII row")
	}
	if !strings.Contains(err.Error(), "non-ASCII") {
		t.Fatalf("rejection text = %v, want the ASCII-only reason", err)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != string(pre) {
		t.Fatalf("rejected ASCII row changed the file: %q", got)
	}
	// The ASCII door still writes ASCII rows.
	if err := AppendJsonlAsciiThenLog(c, path, `{"row": "plain"}`,
		func() error { return nil }); err != nil {
		t.Fatalf("ascii success path: %v", err)
	}
	got, rerr = os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if want := string(pre) + `{"row": "plain"}` + "\n"; string(got) != want {
		t.Fatalf("ascii success wrote %q, want %q", got, want)
	}
}
