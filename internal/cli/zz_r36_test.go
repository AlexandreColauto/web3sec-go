package cli

// zz_r36_test.go — R36 UNWIND-ON-REFUSAL for the two jsonl writers behind
// `hint` and `memory --reflect` (learning.PlannerHint /
// learning.ReflectionEntry).
//
// The law: a write that is REFUSED (torn ledger, held campaign lock, any
// c.Log failure) must leave no side effect behind. Pre-r36 both verbs appended
// their jsonl row BEFORE c.Log took the campaign lock, so a refused log
// stranded the row: no event existed for it, neither jsonl is audited, and the
// retry after the ledger healed appended a SECOND identical row for the same
// single event. These tests pin both repros for both verbs — the jsonl is
// byte-identical to its pre-write state (or still absent), events.jsonl is
// untouched, the verb exits 1 with the refusal text — and pin the healed retry
// (exactly one row, exactly one event) plus the success path.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"websec/internal/state"
)

// r36Path is the campaign-relative path of one store file.
func r36Path(root, cid, name string) string {
	return filepath.Join(root, "campaigns", cid, name)
}

// r36Snap reads a file that may legitimately be absent (had=false).
func r36Snap(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false
		}
		t.Fatalf("read %s: %v", path, err)
	}
	return raw, true
}

// r36Sha is the file's content hash ("(absent)" when it does not exist): the
// before/after evidence every unwind assertion prints.
func r36Sha(raw []byte, had bool) string {
	if !had {
		return "(absent)"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// r36Lines counts non-empty jsonl records (0 when absent).
func r36Lines(raw []byte, had bool) int {
	if !had {
		return 0
	}
	n := 0
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

// r36AssertStore pins the unwind assertion for one store file: byte-identical
// to the pre-write snapshot, or still absent when it did not exist.
func r36AssertStore(t *testing.T, label, path string, pre []byte, had bool) {
	t.Helper()
	got, gotHad := r36Snap(t, path)
	wantSha, gotSha := r36Sha(pre, had), r36Sha(got, gotHad)
	if had != gotHad || (had && wantSha != gotSha) {
		t.Errorf("%s: jsonl NOT unwound — pre-write sha256 %s (%d bytes, "+
			"present=%v) vs post-refusal sha256 %s (%d bytes, present=%v): "+
			"the refused write left its row behind",
			label, wantSha, len(pre), had, gotSha, len(got), gotHad)
		return
	}
	t.Logf("%s: jsonl unwound — sha256 %s on both sides (present=%v)",
		label, wantSha, had)
}

// r36HoldLock takes the campaign's OS lock from a SECOND open file
// description: an external holder, the r13 shape flock defends against
// (flock conflicts are per open-file-description, so this conflicts with the
// in-process webv2 handle too). The returned release is idempotent.
func r36HoldLock(t *testing.T, root, cid string) func() {
	t.Helper()
	path := r36Path(root, cid, "campaign.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open campaign.lock: %v", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("flock campaign.lock: %v", err)
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}
}

// r36TearLedger reproduces repro A verbatim: the events.jsonl tail is cut to a
// torn record with no trailing newline. It returns the pre-tear bytes, which
// are also the sanctioned heal (restore the snapshot).
func r36TearLedger(t *testing.T, root, cid string) []byte {
	t.Helper()
	path := r36Path(root, cid, "events.jsonl")
	orig, had := r36Snap(t, path)
	if !had {
		t.Fatalf("events.jsonl absent — the campaign has no ledger to tear")
	}
	torn := append(append([]byte{}, orig...), []byte(`{"seq": 9, "type": "torn`)...)
	if err := os.WriteFile(path, torn, 0o644); err != nil {
		t.Fatalf("tear ledger: %v", err)
	}
	return orig
}

// r36Refusal is the shared "the verb REFUSED, loudly, with exit 1" pin.
func r36Refusal(t *testing.T, label, want string, code int, out, errS string) {
	t.Helper()
	t.Logf("%s refused: %s", label, r36Report(code, out, errS))
	if code != 1 {
		t.Errorf("%s: exit %d, want 1 (stdout=%q stderr=%q)", label, code, out, errS)
	}
	if !strings.Contains(errS, want) {
		t.Errorf("%s: stderr %q does not carry the refusal text %q",
			label, errS, want)
	}
}

// r36CountEvents counts the campaign's logged events of one type, read from
// the ledger on disk.
func r36CountEvents(t *testing.T, c *state.Campaign, want string) int {
	t.Helper()
	n := 0
	for _, ty := range eventTypes(t, c) {
		if ty == want {
			n++
		}
	}
	return n
}

// r36Verb is one refusable jsonl writer under test.
type r36Verb struct {
	name  string
	store string
	event string
	args  func(cid string) []string
}

var r36Verbs = []r36Verb{
	{
		name:  "hint",
		store: "planner_hints.jsonl",
		event: "learning.planner_hint",
		args: func(cid string) []string {
			return []string{"hint", cid, "--kind", "note", "--content",
				"r36 probe: a hint row must not outlive a refused event"}
		},
	},
	{
		name:  "memory-reflect",
		store: "learnings.jsonl",
		event: "reflection.recorded",
		args: func(cid string) []string {
			return []string{"memory", cid, "--reflect",
				"r36 probe: a reflection row must not outlive a refused event"}
		},
	},
}

// r36Report renders one observed run for the failure messages.
func r36Report(code int, out, errS string) string {
	return fmt.Sprintf("exit=%d stdout=%q stderr=%q", code, out, errS)
}

// TestR36RefusedLogUnwindsBothWriters pins the two repros for both verbs.
//
// Repro A (torn ledger): the events.jsonl tail holds `{"seq": 9, "type":
// "torn` with no trailing newline; the verb exits 1 with the do-not-hand-edit
// refusal, and its jsonl must still be absent (pre-r36 it was created, 203 B,
// and the row stayed).
//
// Repro B (held lock): a second process holds campaign.lock; the verb exits 1
// after the lock budget with "is locked by another process", and its jsonl
// must be byte-identical to its pre-write state (pre-r36 the row landed and
// the file mtime advanced though the event never did).
//
// Both then HEAL and retry: exactly one row, exactly one event — pre-r36 the
// retry appended a second row for the one event.
func TestR36RefusedLogUnwindsBothWriters(t *testing.T) {
	for _, v := range r36Verbs {
		v := v

		t.Run(v.name+"/torn-ledger", func(t *testing.T) {
			root, cid, c := noopCamp(t)
			store := r36Path(root, cid, v.store)
			pre, had := r36Snap(t, store)
			t.Logf("%s pre-write: %s present=%v bytes=%d sha256=%s",
				v.name, v.store, had, len(pre), r36Sha(pre, had))

			ledger := r36TearLedger(t, root, cid)
			evPath := r36Path(root, cid, "events.jsonl")
			evPre, evHad := r36Snap(t, evPath)
			label := v.name + "/torn"

			code, out, errS := run(t,
				append([]string{"--root", root}, v.args(cid)...)...)
			r36Refusal(t, label, "does not parse", code, out, errS)
			if !strings.Contains(errS, "do not hand-edit") {
				t.Errorf("%s: stderr %q lacks the do-not-hand-edit repair text",
					label, errS)
			}
			r36AssertStore(t, label, store, pre, had)
			r36AssertStore(t, label+" events.jsonl", evPath, evPre, evHad)

			// Heal the ledger (restore the pre-tear snapshot) and retry: the
			// refused write must not have left a row to duplicate.
			if err := os.WriteFile(evPath, ledger, 0o644); err != nil {
				t.Fatalf("%s heal: %v", label, err)
			}
			code, out, errS = run(t,
				append([]string{"--root", root}, v.args(cid)...)...)
			if code != 0 {
				t.Fatalf("%s retry: %s", label, r36Report(code, out, errS))
			}
			post, postHad := r36Snap(t, store)
			if n := r36Lines(post, postHad); n != 1 {
				t.Fatalf("%s retry: %s holds %d row(s), want exactly 1 "+
					"(sha256 %s, %d bytes)", label, v.store, n,
					r36Sha(post, postHad), len(post))
			}
			if n := r36CountEvents(t, c, v.event); n != 1 {
				t.Fatalf("%s retry: %d %s event(s), want exactly 1",
					label, n, v.event)
			}
		})

		t.Run(v.name+"/held-lock", func(t *testing.T) {
			root, cid, c := noopCamp(t)
			store := r36Path(root, cid, v.store)
			pre, had := r36Snap(t, store)
			evPath := r36Path(root, cid, "events.jsonl")
			evPre, evHad := r36Snap(t, evPath)
			label := v.name + "/held-lock"
			t.Logf("%s pre-write: %s present=%v bytes=%d sha256=%s; "+
				"events.jsonl sha256=%s", v.name, v.store, had, len(pre),
				r36Sha(pre, had), r36Sha(evPre, evHad))

			release := r36HoldLock(t, root, cid)
			t.Cleanup(release)

			code, out, errS := run(t,
				append([]string{"--root", root}, v.args(cid)...)...)
			r36Refusal(t, label, "is locked by another process", code, out, errS)
			r36AssertStore(t, label, store, pre, had)
			r36AssertStore(t, label+" events.jsonl", evPath, evPre, evHad)

			release()
			code, out, errS = run(t,
				append([]string{"--root", root}, v.args(cid)...)...)
			if code != 0 {
				t.Fatalf("%s retry: %s", label, r36Report(code, out, errS))
			}
			post, postHad := r36Snap(t, store)
			if n := r36Lines(post, postHad); n != 1 {
				t.Fatalf("%s retry: %s holds %d row(s), want exactly 1 "+
					"(sha256 %s, %d bytes)", label, v.store, n,
					r36Sha(post, postHad), len(post))
			}
			if n := r36CountEvents(t, c, v.event); n != 1 {
				t.Fatalf("%s retry: %d %s event(s), want exactly 1",
					label, n, v.event)
			}
		})
	}
}

// TestR36SuccessPathIsUnchanged pins the success path of both verbs: the
// stdout/stderr bytes are the pre-r36 ones, and the campaign ends with exactly
// one row AND exactly one event.
func TestR36SuccessPathIsUnchanged(t *testing.T) {
	t.Run("hint", func(t *testing.T) {
		root, cid, c := noopCamp(t)
		content := "r36 success: exactly one row and one event"
		code, out, errS := run(t, "--root", root, "hint", cid, "--kind",
			"note", "--content", content)
		if code != 0 || errS != "" {
			t.Fatalf("hint success path: %s", r36Report(code, out, errS))
		}
		want := regexp.MustCompile(
			`^HINT-[0-9a-f]{8}: kind=note — ` + regexp.QuoteMeta(content) + "\n$")
		if !want.MatchString(out) {
			t.Fatalf("hint stdout = %q, want %s", out, want)
		}
		store := r36Path(root, cid, "planner_hints.jsonl")
		raw, had := r36Snap(t, store)
		if n := r36Lines(raw, had); n != 1 {
			t.Fatalf("planner_hints.jsonl holds %d row(s), want 1", n)
		}
		if n := r36CountEvents(t, c, "learning.planner_hint"); n != 1 {
			t.Fatalf("%d learning.planner_hint event(s), want 1", n)
		}
	})

	t.Run("memory-reflect", func(t *testing.T) {
		root, cid, c := noopCamp(t)
		text := "r36 success: exactly one reflection row"
		code, out, errS := run(t, "--root", root, "memory", cid, "--reflect", text)
		if code != 0 || errS != "" {
			t.Fatalf("memory --reflect success path: %s",
				r36Report(code, out, errS))
		}
		want := "reflection recorded (round 1): " + text + "\n" +
			"  learnings.jsonl now holds 1 entr(ies)\n"
		if out != want {
			t.Fatalf("memory --reflect stdout = %q, want %q", out, want)
		}
		store := r36Path(root, cid, "learnings.jsonl")
		raw, had := r36Snap(t, store)
		if n := r36Lines(raw, had); n != 1 {
			t.Fatalf("learnings.jsonl holds %d row(s), want 1", n)
		}
		if n := r36CountEvents(t, c, "reflection.recorded"); n != 1 {
			t.Fatalf("%d reflection.recorded event(s), want 1", n)
		}
	})
}
