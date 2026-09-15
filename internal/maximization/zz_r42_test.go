package maximization

// r42 P1 — THE UNWIND DESTROYED THE RECORD IT EXISTS TO PROTECT.
//
// prevFile classified EVERY read error as "the file did not exist", and
// restoreLadderPair's absent branch honored that lie with os.Remove. So when
// an existing finding file was UNREADABLE (chmod 000), `ladder waive`
// returned 'open .../F-<id>.json: permission denied' and DELETED the
// finding: the ladder was restored to its pre-waive bytes pointing at a
// record that no longer existed, verify stayed ok:true, audit PASSed with
// findings=0 problems, doctor exited 0, and the natural retry answered
// 'no finding F-<id> in campaign'. Reachable at every arm that snapshots
// the finding and then reads it: WaiveLadder, ReopenLadder, CompleteLadder
// and ReproduceRung's mint-error arm.
//
// The door now carries the same three pre-call states every other unwind in
// the tree has (findings.prevBytes, state.appendJsonlThenLog, both
// linksThenLog copies): absent, readable, and PRESENT-BUT-UNREADABLE. The
// snapshot REFUSES the verb before its first write on the third state —
// nothing is written, so nothing needs unwinding and no restore arm can
// meet it — restoreLadderPair refuses to remove an unreadable file even if
// one ever reaches it, and it NAMES its own failure instead of swallowing
// it (the '(UNWIND ALSO FAILED: ...)' voice findings.SaveThenLog and
// sandbox's execDirTxn.fail already use).
//
// Pins below: the critic's chmod-000 repro at package level for all four
// reachable arms (before: the file was GONE; after: present, byte-identical,
// the ladder untouched and the operator told the read failed), the literal
// restore-refuses-to-delete pin, the failed-restore disclosure pin (at the
// door and through a real waive), and the pre-existing mirror-longer-than-
// log refusal and honest-success doors re-pinned through the new snapshot.

import (
	"errors"
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
)

// r42ChmodUnreadable makes one file unreadable (mode 0000) for the duration
// of a refusal and restores a readable mode before TempDir cleanup runs.
func r42ChmodUnreadable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o644) })
}

// r42MustExist proves a path is still ON DISK without reading it (a 000-mode
// file still stats): a deleted record must fail here, not in a hash compare.
func r42MustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the record is GONE — the unwind deleted what it exists to "+
			"protect: %v", err)
	}
}

// r42Bytes reads a file after restoring a readable mode, so byte-identity is
// asserted on the bytes themselves (and not on two "absent" hashes agreeing).
func r42Bytes(t *testing.T, path string) []byte {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

// TestR42UnreadableFindingIsNotDeleted is the critic's repro: make the
// finding unreadable, run the verb. Before the fix the verb returned
// 'permission denied' and the finding was GONE; now the verb refuses BEFORE
// any write — the finding is still there with its exact bytes, the ladder is
// byte-identical, no event lands, and the same call succeeds once the file
// is readable again.
func TestR42UnreadableFindingIsNotDeleted(t *testing.T) {
	type arm struct {
		name  string
		fixt  func(t *testing.T, c *state.Campaign) (string, map[string]string)
		verb  func(t *testing.T, c *state.Campaign, fid string, meta map[string]string) error
		event string
	}
	arms := []arm{
		{
			name: "waive",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				fid := objStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
				if _, err := StartLadder(c, fid); err != nil {
					t.Fatal(err)
				}
				return fid, nil
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := WaiveLadder(c, fid,
					"operator cannot exploit further variants", "op")
				return err
			},
			event: "completion.waived",
		},
		{
			name: "reopen",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				return r41WaivedLadder(t, c, "Fee skim via rounding"), nil
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := ReopenLadder(c, fid,
					"a cheaper rung appeared after the waiver", "op")
				return err
			},
			event: "ladder.reopen",
		},
		{
			name: "complete",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				return r41CompletableLadder(t, c, "Rounding loss"), nil
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := CompleteLadder(c, fid, "operator")
				return err
			},
			event: "ladder.complete",
		},
		{
			name: "reproduce-mint",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				fid, rungID, execID := r41FreshReproducibleRung(t, c,
					"Rounding loss")
				return fid, map[string]string{"rung": rungID, "exec": execID}
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := ReproduceRung(c, fid, meta["rung"], meta["exec"], nil)
				return err
			},
			event: "ladder.rung_reproduced",
		},
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			c := newCampaign(t, "r42 unreadable finding "+a.name)
			fid, meta := a.fixt(t, c)
			fp := findings.FindingPath(c, fid)
			lp := ladderPath(c, fid)
			findingBefore := r42Bytes(t, fp)
			ladderBefore := r42Bytes(t, lp)
			eventsBefore := r41Events(t, c, a.event)

			r42ChmodUnreadable(t, fp)
			err := a.verb(t, c, fid, meta)
			if err == nil {
				t.Fatalf("%s accepted an unreadable finding", a.name)
			}
			// The operator must be TOLD the read failed, and which file — the
			// old message never said the tool was about to delete it.
			if !strings.Contains(err.Error(), "permission denied") ||
				!strings.Contains(err.Error(), fid) ||
				!strings.Contains(err.Error(), "refusing before any write") {
				t.Fatalf("%s: the refusal does not name the unreadable file: %v",
					a.name, err)
			}
			// The heart of the pin: still on disk, byte for byte.
			r42MustExist(t, fp)
			if got := r42Bytes(t, fp); string(got) != string(findingBefore) {
				t.Fatalf("%s: finding bytes changed across the refused verb:\n"+
					" before %s\n after  %s", a.name, findingBefore, got)
			}
			// Nothing was written, so nothing needed unwinding: the ladder is
			// byte-identical and no event was appended either.
			if got := r42Bytes(t, lp); string(got) != string(ladderBefore) {
				t.Fatalf("%s: ladder bytes changed across the refused verb:\n"+
					" before %s\n after  %s", a.name, ladderBefore, got)
			}
			if got := r41Events(t, c, a.event); got != eventsBefore {
				t.Fatalf("%s: %d %s event(s) after the refusal, want %d",
					a.name, got, a.event, eventsBefore)
			}
			// The honest retry — same call, readable file — is a REAL verb,
			// not the 'no finding in campaign' the deletion used to answer.
			if err := a.verb(t, c, fid, meta); err != nil {
				t.Fatalf("honest retry of %s after restoring the mode: %v",
					a.name, err)
			}
			if got := r41Events(t, c, a.event); got != eventsBefore+1 {
				t.Fatalf("honest retry of %s emitted %d %s event(s), want %d",
					a.name, got, a.event, eventsBefore+1)
			}
		})
	}
}

// TestR42SnapshotRefusesAnUnreadableLadder pins the symmetric half: the
// snapshot door refuses on the LADDER too, before any write, so no verb can
// reach a restore holding a ladder whose bytes it never saw.
func TestR42SnapshotRefusesAnUnreadableLadder(t *testing.T) {
	c := newCampaign(t, "r42 unreadable ladder")
	fid := objStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	lp := ladderPath(c, fid)
	before := r42Bytes(t, lp)
	r42ChmodUnreadable(t, lp)
	pair, err := snapshotLadderFiles(c, fid)
	if err == nil {
		t.Fatal("the snapshot accepted an unreadable ladder")
	}
	if !strings.Contains(err.Error(), "ladder") ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the ladder refusal does not name the read failure: %v", err)
	}
	if pair.lad.path != "" || pair.fnd.path != "" {
		t.Fatalf("a refused snapshot returned a pair: %+v", pair)
	}
	r42MustExist(t, lp)
	if got := r42Bytes(t, lp); string(got) != string(before) {
		t.Fatal("the refused snapshot touched the ladder")
	}
}

// TestR42RestoreRefusesToRemoveAnUnreadableFile pins the law literally at
// the door, not just at the seam that now prevents the state: if a pair
// carrying present-but-unreadable ever reaches restoreLadderPair, the
// restore must NOT remove the file — absence was never proven and the bytes
// were never seen — and it must SAY SO.
func TestR42RestoreRefusesToRemoveAnUnreadableFile(t *testing.T) {
	c := newCampaign(t, "r42 restore refuses")
	f := confirmedFinding(t, c, "Rounding loss")
	fid := objStr(f, "finding_id")
	fp := findings.FindingPath(c, fid)
	before := r42Bytes(t, fp)

	r42ChmodUnreadable(t, fp)
	fnd := prevFile(fp)
	if !fnd.unreadable || !fnd.had {
		t.Fatalf("prevFile on a 000-mode file = %+v, want present+unreadable",
			fnd)
	}
	// The ladder was never written by this hand-made pair: absent.
	pair := ladderPair{lad: ladderFileSnap{path: ladderPath(c, fid)}, fnd: fnd}
	rerr := restoreLadderPair(pair)
	if rerr == nil {
		t.Fatal("the restore claimed success over bytes it never read")
	}
	if !strings.Contains(rerr.Error(), "NOT touched") ||
		!strings.Contains(rerr.Error(), "permission denied") {
		t.Fatalf("the restore does not say what it refused to do: %v", rerr)
	}
	r42MustExist(t, fp)
	if got := r42Bytes(t, fp); string(got) != string(before) {
		t.Fatalf("the restore destroyed bytes it could not read:\n"+
			" before %s\n after  %s", before, got)
	}
}

// TestR42UnwindNamesItsOwnFailure pins the voice restoreLadderPair used to
// lack: it returned void and swallowed its own failure while every other
// door in the tree names them (findings.SaveThenLog, sandbox's
// execDirTxn.fail, the links/JSONL copies). Both halves are pinned — the
// door called directly, and a REAL verb whose restore cannot complete.
func TestR42UnwindNamesItsOwnFailure(t *testing.T) {
	t.Run("at the door", func(t *testing.T) {
		c := newCampaign(t, "r42 unwind voice")
		f := confirmedFinding(t, c, "Rounding loss")
		fid := objStr(f, "finding_id")
		fp := findings.FindingPath(c, fid)
		before := r42Bytes(t, fp)
		pair := ladderPair{lad: ladderFileSnap{path: ladderPath(c, fid)},
			fnd: prevFile(fp)}
		// The pre-call bytes were readable, but the restore cannot land
		// them: 0444 makes the file readable and unwritable, exactly the
		// shape of an immutable file or a failed ENOSPC write.
		if err := os.Chmod(fp, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(fp, 0o644) })
		refusal := errors.New("ledger refused the append")
		got := unwindLadderPair(pair, refusal)
		if !errors.Is(got, refusal) {
			t.Fatalf("the verb's own refusal was lost: %v", got)
		}
		if !strings.Contains(got.Error(), "UNWIND ALSO FAILED") ||
			!strings.Contains(got.Error(), "permission denied") ||
			!strings.Contains(got.Error(), "F-") {
			t.Fatalf("a failed restore was not named: %v", got)
		}
		if b := r42Bytes(t, fp); string(b) != string(before) {
			t.Fatalf("the failed restore still changed the file:\n"+
				" before %s\n after  %s", before, b)
		}
	})
	t.Run("through a real waive", func(t *testing.T) {
		c := newCampaign(t, "r42 unwind voice via waive")
		f := confirmedFinding(t, c, "Rounding loss")
		fid := objStr(f, "finding_id")
		if _, err := StartLadder(c, fid); err != nil {
			t.Fatal(err)
		}
		fp := findings.FindingPath(c, fid)
		// 0444: still READABLE, so the pre-write snapshot succeeds — but the
		// restore's write cannot land. The ledger is then cut so the verb is
		// refused AFTER both files were rewritten: the one window in which a
		// restore fails for real.
		if err := os.Chmod(fp, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(fp, 0o644) })
		raw := r41Repairable(t, c)
		_, err := WaiveLadder(c, fid,
			"operator cannot exploit further variants", "op")
		if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
			t.Fatalf("waive on a cut ledger = %v (want the projection refusal)",
				err)
		}
		if !strings.Contains(err.Error(), "UNWIND ALSO FAILED") ||
			!strings.Contains(err.Error(), findings.FindingPath(c, fid)) {
			t.Fatalf("the failed finding restore was swallowed: %v", err)
		}
		// Repair the ledger and the file mode: the retry is a real waive.
		if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fp, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := WaiveLadder(c, fid,
			"operator cannot exploit further variants", "op"); err != nil {
			t.Fatalf("honest retry after the disclosed unwind: %v", err)
		}
	})
}

// TestR42LedgerDoorAndHonestSuccessStillHold re-pins the pre-existing doors
// through the NEW snapshot: the honest refusal (the state mirror longer than
// the log) must still leave BOTH files byte-identical and emit nothing, and
// the honest call must still succeed and log exactly once — for all four
// verbs the r42 door touches.
func TestR42LedgerDoorAndHonestSuccessStillHold(t *testing.T) {
	type arm struct {
		name  string
		fixt  func(t *testing.T, c *state.Campaign) (string, map[string]string)
		verb  func(t *testing.T, c *state.Campaign, fid string, meta map[string]string) error
		event string
	}
	arms := []arm{
		{
			name: "waive",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				fid := objStr(confirmedFinding(t, c, "Rounding loss"), "finding_id")
				if _, err := StartLadder(c, fid); err != nil {
					t.Fatal(err)
				}
				return fid, nil
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := WaiveLadder(c, fid,
					"budget exhausted before the ladder closed", "operator")
				return err
			},
			event: "completion.waived",
		},
		{
			name: "reopen",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				return r41WaivedLadder(t, c, "Fee skim via rounding"), nil
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := ReopenLadder(c, fid,
					"a cheaper rung appeared after the waiver", "op")
				return err
			},
			event: "ladder.reopen",
		},
		{
			name: "set-maximal",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				fid, rungID := r41ReproducedRung(t, c, "Rounding loss")
				return fid, map[string]string{"rung": rungID}
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := SetMaximal(c, fid, meta["rung"])
				return err
			},
			event: "ladder.claim_pinned",
		},
		{
			name: "complete",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				return r41CompletableLadder(t, c, "Rounding loss"), nil
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := CompleteLadder(c, fid, "operator")
				return err
			},
			event: "ladder.complete",
		},
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			c := newCampaign(t, "r42 door "+a.name)
			fid, meta := a.fixt(t, c)
			fp := findings.FindingPath(c, fid)
			lp := ladderPath(c, fid)
			findingBefore := r42Bytes(t, fp)
			ladderBefore := r42Bytes(t, lp)
			eventsBefore := r41Events(t, c, a.event)

			raw := r41Repairable(t, c)
			err := a.verb(t, c, fid, meta)
			if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
				t.Fatalf("%s on the cut ledger = %v (want the projection refusal)",
					a.name, err)
			}
			if got := r42Bytes(t, fp); string(got) != string(findingBefore) {
				t.Fatalf("%s: finding bytes changed across the ledger refusal:\n"+
					" before %s\n after  %s", a.name, findingBefore, got)
			}
			if got := r42Bytes(t, lp); string(got) != string(ladderBefore) {
				t.Fatalf("%s: ladder bytes changed across the ledger refusal:\n"+
					" before %s\n after  %s", a.name, ladderBefore, got)
			}
			if got := r41Events(t, c, a.event); got != eventsBefore {
				t.Fatalf("%s: %d %s event(s) after the refusal, want %d",
					a.name, got, a.event, eventsBefore)
			}
			if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := a.verb(t, c, fid, meta); err != nil {
				t.Fatalf("honest %s on the repaired ledger: %v", a.name, err)
			}
			if got := r41Events(t, c, a.event); got != eventsBefore+1 {
				t.Fatalf("honest %s emitted %d %s event(s), want %d",
					a.name, got, a.event, eventsBefore+1)
			}
		})
	}
}
