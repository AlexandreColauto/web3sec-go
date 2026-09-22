package regression

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func regressionCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// gitTarget writes a one-file tree, git-inits it, commits, and returns the
// directory plus the commit a REAL producer will record for it. Copied from
// internal/snapshot/ladder_test.go's gitSetup on purpose (small helpers are
// duplicated, not exported — the house rule): the snapshot the binding is
// tested against must come from snapshot.PinSourceSnapshot, never from a
// hand-written record.
func gitTarget(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("-c", "init.defaultBranch=main", "init", "-q")
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "init")
	return dir, runGit("rev-parse", "HEAD")
}

func TestAddTargetRefusesAnUnknownKindAndShape(t *testing.T) {
	c := regressionCampaign(t, "C-regressaddbad1")
	for _, spec := range []TargetSpec{
		{Kind: "vendor-dump", Program: "Acme", Shape: "vault-erc4626"},
		{Kind: "scabench", Program: "Acme", Shape: "vault-ish"},
		{Kind: "scabench", Program: "", Shape: "vault-erc4626"},
	} {
		if _, err := AddTarget(c, spec); err == nil {
			t.Fatalf("AddTarget accepted %+v", spec)
		}
	}
	targets, err := LoadTargets(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("%d target(s) survived a refused add", len(targets))
	}
}

// realSnapshotFor pins a real git tree into the campaign and returns the commit
// the real producer recorded plus the snapshot's id. The binding must be tested
// against snapshot.PinSourceSnapshot's own record, never a hand-written one.
func realSnapshotFor(t *testing.T, c *state.Campaign) (string, string) {
	t.Helper()
	dir, sha := gitTarget(t)
	snap, err := snapshot.PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(snap, "source"), "git_commit"); got != sha {
		t.Fatalf("the real producer recorded commit %q, want %q", got, sha)
	}
	return sha, validation.ObjStr(snap, "snapshot_id")
}

func TestPinTargetBindsTheSnapshotToTheResolvedSHA(t *testing.T) {
	c := regressionCampaign(t, "C-regresspin0001")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme Vault", RecordID: "acme-vault",
		Repo: "acme/vault", Shape: "vault-erc4626", CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	sha, sid := realSnapshotFor(t, c)
	pinned, err := PinTarget(c, PinSpec{
		TargetID: validation.ObjStr(target, "target_id"), ResolvedSHA: sha,
		SnapshotID: sid, ResolvedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(pinned, "resolved_sha"); got != sha {
		t.Fatalf("resolved_sha = %q, want %q", got, sha)
	}
	if got := validation.ObjStr(pinned, "snapshot_id"); got != sid {
		t.Fatalf("snapshot_id = %q, want %q", got, sid)
	}
}

func TestPinTargetRefusesAHintInsteadOfASHA(t *testing.T) {
	c := regressionCampaign(t, "C-regresspinhint1")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	// §3a: "at least one project (Fenix Finance) records "commit": "main" —
	// a mutable ref. ScaBench's commit field is a hint, not a pin." Measured,
	// it is five codebases, not one (see *The dataset, as it actually is*), but
	// the fixture only needs the one value §3a named.
	_, err = PinTarget(c, PinSpec{
		TargetID:    validation.ObjStr(target, "target_id"),
		ResolvedSHA: "main", SnapshotID: "src-abc123def456", ResolvedBy: "op",
	})
	if err == nil || !strings.Contains(err.Error(), "40-hex") {
		t.Fatalf("err = %v, want a refusal naming the 40-hex requirement", err)
	}
}

func TestPinTargetRefusesASnapshotThatDisagreesWithTheSHA(t *testing.T) {
	c := regressionCampaign(t, "C-regresspinmis1")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := gitTarget(t)
	snap, err := snapshot.PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("a", 40)
	_, err = PinTarget(c, PinSpec{
		TargetID:    validation.ObjStr(target, "target_id"),
		ResolvedSHA: other,
		SnapshotID:  validation.ObjStr(snap, "snapshot_id"),
		ResolvedBy:  "op",
	})
	if err == nil || !strings.Contains(err.Error(), "git_commit") {
		t.Fatalf("err = %v, want a refusal naming the snapshot's git_commit", err)
	}
}

// blockEvents points the campaign's ledger at a directory, so every append
// fails AFTER the projection write has already landed. That ordering is the
// whole fixture: a refusal raised before writeThenLog (an invalid spec, a
// missing target) proves nothing about the unwind.
func blockEvents(t *testing.T, c *state.Campaign) {
	t.Helper()
	blocked := filepath.Join(t.TempDir(), "events-as-a-directory")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	c.EventsPath = blocked
}

// targetFiles is every target record currently on disk.
func targetFiles(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(TargetsDir(c), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails is the ledger-law
// test the P1 self-review found missing: every writer in this package claims
// "unwind on log failure" and nothing exercised it.
//
// The fixture's spec must SURVIVE checkTargetSpec, or the refusal under test
// is the spec refusal and writeThenLog is never reached — that was this test's
// original defect (the reviewer's M1/M8/M9 mutations all left the package
// green). The error is asserted to be the ledger's own failure for the same
// reason: it is the evidence the unwind ran.
func TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails(t *testing.T) {
	c := regressionCampaign(t, "C-regressunwind1")
	blockEvents(t, c)
	_, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err == nil {
		t.Fatal("AddTarget accepted a target whose ledger event could not be written")
	}
	if !strings.Contains(err.Error(), "events-as-a-directory") {
		t.Fatalf("err = %v, want the ledger's own failure — a spec refusal never "+
			"reaches the unwind this test exists to exercise", err)
	}
	if paths := targetFiles(t, c); len(paths) != 0 {
		t.Fatalf("the projection survived a failed ledger write: %v", paths)
	}
}

// assertRestoredTo pins the post-refusal state of a rewritten record: it still
// exists, the refused pin left no resolved_sha on it, and its bytes are the
// pre-pin bytes exactly.
func assertRestoredTo(t *testing.T, c *state.Campaign, tid string, before []byte) {
	t.Helper()
	after, ok, err := Target(c, tid)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("DATA LOSS: the failed pin removed the committed target record %s", tid)
	}
	if got := validation.ObjStr(after, "resolved_sha"); got != "" {
		t.Fatalf("the refused pin left resolved_sha %q on the record", got)
	}
	raw, err := os.ReadFile(targetPath(c, tid))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, raw) {
		t.Fatalf("the restored record is not the pre-pin bytes:\nbefore %s\nafter  %s",
			before, raw)
	}
}

// TestWriteThenLogRestoresAPreExistingRecordOnAFailedRewrite is the data-loss
// case the unconditional os.Remove got wrong. PinTarget REWRITES the record
// AddTarget already committed and ledgered; when its event is refused the
// ORIGINAL bytes must come back, because deleting them leaves the campaign
// with a regression.target.added event naming a target that no longer exists
// (the reviewer's reproduction: ok=false, "DATA LOSS").
func TestWriteThenLogRestoresAPreExistingRecordOnAFailedRewrite(t *testing.T) {
	c := regressionCampaign(t, "C-regressunwind2")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")
	sha, sid := realSnapshotFor(t, c)
	before, err := os.ReadFile(targetPath(c, tid))
	if err != nil {
		t.Fatal(err)
	}
	blockEvents(t, c)
	if _, err := PinTarget(c, PinSpec{
		TargetID: tid, ResolvedSHA: sha, SnapshotID: sid, ResolvedBy: "operator",
	}); err == nil {
		t.Fatal("PinTarget accepted a pin whose ledger event could not be written")
	} else if !strings.Contains(err.Error(), "events-as-a-directory") {
		// The same guard the new-record test carries, for the same reason:
		// a refusal raised BEFORE the projection write (checkPin, a missing
		// target, the spec) leaves the record untouched, so assertRestoredTo
		// would pass without the restore ever running.
		t.Fatalf("err = %v, want the ledger's own failure — a pre-write refusal "+
			"never reaches the restore this test exists to exercise", err)
	}
	assertRestoredTo(t, c, tid, before)
}

// assertFailedUnwind pins the double-failure message: both the ledger's
// refusal and the restore's own failure are named, because returning only the
// ledger error would launder a projection that is still ahead of the log. The
// ledger's error must also stay UNWRAPPABLE (findings.SaveThenLog's %w, not
// %v): the disclosure is worth nothing if a caller cannot errors.As back to
// the refusal that caused it.
func assertFailedUnwind(t *testing.T, err error, ledgerNeedle string) {
	t.Helper()
	if err == nil {
		t.Fatal("the writer accepted a mutation whose ledger event could not be written")
	}
	if !strings.Contains(err.Error(), ledgerNeedle) {
		t.Fatalf("err = %v, want the ledger's own failure (%q)", err, ledgerNeedle)
	}
	if !strings.Contains(err.Error(), "UNWIND ALSO FAILED") ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("a failed restore was not named: %v", err)
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || !strings.Contains(pathErr.Path, ledgerNeedle) {
		t.Fatalf("the ledger's refusal is not unwrappable (want %%w): %v", err)
	}
}

// TestWriteThenLogNamesAFailedUnwind pins the branch the "UNWIND ALSO FAILED"
// wording exists for, which nothing exercised before. A 0444 record is still
// READABLE (so prevBytes snapshots it) but not WRITABLE (so restoreBytes
// cannot land the snapshot back) — the one window in which the unwind itself
// fails, and the only honest outcome is the doubled refusal.
func TestWriteThenLogNamesAFailedUnwind(t *testing.T) {
	c := regressionCampaign(t, "C-regressunwind3")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")
	sha, sid := realSnapshotFor(t, c)
	if err := os.Chmod(targetPath(c, tid), 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(targetPath(c, tid), 0o644) })
	blockEvents(t, c)
	if _, err := PinTarget(c, PinSpec{
		TargetID: tid, ResolvedSHA: sha, SnapshotID: sid, ResolvedBy: "operator",
	}); err != nil {
		assertFailedUnwind(t, err, "events-as-a-directory")
	} else {
		t.Fatal("PinTarget accepted a pin whose ledger event could not be written")
	}
	// The message is not decoration: the projection really does hold
	// post-write bytes with no event, which is what it discloses.
	assertHalfLandDisclosed(t, c, tid, sha)
}

// assertHalfLandDisclosed pins the honesty of the doubled refusal: the
// projection really does hold post-write bytes with no event behind them.
func assertHalfLandDisclosed(t *testing.T, c *state.Campaign, tid, sha string) {
	t.Helper()
	after, ok, err := Target(c, tid)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the failed restore removed the record it could not rewrite")
	}
	if got := validation.ObjStr(after, "resolved_sha"); got != sha {
		t.Fatalf("the disclosed half-land is not on disk: resolved_sha = %q, want %q", got, sha)
	}
}

// assertOneNewEvent pins the OTHER half of the ledger law — "exactly one
// hash-chained event per mutation". Without it a writer that stopped calling
// c.Log altogether (the reviewer's M9) is invisible to every test in this
// package: the records still land, and nothing else reads the log.
func assertOneNewEvent(t *testing.T, c *state.Campaign, before int,
	wantType, wantRef string) {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != before+1 {
		t.Fatalf("%d event(s) in the ledger after the mutation, want %d — "+
			"exactly one hash-chained event per mutation", len(events), before+1)
	}
	ev := events[len(events)-1]
	if got := validation.ObjStr(ev, "type"); got != wantType {
		t.Fatalf("event type = %q, want %q", got, wantType)
	}
	if got := validation.ObjStr(ev, "ref"); got != wantRef {
		t.Fatalf("event ref = %q, want %q", got, wantRef)
	}
	if before == 0 {
		return
	}
	prev := validation.ObjStr(events[before-1], "event_hash")
	if got := validation.ObjStr(ev, "prev_hash"); got != prev {
		t.Fatalf("event prev_hash = %q, want the previous event_hash %q", got, prev)
	}
}

// TestEachWriterAppendsExactlyOneChainedEvent covers all three writers: the
// event each record claims to have is on the log exactly once, and it chains
// to the event before it. The count is re-read before each writer because the
// snapshot producer between them ledgers its own event.
func TestEachWriterAppendsExactlyOneChainedEvent(t *testing.T) {
	c := regressionCampaign(t, "C-regressevents1")
	before := nextSeq(t, c)
	target := addAcmeTarget(t, c)
	tid := validation.ObjStr(target, "target_id")
	assertOneNewEvent(t, c, before, "regression.target.added", tid)
	sha, sid := realSnapshotFor(t, c)
	before = nextSeq(t, c)
	if _, err := PinTarget(c, PinSpec{
		TargetID: tid, ResolvedSHA: sha, SnapshotID: sid, ResolvedBy: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	assertOneNewEvent(t, c, before, "regression.target.pinned", tid)
	before = nextSeq(t, c)
	run, err := RecordRun(c, RunSpec{
		TargetID: tid, Scorer: "eval-gold",
		ScoreFile: writeScoreFile(t, evalGoldFixture),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertOneNewEvent(t, c, before, "regression.run.recorded",
		validation.ObjStr(run, "run_id"))
}

// nextSeq is the ledger's current line count.
func nextSeq(t *testing.T, c *state.Campaign) int {
	t.Helper()
	n, err := c.NextSeq()
	if err != nil {
		t.Fatal(err)
	}
	return n
}
