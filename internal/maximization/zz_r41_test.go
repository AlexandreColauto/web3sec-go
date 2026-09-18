package maximization

// r41 P2 — TWO ladder sites still missed the FINDING-WRITE arm of the r18
// unwind. Both SetMaximal and ReopenLadder captured both baselines and
// saved the ladder doc, then called findings.SaveFinding and returned on
// failure WITHOUT restoring the pair:
//
//	ReopenLadder  : chmod-555 the campaign's findings dir, then reopen a
//	                waiver-closed ladder. rc=2 ("permission denied"), and
//	                the ladder disposition flips "waived" -> "open" while
//	                the finding stays "waived" with ZERO ladder.reopen
//	                events. Retry then says "ladder is already open —
//	                nothing to reopen" and STILL logs nothing: the reopen,
//	                its reason and its actor were permanently unrecorded.
//	SetMaximal    : same door; the ladder pins maximal_rung_id while the
//	                finding's maximization.maximal_rung_id stays None and
//	                ZERO ladder.claim_pinned events land.
//
// The identical arm in CompleteLadder was closed at r40 (the follow-up
// comment around its LoadFinding/SaveFinding arms); WaiveLadder and
// StartLadder already had it. The tests below pin the chmod door for both
// verbs (byte-identity of the pair by sha256, so no half-write can hide),
// the honest ledger-projection door for both, and the honest success path
// for both — the fix must not turn a real reopen or pin into a refusal.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// r41Sha is the byte-identity pin for one file (or "absent").
func r41Sha(t *testing.T, path string) string {
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

// r41Disposition is the ladder doc's disposition state.
func r41Disposition(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	raw, err := os.ReadFile(ladderPath(c, fid))
	if err != nil {
		t.Fatalf("read ladder: %v", err)
	}
	lad, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse ladder: %v", err)
	}
	return validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "disposition")), "state")
}

// r41MaximalRung is the ladder doc's maximal_rung_id ("" when null).
func r41MaximalRung(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	raw, err := os.ReadFile(ladderPath(c, fid))
	if err != nil {
		t.Fatalf("read ladder: %v", err)
	}
	lad, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse ladder: %v", err)
	}
	return validation.ObjStr(lad, "maximal_rung_id")
}

// r41FindingMaximalRung is finding.maximization.maximal_rung_id, "" when the
// key is absent or null (the projection the gate reads).
func r41FindingMaximalRung(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(validation.AsObj(validation.ObjAt(f, "maximization")), "maximal_rung_id")
}

// r41FindingDisposition is finding.maximization.disposition ("" when absent).
func r41FindingDisposition(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(validation.AsObj(validation.ObjAt(f, "maximization")), "disposition")
}

// r41Events counts one event type in the ledger.
func r41Events(t *testing.T, c *state.Campaign, kind string) int {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return strings.Count(string(raw), kind)
}

// r41Unwritable makes the campaign's findings dir read-only for the duration
// of one refusal and restores it before the test's TempDir cleanup runs.
func r41Unwritable(t *testing.T, c *state.Campaign) {
	t.Helper()
	fdir := filepath.Join(c.Dir, "findings")
	if err := os.Chmod(fdir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(fdir, 0o755) })
}

// r41Repairable cuts the ledger to a shorter non-empty PREFIX so the state
// mirror is longer than the log — the honest refusal an operator hits — and
// returns the pre-cut bytes for the retry.
func r41Repairable(t *testing.T, c *state.Campaign) []byte {
	t.Helper()
	for i := 0; i < 3; i++ {
		data := validation.VObj(kv("note", validation.VStr("r41 ledger growth")))
		if _, err := c.Log("note.added", nil, &data); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short to cut: %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return raw
}

// r41WaivedLadder is the critic's fixture: a CONFIRMED finding whose ladder
// was closed by a recorded waiver, so `reopen` has real work to do.
func r41WaivedLadder(t *testing.T, c *state.Campaign, title string) string {
	t.Helper()
	fid := validation.ObjStr(confirmedFinding(t, c, title), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	if _, err := WaiveLadder(c, fid,
		"budget exhausted before the ladder closed", "operator"); err != nil {
		t.Fatal(err)
	}
	if got := r41Disposition(t, c, fid); got != "waived" {
		t.Fatalf("fixture ladder disposition = %q, want waived", got)
	}
	return fid
}

// r41ReproducedRung is the fixture for set-maximal: an open ladder whose one
// added rung was reproduced against a real sandboxed exec record.
func r41ReproducedRung(t *testing.T, c *state.Campaign, title string) (string, string) {
	t.Helper()
	fid := validation.ObjStr(confirmedFinding(t, c, title), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	capUSD, ratio := 1.0, 1.0
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, &capUSD, &ratio, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rungID := validation.ObjStr(rung, "rung_id")
	rec := registerExec(t, c, fid)
	if _, err := ReproduceRung(c, fid, rungID, validation.ObjStr(rec, "exec_id"), nil); err != nil {
		t.Fatal(err)
	}
	if got := r41Disposition(t, c, fid); got != "open" {
		t.Fatalf("fixture ladder disposition = %q, want open", got)
	}
	return fid, rungID
}

// TestR41RefusedReopenFindingWriteLeavesPairUntouched is the critic's exact
// repro at package level: a waiver-closed ladder on a CONFIRMED finding, the
// findings dir made unwritable, then reopen. Before the fix the ladder read
// "open" with the finding still "waived" and zero ladder.reopen events, and
// the retry's already-open early-return made the reopen, its reason and its
// actor permanently unrecorded. Now the refused call restores BOTH files
// byte-for-byte, so the retry is the real, logged reopen.
func TestR41RefusedReopenFindingWriteLeavesPairUntouched(t *testing.T) {
	c := newCampaign(t, "r41 reopen burn")
	fid := r41WaivedLadder(t, c, "Fee skim via rounding")
	r41Unwritable(t, c)
	ladBefore := r41Sha(t, ladderPath(c, fid))
	findBefore := r41Sha(t, findings.FindingPath(c, fid))
	eventsBefore := r41Sha(t, c.EventsPath)
	_, err := ReopenLadder(c, fid, "a cheaper rung appeared after the waiver", "op")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("reopen on an unwritable findings dir = %v (want EACCES)", err)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the refused reopen:\n before %s\n after  %s",
			ladBefore, got)
	}
	if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across the refused reopen:\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r41Sha(t, c.EventsPath); got != eventsBefore {
		t.Fatalf("the refused reopen wrote to the ledger: %s -> %s",
			eventsBefore, got)
	}
	if got := r41Disposition(t, c, fid); got != "waived" {
		t.Fatalf("ladder disposition after the refusal = %q (want waived)", got)
	}
	if got := r41FindingDisposition(t, c, fid); got != "waived" {
		t.Fatalf("finding maximization.disposition = %q (want waived)", got)
	}
	if n := r41Events(t, c, "ladder.reopen"); n != 0 {
		t.Fatalf("%d ladder.reopen event(s) after a refused reopen", n)
	}
	// Nothing was burned: the retry is a REAL reopen and logs exactly once.
	if err := os.Chmod(filepath.Join(c.Dir, "findings"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReopenLadder(c, fid, "a cheaper rung appeared after the waiver",
		"op"); err != nil {
		t.Fatalf("honest retry after the refused reopen: %v", err)
	}
	if n := r41Events(t, c, "ladder.reopen"); n != 1 {
		t.Fatalf("honest retry emitted %d ladder.reopen event(s), want 1", n)
	}
	if got := r41Disposition(t, c, fid); got != "open" {
		t.Fatalf("ladder disposition after the retry = %q (want open)", got)
	}
	if got := r41FindingDisposition(t, c, fid); got != "open" {
		t.Fatalf("finding maximization.disposition after the retry = %q (want open)", got)
	}
}

// TestR41RefusedSetMaximalFindingWriteLeavesPairUntouched is the same door on
// set-maximal: the ladder save stands (maximal_rung_id pinned, history row
// appended) while the finding stamp and the ladder.claim_pinned event never
// land. The fix restores the pair, so the retry pins for real.
func TestR41RefusedSetMaximalFindingWriteLeavesPairUntouched(t *testing.T) {
	c := newCampaign(t, "r41 pin orphan")
	fid, rungID := r41ReproducedRung(t, c, "Flash-loan price manipulation")
	r41Unwritable(t, c)
	ladBefore := r41Sha(t, ladderPath(c, fid))
	findBefore := r41Sha(t, findings.FindingPath(c, fid))
	eventsBefore := r41Sha(t, c.EventsPath)
	_, err := SetMaximal(c, fid, rungID)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("set-maximal on an unwritable findings dir = %v (want EACCES)", err)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the refused pin:\n before %s\n after  %s",
			ladBefore, got)
	}
	if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across the refused pin:\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r41Sha(t, c.EventsPath); got != eventsBefore {
		t.Fatalf("the refused pin wrote to the ledger: %s -> %s", eventsBefore, got)
	}
	if got := r41MaximalRung(t, c, fid); got != "" {
		t.Fatalf("ladder maximal_rung_id after the refusal = %q (want null)", got)
	}
	if got := r41FindingMaximalRung(t, c, fid); got != "" {
		t.Fatalf("finding maximization.maximal_rung_id after the refusal = %q (want null)", got)
	}
	if n := r41Events(t, c, "ladder.claim_pinned"); n != 0 {
		t.Fatalf("%d ladder.claim_pinned event(s) after a refused pin", n)
	}
	if err := os.Chmod(filepath.Join(c.Dir, "findings"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := SetMaximal(c, fid, rungID); err != nil {
		t.Fatalf("honest retry after the refused pin: %v", err)
	}
	if n := r41Events(t, c, "ladder.claim_pinned"); n != 1 {
		t.Fatalf("honest retry emitted %d ladder.claim_pinned event(s), want 1", n)
	}
	if got := r41MaximalRung(t, c, fid); got != rungID {
		t.Fatalf("ladder maximal_rung_id after the retry = %q, want %s", got, rungID)
	}
	if got := r41FindingMaximalRung(t, c, fid); got != rungID {
		t.Fatalf("finding maximal_rung_id after the retry = %q, want %s", got, rungID)
	}
}

// TestR41RefusedReopenLedgerDoorLeavesPairUntouched pins the honest refusal
// an operator can always hit for reopen: grow the ledger, cut events.jsonl to
// a shorter non-empty PREFIX so the mirror is longer than the log, and the
// ladder.reopen append is refused. The pre-existing r18 arm must still bring
// both files back byte-for-byte, and the repaired-ledger retry must log.
func TestR41RefusedReopenLedgerDoorLeavesPairUntouched(t *testing.T) {
	c := newCampaign(t, "r41 reopen ledger door")
	fid := r41WaivedLadder(t, c, "Rounding loss")
	raw := r41Repairable(t, c)
	ladBefore := r41Sha(t, ladderPath(c, fid))
	findBefore := r41Sha(t, findings.FindingPath(c, fid))
	eventsBefore := r41Sha(t, c.EventsPath)
	_, err := ReopenLadder(c, fid, "a cheaper rung appeared after the waiver", "op")
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door reopen = %v (want the projection refusal)", err)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the ledger refusal:\n before %s\n after  %s",
			ladBefore, got)
	}
	if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across the ledger refusal:\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r41Sha(t, c.EventsPath); got != eventsBefore {
		t.Fatalf("the refused reopen touched the ledger: %s -> %s", eventsBefore, got)
	}
	if got := r41Disposition(t, c, fid); got != "waived" {
		t.Fatalf("ladder disposition after the ledger refusal = %q (want waived)", got)
	}
	if n := r41Events(t, c, "ladder.reopen"); n != 0 {
		t.Fatalf("%d ladder.reopen event(s) after the ledger refusal", n)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReopenLadder(c, fid, "a cheaper rung appeared after the waiver",
		"op"); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if n := r41Events(t, c, "ladder.reopen"); n != 1 {
		t.Fatalf("retry emitted %d ladder.reopen event(s), want 1", n)
	}
}

// TestR41RefusedSetMaximalLedgerDoorLeavesPairUntouched is the same
// projection refusal on set-maximal's ladder.claim_pinned append.
func TestR41RefusedSetMaximalLedgerDoorLeavesPairUntouched(t *testing.T) {
	c := newCampaign(t, "r41 pin ledger door")
	fid, rungID := r41ReproducedRung(t, c, "Rounding loss")
	raw := r41Repairable(t, c)
	ladBefore := r41Sha(t, ladderPath(c, fid))
	findBefore := r41Sha(t, findings.FindingPath(c, fid))
	eventsBefore := r41Sha(t, c.EventsPath)
	_, err := SetMaximal(c, fid, rungID)
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door set-maximal = %v (want the projection refusal)", err)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the ledger refusal:\n before %s\n after  %s",
			ladBefore, got)
	}
	if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across the ledger refusal:\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r41Sha(t, c.EventsPath); got != eventsBefore {
		t.Fatalf("the refused pin touched the ledger: %s -> %s", eventsBefore, got)
	}
	if got := r41MaximalRung(t, c, fid); got != "" {
		t.Fatalf("ladder maximal_rung_id after the ledger refusal = %q (want null)", got)
	}
	if got := r41FindingMaximalRung(t, c, fid); got != "" {
		t.Fatalf("finding maximal_rung_id after the ledger refusal = %q (want null)", got)
	}
	if n := r41Events(t, c, "ladder.claim_pinned"); n != 0 {
		t.Fatalf("%d ladder.claim_pinned event(s) after the ledger refusal", n)
	}
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SetMaximal(c, fid, rungID); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if n := r41Events(t, c, "ladder.claim_pinned"); n != 1 {
		t.Fatalf("retry emitted %d ladder.claim_pinned event(s), want 1", n)
	}
}

// TestR41ManualCLISeed is NOT a behaviour test: it builds the two fixtures the
// report's CLI door needs (a waiver-closed ladder on a CONFIRMED finding, and
// an open ladder with a reproduced rung) at WEBV2_R41_SEED and prints their
// ids, so the operator can drive the real binary:
//
//	WEBV2_R41_SEED=/tmp/r41/cli go test ./internal/maximization/ \
//	    -run TestR41ManualCLISeed -v
//	bin/webv2 --root /tmp/r41/cli ladder <C> reopen <F> \
//	    --reason "a cheaper rung appeared after the waiver" --actor op
//	bin/webv2 --root /tmp/r41/cli ladder <C> set-maximal <F> <R>
//
// It is skipped unless the env var is set, so it never touches the normal
// suite.
func TestR41ManualCLISeed(t *testing.T) {
	root := os.Getenv("WEBV2_R41_SEED")
	if root == "" {
		t.Skip("set WEBV2_R41_SEED=<dir> to build the CLI fixtures")
	}
	c, err := state.Init(root, "r41-cli", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign at %s: %v", root, err)
	}
	reopenFid := r41WaivedLadder(t, c, "Fee skim via rounding")
	pinFid, rungID := r41ReproducedRung(t, c, "Flash-loan price manipulation")
	t.Logf("R41SEED-ROOT=%s", root)
	t.Logf("R41SEED-CAMPAIGN=%s", c.CampaignID)
	t.Logf("R41SEED-REOPEN-FINDING=%s", reopenFid)
	t.Logf("R41SEED-PIN-FINDING=%s", pinFid)
	t.Logf("R41SEED-PIN-RUNG=%s", rungID)
}

// ---------------------------------------------------------------------------
// r41 follow-up — the ladder arms BEYOND SetMaximal/ReopenLadder (the audit
// of every write site in maximization.go). Four sites still returned without
// the unwind:
//
//	AddVariant / ExploreAxis : the SaveLadder-error arm (the class
//	    SetMaximal, WaiveLadder, ReopenLadder and StartLadder already close).
//	CompleteLadder           : the same SaveLadder-error arm — its r40
//	    follow-up closed the LoadFinding/SaveFinding arms only.
//	DisproveRung             : the SaveLadder-error arm AND the
//	    learning.queue_memory arm, which returned after the ladder doc had
//	    already been saved "disproved" (no ladder.rung_disproved event).
//	ReproduceRung            : reproduction.MintReproEvidence ran BEFORE the
//	    two baselines were captured, so the mint's own finding write sat
//	    outside the verb's unwind window.
//
// The mint burn is the sharp one. findings.AddEvidence saves the finding
// (the evidence item) and THEN appends finding.evidence_added, with no
// unwind of its own — so when the ledger refuses, the mint returns an error
// with the item already ON the finding and no event behind it. ReproduceRung
// captured its baselines after that mint, so a refused
// ladder.rung_reproduced left the minted evidence (plus its updated_at
// stamp) on the finding with ZERO events anywhere.
//
// WINDOW CHOICE (deliberate; also stated at the fix): once the mint's own
// finding.evidence_added event HAS landed, the mint is a complete file+event
// pair and unwinding only its file half would orphan that event — so the
// finding snapshot the LADDER arms restore is re-captured after a successful
// mint, while the mint's own window is captured BEFORE it. Both halves are
// pinned: the ledger door (mint refused -> finding bytes restored) and the
// chmod-ladders door (mint landed, ladder write refused -> ladder untouched,
// minted evidence kept, retry does not duplicate it).
// ---------------------------------------------------------------------------

// r41LaddersUnwritable makes the campaign's ladders dir read-only for the
// duration of one refusal and restores it before TempDir cleanup runs. The
// refusal it produces is SaveLadder's own write (os.CreateTemp -> EACCES),
// i.e. the first write every one of these verbs makes.
func r41LaddersUnwritable(t *testing.T, c *state.Campaign) {
	t.Helper()
	dir := filepath.Join(c.Dir, "ladders")
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
}

// r41EvidenceCount counts the finding's evidence items.
func r41EvidenceCount(t *testing.T, c *state.Campaign, fid string) int {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load finding: %v", err)
	}
	ev := validation.ObjAt(f, "evidence")
	if ev.Kind != validation.Arr {
		return 0
	}
	return len(ev.A)
}

// r41RungStatus reads one rung's status off the ladder FILE.
func r41RungStatus(t *testing.T, c *state.Campaign, fid, rungID string) string {
	t.Helper()
	raw, err := os.ReadFile(ladderPath(c, fid))
	if err != nil {
		t.Fatalf("read ladder: %v", err)
	}
	lad, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse ladder: %v", err)
	}
	for _, r := range listOf(lad, "variants").A {
		if validation.ObjStr(r, "rung_id") == rungID {
			return validation.ObjStr(r, "status")
		}
	}
	return ""
}

// r41AxisNoted reports whether the ladder's axis_notes carry the axis.
func r41AxisNoted(t *testing.T, c *state.Campaign, fid, axis string) bool {
	t.Helper()
	raw, err := os.ReadFile(ladderPath(c, fid))
	if err != nil {
		t.Fatalf("read ladder: %v", err)
	}
	lad, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse ladder: %v", err)
	}
	return validation.ObjStr(validation.AsObj(validation.ObjAt(lad, "axis_notes")), axis) != ""
}

// r41FreshReproducibleRung is the fixture the mint burn needs: an open ladder
// with one ASSUMED rung and a registered exec whose evidence has NEVER been
// minted, so reproduce_rung really does mint (and therefore really does write
// the finding before its own event).
func r41FreshReproducibleRung(t *testing.T, c *state.Campaign,
	title string) (string, string, string) {
	t.Helper()
	fid := validation.ObjStr(confirmedFinding(t, c, title), "finding_id")
	if _, err := StartLadder(c, fid); err != nil {
		t.Fatal(err)
	}
	rung, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := registerExec(t, c, fid)
	return fid, validation.ObjStr(rung, "rung_id"), validation.ObjStr(rec, "exec_id")
}

// r41CompletableLadder is the fixture complete_ladder needs to reach
// SaveLadder: every axis explored, a reproduced rung pinned as maximal.
func r41CompletableLadder(t *testing.T, c *state.Campaign, title string) string {
	t.Helper()
	fid, rungID := r41ReproducedRung(t, c, title)
	for _, a := range Axes {
		if _, err := ExploreAxis(c, fid, a, "considered and not applicable"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SetMaximal(c, fid, rungID); err != nil {
		t.Fatal(err)
	}
	return fid
}

// TestR41RefusedReproduceRungLedgerDoorUnwindsTheMint is the headline pin:
// with the ledger cut, the mint's own finding.evidence_added append is the
// first append to be refused, and findings.AddEvidence returns with the
// evidence item already saved on the finding. Before the fix ReproduceRung
// captured its baselines AFTER that mint, so the refused
// ladder.rung_reproduced left the finding bytes changed (an evidence item and
// an updated_at stamp) with ZERO events behind it. Now the pre-mint snapshot
// is restored: finding bytes identical, no new evidence item, no event of
// either kind, and the repaired-ledger retry reproduces for real, exactly
// once.
func TestR41RefusedReproduceRungLedgerDoorUnwindsTheMint(t *testing.T) {
	c := newCampaign(t, "r41 reproduce mint burn")
	fid, rungID, execID := r41FreshReproducibleRung(t, c, "Fee skim via rounding")
	raw := r41Repairable(t, c)
	findBefore := r41Sha(t, findings.FindingPath(c, fid))
	ladBefore := r41Sha(t, ladderPath(c, fid))
	evBefore := r41EvidenceCount(t, c, fid)
	mintEventsBefore := r41Events(t, c, "finding.evidence_added")
	_, err := ReproduceRung(c, fid, rungID, execID, nil)
	if err == nil || !strings.Contains(err.Error(), "state projection mirrors") {
		t.Fatalf("ledger-door reproduce = %v (want the projection refusal)", err)
	}
	if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("the minted evidence survived the refused reproduce (the "+
			"mint ran before the baselines were captured):\n before %s\n after  %s",
			findBefore, got)
	}
	if got := r41EvidenceCount(t, c, fid); got != evBefore {
		t.Fatalf("finding evidence items = %d, want %d (the refused mint "+
			"left its item behind)", got, evBefore)
	}
	if got := r41Events(t, c, "finding.evidence_added"); got != mintEventsBefore {
		t.Fatalf("finding.evidence_added events = %d, want %d (the refused "+
			"mint must add none)", got, mintEventsBefore)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the refused reproduce:\n"+
			" before %s\n after  %s", ladBefore, got)
	}
	if got := r41RungStatus(t, c, fid, rungID); got != "assumed" {
		t.Fatalf("rung status after the refusal = %q, want assumed", got)
	}
	if got := r41Events(t, c, "ladder.rung_reproduced"); got != 0 {
		t.Fatalf("%d ladder.rung_reproduced event(s) after the refusal", got)
	}
	// Repair (the cut tail restored), then the retry: exactly one mint and
	// exactly one rung_reproduced.
	if err := os.WriteFile(c.EventsPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReproduceRung(c, fid, rungID, execID, nil); err != nil {
		t.Fatalf("retry on a repaired ledger: %v", err)
	}
	if got := r41Events(t, c, "ladder.rung_reproduced"); got != 1 {
		t.Fatalf("retry emitted %d ladder.rung_reproduced event(s), want 1", got)
	}
	if got := r41Events(t, c, "finding.evidence_added"); got != mintEventsBefore+1 {
		t.Fatalf("retry emitted %d finding.evidence_added event(s), want %d",
			got, mintEventsBefore+1)
	}
	if got := r41EvidenceCount(t, c, fid); got != evBefore+1 {
		t.Fatalf("finding evidence items after the retry = %d, want %d", got, evBefore+1)
	}
	if got := r41RungStatus(t, c, fid, rungID); got != "reproduced" {
		t.Fatalf("rung status after the retry = %q, want reproduced", got)
	}
}

// TestR41RefusedDisproveQueueMemoryArmRestoresLadderPair pins the second
// demonstrable burn: DisproveRung saves the ladder doc (rung -> disproved,
// history row appended) and only THEN calls learning.queue_memory and the
// ledger. A refused queue call used to return with the ladder reading
// "disproved" and no ladder.rung_disproved event anywhere. The seam is the
// door (the real learning.QueueMemory is itself unwound, so a store failure
// is the honest way to reach this arm without a disk trick).
func TestR41RefusedDisproveQueueMemoryArmRestoresLadderPair(t *testing.T) {
	c := newCampaign(t, "r41 disprove queue-memory burn")
	fid, rungID, _ := r41FreshReproducibleRung(t, c, "Fee skim via rounding")
	SetQueueMemory(func(*state.Campaign, MemoryRequest) (validation.Value, error) {
		return validation.VNull(), errors.New("learning store unavailable")
	})
	t.Cleanup(func() { SetQueueMemory(nil) })
	ladBefore := r41Sha(t, ladderPath(c, fid))
	findBefore := r41Sha(t, findings.FindingPath(c, fid))
	_, err := DisproveRung(c, fid, rungID,
		"the pool rejects 1 wei deposits (MIN_DEPOSIT)")
	if err == nil || !strings.Contains(err.Error(), "learning store unavailable") {
		t.Fatalf("refused queue-memory disprove = %v", err)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the refused disprove (saved "+
			"before the queue call):\n before %s\n after  %s", ladBefore, got)
	}
	if got := r41RungStatus(t, c, fid, rungID); got != "assumed" {
		t.Fatalf("rung status after the refusal = %q, want assumed", got)
	}
	if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
		t.Fatalf("finding bytes changed across the refused disprove:\n"+
			" before %s\n after  %s", findBefore, got)
	}
	if got := r41Events(t, c, "ladder.rung_disproved"); got != 0 {
		t.Fatalf("%d ladder.rung_disproved event(s) after the refusal", got)
	}
	// The honest retry (real seam restored) records exactly one event.
	SetQueueMemory(nil)
	if _, err := DisproveRung(c, fid, rungID,
		"the pool rejects 1 wei deposits (MIN_DEPOSIT)"); err != nil {
		t.Fatalf("honest retry: %v", err)
	}
	if got := r41Events(t, c, "ladder.rung_disproved"); got != 1 {
		t.Fatalf("honest retry emitted %d ladder.rung_disproved event(s), want 1", got)
	}
	if got := r41RungStatus(t, c, fid, rungID); got != "disproved" {
		t.Fatalf("rung status after the retry = %q, want disproved", got)
	}
}

// TestR41RefusedSaveLadderArmsLeavePairUntouched is the table for the
// SaveLadder-error arm: with the ladders dir unwritable, SaveLadder's own
// write (CreateTemp) fails as the verb's FIRST write, and every arm must
// leave the ladder and the finding byte-identical with no event, then land
// exactly one event on the honest retry.
//
// HONEST NOTE: validation.WriteJson cleans its temp file on every failure
// path and only ever touches the target through os.Rename, so on this door
// the ladder is untouched whether or not the arm restores — the restore is
// defense-in-depth for the partial-visibility case (ENOSPC mid-rename on
// some mounts) that SetMaximal/WaiveLadder/ReopenLadder already name in
// their comments, and this subtest pins the observable contract. The arms
// with a DEMONSTRABLE burn are the two tests above (the mint and the queue
// call).
func TestR41RefusedSaveLadderArmsLeavePairUntouched(t *testing.T) {
	type arm struct {
		name  string
		fixt  func(t *testing.T, c *state.Campaign) (string, map[string]string)
		verb  func(t *testing.T, c *state.Campaign, fid string, meta map[string]string) error
		event string
		probe func(t *testing.T, c *state.Campaign, fid string, meta map[string]string)
		// findingUntouched is false for ReproduceRung, whose mint legitimately
		// lands its OWN finding event before the ladder write.
		findingUntouched bool
	}
	simpleRung := func(t *testing.T, c *state.Campaign) (string, map[string]string) {
		fid, rungID, execID := r41FreshReproducibleRung(t, c, "Rounding loss")
		return fid, map[string]string{"rung": rungID, "exec": execID}
	}
	arms := []arm{
		{
			name: "AddVariant",
			fixt: simpleRung,
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := AddVariant(c, fid, "late", "a late variant attempt",
					[]string{"cap-saturation"}, nil, nil, nil, nil)
				return err
			},
			event: "ladder.variant_added",
			probe: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) {
				if got := r41LadderRungs(t, c, fid); got != 2 {
					t.Fatalf("ladder variants after the refusal = %d, want 2 "+
						"(base + the fixture rung)", got)
				}
			},
			findingUntouched: true,
		},
		{
			name: "ExploreAxis",
			fixt: simpleRung,
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := ExploreAxis(c, fid, "cap-saturation",
					"no payout cap in this code path")
				return err
			},
			event: "ladder.axis_explored",
			probe: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) {
				if r41AxisNoted(t, c, fid, "cap-saturation") {
					t.Fatal("the axis note survived the refused explore")
				}
			},
			findingUntouched: true,
		},
		{
			name: "DisproveRung",
			fixt: simpleRung,
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := DisproveRung(c, fid, meta["rung"],
					"the pool rejects 1 wei deposits (MIN_DEPOSIT)")
				return err
			},
			event: "ladder.rung_disproved",
			probe: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) {
				if got := r41RungStatus(t, c, fid, meta["rung"]); got != "assumed" {
					t.Fatalf("rung status after the refusal = %q, want assumed", got)
				}
			},
			findingUntouched: true,
		},
		{
			name: "CompleteLadder",
			fixt: func(t *testing.T, c *state.Campaign) (string, map[string]string) {
				return r41CompletableLadder(t, c, "Rounding loss"), map[string]string{}
			},
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := CompleteLadder(c, fid, "operator")
				return err
			},
			event: "ladder.complete",
			probe: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) {
				if got := r41Disposition(t, c, fid); got != "open" {
					t.Fatalf("ladder disposition after the refusal = %q, want open", got)
				}
				if got := r41FindingDisposition(t, c, fid); got == "complete" {
					t.Fatal("the finding was stamped complete by a refused complete")
				}
			},
			findingUntouched: true,
		},
		{
			name: "ReproduceRung",
			fixt: simpleRung,
			verb: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) error {
				_, err := ReproduceRung(c, fid, meta["rung"], meta["exec"], nil)
				return err
			},
			event: "ladder.rung_reproduced",
			probe: func(t *testing.T, c *state.Campaign, fid string,
				meta map[string]string) {
				if got := r41RungStatus(t, c, fid, meta["rung"]); got != "assumed" {
					t.Fatalf("rung status after the refusal = %q, want assumed", got)
				}
			},
			findingUntouched: false,
		},
	}
	for _, a := range arms {
		t.Run(a.name, func(t *testing.T) {
			c := newCampaign(t, "r41 save-ladder arm "+a.name)
			fid, meta := a.fixt(t, c)
			r41LaddersUnwritable(t, c)
			ladBefore := r41Sha(t, ladderPath(c, fid))
			findBefore := r41Sha(t, findings.FindingPath(c, fid))
			eventsBefore := r41Events(t, c, a.event)
			err := a.verb(t, c, fid, meta)
			if err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("%s on an unwritable ladders dir = %v (want EACCES)",
					a.name, err)
			}
			if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
				t.Fatalf("ladder bytes changed across the refused %s:\n"+
					" before %s\n after  %s", a.name, ladBefore, got)
			}
			if a.findingUntouched {
				if got := r41Sha(t, findings.FindingPath(c, fid)); got != findBefore {
					t.Fatalf("finding bytes changed across the refused %s:\n"+
						" before %s\n after  %s", a.name, findBefore, got)
				}
			}
			if got := r41Events(t, c, a.event); got != eventsBefore {
				t.Fatalf("%s: %d %s event(s) after the refusal, want %d",
					a.name, got, a.event, eventsBefore)
			}
			a.probe(t, c, fid, meta)
			if err := os.Chmod(filepath.Join(c.Dir, "ladders"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := a.verb(t, c, fid, meta); err != nil {
				t.Fatalf("honest retry of %s: %v", a.name, err)
			}
			if got := r41Events(t, c, a.event); got != eventsBefore+1 {
				t.Fatalf("honest retry of %s emitted %d %s event(s), want %d",
					a.name, got, a.event, eventsBefore+1)
			}
		})
	}
}

// TestR41ReproduceRungMintLandedIsKeptNotDuplicated pins the window choice:
// when the mint ITSELF succeeded (its finding.evidence_added event landed)
// and only the ladder write was refused, the minted evidence is a complete
// file+event pair and is deliberately NOT unwound (unwinding only its file
// half would orphan the event); the retry must not mint a second item.
func TestR41ReproduceRungMintLandedIsKeptNotDuplicated(t *testing.T) {
	c := newCampaign(t, "r41 reproduce mint-kept")
	fid, rungID, execID := r41FreshReproducibleRung(t, c, "Rounding loss")
	r41LaddersUnwritable(t, c)
	evBefore := r41EvidenceCount(t, c, fid)
	mintEventsBefore := r41Events(t, c, "finding.evidence_added")
	ladBefore := r41Sha(t, ladderPath(c, fid))
	_, err := ReproduceRung(c, fid, rungID, execID, nil)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("reproduce with an unwritable ladders dir = %v (want EACCES)", err)
	}
	if got := r41Sha(t, ladderPath(c, fid)); got != ladBefore {
		t.Fatalf("ladder bytes changed across the refused reproduce:\n"+
			" before %s\n after  %s", ladBefore, got)
	}
	if got := r41RungStatus(t, c, fid, rungID); got != "assumed" {
		t.Fatalf("rung status after the refusal = %q, want assumed", got)
	}
	if got := r41EvidenceCount(t, c, fid); got != evBefore+1 {
		t.Fatalf("finding evidence items = %d, want %d (the mint's own event "+
			"landed, so its item is an authoritative pair and is kept)", got,
			evBefore+1)
	}
	if got := r41Events(t, c, "finding.evidence_added"); got != mintEventsBefore+1 {
		t.Fatalf("finding.evidence_added events = %d, want %d", got,
			mintEventsBefore+1)
	}
	if err := os.Chmod(filepath.Join(c.Dir, "ladders"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReproduceRung(c, fid, rungID, execID, nil); err != nil {
		t.Fatalf("honest retry: %v", err)
	}
	if got := r41Events(t, c, "ladder.rung_reproduced"); got != 1 {
		t.Fatalf("retry emitted %d ladder.rung_reproduced event(s), want 1", got)
	}
	if got := r41Events(t, c, "finding.evidence_added"); got != mintEventsBefore+1 {
		t.Fatalf("the retry minted a SECOND item: finding.evidence_added "+
			"events = %d, want %d (the mint is idempotent per exec+type)",
			got, mintEventsBefore+1)
	}
	if got := r41EvidenceCount(t, c, fid); got != evBefore+1 {
		t.Fatalf("the retry minted a second evidence item: %d items, want %d",
			got, evBefore+1)
	}
	if got := r41RungStatus(t, c, fid, rungID); got != "reproduced" {
		t.Fatalf("rung status after the retry = %q, want reproduced", got)
	}
}

// r41LadderRungs counts the ladder FILE's variants.
func r41LadderRungs(t *testing.T, c *state.Campaign, fid string) int {
	t.Helper()
	raw, err := os.ReadFile(ladderPath(c, fid))
	if err != nil {
		t.Fatalf("read ladder: %v", err)
	}
	lad, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse ladder: %v", err)
	}
	return len(listOf(lad, "variants").A)
}
