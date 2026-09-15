package sections

// R44B (P1-b) at audit section 6 (snapshots) and the inconclusive recheck arm.
//
// P1-b: the section read its store with
//
//	if _, err := os.Stat(snapsRoot); err == nil { entries, _ := os.ReadDir(...) }
//
// — the ReadDir error was DISCARDED, so an unreadable snapshots/ store was
// indistinguishable from an empty one. The critic's repro: one pinned
// snapshot audits green ({"checked":1,"ok":true}); `chmod 000 <c>/snapshots/`
// then reports {"checked":0,"ok":true}, "audit PASS ... snapshots=0
// problem(s)", exit 0. A section that could not read its store verified
// nothing and must say so; a genuinely absent or empty store keeps its honest
// current behaviour, and so does a genuinely missing pin id.
//
// P3-b: recheckInconclusive's ledger arm used to `return ""` on a ledger read
// error while its two siblings refuse. The lead fix (the ledger arm) is in
// the tree; these pins hold it and the stdout arm to the same law: only
// ABSENCE is silent, a READ failure refuses.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func r44bCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r44b", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// r44bChmod makes dir unreadable and proves it: under a uid that ignores mode
// bits (root) the test skips instead of asserting a refusal it cannot create.
func r44bChmod(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod %o %s: %v", mode, dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// r44bPin pins one real source tree and returns the snapshot id.
func r44bPin(t *testing.T, c *state.Campaign) string {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V { uint x; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pinned, err := snapshot.PinSourceSnapshot(c, target, nil, nil)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	return objStr(pinned, "snapshot_id")
}

// TestR44bSnapshotsSectionRefusesUnreadableStore is the critic's repro: a
// green pin, then chmod 000 on the store root.
func TestR44bSnapshotsSectionRefusesUnreadableStore(t *testing.T) {
	c := r44bCampaign(t, "C-r44bsec1")
	sid := r44bPin(t, c)
	if sid == "" {
		t.Fatal("pin returned no snapshot id")
	}
	snapsRoot := filepath.Join(c.Dir, "snapshots")

	// BEFORE: the pin is checked and the section is green.
	before, err := Snapshots(c)
	if err != nil {
		t.Fatalf("green campaign refused: %v", err)
	}
	if n := objAt(before, "checked").I; n != 1 {
		t.Fatalf("BEFORE checked = %d, want 1", n)
	}
	if ok := objAt(before, "ok"); !ok.B {
		t.Fatalf("BEFORE ok = %v, want true", ok)
	}

	r44bChmod(t, snapsRoot, 0o000)
	if _, rerr := os.ReadDir(snapsRoot); rerr == nil {
		t.Skip("cannot make snapshots/ unreadable here (running as root?)")
	}

	// AFTER: the store cannot be listed — a refusal, never a count.
	after, err := Snapshots(c)
	if err == nil {
		t.Fatalf("section certified an unreadable snapshot store: %s",
			validation.DumpsOrdered(after, false))
	}
	for _, want := range []string{"cannot be listed", snapsRoot,
		"permission denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal must name %q: %v", want, err)
		}
	}
}

// TestR44bSnapshotsSectionRefusesNonDirectoryStore: snapshots/ replaced by a
// regular file (ENOTDIR) used to certify checked:0, ok:true.
func TestR44bSnapshotsSectionRefusesNonDirectoryStore(t *testing.T) {
	c := r44bCampaign(t, "C-r44bsec2")
	snapsRoot := filepath.Join(c.Dir, "snapshots")
	if err := os.MkdirAll(snapsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapsRoot, "not-a-pin.txt"),
		[]byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(snapsRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapsRoot, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Snapshots(c)
	if err == nil {
		t.Fatalf("a file where the snapshot store belongs certified: %s",
			validation.DumpsOrdered(got, false))
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), snapsRoot) {
		t.Fatalf("refusal must name the store and the errno: %v", err)
	}
}

// TestR44bSnapshotsSectionRefusesUnreadablePinDir: the store root is fine,
// but one pin dir cannot be read — the per-entry Stat used to `continue`, and
// os.Stat(snapshot.json) used to report "missing snapshot.json" over EACCES.
func TestR44bSnapshotsSectionRefusesUnreadablePinDir(t *testing.T) {
	c := r44bCampaign(t, "C-r44bsec3")
	sid := r44bPin(t, c)
	pinDir := filepath.Join(c.Dir, "snapshots", sid)

	r44bChmod(t, pinDir, 0o000)
	if _, serr := os.Stat(filepath.Join(pinDir, "snapshot.json")); serr == nil {
		t.Skip("cannot make a pin dir unreadable here (running as root?)")
	}

	got, err := Snapshots(c)
	if err == nil {
		t.Fatalf("section dropped an unreadable pin dir: %s",
			validation.DumpsOrdered(got, false))
	}
	for _, want := range []string{"cannot be read", pinDir, "permission denied"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal must name %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "missing snapshot.json") {
		t.Fatalf("a read failure must not be reported as an absent file: %v",
			err)
	}
}

// TestR44bSnapshotsGhostCheckRefusesUnreadableStore: the store lists (mode
// 0400: read yes, search no) but the referenced pin cannot be stat'ed. The
// ghost check's existence Stat ignored every non-NotExist error, so this
// shape certified "no ghost pin" over a store it never inspected.
func TestR44bSnapshotsGhostCheckRefusesUnreadableStore(t *testing.T) {
	c := r44bCampaign(t, "C-r44bsec4")
	sid := r44bPin(t, c)
	snapsRoot := filepath.Join(c.Dir, "snapshots")
	// No directory entries left, so only the ghost check reads the store.
	if err := os.RemoveAll(filepath.Join(snapsRoot, sid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(snapsRoot, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(snapsRoot, 0o755) })
	if _, lerr := os.ReadDir(snapsRoot); lerr != nil {
		t.Skip("cannot list a 0400 directory here (running as root?)")
	}
	if _, serr := os.Stat(filepath.Join(snapsRoot, sid)); serr == nil {
		t.Skip("cannot make a stat fail here (running as root?)")
	}

	got, err := Snapshots(c)
	if err == nil {
		t.Fatalf("ghost check certified a store it could not inspect: %s",
			validation.DumpsOrdered(got, false))
	}
	if !strings.Contains(err.Error(), "cannot be read") ||
		!strings.Contains(err.Error(), sid) {
		t.Fatalf("refusal must name the pin path: %v", err)
	}
}

// TestR44bSnapshotsHonestShapesStayGreen: no store, an empty store, and — as
// a problem, not a refusal — a genuinely missing pin id.
func TestR44bSnapshotsHonestShapesStayGreen(t *testing.T) {
	absent := r44bCampaign(t, "C-r44bsec5")
	if err := os.RemoveAll(filepath.Join(absent.Dir, "snapshots")); err != nil {
		t.Fatal(err)
	}
	got, err := Snapshots(absent)
	if err != nil {
		t.Fatalf("an absent snapshot store is an unpinned campaign: %v", err)
	}
	if n := objAt(got, "checked").I; n != 0 {
		t.Fatalf("absent store: checked = %d, want 0", n)
	}
	if ok := objAt(got, "ok"); !ok.B {
		t.Fatalf("absent store: ok = %v, want true", ok)
	}

	empty := r44bCampaign(t, "C-r44bsec6")
	if err := os.MkdirAll(filepath.Join(empty.Dir, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = Snapshots(empty)
	if err != nil {
		t.Fatalf("an empty snapshot store is an unpinned campaign: %v", err)
	}
	if n := objAt(got, "checked").I; n != 0 {
		t.Fatalf("empty store: checked = %d, want 0", n)
	}
	if ok := objAt(got, "ok"); !ok.B {
		t.Fatalf("empty store: ok = %v, want true", ok)
	}
}

// TestR44bSnapshotsMissingPinIdIsAProblemNotARefusal: the directory is gone
// but the campaign still names the pin — the r4/r12 ghost problem, unchanged.
func TestR44bSnapshotsMissingPinIdIsAProblemNotARefusal(t *testing.T) {
	c := r44bCampaign(t, "C-r44bsec7")
	sid := r44bPin(t, c)
	if err := os.RemoveAll(filepath.Join(c.Dir, "snapshots", sid)); err != nil {
		t.Fatal(err)
	}
	got, err := Snapshots(c)
	if err != nil {
		t.Fatalf("a missing pin id is a problem, not a read failure: %v", err)
	}
	if ok := objAt(got, "ok"); ok.B {
		t.Fatalf("a missing pin id must fail the section: %s",
			validation.DumpsOrdered(got, false))
	}
	body := validation.DumpsOrdered(got, false)
	if !strings.Contains(body, sid) ||
		!strings.Contains(body, "does not exist") {
		t.Fatalf("the ghost problem must name the pin: %s", body)
	}
}

// r44bExecRecord writes one ledger row and returns (execID, execDir).
func r44bExecRecord(t *testing.T, c *state.Campaign, execID string,
	stdoutPath bool) (string, string) {
	t.Helper()
	execDir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(execDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(execID)})
	if stdoutPath {
		rec.O = append(rec.O, validation.KV{K: "stdout_path",
			V: validation.VStr("stdout.log")})
	}
	if err := validation.WriteJson(filepath.Join(execDir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
	return execID, execDir
}

func r44bInconclusive(c *state.Campaign, exec string) string {
	return recheckInconclusive(c, nil, "INV-r44b", validation.VObj(),
		validation.VObj(), validation.VObj(), exec, harness.MiniCertora)
}

// TestR44bInconclusiveLedgerReadFailureMatchesItsSibling: the ledger that
// cannot be listed refuses, and refuses with the sibling arm's own sentence —
// one law, one wording.
func TestR44bInconclusiveLedgerReadFailureMatchesItsSibling(t *testing.T) {
	c := r44bCampaign(t, "C-r44bsec8")
	r44bChmod(t, c.ExecsDir, 0o000)

	why := r44bInconclusive(c, "EXEC-r44b")
	if why == "" {
		t.Fatal("the arm stayed silent about an unreadable ledger")
	}
	for _, want := range []string{"the exec ledger cannot be read", "INV-r44b"} {
		if !strings.Contains(why, want) {
			t.Fatalf("refusal must carry %q: %q", want, why)
		}
	}

	credit := validation.VObj(validation.KV{K: "rung",
		V: validation.VStr(harness.RungProvedBounded)})
	sibling := recheckExecEvidence(c, nil, "INV-r44b", validation.VObj(),
		validation.VObj(), credit, "EXEC-r44b", harness.MiniCertora)
	if sibling != why {
		t.Fatalf("the two arms disagree over one unreadable ledger:\n"+
			"inconclusive: %q\ncredit:       %q", why, sibling)
	}
}

// TestR44bInconclusiveStdoutArmKeepsAbsenceSilentAndRefusesReadFailure pins
// the r44b tightening of the stdout read: an ABSENT capture is the documented
// aged-out silence, a PRESENT capture that cannot be read is a refusal.
func TestR44bInconclusiveStdoutArmKeepsAbsenceSilentAndRefusesReadFailure(t *testing.T) {
	// (a) nothing captured at all: silence.
	none := r44bCampaign(t, "C-r44bsec9")
	_, _ = r44bExecRecord(t, none, "EXEC-r44b", false)
	if why := r44bInconclusive(none, "EXEC-r44b"); why != "" {
		t.Fatalf("a record that captured nothing must stay silent: %q", why)
	}

	// (b) the capture the record names is GONE (aged-out witness): silence.
	pruned := r44bCampaign(t, "C-r44bsec10")
	_, _ = r44bExecRecord(t, pruned, "EXEC-r44b", true)
	if why := r44bInconclusive(pruned, "EXEC-r44b"); why != "" {
		t.Fatalf("a pruned capture is absence, not a lie: %q", why)
	}

	// (c) the capture is THERE but unreadable: refuse, naming the exec and
	// the errno — the same sentence the two sibling arms return.
	denied := r44bCampaign(t, "C-r44bsec11")
	_, execDir := r44bExecRecord(t, denied, "EXEC-r44b", true)
	stdout := filepath.Join(execDir, "stdout.log")
	if err := os.WriteFile(stdout, []byte("PASS\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r44bChmod(t, stdout, 0o000)
	if _, oerr := os.Open(stdout); oerr == nil {
		t.Skip("cannot make stdout.log unreadable here (running as root?)")
	}
	why := r44bInconclusive(denied, "EXEC-r44b")
	for _, want := range []string{"stdout unreadable", "EXEC-r44b",
		"permission denied"} {
		if !strings.Contains(why, want) {
			t.Fatalf("the unreadable capture must refuse with %q: %q", want, why)
		}
	}
}
