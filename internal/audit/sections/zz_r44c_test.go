package sections

// R44C pins the two errno-folded-into-absence sites the critic named in this
// package, at section 15 (eval) and section 3 (execs).
//
// Section 15: the live-findings read was late and folded — `if live, lerr :=
// findings.LoadLiveFindings(c); lerr == nil { liveByProgram[program] = live }`
// — and, upstream of it, evalscore.Score (no error channel) reports a findings
// read failure as ok=false, which Eval turned into ErrSkip. So `chmod 000
// <c>/findings/` did not merely close an advisory block: the section VANISHED
// from the report while claiming nothing at all. A read error is a refusal; a
// genuinely absent or empty store stays the honest, byte-identical rendering
// (that fold lives in findings.LoadAllFindings / ListPrefixedOptional).
//
// Section 3: the ledger read was `if evts, err := c.Events(); err == nil { …
// } else if !os.IsNotExist(err) { return err }`. Absent events.jsonl is folded
// to an empty log INSIDE (*state.Campaign).Events, so no NotExist error can
// ever reach that else-arm: the shape reads as "skip the direction when the
// ledger is unreadable", and the direction is exactly what section 3 exists to
// find. It is now a plain refusal before the direction runs. (The execs/
// STORE half — state.AllExecs — was the r44a fold; it refuses already and is
// pinned by zz_r44a_test.go.)

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func r44cCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r44c", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

// r44cChmod makes path unreadable and PROVES it (a directory with ReadDir, a
// file with ReadFile): under a uid that ignores mode bits (root) the test
// skips instead of asserting a refusal it cannot create.
func r44cChmod(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	mode := os.FileMode(0o600)
	if fi.IsDir() {
		mode = 0o755
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", path, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, mode) })
	if fi.IsDir() {
		if _, err := os.ReadDir(path); err == nil {
			t.Skipf("cannot create an unreadable directory here (%s stayed readable)", path)
		}
		return
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Skipf("cannot create an unreadable file here (%s stayed readable)", path)
	}
}

// r44cSeedExec writes one valid exec record + its two ledger events (the
// shape cmd exec produces), so the section has both halves to check.
func r44cSeedExec(t *testing.T, c *state.Campaign, eid string) {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, eid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdout, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		validation.KV{K: "exec_id", V: validation.VStr(eid)},
		validation.KV{K: "campaign_id", V: validation.VStr(c.CampaignID)},
		validation.KV{K: "profile", V: validation.VStr("host-readonly")},
		validation.KV{K: "finding_id", V: validation.VNull()},
		validation.KV{K: "artifact_id", V: validation.VNull()},
		validation.KV{K: "command", V: validation.VStr("true")},
		validation.KV{K: "policy_verdict", V: validation.VObj(
			validation.KV{K: "allowed", V: validation.VBool(true)},
			validation.KV{K: "violations", V: validation.VArr()})},
		validation.KV{K: "origin", V: validation.VStr("locally-executed")},
		validation.KV{K: "reported_by", V: validation.VNull()},
		validation.KV{K: "started_at", V: validation.VStr("2026-01-01T00:00:00+00:00")},
		validation.KV{K: "finished_at", V: validation.VStr("2026-01-01T00:00:01+00:00")},
		validation.KV{K: "exit_status", V: validation.VInt(0)},
		validation.KV{K: "stdout_path", V: validation.VStr(stdout)},
		validation.KV{K: "stderr_path", V: validation.VStr(filepath.Join(dir, "stderr.log"))},
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("sandbox.exec.registered", &eid, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("sandbox.exec", &eid, nil); err != nil {
		t.Fatal(err)
	}
}

// r44cEvalCampaign opens a scratch campaign pinning ES03BankReentrancy, which
// matches exactly one case in the shipped pack (so the eval presence gate is
// OPEN and the section renders).
func r44cEvalCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "ES03BankReentrancy",
		state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	if _, err := os.Stat(c.FindingsDir); err != nil {
		t.Fatalf("state.Init did not create %s: %v", c.FindingsDir, err)
	}
	return c
}

// --- section 15 (eval) -------------------------------------------------

// TestR44cEvalRefusesUnreadableFindingsStore: before r44c this returned
// ErrSkip (the section was omitted from the report as if the campaign matched
// no suite case) because evalscore.Score folded the read error into ok=false;
// the late fold at the I3 block then never even ran.
func TestR44cEvalRefusesUnreadableFindingsStore(t *testing.T) {
	c := r44cEvalCampaign(t, "C-r44cevalr1")
	r44cChmod(t, c.FindingsDir)

	sec, err := Eval(c)
	if err == nil {
		t.Fatalf("Eval scored a findings store it could not read: %s",
			validation.CanonCompact(sec))
	}
	if errors.Is(err, ErrSkip) {
		t.Fatalf("a findings READ failure still vanished as ErrSkip: %v", err)
	}
	if !strings.Contains(err.Error(), c.FindingsDir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the findings store and the errno: %v", err)
	}
}

// The ENOTDIR shape: findings/ replaced by a regular file (no chmod needed).
func TestR44cEvalRefusesNonDirectoryFindingsStore(t *testing.T) {
	c := r44cEvalCampaign(t, "C-r44cevalr2")
	if err := os.RemoveAll(c.FindingsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.FindingsDir, []byte("not a store\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sec, err := Eval(c)
	if err == nil {
		t.Fatalf("Eval scored a non-directory findings store: %s",
			validation.CanonCompact(sec))
	}
	if !strings.Contains(err.Error(), c.FindingsDir) ||
		!strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("refusal must name the findings store and ENOTDIR: %v", err)
	}
}

// TestR44cEvalUnreadableRowRefuses: the store lists, but one F-*.json row
// cannot be read — that is a read failure too, not an empty row.
func TestR44cEvalUnreadableRowRefuses(t *testing.T) {
	c := r44cEvalCampaign(t, "C-r44cevalr3")
	row := filepath.Join(c.FindingsDir, "F-r44c0000001.json")
	f := validation.VObj(
		KV("finding_id", validation.VStr("F-r44c0000001")),
		KV("status", validation.VStr("CONFIRMED")),
		KV("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		KV("root_cause", validation.VObj(KV("class", validation.VStr("reentrancy")))),
		KV("affected", validation.VArr(
			validation.VObj(KV("path", validation.VStr("ES03BankReentrancy.sol"))))),
	)
	if err := validation.WriteJson(row, f, ""); err != nil {
		t.Fatal(err)
	}
	r44cChmod(t, row)

	_, err := Eval(c)
	if err == nil {
		t.Fatal("Eval scored a findings store holding an unreadable row")
	}
	if !strings.Contains(err.Error(), "F-r44c0000001.json") ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the unreadable row and the errno: %v", err)
	}
}

// TestR44cEvalAbsentAndEmptyFindingsStoresStayGreen: absence is a fact. A
// campaign with no findings/ directory (and one with an empty one) keeps the
// exact pre-r44c rendering: section present, ok=true, and both live-gated
// blocks ABSENT because the (genuinely) empty set closes them.
func TestR44cEvalAbsentAndEmptyFindingsStoresStayGreen(t *testing.T) {
	for _, shape := range []string{"absent", "empty"} {
		t.Run(shape, func(t *testing.T) {
			c := r44cEvalCampaign(t, "C-r44cevalg"+shape[:1])
			if shape == "absent" {
				if err := os.RemoveAll(c.FindingsDir); err != nil {
					t.Fatal(err)
				}
			}
			sec, err := Eval(c)
			if err != nil {
				t.Fatalf("%s findings store must stay green: %v", shape, err)
			}
			if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
				t.Fatalf("%s store: ok = %v, want true", shape, ok)
			}
			lines := []string{}
			for _, l := range objAt(sec, "lines").A {
				lines = append(lines, l.S)
			}
			joined := strings.Join(lines, "\n")
			if !strings.Contains(joined, "- false positives") {
				t.Fatalf("%s store lost the pinned section lines:\n%s",
					shape, joined)
			}
			if strings.Contains(joined, "acceptance-band precision") ||
				strings.Contains(joined, "by gold class") {
				t.Fatalf("%s store rendered a live-gated block from no live "+
					"findings:\n%s", shape, joined)
			}
		})
	}
}

// --- section 3 (execs) -------------------------------------------------

// TestR44cExecsRefusesUnreadableLedger: the ledger half of section 3 must
// refuse, not skip. Deleting the events directory's protection is the cheap
// repro; the assertion is on the error naming the ledger path and the errno.
func TestR44cExecsRefusesUnreadableLedger(t *testing.T) {
	c := r44cCampaign(t, "C-r44cexecr1")
	r44cSeedExec(t, c, "EXEC-0000000001")
	r44cChmod(t, c.EventsPath)

	sec, err := Execs(c)
	if err == nil {
		t.Fatalf("Execs certified an unreadable ledger: %s",
			validation.CanonCompact(sec))
	}
	if !strings.Contains(err.Error(), c.EventsPath) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the ledger and the errno: %v", err)
	}
}

// The EISDIR shape: events.jsonl replaced by a directory. This is the shape
// the old `else if !os.IsNotExist(err)` arm was written for; the new shape
// refuses for the same reason without guessing with IsNotExist.
func TestR44cExecsRefusesNonFileLedger(t *testing.T) {
	c := r44cCampaign(t, "C-r44cexecr2")
	r44cSeedExec(t, c, "EXEC-0000000001")
	if err := os.Remove(c.EventsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.EventsPath, 0o755); err != nil {
		t.Fatal(err)
	}

	sec, err := Execs(c)
	if err == nil {
		t.Fatalf("Execs certified an events.jsonl that is a directory: %s",
			validation.CanonCompact(sec))
	}
	if !strings.Contains(err.Error(), c.EventsPath) ||
		!strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("refusal must name the ledger and EISDIR: %v", err)
	}
}

// TestR44cExecsAbsentLedgerStaysGreen: absence is a fact in BOTH spellings
// the filesystem gives it for a missing ledger — no events.jsonl at all, and
// a dangling symlink (ENOENT, the codified absence test). The record half
// still runs, so checked=1, and no direction invents a problem.
func TestR44cExecsAbsentLedgerStaysGreen(t *testing.T) {
	for _, shape := range []string{"missing", "dangling"} {
		t.Run(shape, func(t *testing.T) {
			c := r44cCampaign(t, "C-r44cexecg"+shape[:1])
			r44cSeedExec(t, c, "EXEC-0000000001")
			if err := os.Remove(c.EventsPath); err != nil {
				t.Fatal(err)
			}
			if shape == "dangling" {
				if err := os.Symlink(filepath.Join(t.TempDir(), "gone.jsonl"),
					c.EventsPath); err != nil {
					t.Fatal(err)
				}
			}
			sec, err := Execs(c)
			if err != nil {
				t.Fatalf("%s ledger must stay green: %v", shape, err)
			}
			if got := objAt(sec, "checked"); got.Kind != validation.Int || got.I != 1 {
				t.Fatalf("%s ledger: checked = %v, want 1", shape, got)
			}
			if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
				t.Fatalf("%s ledger: ok = %v, want true", shape, ok)
			}
		})
	}
}

// TestR44cExecsEventsWithoutRecordsStillBurnsGreen keeps the r13 direction
// honest after the rewrite: with a READABLE ledger naming a record that is
// gone, the section still burns red (the residue it exists to find).
func TestR44cExecsEventsWithoutRecordsStillBurnsGreen(t *testing.T) {
	c := r44cCampaign(t, "C-r44cexecg3")
	r44cSeedExec(t, c, "EXEC-0000000001")
	if err := os.RemoveAll(filepath.Join(c.ExecsDir, "EXEC-0000000001")); err != nil {
		t.Fatal(err)
	}

	sec, err := Execs(c)
	if err != nil {
		t.Fatalf("Execs: %v", err)
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || ok.B {
		t.Fatalf("deleted record still certified ok=true: %s",
			validation.CanonCompact(sec))
	}
	problems := objAt(sec, "problems").A
	if len(problems) != 2 {
		t.Fatalf("problems = %d, want 2 (one per ledger event): %s",
			len(problems), fmt.Sprint(problems))
	}
	for _, p := range problems {
		if !strings.Contains(p.S, "no exec record survives on disk") {
			t.Fatalf("unexpected problem text: %s", p.S)
		}
	}
}
