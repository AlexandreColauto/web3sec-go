package cli

// r38b — P2-2 at the CLI boundary: evidence laundering through the 10 MiB
// capture cap. A capture the exec record's own output_capture marks
// TRUNCATED is unfit for evidence on every consumer path:
//
//	MINT   `webv2 mint` refuses it (exit 2, "mint failed: exec ...:
//	       stdout capture marked truncated: kept N of M bytes"), because
//	       mint's exec-record gate is findings.ValidateExecRecord — the
//	       same refusal findings pins in exec_evidence_test.go;
//	VERIFY `webv2 verify --harness-result` refuses to bind a rung from
//	       truncated stdout (exit 2): the run's verdict lines could sit
//	       past the cap in either direction, so what the kept prefix shows
//	       is unprovable both ways — absence AND presence;
//	CONTROL an UNtruncated capture mints and binds exactly as before —
//	       the gate is additive, and every pinned untruncated stdout byte
//	       stays identical.
//
// The laundering flip itself (filler mint accepted before the gate, refused
// after) was pinned against a live docker-networkless run — the record's
// honest accounting (cap_bytes 10485760, stdout_total_bytes 10485819,
// stdout_truncated true) is the shape these tests write onto the fixture
// records.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// TestR38bMintRefusesTruncatedCapture pins the mint refusal: an exec whose
// record marks stdout truncated cannot mint E4 evidence — exit 2, the
// MintError rendering, and NO evidence item on the finding.
func TestR38bMintRefusesTruncatedCapture(t *testing.T) {
	f := t20Setup(t)
	id := r38bSeedExec(t, f.c, f.fid, 0,
		"Ran 1 test in 3ms (test suite successful)\n",
		r38bTruncatedCapture(10485819))
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", id, "--description", "the PoC reproduced it",
		"--type", "foundry-test")
	if code != 2 {
		t.Fatalf("exit %d, want 2 (out=%q err=%q)", code, out, errS)
	}
	want := "mint failed: exec " + id + ": stdout capture marked truncated: " +
		"kept 10485760 of 10485819 bytes (cap_bytes 10485760, " +
		"stdout_truncated=true)"
	if !strings.Contains(errS, want) {
		t.Fatalf("stderr\n%q\nwant substring\n%q", errS, want)
	}
	// The refusal is exit-code-honest AND lands nothing: no evidence item.
	finding, err := findings.LoadFinding(f.c, f.fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range validation.ObjAt(finding, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == id {
			t.Fatalf("a truncated exec minted evidence: %s",
				validation.CanonCompact(e))
		}
	}
}

// TestR38bMintUntruncatedUnchanged pins the control: the same exec shape
// whose capture is marked NOT truncated mints exactly as before — the
// stdout line keeps its pinned shape and the item lands at level E4.
func TestR38bMintUntruncatedUnchanged(t *testing.T) {
	f := t20Setup(t)
	id := r38bSeedExec(t, f.c, f.fid, 0,
		"Ran 1 test in 3ms (test suite successful)\n"+
			"Suite result: ok. 1 passed; 0 failed\n",
		r38bCompleteCapture(105))
	code, out, errS := run(t, "--root", f.root, "mint", f.c.CampaignID,
		f.fid, "--exec", id, "--description", "the PoC reproduced it",
		"--type", "foundry-test")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	want := f.fid + ": minted foundry-test evidence from " + id +
		" — level E4\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestR38bHarnessBindRefusesTruncatedCapture pins the binder's refusal: a
// run whose record marks stdout truncated never maps a rung — exit 2 with
// the observed capture accounting, and verification.harness stays UNwritten
// on the invariant entry.
func TestR38bHarnessBindRefusesTruncatedCapture(t *testing.T) {
	c, root := mcCamp(t, "r38b-bind")
	execID := "EXEC-trunc"
	mcHarnessExec(t, c, execID, mcViolatedCallsLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)},
		1)
	r38bMarkRecordCapture(t, c, execID, r38bTruncatedCapture(10485819))
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (out=%q err=%q)", code, out, errS)
	}
	want := "verify: exec '" + execID + "' stdout is unfit to bind a rung: " +
		"stdout capture marked truncated: kept 10485760 of 10485819 bytes " +
		"(cap_bytes 10485760, stdout_truncated=true)"
	if !strings.Contains(errS, want) {
		t.Fatalf("stderr\n%q\nwant substring\n%q", errS, want)
	}
	if !strings.Contains(errS, "absence AND their presence are unprovable") {
		t.Fatalf("refusal must name the both-ways unprovability: %q", errS)
	}
	if entry := mcHarness(t, c); entry.Kind == validation.Obj {
		t.Fatalf("a truncated capture bound a rung: %s",
			validation.CanonCompact(entry))
	}
}

// TestR38bHarnessBindUntruncatedUnchanged pins the control: an untruncated
// capture binds exactly as before (the counterexample rung lands, the
// pinned print shape is unchanged).
func TestR38bHarnessBindUntruncatedUnchanged(t *testing.T) {
	c, root := mcCamp(t, "r38b-bind-ok")
	execID := "EXEC-ok"
	mcHarnessExec(t, c, execID, mcViolatedCallsLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)},
		1)
	r38bMarkRecordCapture(t, c, execID, r38bCompleteCapture(1086))
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", execID)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if out != "INV-1: counterexample (minicertora, "+execID+")\n" {
		t.Fatalf("out = %q", out)
	}
	if got := validation.ObjStr(mcHarness(t, c), "rung"); got != "counterexample" {
		t.Fatalf("rung = %q, want counterexample", got)
	}
}

// r38bTruncatedCapture is output_capture for a stdout capture that hit the
// 10 MiB cap (the run path's own key order).
func r38bTruncatedCapture(total int64) []validation.KV {
	return []validation.KV{
		kvT("cap_bytes", validation.VInt(10485760)),
		kvT("stdout_total_bytes", validation.VInt(total)),
		kvT("stdout_truncated", validation.VBool(true)),
		kvT("stderr_total_bytes", validation.VInt(0)),
		kvT("stderr_truncated", validation.VBool(false)),
		kvT("output_withheld", validation.VBool(false)),
	}
}

// r38bCompleteCapture is output_capture for a capture under the cap: no
// stream marked truncated.
func r38bCompleteCapture(total int64) []validation.KV {
	return []validation.KV{
		kvT("cap_bytes", validation.VInt(10485760)),
		kvT("stdout_total_bytes", validation.VInt(total)),
		kvT("stdout_truncated", validation.VBool(false)),
		kvT("stderr_total_bytes", validation.VInt(0)),
		kvT("stderr_truncated", validation.VBool(false)),
		kvT("output_withheld", validation.VBool(false)),
	}
}

// r38bMarkRecordCapture appends the given output_capture to one exec's
// on-disk record (validation.ReadJson + WriteJson round-trip; the shape is
// what the live run path writes, so it stays sandbox_execution-valid).
func r38bMarkRecordCapture(t *testing.T, c *state.Campaign, execID string,
	kvs []validation.KV) {
	t.Helper()
	path := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	rec, err := validation.ReadJson(path)
	if err != nil {
		t.Fatal(err)
	}
	rec.O = append(rec.O, validation.KV{K: "output_capture",
		V: validation.VObj(kvs...)})
	if err := validation.WriteJson(path, rec, "sandbox_execution"); err != nil {
		t.Fatalf("rewriting %s: %v", path, err)
	}
}

// r38bSeedExec writes the docker-networkless exec record these tests measure
// — capture accounting INCLUDED — and NO carrier event, returning its exec id.
//
// The record is a FIXTURE standing in for what a live run writes, and it is
// seeded out-of-band for the same reason the two harness seeds are
// (scripts/verify-full.sh's seed_p2_exec, scripts/golden-run.py's seed_exec):
// a sandbox.exec event commits the ledger to the record's digest (v1.6), so a
// record shaped AFTER its event is exactly the post-hoc edit the anchor
// refuses. These tests measure the truncation gate, not the anchor, so their
// fixture must not be that edit — before the anchor they rewrote a
// RegisterExec record in place, which is now indistinguishable from the
// tamper (TestMintRefusesAnExecRecordEditedAfterTheEvent owns that subject).
func r38bSeedExec(t *testing.T, c *state.Campaign, fid string, exitStatus int64,
	stdout string, capture []validation.KV) string {
	t.Helper()
	execID := "EXEC-" + validation.Sha256Hex([]byte(stdout))[:10]
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdoutPath, []byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderrPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := r38bRecord(c, fid, execID, exitStatus, stdout, stdoutPath,
		stderrPath, capture)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	return execID
}

// r38bRecord is the record body r38bSeedExec writes: the docker-networkless
// shape a live run produces, with the capture accounting already in place.
func r38bRecord(c *state.Campaign, fid, execID string, exitStatus int64,
	stdout, stdoutPath, stderrPath string, capture []validation.KV) validation.Value {
	return validation.VObj(
		kvT("exec_id", validation.VStr(execID)),
		kvT("campaign_id", validation.VStr(c.CampaignID)),
		kvT("profile", validation.VStr("docker-networkless")),
		kvT("finding_id", validation.VStr(fid)),
		kvT("artifact_id", validation.VNull()),
		kvT("command", validation.VStr("forge test --match-test poc")),
		kvT("policy_verdict", validation.VObj(
			kvT("allowed", validation.VBool(true)),
			kvT("violations", validation.VArr()))),
		kvT("container", validation.VNull()),
		kvT("origin", validation.VStr("locally-executed")),
		kvT("reported_by", validation.VNull()),
		kvT("started_at", validation.VStr("2026-09-11T05:06:07+00:00")),
		kvT("finished_at", validation.VStr("2026-09-11T05:06:08+00:00")),
		kvT("exit_status", validation.VInt(exitStatus)),
		kvT("stdout_path", validation.VStr(stdoutPath)),
		kvT("stderr_path", validation.VStr(stderrPath)),
		kvT("artifact_hashes", validation.VObj(
			kvT("stdout.log", validation.VStr(validation.Sha256Hex([]byte(stdout)))),
			kvT("stderr.log", validation.VStr(validation.Sha256Hex(nil))))),
		kvT("output_capture", validation.VObj(capture...)),
	)
}
