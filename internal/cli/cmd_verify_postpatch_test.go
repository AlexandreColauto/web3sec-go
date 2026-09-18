package cli

// Task 8 (G11) CLI tests — `verify <campaign> --post-patch FINDING
// --exec EXEC [--snapshot SID]`: the exit-2 matrix (missing --exec,
// unknown ids), the record write (verification.patch_regression via the
// findings.SaveFinding path), the snapshot advisory, and the fail-open pin
// (finding status byte-identical pre/post).

import (
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// ppCliExec registers one EXEC record and returns its id.
func ppCliExec(t *testing.T, c *state.Campaign, stdout string,
	exit int) string {
	t.Helper()
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile:    "docker-networkless",
		Command:    "forge test --match-test test_exploit",
		ReportedBy: "pytest-harness", ExitStatus: exit, StdoutText: stdout})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return validation.ObjStr(rec, "exec_id")
}

// ppCliCite appends one minted-style evidence item citing execID.
func ppCliCite(t *testing.T, c *state.Campaign, fid, execID string) {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ev := validation.ObjAt(f, "evidence")
	if ev.Kind != validation.Arr {
		ev = validation.VArr()
	}
	ev.A = append(ev.A, validation.VObj(
		kvT("evidence_id", validation.VStr("EV-ppbaseline")),
		kvT("level", validation.VStr("E4")),
		kvT("type", validation.VStr("foundry-test")),
		kvT("artifact_id", validation.VStr(execID)),
		kvT("description", validation.VStr("baseline reproduction")),
		kvT("command",
			validation.VStr("forge test --match-test test_exploit")),
		kvT("sandbox_profile",
			validation.VStr("docker-networkless"))))
	f.O = validation.SetOrAppend(f.O, "evidence", ev)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
}

// ppCliSetup seeds a campaign + finding + cited baseline exec.
func ppCliSetup(t *testing.T) (*state.Campaign, string, string, string) {
	t.Helper()
	c, root := t15Campaign(t, "post-patch")
	f := t15Finding(t, c, "the post-patch hypothesis", "logic-error")
	fid := validation.ObjStr(f, "finding_id")
	base := ppCliExec(t, c, "PASS: test_exploit\n", 0)
	ppCliCite(t, c, fid, base)
	return c, root, fid, base
}

// ppCliRegression reads the verification.patch_regression record.
func ppCliRegression(t *testing.T, c *state.Campaign,
	fid string) validation.Value {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(validation.ObjAt(f, "verification"), "patch_regression")
}

func TestVerifyPostPatchNeedsExec(t *testing.T) {
	c, root, fid, _ := ppCliSetup(t)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if !strings.Contains(errS, "--exec") {
		t.Fatalf("stderr %q must name the flag", errS)
	}
}

func TestVerifyPostPatchUnknownFinding(t *testing.T) {
	c, root, _, _ := ppCliSetup(t)
	exec := ppCliExec(t, c, "PASS: test_exploit\n", 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", "F-nope", "--exec", exec)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if !strings.Contains(errS, "F-nope") {
		t.Fatalf("stderr %q must name the finding", errS)
	}
	if strings.Contains(errS, "Traceback") {
		t.Fatalf("stderr carries a traceback: %q", errS)
	}
}

func TestVerifyPostPatchUnknownExec(t *testing.T) {
	c, root, fid, _ := ppCliSetup(t)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid, "--exec", "EXEC-nope")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if !strings.Contains(errS, "EXEC-nope") {
		t.Fatalf("stderr %q must name the exec", errS)
	}
}

func TestVerifyPostPatchStillReproducible(t *testing.T) {
	c, root, fid, base := ppCliSetup(t)
	next := ppCliExec(t, c, "PASS: test_exploit\n", 0)
	statusBefore := ppCliStatus(t, c, fid)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid, "--exec", next)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{fid, "still_reproducible", base, next} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q must contain %q", out, want)
		}
	}
	pr := ppCliRegression(t, c, fid)
	if validation.ObjStr(pr, "verdict") != "still_reproducible" ||
		validation.ObjStr(pr, "exec") != next || validation.ObjStr(pr, "base_exec") != base {
		t.Fatalf("record = %s", validation.CanonCompact(pr))
	}
	if validation.ObjStr(pr, "detail") == "" {
		t.Fatal("record must carry the detail")
	}
	if got := ppCliStatus(t, c, fid); got != statusBefore {
		t.Fatalf("status moved %q -> %q", statusBefore, got)
	}
}

func TestVerifyPostPatchFixed(t *testing.T) {
	c, root, fid, base := ppCliSetup(t)
	next := ppCliExec(t, c, "FAIL: test_exploit\n", 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid, "--exec", next)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "fixed") {
		t.Fatalf("output %q must name the verdict", out)
	}
	pr := ppCliRegression(t, c, fid)
	if validation.ObjStr(pr, "verdict") != "fixed" ||
		validation.ObjStr(pr, "base_exec") != base {
		t.Fatalf("record = %s", validation.CanonCompact(pr))
	}
}

func TestVerifyPostPatchNoBaseline(t *testing.T) {
	c, root := t15Campaign(t, "post-patch")
	f := t15Finding(t, c, "the lonely hypothesis", "logic-error")
	fid := validation.ObjStr(f, "finding_id")
	next := ppCliExec(t, c, "PASS: test_exploit\n", 0)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid, "--exec", next)
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "indeterminate") {
		t.Fatalf("output %q must name the verdict", out)
	}
	pr := ppCliRegression(t, c, fid)
	if validation.ObjStr(pr, "verdict") != "indeterminate" {
		t.Fatalf("record = %s", validation.CanonCompact(pr))
	}
	if validation.ObjStr(pr, "detail") != "no baseline repro exec on the finding" {
		t.Fatalf("detail = %q", validation.CanonCompact(pr))
	}
}

func TestVerifyPostPatchSnapshotRecorded(t *testing.T) {
	c, root, fid, _ := ppCliSetup(t)
	next := ppCliExec(t, c, "FAIL: test_exploit\n", 1)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid, "--exec", next,
		"--snapshot", "SID-pinned0001")
	if code != 0 {
		t.Fatalf("exit %d: out=%q err=%q", code, out, errS)
	}
	pr := ppCliRegression(t, c, fid)
	if validation.ObjStr(pr, "snapshot") != "SID-pinned0001" {
		t.Fatalf("record = %s", validation.CanonCompact(pr))
	}
	// The snapshot is recorded, not compared: the tree comparison is a
	// later step, and the output says so.
	if !strings.Contains(out, "tree comparison") {
		t.Fatalf("output %q must note the deferred tree comparison", out)
	}
}

// TestVerifyPostPatchFindingByteStable pins the fail-open law at the byte
// level: after the verdict, the finding file differs from before ONLY in
// updated_at and the new verification.patch_regression record — status,
// evidence, and everything else are byte-identical.
func TestVerifyPostPatchFindingByteStable(t *testing.T) {
	c, root, fid, _ := ppCliSetup(t)
	next := ppCliExec(t, c, "FAIL: test_exploit\n", 1)
	before, err := os.ReadFile(findings.FindingPath(c, fid))
	if err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--post-patch", fid, "--exec", next)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	after, err := os.ReadFile(findings.FindingPath(c, fid))
	if err != nil {
		t.Fatal(err)
	}
	norm := func(raw []byte, stripPR bool) string {
		v, err := validation.ParseOrdered(raw)
		if err != nil {
			t.Fatal(err)
		}
		out := validation.Value{Kind: validation.Obj}
		for _, fkv := range v.O {
			if fkv.K == "updated_at" {
				continue
			}
			if stripPR && fkv.K == "verification" {
				nv := validation.Value{Kind: validation.Obj}
				for _, vkv := range fkv.V.O {
					if vkv.K == "patch_regression" {
						continue
					}
					nv.O = append(nv.O, vkv)
				}
				// The branch creates verification holding only the new
				// record: with it stripped, an empty shell must not
				// count as a change.
				if len(nv.O) == 0 {
					continue
				}
				fkv.V = nv
			}
			out.O = append(out.O, fkv)
		}
		return validation.CanonCompact(out)
	}
	if norm(before, false) != norm(after, true) {
		t.Fatal("finding changed outside updated_at + patch_regression")
	}
}

func TestVerifySnapshotNeedsPostPatch(t *testing.T) {
	c, root := t15Campaign(t, "post-patch")
	code, _, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--snapshot", "SID-pinned0001")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "--post-patch") {
		t.Fatalf("stderr %q must name the flag", errS)
	}
}

func TestVerifyPostPatchHelp(t *testing.T) {
	c, root := t15Campaign(t, "post-patch")
	_ = c
	code, out, _ := run(t, "--root", root, "verify", "--help")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"--post-patch", "--snapshot",
		"tree comparison", "ignored with --post-patch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help must mention %q:\n%s", want, out)
		}
	}
}

// ppCliStatus reads the finding's status field.
func ppCliStatus(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(f, "status")
}
