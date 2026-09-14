package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestExecEventsWithoutRecordsBurnRed pins r13 issue 5: deleting
// execs/EXEC-*/ wholesale left the ledger asserting a run that happened
// with zero problems from section 3 — the projection law has to cover
// execs too: an event names a record, the record must exist.
func TestExecEventsWithoutRecordsBurnRed(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "ExecGhostProgram", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Hand-write one finished exec record + its ledger event (the shape
	// cmd exec produces).
	eid := "EXEC-0000000001"
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
	ref := eid
	if _, err := c.Log("sandbox.exec.registered", &ref, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("sandbox.exec", &ref, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := Execs(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(rep, "ok").B {
		t.Fatalf("complete exec must be green: %s",
			validation.DumpsOrdered(rep, false))
	}
	// rm -rf the record; the events remain.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rep, err = Execs(c)
	if err != nil {
		t.Fatal(err)
	}
	body := validation.DumpsOrdered(rep, false)
	if objAt(rep, "ok").B || !strings.Contains(body, eid) {
		t.Fatalf("ghost exec events must burn red naming %s: %s",
			eid, body)
	}
}

// TestPlantedRecordStaysUnpoliced pins the r16 REFUSAL: the
// records-without-events direction cannot distinguish the frozen
// golden's legitimate seeded records from hand plants (byte-identical
// shapes), so the audit does not flag either. The mirror direction
// (event without its record) stays policed (r13 test above). If a
// provenance mechanism ever marks seeded records, revisit — until
// then a silent-but-accurate audit beats a false fire on the golden.
func TestPlantedRecordStaysUnpoliced(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Planted Exec Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	eid := "EXEC-realreal01"
	dir := filepath.Join(c.ExecsDir, eid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	if err := os.WriteFile(stdout, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mk := func(id string) validation.Value {
		return validation.VObj(
			validation.KV{K: "exec_id", V: validation.VStr(id)},
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
	}
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		mk(eid), "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	ref := eid
	if _, err := c.Log("sandbox.exec.registered", &ref, nil); err != nil {
		t.Fatal(err)
	}
	fake := "EXEC-forged002"
	fdir := filepath.Join(c.ExecsDir, fake)
	if err := os.MkdirAll(fdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fdir, "stdout.log"), []byte("y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(fdir, "exec_record.json"),
		mk(fake), "sandbox_execution"); err != nil {
		t.Fatal(err)
	}
	rep, err := Execs(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(rep, "ok").B {
		t.Fatalf("the refused direction must not fire (golden depends "+
			"on its silence): %s", validation.DumpsOrdered(rep, false))
	}
}
