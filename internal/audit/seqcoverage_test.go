// Port of the audit half of tests/test_sequence_guidance.py: audit §12
// flags an uncovered on-chain sequence finding, passes once a covered
// attempt is recorded, and skips malformed attempt entries per-entry instead
// of degrading the whole section.
package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/sandbox"
	"websec/internal/sequencepoc"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const seqForkCmd = "forge test --fork-url http://127.0.0.1:8545 " +
	"--fork-block-number 20000000 --match-test test_sequence"

func seqKV(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// seqSet is the ordered-dict assignment.
func seqSet(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, seqKV(key, v))
}

// seqList is listOf over a Null/non-array value.
func seqList(v validation.Value) []validation.Value {
	if v.Kind == validation.Arr {
		return v.A
	}
	return nil
}

// seqSpec is SPEC in tests/test_sequence_guidance.py.
func seqSpec(t *testing.T, fid string) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(`{
      "spec_id": "SEQ-TEST-04",
      "finding_id": "` + fid + `",
      "actors": {"attacker": "anvil:0",
                 "victim": "0x` + strings.Repeat("aa", 20) + `"},
      "steps": [
        {"step": 1, "actor": "attacker", "target": "0x` +
		strings.Repeat("cd", 20) + `",
         "function": "deposit(uint256)", "args": ["1"]},
        {"step": 2, "actor": "victim", "target": "0x` +
		strings.Repeat("cd", 20) + `",
         "function": "drain()"}],
      "final_assertions": []}`))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// seqAuditCampaign is _mk + _pin_fork: a live POSSIBLE finding declaring the
// two-step SEQ on a campaign with a chain (fork) pin, so §12's
// onchain_sequence_required predicate is in effect.
func seqAuditCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		seqKV("title", validation.VStr("multi-tx sequence bug")),
		seqKV("root_cause", validation.VObj(
			seqKV("class", validation.VStr("access-control")),
			seqKV("description", validation.VStr("missing check across two calls")))),
		seqKV("affected", validation.VArr(validation.VObj(
			seqKV("path", validation.VStr("src/V.sol")),
			seqKV("contract", validation.VStr("V")),
			seqKV("function", validation.VStr("claim"))))),
		seqKV("attacker", validation.VObj(
			seqKV("profile", validation.VStr("arbitrary EOA")),
			seqKV("capabilities", validation.VArr()))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = seqSet(f.O, "status", validation.VStr("POSSIBLE"))
	f.O = seqSet(f.O, "exploit_sequence", validation.VArr(
		validation.VObj(
			seqKV("step", validation.VInt(1)),
			seqKV("actor", validation.VStr("alice")),
			seqKV("action", validation.VStr("deposit"))),
		validation.VObj(
			seqKV("step", validation.VInt(2)),
			seqKV("actor", validation.VStr("bob")),
			seqKV("action", validation.VStr("drain")))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "C.sol"), []byte("// c"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, src, nil, nil); err != nil {
		t.Fatal(err)
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	chain := validation.VObj(
		seqKV("chain_id", validation.VInt(1)),
		seqKV("fork_block", validation.VInt(1000)),
		seqKV("rpc", validation.VStr("local-anvil")))
	if _, err := snapshot.AttachChainPin(c, *sid, chain); err != nil {
		t.Fatal(err)
	}
	return c, fid
}

// seqSection reads sections.sequence_coverage out of a full audit report.
func seqSection(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	Setup() // the CLI calls this before audit_campaign
	rep, err := AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	sec := validation.ObjAt(validation.ObjAt(rep, "sections"), "sequence_coverage")
	if sec.Kind != validation.Obj {
		t.Fatalf("section = %v", sec)
	}
	return sec
}

func seqInt(t *testing.T, sec validation.Value, key string) int64 {
	t.Helper()
	v := validation.ObjAt(sec, key)
	if v.Kind != validation.Int {
		t.Fatalf("%s = %v, want int", key, v)
	}
	return v.I
}

func seqPlant(t *testing.T, c *state.Campaign, fid string,
	mutate func(validation.Value) validation.Value) {
	t.Helper()
	p := findings.FindingPath(c, fid)
	f, err := validation.ReadJson(p)
	if err != nil {
		t.Fatal(err)
	}
	f = mutate(f)
	if err := os.WriteFile(p, []byte(validation.DumpIndented(f)),
		0o644); err != nil {
		t.Fatal(err)
	}
}

// seqStageCovered writes the covered spec + result pair into rec's output
// dir (the same shape the runner produces).
func seqStageCovered(t *testing.T, c *state.Campaign, fid string,
	rec validation.Value) {
	t.Helper()
	spec := seqSpec(t, fid)
	out := filepath.Dir(validation.ObjStr(rec, "stdout_path"))
	if err := os.WriteFile(filepath.Join(out, "spec.json"),
		sequencepoc.CanonicalJSON(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	result := validation.VObj(
		seqKV("spec_hash", validation.VStr(sequencepoc.SpecHash(spec))),
		seqKV("steps", validation.VArr(
			validation.VObj(
				seqKV("step", validation.VInt(1)),
				seqKV("actor", validation.VStr("attacker")),
				seqKV("tx_hash", validation.VStr("0x"+
					strings.Repeat("1", 64))),
				seqKV("status", validation.VStr("success")),
				seqKV("revert_reason", validation.VNull())),
			validation.VObj(
				seqKV("step", validation.VInt(2)),
				seqKV("actor", validation.VStr("victim")),
				seqKV("tx_hash", validation.VStr("0x"+
					strings.Repeat("2", 64))),
				seqKV("status", validation.VStr("success")),
				seqKV("revert_reason", validation.VNull())))),
		seqKV("final_assertions", validation.VArr()),
		seqKV("overall", validation.VStr("pass")),
		seqKV("generated_at", validation.VStr("2026-07-15T00:00:00Z")))
	if err := os.WriteFile(filepath.Join(out, "sequence_result.json"),
		[]byte(validation.DumpIndented(result)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAuditSectionFlagsUncovered(t *testing.T) {
	c, _ := seqAuditCampaign(t)
	sec := seqSection(t, c)
	if n := seqInt(t, sec, "required"); n != 1 {
		t.Errorf("required = %d, want 1", n)
	}
	if n := seqInt(t, sec, "covered"); n != 0 {
		t.Errorf("covered = %d, want 0", n)
	}
	if v := validation.ObjAt(sec, "ok"); v.Kind != validation.Bool || v.B {
		t.Errorf("ok = %v, want false", v)
	}
	rows := seqList(validation.ObjAt(sec, "rows"))
	if len(rows) != 1 || validation.ObjAt(rows[0], "problem").Kind != validation.Str {
		t.Fatalf("rows = %s", validation.DumpIndented(validation.ObjAt(sec, "rows")))
	}
}

func TestAuditSectionPassesWhenCovered(t *testing.T) {
	c, fid := seqAuditCampaign(t)
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile:    "fork-runner",
		Command:    seqForkCmd,
		ReportedBy: "pytest-harness",
		FindingID:  &fid,
		StdoutText: "PASS: test_sequence\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	seqStageCovered(t, c, fid, rec)
	tier, execID := "T4", validation.ObjStr(rec, "exec_id")
	if _, err := reproduction.RecordAttempt(c, fid, "reproduced",
		reproduction.RecordOpts{Tier: &tier, ExecID: &execID}); err != nil {
		t.Fatal(err)
	}
	sec := seqSection(t, c)
	if n := seqInt(t, sec, "required"); n != 1 {
		t.Errorf("required = %d, want 1", n)
	}
	if n := seqInt(t, sec, "covered"); n != 1 {
		t.Errorf("covered = %d, want 1", n)
	}
	if v := validation.ObjAt(sec, "ok"); v.Kind != validation.Bool || !v.B {
		t.Errorf("ok = %v, want true", v)
	}
}

func TestAuditSkipsMalformedAttemptEntries(t *testing.T) {
	// M4 pin: one bad attempt entry must not throw the whole §12 section
	// into the degraded branch (required: None) — it is skipped per-entry.
	c, fid := seqAuditCampaign(t)
	seqPlant(t, c, fid, func(f validation.Value) validation.Value {
		f.O = seqSet(f.O, "verification", validation.VObj(
			seqKV("reproduction", validation.VObj(
				seqKV("attempts", validation.VArr(
					validation.VStr("bad"),
					validation.VNull(),
					validation.VObj(seqKV("artifact_id",
						validation.VStr("EXEC-nope")))))))))
		return f
	})
	sec := seqSection(t, c)
	if n := seqInt(t, sec, "required"); n != 1 {
		t.Fatalf("required = %d, want 1 (degraded?)", n)
	}
	if n := seqInt(t, sec, "covered"); n != 0 {
		t.Errorf("covered = %d, want 0", n)
	}
	if v := validation.ObjAt(sec, "ok"); v.Kind != validation.Bool || v.B {
		t.Errorf("ok = %v, want false", v)
	}
	for _, p := range seqList(validation.ObjAt(sec, "problems")) {
		if p.Kind == validation.Str && strings.Contains(p.S, "section failed") {
			t.Errorf("section degraded: %q", p.S)
		}
	}
}
