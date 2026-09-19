// Port of tests/test_fork_poc_immunize.py — the fork-PoC half: the latest
// required step before the bounty gate. Only a ledger-traced SUCCEEDED
// fork-runner exec proves a finding's PoC; unit-harness evidence (E4) proves
// semantics, not mainnet.
package forkpoc

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/completion"
	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// forkPocAPI adapts this package to completion.ForkPocAPI so the proof runs
// against the REAL fork_poc_evidence (Python's function-level import).
type forkPocAPI struct{}

func (forkPocAPI) ForkPocEvidence(c *state.Campaign,
	f validation.Value) (validation.Value, *string, error) {
	return ForkPocEvidence(c, f)
}

// fixtureCampaign is the `camp` fixture: a campaign with a pinned target.
func fixtureCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "t")
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "src", "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// execRecord writes a finished EXEC record (sandbox.register_exec's ledger
// shape) and returns it.
func execRecord(t *testing.T, c *state.Campaign, execID, profile,
	findingID, command string, exitStatus int64,
	stdoutText string) validation.Value {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, "stdout.log")
	stderr := filepath.Join(dir, "stderr.log")
	if err := os.WriteFile(stdout, []byte(stdoutText), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stderr, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr(profile)),
		kv("finding_id", validation.VStr(findingID)),
		kv("artifact_id", validation.VNull()),
		kv("command", validation.VStr(command)),
		kv("exit_status", validation.VInt(exitStatus)),
		kv("stdout_path", validation.VStr(stdout)),
		kv("stderr_path", validation.VStr(stderr)),
	)
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
	return rec
}

// evidenceItem is conftest.evidence_item.
func evidenceItem(rec validation.Value, level, typ, desc, eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr(desc)),
		kv("sandbox_profile", validation.ObjAt(rec, "profile")),
		kv("artifact_id", validation.ObjAt(rec, "exec_id")),
	)
}

// seedGlobalMemory is conftest.seed_global_memory_row: one approved row in
// the (test-isolated) user-global shared-memory tier.
func seedGlobalMemory(t *testing.T) {
	t.Helper()
	row := validation.VObj(
		kv("memory_id", validation.VStr("MEM-shared01")),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Shared memory pattern")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Seeded incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	wrapper := validation.VArr(validation.VObj(
		kv("program_key", validation.VStr("test|other|-")),
		kv("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("row", row),
		kv("scope", validation.VStr("global"))))
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return wrapper.A, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(
			func(string) ([]validation.Value, error) { return nil, nil })
	})
}

// forkpocFloorSeq mints unique ids for the manual floor items the fixtures
// attach before a status whose evidence floor is above E0.
var forkpocFloorSeq int

// floorEvidence attaches a manual (non-exec) item at *level* — the evidence a
// status floor demands before the status stamp. It is the finding's first rise
// above E0, so it pays the discovery slot once; the exec-backed E4 evidence
// confirmUnitOnly attaches afterwards rides that same rise for free.
func floorEvidence(t *testing.T, c *state.Campaign, fid, level string) {
	t.Helper()
	forkpocFloorSeq++
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr(
			fmt.Sprintf("EV-forkfloor-%04d", forkpocFloorSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(
			"manual code reading at triage: the path to the sink is reachable")))); err != nil {
		t.Fatalf("add floor evidence %s: %v", level, err)
	}
}

// confirmUnitOnly is _confirm_unit_only: a CONFIRMED finding proven by a UNIT
// harness (E4) alone — the exact state the new stage exists to reject.
func confirmUnitOnly(t *testing.T, c *state.Campaign) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(
			"Rescue function drains user balances without role check")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("cwe", validation.VStr("CWE-284")),
			kv("description", validation.VStr("rescue() sends every token "+
				"to the caller, no role check")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("V")),
			kv("function", validation.VStr("rescue"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	// R3-3: POSSIBLE carries an E2 floor, so the shared advance helper earns
	// it BEFORE the status stamp (evidence floors gate every status).
	floorEvidence(t, c, fid, "E2")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	rec := execRecord(t, c, "EXEC-0000000001", "docker-networkless", fid,
		"forge test --match-test test_exploit", 0, "PASS: test_exploit\n")
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E4",
		"foundry-test", "unit harness repro", "EV-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"no role check found"); err != nil {
		t.Fatal(err)
	}
	seedGlobalMemory(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = append(ver.O, kv("reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T1")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr()))))
	vf.O = setOrAppendValue(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "unit gate passed",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	return fid
}

// setOrAppendValue is the ordered-dict assignment.
func setOrAppendValue(o []validation.KV, key string,
	v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, kv(key, v))
}

// forkExec is _fork_exec: a succeeded fork-runner run on the pinned fork.
func forkExec(t *testing.T, c *state.Campaign, fid string) validation.Value {
	t.Helper()
	return execRecord(t, c, "EXEC-0000000002", "fork-runner", fid,
		"forge test --fork-url http://127.0.0.1:8545 "+
			"--fork-block-number 20000000 --match-test test_exploit", 0,
		"PASS: test_exploit\n")
}

// mint installs the real fork_poc evidence seam (Python's function-level
// import) and restores the default afterwards.
func mint(t *testing.T) {
	t.Helper()
	completion.SetForkPocEvidence(forkPocAPI{})
	t.Cleanup(func() { completion.SetForkPocEvidence(nil) })
}

// test_proof_vacuously_true_without_confirmed.
func TestProofVacuouslyTrueWithoutConfirmed(t *testing.T) {
	c := fixtureCampaign(t)
	proof, err := completion.ProofStatus(c, "mainnet-fork-poc")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(proof, "done").Kind != validation.Bool ||
		!validation.ObjAt(proof, "done").B {
		t.Fatalf("done = %s, want true", validation.PyRepr(validation.ObjAt(proof, "done")))
	}
	if note := validation.ObjStr(proof, "note"); !strings.Contains(note, "vacuously") {
		t.Fatalf("note = %q, want 'vacuously'", note)
	}
}

// test_confirmed_unit_only_lacks_fork_proof.
func TestConfirmedUnitOnlyLacksForkProof(t *testing.T) {
	c := fixtureCampaign(t)
	mint(t)
	fid := confirmUnitOnly(t, c)
	proof, err := completion.ProofStatus(c, "mainnet-fork-poc")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(proof, "done").Kind != validation.Bool ||
		validation.ObjAt(proof, "done").B {
		t.Fatalf("done = %s, want false",
			validation.PyRepr(validation.ObjAt(proof, "done")))
	}
	found := false
	for _, m := range listAt(proof, "missing") {
		if m.Kind == validation.Str && strings.Contains(m.S, fid) {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing does not name %s: %s", fid,
			validation.PyRepr(validation.ObjAt(proof, "missing")))
	}
	ok, why, err := ForkPocStatus(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("unit-only finding must not have a proven fork PoC")
	}
	if !strings.Contains(why, "fork") {
		t.Fatalf("reason = %q, want 'fork'", why)
	}
	gaps, err := ForkPocGaps(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) == 0 {
		t.Fatal("fork_poc_gaps must report one gap")
	}
}

// test_fork_runner_exec_proves_the_poc.
func TestForkRunnerExecProvesThePoc(t *testing.T) {
	c := fixtureCampaign(t)
	mint(t)
	fid := confirmUnitOnly(t, c)
	rec := forkExec(t, c, fid)
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E5",
		"fork-test", "mainnet fork repro", "EV-f")); err != nil {
		t.Fatal(err)
	}
	ok, why, err := ForkPocStatus(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.Contains(why, validation.ObjStr(rec, "exec_id")) {
		t.Fatalf("status = %v %q, want proven and naming %s", ok, why,
			validation.ObjStr(rec, "exec_id"))
	}
	proof, err := completion.ProofStatus(c, "mainnet-fork-poc")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(proof, "done").Kind != validation.Bool ||
		!validation.ObjAt(proof, "done").B {
		t.Fatalf("done = %s, want true",
			validation.PyRepr(validation.ObjAt(proof, "done")))
	}
	gaps, err := ForkPocGaps(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none", gaps)
	}
}

// test_forged_fork_profile_is_rejected: an evidence item CLAIMING fork-runner
// while the ledger says docker-networkless is a lie the proof refuses.
func TestForgedForkProfileIsRejected(t *testing.T) {
	c := fixtureCampaign(t)
	mint(t)
	fid := confirmUnitOnly(t, c)
	rec := execRecord(t, c, "EXEC-0000000003", "docker-networkless", fid,
		"forge test --match-test test_exploit", 0, "PASS: test_exploit\n")
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = setOrAppendValue(f.O, "evidence", validation.VArr(
		append(listAt(f, "evidence"), validation.VObj(
			kv("evidence_id", validation.VStr("EV-fake")),
			kv("level", validation.VStr("E5")),
			kv("type", validation.VStr("fork-test")),
			kv("description", validation.VStr("claims mainnet fork repro")),
			kv("sandbox_profile", validation.VStr("fork-runner")),
			kv("artifact_id", validation.ObjAt(rec, "exec_id"))))...))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	ok, why, err := ForkPocStatus(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a forged fork profile must not prove the PoC")
	}
	if !strings.Contains(why, "ledger") {
		t.Fatalf("reason = %q, want 'ledger'", why)
	}
}

// test_failed_fork_run_proves_nothing: the proof checks the ledger's
// exit_status even when the evidence claims success.
func TestFailedForkRunProvesNothing(t *testing.T) {
	c := fixtureCampaign(t)
	mint(t)
	fid := confirmUnitOnly(t, c)
	rec := execRecord(t, c, "EXEC-0000000004", "fork-runner", fid,
		"forge test --fork-url x", 1, "FAIL: test_exploit\n")
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = setOrAppendValue(f.O, "evidence", validation.VArr(
		append(listAt(f, "evidence"), validation.VObj(
			kv("evidence_id", validation.VStr("EV-fake")),
			kv("level", validation.VStr("E5")),
			kv("type", validation.VStr("fork-test")),
			kv("description", validation.VStr("claims mainnet fork repro")),
			kv("sandbox_profile", validation.VStr("fork-runner")),
			kv("artifact_id", validation.ObjAt(rec, "exec_id"))))...))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	ok, why, err := ForkPocStatus(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a failed fork run must not prove the PoC")
	}
	if !strings.Contains(why, "ledger") {
		t.Fatalf("reason = %q, want 'ledger'", why)
	}
}

// --- docker e2e (WEBV2_DOCKER_TESTS=1) -------------------------------------

// TestDockerForkRunnerProvesThePoc runs a REAL forge fork test in the foundry
// image (anvil as the fork endpoint), registers the exec from its captured
// output, mints it as E5 and asserts the proof holds. Gated: the default
// suite must stay pure-logic.
func TestDockerForkRunnerProvesThePoc(t *testing.T) {
	if os.Getenv("WEBV2_DOCKER_TESTS") == "" {
		t.Skip("WEBV2_DOCKER_TESTS=1 to run")
	}
	out, err := runFoundryForkTest(t, "fork-poc-e2e", nil)
	if err != nil {
		t.Fatalf("forge fork run failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[PASS] test_exploit") {
		t.Fatalf("forge fork run did not pass:\n%s", out)
	}
	c := fixtureCampaign(t)
	mint(t)
	fid := confirmUnitOnly(t, c)
	rec := execRecord(t, c, "EXEC-0000000005", "fork-runner", fid,
		"forge test --fork-url http://127.0.0.1:8545 "+
			"--match-test test_exploit", 0, out)
	if _, err := findings.AddEvidence(c, fid, evidenceItem(rec, "E5",
		"fork-test", "real mainnet-fork-style repro", "EV-docker")); err != nil {
		t.Fatal(err)
	}
	ok, why, err := ForkPocStatus(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("a real forge fork run must prove the PoC: %q", why)
	}
	gaps, err := ForkPocGaps(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none", gaps)
	}
}

// runFoundryForkTest streams testdata/<name> into the foundry image (the
// container has no visibility into the Go test's temp dirs), optionally
// replaces src/Counter.sol with patch, starts a local anvil and runs the fork
// test against it. Returns the combined output and the command error.
func runFoundryForkTest(t *testing.T, name string,
	patch []byte) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", "run", "-i", "--rm", foundryImage,
		"mkdir -p /tmp/w && tar -x -C /tmp/w && cd /tmp/w && "+
			"(anvil --silent >/tmp/anvil.log 2>&1 &) && sleep 2 && "+
			"forge test --fork-url http://127.0.0.1:8545 "+
			"--match-test test_exploit -vv")
	cmd.Stdin = fixtureTar(t, name, patch)
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}

// fixtureTar builds the tar stream for one testdata fixture, applying patch
// over src/Counter.sol when non-nil.
func fixtureTar(t *testing.T, name string, patch []byte) *bytes.Buffer {
	t.Helper()
	root := filepath.Join("testdata", name)
	files := map[string][]byte{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if patch != nil {
		files[filepath.Join("src", "Counter.sol")] = patch
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for rel := range files {
		names = append(names, rel)
	}
	sort.Strings(names)
	for _, rel := range names {
		hdr := &tar.Header{Name: rel, Mode: 0o644,
			Size: int64(len(files[rel]))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[rel]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

// foundryImage is the one image the docker e2e uses.
const foundryImage = "ghcr.io/foundry-rs/foundry:latest"

// copyTree copies the small fixture tree (regular files, no symlinks).
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
