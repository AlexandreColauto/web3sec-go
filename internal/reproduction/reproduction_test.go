package reproduction

// P2 reproduction tests — 1:1 ports of the live Python twins:
// tests/test_sandbox_repro.py (E4 gate, T0 reachability),
// tests/test_mint_citation.py (citation preservation + rollback),
// tests/test_evidence_integrity.py (idempotency, forge gates, exec reuse),
// tests/test_independent_verification.py (E6),
// tests/test_runbook_flow.py (the RUNBOOK confirm flow).

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/orchestrator"
	"websec/internal/sandbox"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func newCampaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c
}

// hypoPayload is test_independent_verification.py::hypo (the bridge default).
func hypoPayload(class string, extra ...validation.KV) validation.Value {
	o := []validation.KV{
		kv("title", validation.VStr(
			"Bridge relayer can replay a finalized message on chain B")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr(
				"the finalized-branch check is keyed on a source-chain id "+
					"that is not verified")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Bridge.sol")),
			kv("function", validation.VStr("finalizeDeposit"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr("bridge-canonical")),
			kv("extractable_usd", validation.VInt(4000000)))),
	}
	return validation.VObj(append(o, extra...)...)
}

func ingest(t *testing.T, c *state.Campaign, payload validation.Value,
	trajectory, stage string) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, payload, trajectory, stage, "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return validation.ObjStr(f, "finding_id")
}

// evSeq numbers the manual fixture items minted by manualEvidence so every
// evidence_id is unique (the schema pins the EV-<token> shape).
var evSeq int

// manualEvidence is the fixture-only evidence idiom: one hand-authored item at
// the given level. It exists so a PLAIN fixture advance can satisfy the status
// evidence floors (POSSIBLE needs E2) without faking execution evidence — E4
// and above still have to come from a real sandbox.RegisterExec record.
func manualEvidence(t *testing.T, c *state.Campaign, fid, level, desc string) {
	t.Helper()
	evSeq++
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-manual-"+strconv.Itoa(evSeq))),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("manual")),
		kv("description", validation.VStr(desc)),
	)
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add manual evidence: %v", err)
	}
}

// advancePossible is the shared fixture advance to POSSIBLE: attach the E2
// reachability item the status floor now demands, then make the move. Tests
// whose subject is NOT the floor ride this; a test that asserts the floor
// refusal itself calls findings.Transition directly on a bare finding.
func advancePossible(t *testing.T, c *state.Campaign, fid, reason string) {
	t.Helper()
	manualEvidence(t, c, fid, "E2",
		"reachability: unguarded entry point is callable by an arbitrary EOA")
	if _, err := findings.Transition(c, fid, "POSSIBLE", reason, "", "", false); err != nil {
		t.Fatalf("transition POSSIBLE: %v", err)
	}
}

// toPossible is to_possible: ingest + transition to POSSIBLE.
func toPossible(t *testing.T, c *state.Campaign, payload validation.Value) string {
	t.Helper()
	fid := ingest(t, c, payload, "integration", "")
	advancePossible(t, c, fid, "triage")
	return fid
}

// sandboxedExec is conftest.sandboxed_exec.
func sandboxedExec(t *testing.T, c *state.Campaign, findingID, profile,
	reportedBy string) validation.Value {
	t.Helper()
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: profile, Command: "forge test --match-test test_exploit",
		FindingID: optStr(findingID), ReportedBy: reportedBy,
		StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return rec
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optIntPtr(i int) *int { return &i }

// registerExec is SB.register_exec with explicit stdout/exit.
func registerExec(t *testing.T, c *state.Campaign, profile, command,
	stdout, reportedBy string, exit int, findingID string) validation.Value {
	t.Helper()
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: profile, Command: command, ReportedBy: reportedBy,
		ExitStatus: exit, FindingID: optStr(findingID), StdoutText: stdout})
	if err != nil {
		t.Fatalf("register exec: %v", err)
	}
	return rec
}

// Port of test_sandbox_repro.py::test_e4_evidence_rejects_host_profile.
func TestE4EvidenceRejectsHostProfile(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	sb, err := sandbox.NewSandbox(c, "host-readonly")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := sb.Run("echo x", sandbox.RunOpts{Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	fid := ingest(t, c, validation.VObj(
		kv("title", validation.VStr(
			"Public mint drains vault through unguarded path")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("missing role check on mint")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("mint"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))),
		"code", "")
	_, err = MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "unit repro",
		nil, nil)
	if err == nil || !strings.Contains(err.Error(), "sandbox") {
		t.Fatalf("err = %v, want a sandbox-profile refusal", err)
	}
}

// solSource is test_sandbox_repro.py::SOL.
const solSource = `
contract Vault {
    uint256 public total;
    function deposit(uint256 a) external { total += a; }
    function _internal(uint256 a) internal { total -= a; }
    function pull(uint256 a) external { _internal(a); }
    function guarded(address o) external onlyOwner { _internal(a_amount(o)); }
}
`

// Port of test_sandbox_repro.py::test_t0_static_reachability. The structural
// index itself is P3 (unported): the seam is installed with the exact node
// shape structural_index emits, so the reachability ALGORITHM under test is
// the real one.
func TestT0StaticReachability(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	target := filepath.Join(t.TempDir(), "t")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte(solSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatalf("pin: %v", err)
	}
	index := validation.VObj(kv("nodes", validation.VArr(
		validation.VObj(kv("id", validation.VStr("fn-deposit")),
			kv("kind", validation.VStr("function")),
			kv("name", validation.VStr("deposit")),
			kv("is_entry_point", validation.VBool(true))),
		validation.VObj(kv("id", validation.VStr("fn-pull")),
			kv("kind", validation.VStr("function")),
			kv("name", validation.VStr("pull")),
			kv("is_entry_point", validation.VBool(true))),
		validation.VObj(kv("id", validation.VStr("fn-guarded")),
			kv("kind", validation.VStr("function")),
			kv("name", validation.VStr("guarded")),
			kv("is_entry_point", validation.VBool(true)),
			kv("guarded_by", validation.VStr("onlyOwner"))),
	)))
	SetStructuralIndex(StructuralIndexAPI{
		UnguardedEntryPoints: func(idx validation.Value) []validation.Value {
			var out []validation.Value
			for _, n := range validation.ObjAt(idx, "nodes").A {
				if !boolOf(validation.ObjAt(n, "is_entry_point")) {
					continue
				}
				if validation.ObjAt(n, "guarded_by").Kind == validation.Null {
					out = append(out, n)
				}
			}
			return out
		},
		PathExists: func(_ validation.Value, src, dst string) ([]string, bool) {
			if src == "fn-pull" && dst == "fn-pull" {
				return []string{"fn-pull"}, true
			}
			return nil, false
		},
	})
	t.Cleanup(func() { SetStructuralIndex(StructuralIndexAPI{}) })
	fid := ingest(t, c, validation.VObj(
		kv("title", validation.VStr(
			"Attacker shrinks total accounting via pull path")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("economic-invariant")),
			kv("description", validation.VStr("internal path reachable")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("t/Vault.sol")),
			kv("function", validation.VStr("pull"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))),
		"code", "")
	res, err := StaticReachability(c, fid, index)
	if err != nil {
		t.Fatal(err)
	}
	if !boolOf(validation.ObjAt(res, "reachable")) {
		t.Fatalf("reachable = false: %s", validation.CanonCompact(res))
	}
	if len(validation.ObjAt(res, "witness").A) == 0 {
		t.Error("witness must be non-empty")
	}
	updated, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	levels := map[string]bool{}
	for _, e := range validation.ObjAt(updated, "evidence").A {
		levels[validation.ObjStr(e, "level")] = true
	}
	if !levels["E2"] {
		t.Errorf("evidence levels = %v, want E2 (T0 mints E2)", levels)
	}
}

// TestStaticReachabilityGuardBranches pins the two early returns.
func TestStaticReachabilityGuardBranches(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	// no function recorded
	fid := ingest(t, c, validation.VObj(
		kv("title", validation.VStr("A hypothesis with no function at all")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr("mechanism described in detail")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))),
		"code", "")
	res, err := StaticReachability(c, fid, validation.VObj(
		kv("nodes", validation.VArr())))
	if err != nil {
		t.Fatal(err)
	}
	if boolOf(validation.ObjAt(res, "reachable")) ||
		validation.ObjStr(res, "reason") != "no function recorded on finding" {
		t.Fatalf("res = %s", validation.CanonCompact(res))
	}
	// function not in the index
	fid2 := ingest(t, c, validation.VObj(
		kv("title", validation.VStr("A hypothesis naming a missing function")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr("mechanism described in detail")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("ghost"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))),
		"code", "")
	res2, err := StaticReachability(c, fid2, validation.VObj(
		kv("nodes", validation.VArr())))
	if err != nil {
		t.Fatal(err)
	}
	if boolOf(validation.ObjAt(res2, "reachable")) ||
		validation.ObjStr(res2, "reason") != "function 'ghost' not in index" {
		t.Fatalf("res2 = %s", validation.CanonCompact(res2))
	}
}

// integrityHypo is test_evidence_integrity.py::_hypo.
func integrityHypo(t *testing.T, c *state.Campaign, class string) string {
	t.Helper()
	return ingest(t, c, validation.VObj(
		kv("title", validation.VStr("integrity hypothesis "+class)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr(
				"a hypothesis exercising evidence integrity rules")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/T.sol")),
			kv("contract", validation.VStr("T")),
			kv("function", validation.VStr("withdraw"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("EOA")),
			kv("capabilities", validation.VArr())))),
		"code", "11")
}

// Port of test_evidence_integrity.py::test_mint_repro_evidence_is_idempotent.
func TestMintReproEvidenceIsIdempotent(t *testing.T) {
	c := newCampaign(t, "integrity")
	fid := integrityHypo(t, c, "reentrancy")
	rec := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	execID := validation.ObjStr(rec, "exec_id")
	tier := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	out1, err := MintReproEvidence(c, fid, execID, "drains via reentry", &tier, nil)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := MintReproEvidence(c, fid, execID, "drains via reentry", &tier, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(out1, "finding_id") != validation.ObjStr(out2, "finding_id") {
		t.Error("idempotent mint must return the same finding")
	}
	same := 0
	for _, e := range validation.ObjAt(out1, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			same++
		}
	}
	if same != 1 {
		t.Errorf("evidence items citing the exec = %d, want 1", same)
	}
}

// TestMintReproEvidenceSameExecDifferentType pins feedback-triage A2: the
// reference keyed idempotency on the exec alone, so minting the same exec
// under a second evidence type silently hit the no-op branch and never
// landed. Fixed: the (exec, type) pair is the key — a second type mints, a
// repeat of the same type is still a no-op.
func TestMintReproEvidenceSameExecDifferentType(t *testing.T) {
	c := newCampaign(t, "integrity2")
	fid := integrityHypo(t, c, "reentrancy")
	rec := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	execID := validation.ObjStr(rec, "exec_id")
	tier := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	// First mint: no explicit type → tier-derived foundry-test (E4).
	out1, err := MintReproEvidence(c, fid, execID, "drains via reentry",
		&tier, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Second mint: same exec, explicit second type → must land.
	diff := "differential"
	out2, err := MintReproEvidence(c, fid, execID, "differential check", &tier,
		&diff)
	if err != nil {
		t.Fatalf("second-type mint refused: %v", err)
	}
	count := map[string]int{}
	for _, e := range validation.ObjAt(out2, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			count[validation.ObjStr(e, "type")]++
		}
	}
	if count["foundry-test"] != 1 || count["differential"] != 1 {
		t.Fatalf("evidence by type = %v, want one foundry-test and one "+
			"differential", count)
	}
	// Third mint: same exec, same type as the first → still a no-op.
	out3, err := MintReproEvidence(c, fid, execID, "again", &tier, nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(out3, "finding_id") != validation.ObjStr(out1, "finding_id") ||
		len(validation.ObjAt(out3, "evidence").A) != len(validation.ObjAt(out2, "evidence").A) {
		t.Fatal("same-(exec,type) mint must be an idempotent no-op")
	}
}

// Port of test_evidence_integrity.py::test_mint_reject_forge_no_tests.
func TestMintRejectForgeNoTests(t *testing.T) {
	c := newCampaign(t, "integrity")
	fid := integrityHypo(t, c, "reentrancy")
	rec := registerExec(t, c, "docker-networkless",
		"forge test --match-test none",
		"No tests found in test\nRan 0 tests\n", "operator", 0, fid)
	tier := "T2"
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "nothing ran",
		&tier, nil)
	if err == nil || !strings.Contains(err.Error(), "No tests found") {
		t.Fatalf("err = %v", err)
	}
}

// Port of test_evidence_integrity.py::test_mint_reject_failing_forge.
func TestMintRejectFailingForge(t *testing.T) {
	c := newCampaign(t, "integrity")
	fid := integrityHypo(t, c, "reentrancy")
	rec := registerExec(t, c, "docker-networkless",
		"forge test --match-test poc",
		"Ran 1 test for test/poc.t.sol\n[FAIL] poc\n", "operator", 0, fid)
	tier := "T2"
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "suite failed",
		&tier, nil)
	if err == nil || !strings.Contains(err.Error(), "failing") {
		t.Fatalf("err = %v", err)
	}
}

// Port of test_evidence_integrity.py::test_record_attempt_rejects_reused_exec.
func TestRecordAttemptRejectsReusedExec(t *testing.T) {
	c := newCampaign(t, "integrity")
	fid := integrityHypo(t, c, "reentrancy")
	rec := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	execID := validation.ObjStr(rec, "exec_id")
	tier := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	_, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID, Tier: &tier})
	if err == nil || !strings.Contains(err.Error(), "already cited") {
		t.Fatalf("err = %v", err)
	}
}

// Port of test_evidence_integrity.py::test_attempt_and_mint_one_call_for_passing_repro.
func TestAttemptAndMintOneCallForPassingRepro(t *testing.T) {
	c := newCampaign(t, "integrity")
	fid := integrityHypo(t, c, "reentrancy")
	rec := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	execID := validation.ObjStr(rec, "exec_id")
	tier, etype := "T2", "foundry-test"
	out, err := AttemptAndMint(c, fid, execID, "unit PoC drains", &tier, &etype)
	if err != nil {
		t.Fatal(err)
	}
	repro := validation.ObjAt(validation.ObjAt(validation.ObjAt(out, "verification"), "reproduction"), "status")
	if repro.S != "reproduced" {
		t.Errorf("repro.status = %q", repro.S)
	}
	if tierReached(out) != "T2" {
		t.Errorf("tier_reached = %q", tierReached(out))
	}
	level, err := findings.FindingLevel(out)
	if err != nil {
		t.Fatal(err)
	}
	if level != "E4" {
		t.Errorf("level = %q, want E4", level)
	}
	if n := len(validation.ObjAt(validation.ObjAt(validation.ObjAt(out, "verification"), "reproduction"),
		"attempts").A); n != 1 {
		t.Errorf("attempts = %d, want 1", n)
	}
	found := false
	for _, e := range validation.ObjAt(out, "evidence").A {
		if validation.ObjStr(e, "artifact_id") == execID {
			found = true
		}
	}
	if !found {
		t.Error("no evidence item cites the exec")
	}
}

// Port of test_evidence_integrity.py::test_mint_validates_evidence_type.
func TestMintValidatesEvidenceType(t *testing.T) {
	c := newCampaign(t, "integrity")
	fid := integrityHypo(t, c, "reentrancy")
	rec := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	tier := "T2"
	bad := "not-a-real-type"
	_, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "mislabelled",
		&tier, &bad)
	if err == nil || !strings.Contains(err.Error(), "evidence type") {
		t.Fatalf("err = %v", err)
	}
}

// --- mint citation (test_mint_citation.py) ---------------------------------

// citationCamp is the `camp` fixture: pinned source, model-loaded protocol
// with a model-derived INV-1 (no docs -> the guardrail applies).
func citationCamp(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := newCampaign(t, "mint-rollback")
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"), []byte(
		"contract Vault { uint256 public totalAssets; function deposit() "+
			"external payable {} }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	model := validation.VObj(
		kv("protocol_id", validation.VStr("vault")),
		kv("name", validation.VStr("Vault")),
		kv("snapshot_id", validation.VStr("unpinned")),
		kv("chains", validation.VArr(validation.VStr("ethereum"))),
		kv("subsystems", validation.VArr(validation.VStr("defi-vault"))),
		kv("contracts", validation.VArr(validation.VObj(
			kv("name", validation.VStr("Vault")),
			kv("path", validation.VStr("Vault.sol")),
			kv("role", validation.VStr("core")),
			kv("in_scope", validation.VBool(true)),
			kv("entry_points", validation.VArr(validation.VStr("deposit"))),
			kv("state_variables", validation.VArr(validation.VObj(
				kv("name", validation.VStr("totalAssets")),
				kv("kind", validation.VStr("balance")),
				kv("accounting", validation.VBool(true)))))))),
		kv("actors", validation.VArr(validation.VObj(
			kv("id", validation.VStr("user")),
			kv("kind", validation.VStr("EOA")),
			kv("trust", validation.VStr("externally-owned"))))),
		kv("assets", validation.VArr(validation.VObj(
			kv("id", validation.VStr("share")),
			kv("kind", validation.VStr("share")),
			kv("erc", validation.VStr("4626")),
			kv("decimals", validation.VInt(18))))),
		kv("liabilities", validation.VArr()),
		kv("privileges", validation.VArr()),
		kv("trust_boundaries", validation.VArr()),
		kv("relations", validation.VArr()),
		kv("state_machines", validation.VArr()),
		kv("economic_relations", validation.VArr()),
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"the exchange rate must not move for existing shares from "+
					"out-of-band transfers")),
			kv("applies_to", validation.VArr(validation.VStr("Vault"))),
			kv("kind", validation.VStr("economic")),
			kv("severity_if_broken", validation.VStr("critical"))))),
		kv("oracles", validation.VArr()),
	)
	if _, err := orchestrator.New(c).LoadProtocolModel(model); err != nil {
		t.Fatalf("load protocol model: %v", err)
	}
	payload := validation.VObj(
		kv("title", validation.VStr("Out-of-band transfer inflates per-share price")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("cwe", validation.VStr("CWE-682")),
			kv("description", validation.VStr(
				"direct transfer inflates the denominator without minting shares")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("Vault.sol")),
			kv("function", validation.VStr("deposit"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("invariant", validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"the exchange rate must not move for existing shares")))),
	)
	return c, ingest(t, c, payload, "model", "")
}

// Port of test_mint_citation.py::test_guardrail_rejection_preserves_citation.
func TestGuardrailRejectionPreservesCitation(t *testing.T) {
	c, fid := citationCamp(t)
	installInvariantGuard()
	rec := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	execID := validation.ObjStr(rec, "exec_id")
	tier := "T2"
	if _, err := AttemptAndMint(c, fid, execID, "PoC inflates price",
		&tier, nil); err == nil || !strings.Contains(err.Error(), "level rise blocked") {
		t.Fatalf("err = %v, want the guardrail refusal", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	repro := validation.ObjAt(validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction"), "attempts")
	if len(repro.A) != 0 {
		t.Errorf("attempts = %s, want none (a failed mint must not record one)",
			validation.CanonCompact(repro))
	}
	if ev := validation.ObjAt(f, "evidence"); len(ev.A) != 0 {
		t.Errorf("evidence = %s, want none", validation.CanonCompact(ev))
	}
	// fix the guardrail the sanctioned way
	checkPath := filepath.Join(c.ArtifactsDir, "inv1-check.md")
	if err := os.WriteFile(checkPath, []byte(
		"# INV-1 checked against code\ntotalAssets is written only by "+
			"deposit(); a raw transfer() moves balanceOf(this) without "+
			"updating it — the rate moves."), 0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("detector", checkPath, "INV-1 code check", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-1", aid); err != nil {
		t.Fatalf("verify invariant: %v", err)
	}
	// the SAME exec now mints
	out, err := AttemptAndMint(c, fid, execID, "PoC inflates price", &tier, nil)
	if err != nil {
		t.Fatal(err)
	}
	level, err := findings.FindingLevel(out)
	if err != nil {
		t.Fatal(err)
	}
	if level != "E4" {
		t.Errorf("level = %q, want E4", level)
	}
	arts := []string{}
	for _, a := range validation.ObjAt(validation.ObjAt(validation.ObjAt(out, "verification"), "reproduction"),
		"attempts").A {
		arts = append(arts, validation.ObjStr(a, "artifact_id"))
	}
	if len(arts) != 1 || arts[0] != execID {
		t.Errorf("attempt artifact_ids = %v, want [%s]", arts, execID)
	}
	// and now the citation IS consumed
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: &execID}); err == nil ||
		!strings.Contains(err.Error(), "already cited") {
		t.Fatalf("err = %v, want already cited", err)
	}
}

// Port of test_mint_citation.py::test_rollback_restores_prior_attempt_state.
func TestRollbackRestoresPriorAttemptState(t *testing.T) {
	c, fid := citationCamp(t)
	installInvariantGuard()
	rec1 := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	checkPath := filepath.Join(c.ArtifactsDir, "inv1-check.md")
	if err := os.WriteFile(checkPath, []byte(
		"# INV-1 checked\nverified against deposit()."), 0o644); err != nil {
		t.Fatal(err)
	}
	aid, err := c.RegisterArtifact("detector", checkPath, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invariants.VerifyInvariantStatement(c, "INV-1", aid); err != nil {
		t.Fatal(err)
	}
	tier := "T2"
	if _, err := AttemptAndMint(c, fid, validation.ObjStr(rec1, "exec_id"), "PoC #1",
		&tier, nil); err != nil {
		t.Fatal(err)
	}
	rec2 := sandboxedExec(t, c, fid, "docker-networkless", "pytest-harness")
	bad := "not-a-type"
	if _, err := AttemptAndMint(c, fid, validation.ObjStr(rec2, "exec_id"), "PoC #2",
		&tier, &bad); err == nil ||
		!strings.Contains(err.Error(), "unknown evidence type") {
		t.Fatalf("err = %v", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	arts := []string{}
	for _, a := range validation.ObjAt(validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction"),
		"attempts").A {
		arts = append(arts, validation.ObjStr(a, "artifact_id"))
	}
	if len(arts) != 1 || arts[0] != validation.ObjStr(rec1, "exec_id") {
		t.Errorf("attempt artifact_ids = %v, want [%s]", arts,
			validation.ObjStr(rec1, "exec_id"))
	}
}

// --- independent verification (test_independent_verification.py) -----------

// attachReproBundle is attach_repro_bundle: everything the CONFIRMED gate
// needs except the rung itself.
func attachReproBundle(t *testing.T, c *state.Campaign, fid, level,
	reportedBy string) validation.Value {
	t.Helper()
	rec := sandboxedExec(t, c, fid, "docker-networkless", reportedBy)
	item := validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+fid[len(fid)-6:])),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr("fork-test")),
		kv("description", validation.VStr("fork repro replays the message")),
		kv("sandbox_profile", validation.VStr("docker-networkless")),
		kv("artifact_id", validation.VStr(validation.ObjStr(rec, "exec_id"))),
	)
	if _, err := findings.AddEvidence(c, fid, item); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"checked every control"); err != nil {
		t.Fatal(err)
	}
	seedMemoryStore(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(kv("memory_ids", validation.VArr(
			validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(f, "verification")
	ver = setKey(ver, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T3")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr())))
	f = setKey(f, "verification", ver)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return rec
}

// seedMemoryStore is conftest.seed_global_memory_row: one approved shared row
// through the findings seam (the store itself is another task).
func seedMemoryStore(t *testing.T) {
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
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		return []validation.Value{validation.VObj(kv("row", row))}, nil
	})
	findings.SetLearningAllMemory(func(*state.Campaign) ([]validation.Value, error) {
		return nil, nil
	})
}

// Port of test_independent_verification.py::test_bridge_class_is_dead_end_without_e6:
// a bridge-message finding carries an E6 CONFIRMED floor, so an E5 bundle is a
// dead end — the transition itself must refuse and name the missing rung.
func TestBridgeClassIsDeadEndWithoutE6(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := toPossible(t, c, hypoPayload("bridge-message"))
	attachReproBundle(t, c, fid, "E5", "reproducer-a")
	_, err := findings.Transition(c, fid, "CONFIRMED",
		"E5 is not enough for a bridge", "", "", false)
	if err == nil || !strings.Contains(err.Error(), "E6") {
		t.Fatalf("err = %v; want the E6 floor refusal", err)
	}
}

// Port of test_independent_verification.py::test_mint_e6_requires_a_different_execution.
func TestMintE6RequiresDifferentExecution(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := toPossible(t, c, hypoPayload("bridge-message"))
	rec := attachReproBundle(t, c, fid, "E5", "reproducer-a")
	_, err := MintIndependentEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"re-running the same artifact", "reproducer-a")
	if err == nil || !strings.Contains(err.Error(), "already backs evidence") {
		t.Fatalf("err = %v", err)
	}
}

// Port of test_independent_verification.py::test_mint_e6_requires_a_different_reporter.
func TestMintE6RequiresDifferentReporter(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := toPossible(t, c, hypoPayload("bridge-message"))
	attachReproBundle(t, c, fid, "E5", "reproducer-a")
	rec := registerExec(t, c, "fork-runner", "forge test --mt replay",
		"Ran 1 test\n[PASS] replay\n", "reproducer-a", 0, fid)
	_, err := MintIndependentEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"same hands, new run", "reproducer-a")
	if err == nil || !strings.Contains(err.Error(), "already produced the original") {
		t.Fatalf("err = %v", err)
	}
}

// Port of test_independent_verification.py::test_mint_e6_needs_a_named_verifier.
func TestMintE6NeedsNamedVerifier(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := toPossible(t, c, hypoPayload("bridge-message"))
	attachReproBundle(t, c, fid, "E5", "reproducer-a")
	rec := registerExec(t, c, "fork-runner", "forge test",
		"Ran 1 test\n[PASS] replay\n", "verifier-b", 0, fid)
	_, err := MintIndependentEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "x", "")
	if err == nil || !strings.Contains(err.Error(), "verifier") {
		t.Fatalf("err = %v", err)
	}
}

// Port of test_independent_verification.py::test_e6_unblocks_the_bridge_confirmation.
func TestE6UnblocksBridgeConfirmation(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := toPossible(t, c, hypoPayload("bridge-message"))
	attachReproBundle(t, c, fid, "E5", "reproducer-a")
	rec := registerExec(t, c, "fork-runner", "forge test --mt independent_replay",
		"Ran 1 test\n[PASS] replay\n", "verifier-b", 0, fid)
	out, err := MintIndependentEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"independent rerun at the same block", "verifier-b")
	if err != nil {
		t.Fatal(err)
	}
	ev := validation.ObjAt(out, "evidence")
	if len(ev.A) == 0 || validation.ObjStr(ev.A[len(ev.A)-1], "level") != "E6" {
		t.Errorf("last evidence = %s", validation.CanonCompact(ev))
	}
	ind := validation.ObjAt(validation.ObjAt(out, "verification"), "independent_reproduction")
	if validation.ObjStr(ind, "status") != "matches" || validation.ObjStr(ind, "verifier") != "verifier-b" {
		t.Errorf("independent_reproduction = %s", validation.CanonCompact(ind))
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED",
		"independently reproduced", "", "", false); err != nil {
		t.Fatalf("transition CONFIRMED: %v", err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f, "status") != "CONFIRMED" {
		t.Errorf("status = %q", validation.ObjStr(f, "status"))
	}
}

// Port of test_independent_verification.py::test_e6_rejects_host_profile_exec.
func TestE6RejectsHostProfileExec(t *testing.T) {
	c := newCampaign(t, "Acme Program")
	fid := toPossible(t, c, hypoPayload("bridge-message"))
	attachReproBundle(t, c, fid, "E5", "reproducer-a")
	rec := registerExec(t, c, "host-readonly", "forge test", "PASS: x\n",
		"verifier-b", 0, fid)
	_, err := MintIndependentEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "x", "b")
	if err == nil || !strings.Contains(err.Error(), "container/VM/fork") {
		t.Fatalf("err = %v", err)
	}
}

// --- runbook flow (test_runbook_flow.py) -----------------------------------

func runbookCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c := newCampaign(t, "Acme Program")
	target := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"), []byte(
		"contract Vault { function rescue(address t) external { } }"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

func runbookPayload() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr(
			"Unguarded rescue function moves protocol-held tokens")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("cwe", validation.VStr("CWE-862")),
			kv("description", validation.VStr(
				"rescue has no role check, any caller transfers protocol-held "+
					"tokens out")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("target/Vault.sol")),
			kv("function", validation.VStr("rescue"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	)
}

// Port of test_runbook_flow.py::test_runbook_confirm_flow.
func TestRunbookConfirmFlow(t *testing.T) {
	c := runbookCamp(t)
	fid := ingest(t, c, runbookPayload(), "attacker", "06")
	advancePossible(t, c, fid, "triage passed")
	rec := registerExec(t, c, "docker-networkless", "forge test --match-test poc",
		"PASS: poc\n", "operator", 0, fid)
	tier := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: ptrStr(validation.ObjStr(rec, "exec_id")), Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	if _, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"),
		"unit PoC drains", &tier, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"no compensating control"); err != nil {
		t.Fatal(err)
	}
	seedMemoryStore(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(kv("memory_ids", validation.VArr(
			validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gates passed",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f, "status") != "CONFIRMED" {
		t.Errorf("status = %q", validation.ObjStr(f, "status"))
	}
	level, err := findings.FindingLevel(f)
	if err != nil {
		t.Fatal(err)
	}
	if level != "E4" {
		t.Errorf("level = %q, want E4", level)
	}
	repro := validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction")
	if validation.ObjStr(repro, "status") != "reproduced" ||
		validation.ObjStr(repro, "tier_reached") != "T2" {
		t.Errorf("reproduction = %s", validation.CanonCompact(repro))
	}
}

// Port of test_runbook_flow.py::test_runbook_independent_verification_flow.
func TestRunbookIndependentVerificationFlow(t *testing.T) {
	c := runbookCamp(t)
	fid := ingest(t, c, runbookPayload(), "attacker", "")
	advancePossible(t, c, fid, "triage")
	rec := registerExec(t, c, "docker-networkless", "forge test",
		"Ran 1 test for test/poc.t.sol\n[PASS] poc\n", "reproducer", 0, fid)
	tier := "T2"
	if _, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: ptrStr(validation.ObjStr(rec, "exec_id")), Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	if _, err := MintReproEvidence(c, fid, validation.ObjStr(rec, "exec_id"), "PoC drains",
		&tier, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed",
		"no control"); err != nil {
		t.Fatal(err)
	}
	seedMemoryStore(t)
	if _, err := findings.RecordMemoryCheck(c, fid, []validation.Value{
		validation.VObj(kv("memory_ids", validation.VArr(
			validation.VStr("MEM-shared01"))),
			kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "CONFIRMED", "gates",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	other := registerExec(t, c, "fork-runner", "forge test --mt independent",
		"Ran 1 test for test/ind.t.sol\n[PASS] ind\n", "verifier-b", 0, fid)
	out, err := MintIndependentEvidence(c, fid, validation.ObjStr(other, "exec_id"),
		"same block, same drain", "verifier-b")
	if err != nil {
		t.Fatal(err)
	}
	level, err := findings.FindingLevel(out)
	if err != nil {
		t.Fatal(err)
	}
	if level != "E6" {
		t.Errorf("level = %q, want E6", level)
	}
}

// --- record_attempt guidance (the budget/ladder contract) ------------------

// TestRecordAttemptGuidance pins the guidance ladder of record_attempt.
func TestRecordAttemptGuidance(t *testing.T) {
	c := newCampaign(t, "guidance")
	fid := integrityHypo(t, c, "reentrancy")
	rec := sandboxedExec(t, c, fid, "docker-networkless", "h")
	g, err := RecordAttempt(c, fid, "reproduced",
		RecordOpts{ExecID: ptrStr(validation.ObjStr(rec, "exec_id"))})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(g, "action") != "mint-evidence" || validation.ObjStr(g, "level") != "E4" {
		t.Errorf("guidance = %s", validation.CanonCompact(g))
	}
	falsified, err := RecordAttempt(c, fid, "falsified", RecordOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(falsified, "action") != "hypothesis-dead" {
		t.Errorf("falsified guidance = %s", validation.CanonCompact(falsified))
	}
	env := "environment"
	retry, err := RecordAttempt(c, fid, "failed",
		RecordOpts{FailureClass: &env})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(retry, "action") != "retry" || !boolOf(validation.ObjAt(retry, "fresh_context")) {
		t.Errorf("environment guidance = %s", validation.CanonCompact(retry))
	}
}

// reproStatus reads verification.reproduction.status off the stored finding.
func reproStatus(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(validation.ObjAt(
		validation.ObjAt(f, "verification"), "reproduction"), "status")
}

// TestRecordAttemptStatusIsBestOutcome is R3-6 (Morph r3 defect 6): a later
// diagnostic failure used to overwrite `reproduced` with `attempted` and
// un-qualify the reproduction-reproduced CONFIRMED clause. The STATUS now
// tracks the best outcome ever recorded; the attempts ledger keeps every
// failure honestly.
func TestRecordAttemptStatusIsBestOutcome(t *testing.T) {
	c := newCampaign(t, "best")
	fid := integrityHypo(t, c, "reentrancy")
	if _, err := RecordAttempt(c, fid, "reproduced", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordAttempt(c, fid, "failed", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := reproStatus(t, c, fid); got != "reproduced" {
		t.Fatalf("status after reproduced+failed = %q, want reproduced", got)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(validation.ObjAt(validation.ObjAt(validation.ObjAt(
		f, "verification"), "reproduction"), "attempts").A); n != 2 {
		t.Fatalf("attempts = %d, want 2 (the failure stays recorded)", n)
	}
	// falsified outranks attempted/blocked but never demotes a reproduced;
	// and a fresh reproduced still lifts a mere-attempted record.
	if _, err := RecordAttempt(c, fid, "falsified", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := reproStatus(t, c, fid); got != "reproduced" {
		t.Fatalf("status = %q, want reproduced (best stays)", got)
	}
	c2 := newCampaign(t, "best2")
	fid2 := integrityHypo(t, c2, "reentrancy")
	if _, err := RecordAttempt(c2, fid2, "failed", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordAttempt(c2, fid2, "blocked", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordAttempt(c2, fid2, "falsified", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := reproStatus(t, c2, fid2); got != "falsified" {
		t.Fatalf("status = %q, want falsified (beats attempted/blocked)", got)
	}
	if _, err := RecordAttempt(c2, fid2, "reproduced", RecordOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := reproStatus(t, c2, fid2); got != "reproduced" {
		t.Fatalf("status = %q, want reproduced (upward update works)", got)
	}
}

// TestRecordAttemptOutcomeValidation pins the ValueError text.
func TestRecordAttemptOutcomeValidation(t *testing.T) {
	c := newCampaign(t, "guidance")
	fid := integrityHypo(t, c, "reentrancy")
	_, err := RecordAttempt(c, fid, "bogus", RecordOpts{})
	if err == nil || !strings.Contains(err.Error(), "unknown attempt outcome") {
		t.Fatalf("err = %v", err)
	}
}

// TestRecordAttemptTierLadderMonotonic pins the monotonic ladder refusal.
func TestRecordAttemptTierLadderMonotonic(t *testing.T) {
	c := newCampaign(t, "guidance")
	fid := integrityHypo(t, c, "reentrancy")
	t3, t1 := "T3", "T1"
	if _, err := RecordAttempt(c, fid, "failed", RecordOpts{Tier: &t3}); err != nil {
		t.Fatal(err)
	}
	_, err := RecordAttempt(c, fid, "failed", RecordOpts{Tier: &t1})
	if err == nil || !strings.Contains(err.Error(), "monotonic") {
		t.Fatalf("err = %v", err)
	}
	_, err = RecordAttempt(c, fid, "failed", RecordOpts{Tier: ptrStr("T9")})
	if err == nil || !strings.Contains(err.Error(), "unknown reproduction tier") {
		t.Fatalf("err = %v", err)
	}
}

// TestRecordAttemptBudgetExhausted pins the budget RuntimeError.
func TestRecordAttemptBudgetExhausted(t *testing.T) {
	c := newCampaign(t, "guidance")
	fid := integrityHypo(t, c, "reentrancy")
	budget, err := c.Budget()
	if err != nil {
		t.Fatal(err)
	}
	max := intOf(validation.ObjAt(budget, "max_repro_attempts_per_finding"))
	for i := 0; i < max; i++ {
		if _, err := RecordAttempt(c, fid, "failed", RecordOpts{}); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err = RecordAttempt(c, fid, "failed", RecordOpts{})
	if err == nil || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("err = %v", err)
	}
}

// --- small helpers ----------------------------------------------------------

func ptrStr(s string) *string { return &s }

// installInvariantGuard wires the real guardrail once (main.go wires it at
// boot in production; the seam has no restore, and no other test in this
// package hangs evidence off an invariant).
var guardOnce sync.Once

func installInvariantGuard() {
	guardOnce.Do(func() {
		findings.SetInvariantGuard(invariants.AssertInvariantsVerified)
	})
}

func boolOf(v validation.Value) bool { return v.Kind == validation.Bool && v.B }

func tierReached(f validation.Value) string {
	repro := validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction")
	return validation.ObjStr(repro, "tier_reached")
}
