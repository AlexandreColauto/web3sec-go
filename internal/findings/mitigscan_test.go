package findings

// mitigscan_test.go: G5 — the structural-defense scanner. Pattern law
// (first match wins: guard-modifier > cei-order > eip712-binding >
// pull-pattern), the evalsuite fixture oracle (ES17/CEI hit, ES03 absent,
// ES16 ack+mitigation coexistence, ES12 eip712 absent), inline positives
// for guard (modifier + lock variants), EIP-712 and pull, the guard-beats-
// cei precedence proof, determinism, the no-bounty/no-ack/no-status
// non-interference checks, and the ingest hook.

import (
	"strings"
	"testing"

	"websec/assets"
	"websec/internal/state"
	"websec/internal/validation"
)

// evalSrc reads an evalsuite source through the embedded pack (the brief's
// fixture oracle: assets.EvalSuiteFS, not the working tree).
func evalSrc(t *testing.T, name string) string {
	t.Helper()
	raw, err := assets.EvalSuiteFS.ReadFile("evalsuite/src/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// mitigCamp pins the named evalsuite sources under src/ (same relative
// paths the record's file field must carry).
func mitigCamp(t *testing.T, names ...string) *state.Campaign {
	t.Helper()
	files := map[string]string{}
	for _, n := range names {
		files["src/"+n] = evalSrc(t, n)
	}
	c, _ := ackCamp(t, files)
	return c
}

// mitigFinding builds a finding on path/function whose mechanism prose
// names mechFn (region scoping keys on that mention).
func mitigFinding(t *testing.T, c *state.Campaign, path, mechFn,
	mechText string) validation.Value {
	t.Helper()
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr(path)),
			kv("function", validation.VStr(mechFn)))),
	})
	f.O = validation.SetOrAppend(f.O, "root_cause", validation.VObj(
		kv("class", validation.VStr("unclassified")),
		kv("description", validation.VStr(mechText))))
	return f
}

// mitigDecode unwraps a hit record or fails the test.
func mitigDecode(t *testing.T, hit bool, rec validation.Value) (pattern,
	file, line, evidence string) {
	t.Helper()
	if !hit {
		t.Fatal("want a hit")
	}
	if rec.Kind != validation.Str {
		t.Fatalf("record must be a string, got kind %v", rec.Kind)
	}
	pattern, file, line, evidence, ok := ParseMitigationPresent(rec.S)
	if !ok {
		t.Fatalf("record does not decode: %q", rec.S)
	}
	return pattern, file, line, evidence
}

func TestMitigScanCEIOrderEffectsBeforeInteraction(t *testing.T) {
	c := mitigCamp(t, "ES17CleanControl.sol")
	f := mitigFinding(t, c, "src/ES17CleanControl.sol", "withdraw",
		"the withdraw handler forwards deposits via call after zeroing")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	pattern, file, line, evidence := mitigDecode(t, hit, rec)
	if pattern != "cei-order" {
		t.Errorf("pattern = %q, want cei-order", pattern)
	}
	if file != "src/ES17CleanControl.sol" {
		t.Errorf("file = %q", file)
	}
	if line != "11" {
		t.Errorf("line = %q, want 11 (the effects-first write)", line)
	}
	if evidence == "" || len([]rune(evidence)) > 120 {
		t.Errorf("evidence must be a <=120-char snippet, got %q", evidence)
	}
	// Determinism: a second scan is byte-equal.
	hit2, rec2, err := ScanMitigations(c, f)
	if err != nil || !hit2 || rec2.S != rec.S {
		t.Errorf("re-scan must be byte-equal: hit=%v err=%v %q vs %q",
			hit2, err, rec.S, rec2.S)
	}
}

func TestMitigScanES17SweepAbsent(t *testing.T) {
	c := mitigCamp(t, "ES17CleanControl.sol")
	// sweep pushes funds with no write and no guard: no statement applies.
	f := mitigFinding(t, c, "src/ES17CleanControl.sol", "sweep",
		"the sweep payout to the owner pushes the whole balance")
	hit, _, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Error("sweep must not match: no write precedes its transfer")
	}
}

// noCallSol: a state write with NO interaction anywhere — an interaction
// that never happens earns no cei-order credit, and no other pattern
// applies (no guard, no EIP-712 marker, non-claim function name), so the
// verdict must be clean.
const noCallSol = `pragma solidity ^0.8.24;
contract NoCall {
    mapping(address => uint256) public deposits;
    function store() external {
        deposits[msg.sender] = 0;
    }
}
`

func TestMitigScanCEIOrderWriteWithoutCallAbsent(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/NoCall.sol": noCallSol})
	f := mitigFinding(t, c, "src/NoCall.sol", "store",
		"the store handler zeroes deposits with no interaction")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Errorf("write with no call must match nothing, got %q", rec.S)
	}
}

// loopSol: write-before-call, but embedded in a for loop — loop-safety
// can't be regex-proved, so cei-order must not fire (and no other pattern
// applies: non-claim name, deposits mapping, no guard, no EIP-712 marker).
const loopSol = `pragma solidity ^0.8.24;
contract Loopy {
    mapping(address => uint256) public deposits;
    function distribute(address[] calldata rs) external {
        for (uint i = 0; i < rs.length; i++) {
            address r = rs[i];
            deposits[r] = 0;
            (bool ok, ) = r.call{value: 1}("");
            require(ok, "send");
        }
    }
}
`

func TestMitigScanCEIOrderLoopDisqualifies(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Loopy.sol": loopSol})
	f := mitigFinding(t, c, "src/Loopy.sol", "distribute",
		"the distribute handler zeroes deposits then calls in a loop")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Errorf("write-in-loop must match nothing, got %q", rec.S)
	}
}

func TestMitigScanES03Absent(t *testing.T) {
	c := mitigCamp(t, "ES03BankReentrancy.sol")
	f := mitigFinding(t, c, "src/ES03BankReentrancy.sol", "withdraw",
		"the withdraw handler calls before zeroing bal")
	hit, _, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Error("ES03 withdraw is CEI-broken with no guard: zero patterns")
	}
	// A recorded clean scan leaves the field absent.
	fid := saveAckFinding(t, c, f)
	if hit, err := RecordMitigationScan(c, fid); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Error("record must report no hit")
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldAt(objAt(stored, "dedup_meta"),
		"mitigation_present"); ok {
		t.Error("a clean scan must leave mitigation_present absent")
	}
}

func TestMitigScanES16Coexist(t *testing.T) {
	c := mitigCamp(t, "ES16AckDecoyVault.sol")
	f := mitigFinding(t, c, "src/ES16AckDecoyVault.sol", "withdraw",
		"the withdraw handler reviewed, CEI holds, pays after zeroing")
	fid := saveAckFinding(t, c, f)
	// The tranche's one-two punch: ackscan hits the TODO, mitigscan hits
	// the CEI-correct body — independently.
	ackHit, err := RecordAckScan(c, fid)
	if err != nil || !ackHit {
		t.Fatalf("ackscan: hit=%v err=%v", ackHit, err)
	}
	mitHit, err := RecordMitigationScan(c, fid)
	if err != nil || !mitHit {
		t.Fatalf("mitigscan: hit=%v err=%v", mitHit, err)
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	dm := objAt(stored, "dedup_meta")
	if objStr(objAt(dm, "in_code_ack"), "phrase") != "todo" {
		t.Errorf("in_code_ack must survive: %v", objAt(dm, "in_code_ack"))
	}
	mp := objAt(dm, "mitigation_present")
	pattern, _, line, _, ok := ParseMitigationPresent(mp.S)
	if !ok || pattern != "cei-order" || line != "12" {
		t.Errorf("mitigation_present = %q, want cei-order at 12", mp.S)
	}
	// Each scan is idempotent: re-running changes neither record (the
	// store stamps updated_at on every save, so the comparison is scoped
	// to the scan-owned dedup_meta subtree).
	again, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	before := validation.CanonSpaced(objAt(again, "dedup_meta"))
	if _, err := RecordAckScan(c, fid); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordMitigationScan(c, fid); err != nil {
		t.Fatal(err)
	}
	after, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(objAt(after, "dedup_meta")) != before {
		t.Error("re-scans must leave the stored records byte-equal")
	}
}

// guardSol: 12 lines; nonReentrant on the signature AND a CEI-correct body
// (write L8 precedes call L9) — guard must beat cei (first-match law).
const guardSol = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract Guarded {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external nonReentrant {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send");
    }
}
`

func TestMitigScanGuardModifier(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Guarded.sol": guardSol})
	f := mitigFinding(t, c, "src/Guarded.sol", "withdraw",
		"the withdraw handler is guarded and pays after zeroing")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	pattern, file, line, _ := mitigDecode(t, hit, rec)
	if pattern != "guard-modifier" {
		t.Errorf("pattern = %q, want guard-modifier (beats cei-order)",
			pattern)
	}
	if file != "src/Guarded.sol" || line != "6" {
		t.Errorf("record = %v, want Guarded.sol at 6", rec)
	}
}

// lockSol: the body opens with a lock check and the file writes the lock
// both ways — the second disjunct of guard-modifier. The body is NOT
// CEI-correct (write L11 follows call L9), isolating the lock path.
const lockSol = `pragma solidity ^0.8.24;
contract Locked {
    mapping(address => uint256) public bal;
    bool private locked;
    function withdraw() external {
        if (locked) revert("locked");
        locked = true;
        uint256 a = bal[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send");
        bal[msg.sender] = 0;
        locked = false;
    }
}
`

func TestMitigScanGuardLock(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Locked.sol": lockSol})
	f := mitigFinding(t, c, "src/Locked.sol", "withdraw",
		"the withdraw handler locks around the call")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	pattern, _, line, _ := mitigDecode(t, hit, rec)
	if pattern != "guard-modifier" || line != "6" {
		t.Errorf("record = %v, want guard-modifier at 6", rec)
	}
}

// eipSol: 6 lines; the only marker is the separator, so eip712-binding is
// the verdict by elimination as well as by rule.
const eipSol = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract SigOK {
    bytes32 public DOMAIN_SEPARATOR;
    function withdraw(uint256 a) external { require(a > 0); }
}
`

func TestMitigScanEIP712(t *testing.T) {
	// ES12 is the negative: no binding marker anywhere (the bug), so the
	// record — if any — must not be eip712-binding. (Its withdraw body is
	// CEI-correct, so cei-order is the verdict there.)
	c := mitigCamp(t, "ES12SignatureReplay.sol")
	f := mitigFinding(t, c, "src/ES12SignatureReplay.sol", "withdraw",
		"the withdraw handler verifies the digest then pays")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if pattern, _, _, _, ok := ParseMitigationPresent(rec.S); !hit ||
		!ok || pattern == "eip712-binding" {
		t.Errorf("ES12 must not report eip712-binding: hit=%v %q",
			hit, rec.S)
	}
	// The inline positive.
	c2, _ := ackCamp(t, map[string]string{"src/SigOK.sol": eipSol})
	f2 := mitigFinding(t, c2, "src/SigOK.sol", "withdraw",
		"the withdraw handler takes a bound digest")
	hit, rec, err = ScanMitigations(c2, f2)
	if err != nil {
		t.Fatal(err)
	}
	pattern, _, line, _ := mitigDecode(t, hit, rec)
	if pattern != "eip712-binding" || line != "4" {
		t.Errorf("record = %v, want eip712-binding at 4", rec)
	}
}

// pullSol: claim() writes owed AFTER the call — deliberately not
// CEI-correct, so pull-pattern is the verdict by elimination and by rule.
const pullSol = `pragma solidity ^0.8.24;
contract Pull {
    mapping(address => uint256) public owed;
    function claim() external {
        uint256 a = owed[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send");
        owed[msg.sender] = 0;
    }
}
`

func TestMitigScanPull(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Pull.sol": pullSol})
	f := mitigFinding(t, c, "src/Pull.sol", "claim",
		"the claim handler pays out the caller's owed share")
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		t.Fatal(err)
	}
	pattern, _, line, _ := mitigDecode(t, hit, rec)
	if pattern != "pull-pattern" || line != "8" {
		t.Errorf("record = %v, want pull-pattern at 8", rec)
	}
}

func TestMitigScanNoPin(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Clean.sol": "contract Clean {}\n"})
	f := mitigFinding(t, c, "src/Clean.sol", "ok",
		"the ok handler does nothing")
	f = withField(f, "snapshot_ids", validation.VObj(
		kv("source", validation.VStr("unpinned")),
		kv("deployment", validation.VNull()),
		kv("chain", validation.VNull())))
	if hit, _, err := ScanMitigations(c, f); err == nil {
		t.Error("want an error for an unpinned finding")
	} else if hit {
		t.Error("hit must be false on error")
	}
	// A skipped record call leaves the finding untouched (fail-open).
	fid := saveAckFinding(t, c, f)
	if hit, err := RecordMitigationScan(c, fid); err == nil {
		t.Error("want the skip reason")
	} else if hit {
		t.Error("hit must be false")
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if dm := objAt(stored, "dedup_meta"); dm.Kind == validation.Obj {
		t.Errorf("a skipped scan must not create dedup_meta: %v", dm)
	}
}

func TestMitigScanNonInterference(t *testing.T) {
	c := mitigCamp(t, "ES17CleanControl.sol")
	f := mitigFinding(t, c, "src/ES17CleanControl.sol", "withdraw",
		"the withdraw handler forwards deposits via call after zeroing")
	fid := saveAckFinding(t, c, f)
	if _, err := RecordMitigationScan(c, fid); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldAt(stored, "bounty"); ok {
		t.Error("mitigscan must never write bounty.*")
	}
	if _, ok := fieldAt(objAt(stored, "dedup_meta"), "in_code_ack"); ok {
		t.Error("mitigscan must never touch in_code_ack")
	}
	if got := objStr(stored, "status"); got != "HYPOTHESIS" {
		t.Errorf("status = %q, must be unchanged", got)
	}
}

func TestIngestHooksMitigScan(t *testing.T) {
	c := mitigCamp(t, "ES17CleanControl.sol")
	payload := hypoPayload()
	payload = withField(payload, "affected", validation.VArr(
		validation.VObj(
			kv("path", validation.VStr("src/ES17CleanControl.sol")),
			kv("function", validation.VStr("withdraw")))))
	payload = withField(payload, "root_cause", validation.VObj(
		kv("class", validation.VStr("unclassified")),
		kv("description", validation.VStr(
			"the withdraw handler forwards deposits via call after "+
				"zeroing"))))
	f, err := IngestHypothesis(c, payload, "code", "discovery", "")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := LoadFinding(c, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	mp := objAt(objAt(stored, "dedup_meta"), "mitigation_present")
	pattern, file, line, _, ok := ParseMitigationPresent(mp.S)
	if !ok || pattern != "cei-order" || file != "src/ES17CleanControl.sol" ||
		line != "11" {
		t.Errorf("ingest must carry the mitigation record: %q", mp.S)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	seenMit, seenIngest := false, false
	for _, e := range events {
		switch objStr(e, "type") {
		case "finding.mitigation_scanned":
			seenMit = true
			if !objAt(objAt(e, "data"), "hit").B {
				t.Error("mitigation_scanned hit must be true")
			}
		case "finding.ingested":
			seenIngest = true
		}
	}
	if !seenIngest || !seenMit {
		t.Errorf("events: ingested=%v mitigation_scanned=%v",
			seenIngest, seenMit)
	}
	if !strings.Contains(validation.CanonSpaced(stored), "cei-order") {
		t.Error("stored finding must contain the pattern id")
	}
}
