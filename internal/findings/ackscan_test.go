package findings

// ackscan_test.go: A2 — the in-code acknowledgement matcher. Phrase
// windowing (±12, first line wins, most specific phrase wins), multi-anchor
// order, function resolution, the index-resolved call sites, the idempotent
// re-scan (hit replaces, clean clears), the no-hit case, and the ingest
// hook (the flag is present from the moment a finding is filed).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// stubSol is the pin fixture. Line map (1-based):
//
//	1  // SPDX-License-Identifier: MIT
//	2  pragma solidity ^0.8.0;
//	3  (blank)
//	4  contract Vault {
//	5      // TODO: implement the drop handler properly
//	6      function drop(uint256 amount) external {
//	7          revert("not implemented");
//	8      }
//	9  }
const stubSol = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    // TODO: implement the drop handler properly
    function drop(uint256 amount) external {
        revert("not implemented");
    }
}
`

// farSol: the fixme sits at line 1, 17 lines from the function at 18 —
// OUTSIDE the ±12 window around 18, INSIDE the window around line 10.
const farSol = `// fixme: ancient comment
line3
line4
line5
line6
line7
line8
line9
line10
line11
line12
line13
line14
line15
line16
contract Far {
    function run() external {}
}
`

// prioritySol: one line carrying two phrases — the most specific
// ("not implemented") must win over "stub".
const prioritySol = `contract Priority {
    // stub, not implemented
    function x() external {}
}
`

// boundarySol: lookalikes that must NOT match (word boundaries).
const boundarySol = `contract Boundary {
    // the hackathon todos were great
    function y() external {}
}
`

// ackCamp pins a source tree and returns (campaign, target-dir).
func ackCamp(t *testing.T, files map[string]string) (*state.Campaign,
	string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Ack Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	for name, body := range files {
		p := filepath.Join(target, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c, target
}

// ackFinding builds a minimal finding with the given affected entries and
// exploit_sequence calls, pinned to the campaign's source snapshot.
func ackFinding(t *testing.T, c *state.Campaign, aff []validation.KV,
	calls ...string) validation.Value {
	t.Helper()
	affArr := validation.VArr()
	for _, k := range aff {
		affArr.A = append(affArr.A, k.V)
	}
	seq := validation.VArr()
	if len(calls) > 0 {
		seq = validation.VArr(validation.VObj(
			kv("step", validation.VInt(1)),
			kv("action", validation.VStr("calls the flagged handler")),
			kv("calls", validation.VArr(
				func() (out []validation.Value) {
					for _, cs := range calls {
						out = append(out, validation.VStr(cs))
					}
					return
				}()...))))
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(st, "active_snapshot_id")
	return validation.VObj(
		kv("title", validation.VStr("ack scan fixture")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("unclassified")),
			kv("description", validation.VStr("placeholder description "+
				"for the ack scan fixture")))),
		kv("affected", affArr),
		kv("exploit_sequence", seq),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("snapshot_ids", validation.VObj(
			kv("source", validation.VStr(sid)),
			kv("deployment", validation.VNull()),
			kv("chain", validation.VNull()))),
	)
}

// saveAckFinding writes the fixture finding under a fixed id, filling the
// required bookkeeping fields the schema demands of a stored finding.
func saveAckFinding(t *testing.T, c *state.Campaign, f validation.Value) string {
	t.Helper()
	ts := "2026-09-10T00:00:00+00:00"
	f = withField(f, "finding_id", validation.VStr("F-000000000001"))
	f = withField(f, "campaign_id", validation.VStr(c.CampaignID))
	f = withField(f, "status", validation.VStr("HYPOTHESIS"))
	f = withField(f, "trajectory", validation.VStr("code"))
	f = withField(f, "created_at", validation.VStr(ts))
	f = withField(f, "updated_at", validation.VStr(ts))
	f = withField(f, "evidence", validation.VArr())
	f = withField(f, "risk", validation.VObj())
	f = withField(f, "dedup", validation.VObj())
	f = withField(f, "history", validation.VArr(validation.VObj(
		kv("at", validation.VStr(ts)),
		kv("from", validation.VStr("NEW")),
		kv("to", validation.VStr("HYPOTHESIS")),
		kv("reason", validation.VStr("ack scan fixture")),
		kv("actor", validation.VStr("test")))))
	if err := SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return "F-000000000001"
}

func withField(f validation.Value, key string, v validation.Value) validation.Value {
	f.O = validation.SetOrAppend(f.O, key, v)
	return f
}

func TestAckScanHitInWindow(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Stub.sol": stubSol,
		"src/Clean.sol": "contract Clean {}\n"})
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Stub.sol")),
			kv("lines", validation.VArr(validation.VInt(7)))))},
	)
	hit, ack, err := ScanInCodeAck(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("want a hit")
	}
	if got := validation.ObjStr(ack, "file"); got != "src/Stub.sol" {
		t.Errorf("file = %q", got)
	}
	if got := validation.ObjAt(ack, "line").I; got != 5 {
		t.Errorf("line = %d, want 5 (the TODO, first in window order)", got)
	}
	if got := validation.ObjStr(ack, "phrase"); got != "todo" {
		t.Errorf("phrase = %q", got)
	}
	if got := validation.ObjStr(ack, "window"); got != fmt.Sprint(AckWindow) {
		t.Errorf("window = %q", got)
	}
}

func TestAckScanWindowEdge(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Far.sol": farSol})
	// anchor 18 (the function): window 6..30 excludes the line-1 fixme
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Far.sol")),
			kv("lines", validation.VArr(validation.VInt(18)))))},
	)
	if hit, _, err := ScanInCodeAck(c, f); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Error("anchor 18 must miss the line-1 fixme (17 away > 12)")
	}
	// anchor 10 (a padding line): window 1..22 includes it
	f2 := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Far.sol")),
			kv("lines", validation.VArr(validation.VInt(10)))))},
	)
	hit, ack, err := ScanInCodeAck(c, f2)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || validation.ObjStr(ack, "phrase") != "fixme" ||
		validation.ObjAt(ack, "line").I != 1 {
		t.Errorf("want the line-1 fixme, got hit=%v ack=%v", hit, ack)
	}
}

func TestAckScanPhrasePrecedence(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Priority.sol": prioritySol})
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Priority.sol")),
			kv("lines", validation.VArr(validation.VInt(2)))))},
	)
	hit, ack, err := ScanInCodeAck(c, f)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if got := validation.ObjStr(ack, "phrase"); got != "not implemented" {
		t.Errorf("phrase = %q, want the most specific phrase", got)
	}
}

func TestAckScanWordBoundary(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Boundary.sol": boundarySol})
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Boundary.sol")),
			kv("lines", validation.VArr(validation.VInt(2)))))},
	)
	if hit, _, err := ScanInCodeAck(c, f); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Error("hackathon/todos must not match hack/todo")
	}
}

func TestAckScanFunctionResolution(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Stub.sol": stubSol})
	// no lines: the function definition (line 6) anchors the window, which
	// reaches the line-5 TODO.
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Stub.sol")),
			kv("function", validation.VStr("drop"))))},
	)

	hit, ack, err := ScanInCodeAck(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || validation.ObjAt(ack, "line").I != 5 {
		t.Errorf("want the line-5 TODO via the function anchor, got hit=%v "+
			"ack=%v", hit, ack)
	}
}

func TestAckScanMultiAnchor(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{
		"src/Clean.sol": "contract Clean {\n    function ok() external {}\n}\n",
		"src/Stub.sol":  stubSol,
	})
	// the clean anchor first, the stub anchor second — the hit comes from
	// the second.
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Clean.sol")),
			kv("lines", validation.VArr(validation.VInt(2))))),
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Stub.sol")),
			kv("lines", validation.VArr(validation.VInt(7)))))},
	)
	hit, ack, err := ScanInCodeAck(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || validation.ObjStr(ack, "file") != "src/Stub.sol" {
		t.Errorf("want the Stub.sol hit, got hit=%v ack=%v", hit, ack)
	}
}

func TestAckScanIndexCallSite(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{
		"src/Clean.sol": "contract Clean {\n    function ok() external {}\n}\n",
		"src/Stub.sol":  stubSol,
	})
	// the structural index artifact maps the contract name to its file;
	// the exploit_sequence call site "Vault.drop" resolves through it.
	idx := validation.VObj(
		kv("nodes", validation.VArr(
			validation.VObj(
				kv("id", validation.VStr("src/Stub.sol::Vault")),
				kv("kind", validation.VStr("contract")),
				kv("name", validation.VStr("Vault")),
				kv("path", validation.VStr("src/Stub.sol")),
				kv("line", validation.VInt(4))),
			validation.VObj(
				kv("id", validation.VStr("src/Stub.sol::Vault.drop")),
				kv("kind", validation.VStr("function")),
				kv("name", validation.VStr("drop")),
				kv("path", validation.VStr("src/Stub.sol")),
				kv("line", validation.VInt(6))))),
		kv("edges", validation.VArr()),
	)
	if err := os.WriteFile(filepath.Join(c.ArtifactsDir,
		"structural_index.json"), []byte(validation.CanonSpaced(idx)), 0o644); err != nil {
		t.Fatal(err)
	}
	// the affected entry is unresolvable on its own (no lines, no
	// function) — the call site carries the scan.
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Clean.sol"))))},
		"Vault.drop")
	hit, ack, err := ScanInCodeAck(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || validation.ObjStr(ack, "file") != "src/Stub.sol" {
		t.Errorf("want the index-resolved Stub.sol hit, got hit=%v ack=%v",
			hit, ack)
	}
}

func TestAckScanNoPin(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Ack Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	f := ackFinding(t, c, nil)
	f = withField(f, "snapshot_ids", validation.VObj(
		kv("source", validation.VStr("unpinned")),
		kv("deployment", validation.VNull()),
		kv("chain", validation.VNull())))
	if hit, _, err := ScanInCodeAck(c, f); err == nil {
		t.Error("want an error for an unpinned finding")
	} else if hit {
		t.Error("hit must be false on error")
	}
}

func TestAckScanNoAnchor(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Clean.sol": "contract Clean {}\n"})
	// a path only: no lines, no function, no index — nothing to scan
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Clean.sol"))))},
	)
	if hit, _, err := ScanInCodeAck(c, f); err == nil {
		t.Error("want a no-anchor error")
	} else if hit {
		t.Error("hit must be false on error")
	} else if !strings.Contains(err.Error(), "no scannable anchor") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestRecordAckScanIdempotent(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Stub.sol": stubSol})
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Stub.sol")),
			kv("lines", validation.VArr(validation.VInt(7)))))},
	)
	fid := saveAckFinding(t, c, f)

	for i := 0; i < 2; i++ {
		hit, err := RecordAckScan(c, fid)
		if err != nil {
			t.Fatal(err)
		}
		if !hit {
			t.Fatal("want a hit")
		}
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	dm := validation.ObjAt(stored, "dedup_meta")
	if dm.Kind != validation.Obj {
		t.Fatal("dedup_meta missing")
	}
	ack := validation.ObjAt(dm, "in_code_ack")
	if validation.ObjStr(ack, "phrase") != "todo" || validation.ObjAt(ack, "line").I != 5 {
		t.Errorf("record = %v", ack)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.ack_scanned" {
			n++
			if !validation.ObjAt(validation.ObjAt(e, "data"), "hit").B {
				t.Errorf("event %d: hit must be true", n)
			}
		}
	}
	if n != 2 {
		t.Errorf("ack_scanned events = %d, want 2 (one per scan)", n)
	}
}

func TestRecordAckScanClearsOnClean(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{
		"src/Clean.sol": "contract Clean {\n    function ok() external {}\n}\n",
		"src/Stub.sol":  stubSol,
	})
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Stub.sol")),
			kv("lines", validation.VArr(validation.VInt(7)))))},
	)
	fid := saveAckFinding(t, c, f)
	if hit, err := RecordAckScan(c, fid); err != nil || !hit {
		t.Fatalf("first scan: hit=%v err=%v", hit, err)
	}
	// the finding's anchor moves to the clean file — the re-scan must
	// clear the stored record.
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	stored.O = validation.SetOrAppend(stored.O, "affected", validation.VArr(
		validation.VObj(
			kv("path", validation.VStr("src/Clean.sol")),
			kv("lines", validation.VArr(validation.VInt(2))))))
	if err := SaveFinding(c, &stored); err != nil {
		t.Fatal(err)
	}
	hit, err := RecordAckScan(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Error("second scan must be clean")
	}
	after, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldAt(validation.ObjAt(after, "dedup_meta"), "in_code_ack"); ok {
		t.Error("a clean re-scan must clear the stored record")
	}
}

func TestRecordAckScanSkipReason(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Clean.sol": "contract Clean {}\n"})
	// no lines, no function, no index: the scan cannot run — the record
	// call returns the reason and leaves the finding untouched.
	f := ackFinding(t, c, []validation.KV{
		kv("affected", validation.VObj(
			kv("path", validation.VStr("src/Clean.sol"))))},
	)
	fid := saveAckFinding(t, c, f)
	if hit, err := RecordAckScan(c, fid); err == nil {
		t.Error("want the skip reason")
	} else if hit {
		t.Error("hit must be false")
	} else if !strings.Contains(err.Error(), "no scannable anchor") {
		t.Errorf("error = %q", err.Error())
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if dm := validation.ObjAt(stored, "dedup_meta"); dm.Kind == validation.Obj {
		t.Errorf("a skipped scan must not create dedup_meta: %v", dm)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.ack_scanned" {
			t.Error("a skipped scan must not log an event")
		}
	}
}

func TestIngestHooksAckScan(t *testing.T) {
	c, _ := ackCamp(t, map[string]string{"src/Stub.sol": stubSol})
	payload := hypoPayload()
	payload = withField(payload, "affected", validation.VArr(
		validation.VObj(
			kv("path", validation.VStr("src/Stub.sol")),
			kv("lines", validation.VArr(validation.VInt(7))))))
	f, err := IngestHypothesis(c, payload, "code", "discovery", "")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := LoadFinding(c, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	ack := validation.ObjAt(validation.ObjAt(stored, "dedup_meta"), "in_code_ack")
	if validation.ObjStr(ack, "phrase") != "todo" || validation.ObjAt(ack, "line").I != 5 {
		t.Errorf("ingest must carry the ack record: %v", ack)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	seenAck, seenIngest := false, false
	for _, e := range events {
		switch validation.ObjStr(e, "type") {
		case "finding.ack_scanned":
			seenAck = true
			if !validation.ObjAt(validation.ObjAt(e, "data"), "hit").B {
				t.Error("ack_scanned hit must be true")
			}
		case "finding.ingested":
			seenIngest = true
		}
	}
	if !seenIngest || !seenAck {
		t.Errorf("events: ingested=%v ack_scanned=%v", seenIngest, seenAck)
	}
}
