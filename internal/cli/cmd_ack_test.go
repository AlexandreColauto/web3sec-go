package cli

// cmd_ack_test.go: the CLI half of A2 — `webv2 ack <campaign> [finding]`
// scans the pinned source for in-code acknowledgements around the finding's
// anchors. A hit prints the quote line, a clean scan prints clean, an
// unscannable finding is skipped with the reason (still exit 0), and a
// missing finding falls through to the generic handler (exit 1).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

const ackStubSol = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    // TODO: implement the drop handler properly
    function drop(uint256 amount) external {
        revert("not implemented");
    }
}
`

// ackCliCamp inits a campaign through the CLI and pins a source tree.
func ackCliCamp(t *testing.T, files map[string]string) (*state.Campaign,
	string) {
	t.Helper()
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
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
	return c, root
}

// ackCliFinding ingests a hypothesis whose affected entry is the given path
// and 1-based lines (no lines => path only).
func ackCliFinding(t *testing.T, c *state.Campaign, title, path string,
	lines ...int64) string {
	t.Helper()
	aff := validation.VObj(kvT("path", validation.VStr(path)))
	if len(lines) > 0 {
		var lv []validation.Value
		for _, n := range lines {
			lv = append(lv, validation.VInt(n))
		}
		aff = validation.VObj(
			kvT("path", validation.VStr(path)),
			kvT("lines", validation.VArr(lv...)))
	}
	payload := validation.VObj(
		kvT("title", validation.VStr(title)),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr("unclassified")),
			kvT("description", validation.VStr(
				"ack cli fixture finding mechanism")))),
		kvT("affected", validation.VArr(aff)),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()))),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(f, "finding_id")
}

func TestAckSingleHit(t *testing.T) {
	c, root := ackCliCamp(t, map[string]string{"src/Stub.sol": ackStubSol})
	fid := ackCliFinding(t, c, "the drop handler", "src/Stub.sol", 7)
	code, out, errS := run(t, "--root", root, "ack", c.CampaignID, fid)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	want := fid + ": ack — src/Stub.sol:5 \"todo\" (window ±12)\n"
	if out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
}

func TestAckAllFindings(t *testing.T) {
	c, root := ackCliCamp(t, map[string]string{
		"src/Stub.sol":  ackStubSol,
		"src/Clean.sol": "contract Clean {\n    function ok() external {}\n}\n",
	})
	f1 := ackCliFinding(t, c, "the drop handler", "src/Stub.sol", 7)
	f2 := ackCliFinding(t, c, "the clean handler", "src/Clean.sol", 2)
	code, out, errS := run(t, "--root", root, "ack", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, f1+": ack — src/Stub.sol:5 \"todo\" "+
		"(window ±12)\n") {
		t.Fatalf("missing hit line:\n%s", out)
	}
	if !strings.Contains(out, f2+": clean — no in-code acknowledgement "+
		"in window\n") {
		t.Fatalf("missing clean line:\n%s", out)
	}
	if !strings.Contains(out, "2 findings: 1 ack, 1 clean, 0 skipped\n") {
		t.Fatalf("missing summary:\n%s", out)
	}
}

func TestAckSkipped(t *testing.T) {
	c, root := ackCliCamp(t, map[string]string{
		"src/Clean.sol": "contract Clean {\n    function ok() external {}\n}\n",
	})
	// a path only: no lines, no function, no index — nothing to scan
	fid := ackCliFinding(t, c, "the path-only finding", "src/Clean.sol")
	code, out, errS := run(t, "--root", root, "ack", c.CampaignID, fid)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, fid+": skipped — no scannable anchor") {
		t.Fatalf("output = %q", out)
	}
}

func TestAckUnknownFinding(t *testing.T) {
	_, root := ackCliCamp(t, map[string]string{
		"src/Clean.sol": "contract Clean {}\n"})
	code, out, errS := run(t, "--root", root, "ack", "C-nope", "F-123456789012")
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q\n%s", code, out, errS)
	}
}

func TestAckArgparse(t *testing.T) {
	_, root := ackCliCamp(t, map[string]string{
		"src/Clean.sol": "contract Clean {}\n"})

	code, out, errS := run(t, "--root", root, "ack")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, out, errS)
	}
	if !strings.Contains(errS, "the following arguments are required: "+
		"campaign") {
		t.Fatalf("stderr %q", errS)
	}
	if !strings.Contains(errS, "usage: webv2 ack") {
		t.Fatalf("usage block missing:\n%s", errS)
	}

	code, out, errS = run(t, "--root", root, "ack", "C-1", "F-1", "extra")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, out, errS)
	}
	if !strings.Contains(errS, "unrecognized arguments: extra") {
		t.Fatalf("stderr %q", errS)
	}

	code, out, errS = run(t, "--root", root, "ack", "C-1", "--bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, out, errS)
	}
	if !strings.Contains(errS, "unrecognized arguments: --bogus") {
		t.Fatalf("stderr %q", errS)
	}
}
