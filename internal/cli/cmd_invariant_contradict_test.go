package cli

// P1b CLI tests — `invariant-contradict` (ord 25).
//
// Ports: tests/test_role_isolation.py::test_cli_invariant_contradict_and_verify_paths
// (the error path must be one exit-2 line, no traceback) plus the happy path
// and the argparse surface.

import (
	"strings"
	"testing"
)

func TestInvariantContradict(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	t15SeedInvariant(t, c, "INV-1", "totalAssets monotone except withdraw")
	code, out, errS := run(t, "--root", root, "invariant-contradict",
		c.CampaignID, "INV-1", "--evidence", "src/V.sol#L1")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "INV-1: CONTRADICTED (") {
		t.Fatalf("output %q", out)
	}
}

func TestInvariantContradictUnknownIDExits2OneLine(t *testing.T) {
	c, root := t15Campaign(t, "inv")
	code, _, errS := run(t, "--root", root, "invariant-contradict",
		c.CampaignID, "INV-NOPE", "--evidence", "src/V.sol#L1")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if strings.Count(errS, "\n") != 1 || !strings.Contains(errS, "INV-NOPE") {
		t.Fatalf("stderr %q must be one line naming the id", errS)
	}
}

func TestInvariantContradictMissingEvidenceIsArgparse(t *testing.T) {
	code, _, errS := run(t, "invariant-contradict", "C-x", "INV-1")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["invariant-contradict"] +
		"webv2 invariant-contradict: error: the following arguments are " +
		"required: --evidence\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestInvariantContradictMissingAllIsArgparse(t *testing.T) {
	code, _, errS := run(t, "invariant-contradict")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["invariant-contradict"] +
		"webv2 invariant-contradict: error: the following arguments are " +
		"required: campaign, inv_id, --evidence\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
