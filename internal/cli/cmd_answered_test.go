package cli

// T14 cmd_answered tests: the closure-provenance rules (reason required),
// the Q-* and L-* routes, and the plan-missing guard. Vectors captured from
// the live Python CLI (.scratch/t14/py5.json twin run).

import (
	"strings"
	"testing"
)

func TestAnsweredRequiresReason(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-001",
		"answered")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "answered: 'answered' requires --reason (why). Pass --ref too " +
		"when the answer rests on evidence (finding/exec/artifact/file#L).\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestAnsweredPriorityClosure(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason", "the vault is empty on first deposit",
		"--ref", "src/ShareVault.sol#L42", "--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "Q-001: status -> answered (ref: src/ShareVault.sol#L42)\n" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	// re-closing with a different status keeps the stored evidence ref
	code, out, _ = run(t, "--root", root, "answered", cid, "Q-001",
		"not-applicable", "--reason", "it does not apply here at all",
		"--actor", "op")
	if code != 0 {
		t.Fatalf("re-close exit %d", code)
	}
	if out != "Q-001: status -> not-applicable "+
		"(ref: src/ShareVault.sol#L42)\n" {
		t.Fatalf("re-close stdout = %q", out)
	}
}

func TestAnsweredUnknownPriority(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "Q-999",
		"answered", "--reason", "no such priority (fixture)")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "answered failed: no priority 'Q-999' in the campaign plan\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestAnsweredLensFamilies(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	// an L-* closure must attest every seeded family
	code, _, errS := run(t, "--root", root, "answered", cid, "L-01",
		"answered", "--reason", "missing families here", "--actor", "op")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "answered: L-01 has unattested families (missing: protocol). " +
		"Pass --families protocol (or attest none apply) with --reason (why).\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
	code, out, errS := run(t, "--root", root, "answered", cid, "L-01",
		"answered", "--families", "protocol", "--reason",
		"the protocol stays live under every reachable state", "--actor", "op")
	if code != 0 {
		t.Fatalf("attested exit %d: %q", code, errS)
	}
	if out != "L-01: status -> answered\n" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestAnsweredLensSymmetry(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	code, out, errS := run(t, "--root", root, "answered", cid, "L-03",
		"answered", "--families", "protocol", "--symmetry",
		"protocol=deposit|withdraw", "--reason",
		"the siblings enforce the same check", "--actor", "op")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "L-03: status -> answered\n" {
		t.Fatalf("stdout = %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestAnsweredNoPlan(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "answered", cid, "Q-001",
		"answered", "--reason", "no plan loaded yet")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "no campaign plan loaded (webv2 plan "+cid+")\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestAnsweredInvalidStatus(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "answered", cid, "Q-001", "bogus",
		"--reason", "x")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "argument status: invalid choice: 'bogus' "+
		"(choose from 'open', 'assigned', 'answered', 'not-applicable', "+
		"'deprioritized', 'blocked')") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestAnsweredHelp(t *testing.T) {
	code, out, errS := run(t, "answered", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14AnsweredHelp {
		t.Fatalf("help = %q, want %q", out, t14AnsweredHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}
