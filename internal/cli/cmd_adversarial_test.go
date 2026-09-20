package cli

// cmd_adversarial_test.go: the CLI half of IMPROVEMENTS B2 —
// `webv2 adversarial-game` records who profits from the freeze, how the
// profit works, and why the challenge path does not undo it. A short field
// exits 2 (`adversarial-game failed: ...`); a missing finding falls through
// to the generic handler (exit 1); the clause is persisted and logged.

import (
	"strconv"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

const (
	cliAgWho = "the sequencer operator — every frozen hour pays their " +
		"uptime fees while rival bridges lose the deposits in transit"
	cliAgMech = "freezing withdrawals lets the operator's own staked " +
		"position absorb the fee flow while the halted bridge bleeds " +
		"TVL to competitors"
	cliAgInter = "the timelock challenge path expires into a no-op once " +
		"the upgrade queue is blocked, so the freeze cannot be voted " +
		"away before the challenge window closes"
	// cliAgAttack (morph §7.2): the strongest attacker variant the interplay
	// answer must survive — a proof-VALID bad state, not a malformed one.
	cliAgAttack = "the strongest variant is a proof-valid bad batch: the " +
		"operator posts a fake prev root and proves a valid transition " +
		"FROM it, so the challenge verifies and the freeze survives"
)

func TestAdversarialGameRecordsAndPrints(t *testing.T) {
	c, root := t15Campaign(t, "adversarial-game")
	f := t15Finding(t, c, "a chain-freeze hypothesis", "chain-freeze")
	fid := validation.ObjStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid,
		"--who-profit", cliAgWho, "--mechanism", cliAgMech,
		"--interplay", cliAgInter,
		"--strongest-attacker", cliAgAttack)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	want := fid + ": adversarial-game clause recorded (who_profits " +
		strconv.Itoa(len([]rune(cliAgWho))) +
		" chars) — the adversarial-game gate clause is now complete"
	if !strings.Contains(out, want) {
		t.Fatalf("output %q, want %q", out, want)
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ag := validation.ObjAt(stored, "adversarial_game")
	if validation.ObjStr(ag, "who_profits") != cliAgWho ||
		validation.ObjStr(ag, "profit_mechanism") != cliAgMech ||
		validation.ObjStr(ag, "challenge_interplay") != cliAgInter ||
		validation.ObjStr(ag, "strongest_attacker") != cliAgAttack {
		t.Errorf("persisted clause = %s", validation.CanonSpaced(ag))
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if validation.ObjStr(last, "type") != "finding.adversarial_game_set" {
		t.Errorf("event type = %q", validation.ObjStr(last, "type"))
	}
}

// TestAdversarialGameEqualsForm: the --flag=VALUE form parses identically.
func TestAdversarialGameEqualsForm(t *testing.T) {
	c, root := t15Campaign(t, "adversarial-game-eq")
	f := t15Finding(t, c, "a sequencer-halt hypothesis", "sequencer-halt")
	fid := validation.ObjStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid,
		"--who-profit="+cliAgWho, "--mechanism="+cliAgMech,
		"--interplay="+cliAgInter,
		"--strongest-attacker="+cliAgAttack)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q\n%s", code, errS, out)
	}
	if !strings.Contains(out, fid+": adversarial-game clause recorded") {
		t.Fatalf("output %q", out)
	}
}

// TestAdversarialGameShortFieldExitsTwo: a label is not an argument — the
// setter refuses below the 20-char floor and nothing persists.
func TestAdversarialGameShortFieldExitsTwo(t *testing.T) {
	c, root := t15Campaign(t, "adversarial-game-short")
	f := t15Finding(t, c, "a chain-freeze hypothesis", "chain-freeze")
	fid := validation.ObjStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid,
		"--who-profit", cliAgWho, "--mechanism", "short",
		"--interplay", cliAgInter,
		"--strongest-attacker", cliAgAttack)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS, "adversarial-game failed: ") ||
		!strings.Contains(errS,
			"adversarial_game.profit_mechanism must be >= 20 characters "+
				"(have 5)") {
		t.Fatalf("stderr %q", errS)
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(stored, "adversarial_game").Kind != validation.Null {
		t.Error("a rejected clause must not persist")
	}

	// the fourth arm has its own floor (morph §7.2): a strongest_attacker
	// stub is refused exactly like the other three.
	c2, root2 := t15Campaign(t, "adversarial-game-short-attacker")
	f2 := t15Finding(t, c2, "a sequencer-halt hypothesis", "sequencer-halt")
	fid2 := validation.ObjStr(f2, "finding_id")
	code, out, errS = run(t, "--root", root2, "adversarial-game",
		c2.CampaignID, fid2,
		"--who-profit", cliAgWho, "--mechanism", cliAgMech,
		"--interplay", cliAgInter, "--strongest-attacker", "short")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"adversarial_game.strongest_attacker must be >= 20 characters "+
			"(have 5)") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestAdversarialGameArgparseFailures: the required flags and positionals
// are argparse errors (exit 2), in the house format.
func TestAdversarialGameArgparseFailures(t *testing.T) {
	c, root := t15Campaign(t, "adversarial-game-argparse")
	f := t15Finding(t, c, "a chain-freeze hypothesis", "chain-freeze")
	fid := validation.ObjStr(f, "finding_id")

	// all four flags missing
	code, out, errS := run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"the following arguments are required: --who-profit, "+
			"--mechanism, --interplay, --strongest-attacker") {
		t.Fatalf("stderr %q", errS)
	}
	if !strings.Contains(errS, "usage: webv2 adversarial-game") {
		t.Fatalf("usage block missing:\n%s", errS)
	}

	// one flag missing: only it is listed
	code, out, errS = run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid, "--who-profit", cliAgWho,
		"--interplay", cliAgInter,
		"--strongest-attacker", cliAgAttack)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"the following arguments are required: --mechanism") {
		t.Fatalf("stderr %q", errS)
	}

	// the finding positional missing: campaign, finding order
	code, out, errS = run(t, "--root", root, "adversarial-game",
		"--who-profit", cliAgWho, "--mechanism", cliAgMech,
		"--interplay", cliAgInter,
		"--strongest-attacker", cliAgAttack)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"the following arguments are required: campaign, finding") {
		t.Fatalf("stderr %q", errS)
	}

	// dangling --mechanism
	code, out, errS = run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid, "--who-profit", cliAgWho, "--mechanism")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"argument --mechanism: expected one argument") {
		t.Fatalf("dangling-flag stderr %q", errS)
	}

	// dangling --strongest-attacker (morph §7.2: the new arm mirrors
	// --interplay's bare/= /missing-value cases)
	code, out, errS = run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid, "--who-profit", cliAgWho, "--mechanism", cliAgMech,
		"--interplay", cliAgInter, "--strongest-attacker")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS,
		"argument --strongest-attacker: expected one argument") {
		t.Fatalf("dangling-strongest stderr %q", errS)
	}

	// overflow positional: unrecognized (root-parser message)
	code, out, errS = run(t, "--root", root, "adversarial-game",
		c.CampaignID, fid, "extra",
		"--who-profit", cliAgWho, "--mechanism", cliAgMech,
		"--interplay", cliAgInter,
		"--strongest-attacker", cliAgAttack)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS, "unrecognized arguments: extra") {
		t.Fatalf("overflow stderr %q", errS)
	}
}

// TestAdversarialGameUnknownFinding: the generic handler (exit 1), like the
// other finding-level verbs.
func TestAdversarialGameUnknownFinding(t *testing.T) {
	c, root := t15Campaign(t, "adversarial-game-unknown")
	code, out, errS := run(t, "--root", root, "adversarial-game",
		c.CampaignID, "F-nope",
		"--who-profit", cliAgWho, "--mechanism", cliAgMech,
		"--interplay", cliAgInter,
		"--strongest-attacker", cliAgAttack)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %q\n%s", code, errS, out)
	}
	if !strings.Contains(errS, "no finding") {
		t.Fatalf("stderr %q", errS)
	}
}
