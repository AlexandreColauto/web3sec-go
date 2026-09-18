package cli

// T14 cmd_floors tests: the list table (with and without overrides), set,
// unset, and the parser's parent-flag placement. Vectors captured from the
// live Python CLI (py5.json [untracked] twin run).

import (
	"strings"
	"testing"
)

func TestFloorsListTable(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "floors", cid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "effective CONFIRMED floors (22 classes):\n") {
		t.Fatalf("stdout = %q", out[:60])
	}
	for _, want := range []string{
		"  access-control               E4  default E4\n",
		"  bridge-message               E6 *  default E6\n",
		"  centralization-risk          None  default E5\n",
		"  reentrancy                   E4  default E4\n",
		"  * = floor needs a deployment/chain pin and fork RPC — " +
			"`webv2 brief` shows which are structurally unreachable\n",
		"  classes without a listed floor default to the STATUS_FLOOR " +
			"CONFIRMED level (E5) — the most conservative assumption for " +
			"unknown classes\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q", want)
		}
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestFloorsSetUnset(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "floors", cid, "set",
		"reentrancy", "E5", "--actor", "lead", "--reason",
		"mainnet fork now reachable")
	if code != 0 {
		t.Fatalf("set exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out,
		"floor policy set: reentrancy -> E5 (actor lead, ") {
		t.Fatalf("set stdout = %q", out)
	}
	if !strings.HasSuffix(out, ")\n") {
		t.Fatalf("set stdout = %q", out)
	}
	// the table now shows the override on the reentrancy row
	code, out, _ = run(t, "--root", root, "floors", cid)
	if code != 0 {
		t.Fatalf("list exit %d", code)
	}
	if !strings.Contains(out, "  reentrancy                   E5 *  "+
		"OVERRIDE of E4 (by lead: mainnet fork now reachable)\n") {
		t.Fatalf("override row = %q", out)
	}
	code, out, errS = run(t, "--root", root, "floors", cid, "unset",
		"reentrancy", "--actor", "lead", "--reason", "no longer overridden")
	if code != 0 {
		t.Fatalf("unset exit %d: %q", code, errS)
	}
	if out != "floor policy cleared: reentrancy (actor lead) — falls back "+
		"to the built-in default\n" {
		t.Fatalf("unset stdout = %q", out)
	}
}

func TestFloorsUnsetWithoutOverride(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "floors", cid, "unset",
		"reentrancy", "--actor", "lead", "--reason", "already cleared")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "clear failed: \"no floor override for class 'reentrancy' in " +
		"this campaign\"\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestFloorsSetValidation(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "floors", cid, "set",
		"bad_class", "E5", "--actor", "lead", "--reason",
		"kebab-case is required here")
	if code != 1 {
		t.Fatalf("bad class exit %d: %q", code, errS)
	}
	if errS != "error: bug class must be kebab-case (a-z 0-9 -), got "+
		"'bad_class'\n" {
		t.Fatalf("bad class stderr = %q", errS)
	}
	code, _, errS = run(t, "--root", root, "floors", cid, "set",
		"reentrancy", "E5", "--actor", "lead", "--reason", "short")
	if code != 1 {
		t.Fatalf("short reason exit %d: %q", code, errS)
	}
	if errS != "error: floor overrides require a written reason (>= 10 "+
		"chars) — an unnamed preference is not a policy\n" {
		t.Fatalf("short reason stderr = %q", errS)
	}
}

func TestFloorsJSONAfterCampaign(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	// --json is a parent-parser flag: legal AFTER the campaign positional
	// (regression: it used to be reported as unrecognized)
	code, out, errS := run(t, "--root", root, "floors", cid, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "{\n  \"default_note\": ") {
		t.Fatalf("stdout = %q", out[:60])
	}
	if !strings.Contains(out, "\"class\": \"reentrancy\"") {
		t.Fatalf("stdout missing reentrancy row: %q", out)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestFloorsUnsetRequiresReason(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "floors", cid, "unset",
		"reentrancy", "--actor", "a")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(errS, "webv2 floors campaign unset: error: the "+
		"following arguments are required: --reason\n") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestFloorsHelp(t *testing.T) {
	code, out, errS := run(t, "floors", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14FloorsHelp {
		t.Fatalf("help = %q, want %q", out, t14FloorsHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestFloorsSetUnknownClassDiscloses pins r8-5: an out-of-taxonomy floor
// stays ACCEPTED (open vocabulary law) but names its inertness on stderr
// — the operator learns a typo costs protection, not that the taxonomy is
// closed.
func TestFloorsSetUnknownClassDiscloses(t *testing.T) {
	c, root := t15Campaign(t, "floors-unknown")
	code, out, errS := run(t, "--root", root, "floors", c.CampaignID,
		"set", "not-a-class", "E4", "--actor", "operator",
		"--reason", "we plan to file this class of drain soon")
	if code != 0 {
		t.Fatalf("open vocabulary must stay accepted: exit %d %q",
			code, errS)
	}
	if !strings.Contains(out, "floor policy set") {
		t.Fatalf("stdout stays the twin line: %q", out)
	}
	if !strings.Contains(errS, "not a known taxonomy class") {
		t.Fatalf("inertness must be disclosed: %q", errS)
	}
	// A canonical class says nothing extra.
	code, _, errS = run(t, "--root", root, "floors", c.CampaignID,
		"set", "reentrancy", "E4", "--actor", "operator",
		"--reason", "hard floor for value-moving paths in this program")
	if code != 0 || strings.Contains(errS, "not a known") {
		t.Fatalf("known class must be quiet: exit %d %q", code, errS)
	}
}
