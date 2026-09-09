package cli

// cmd_terminals tests — `terminals` (ord 9): argparse vectors, the captured
// empty report, and the shortest-path / materialized formatting including the
// shared net-at-risk suffix.

import (
	"bytes"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestTerminalsArgparse(t *testing.T) {
	t23WantHelp(t, []string{"terminals", "--help"}, t23TerminalsHelp)
}

// TestTerminalsEmptyReport is the captured Python vector: the EOA baseline
// line, the enumeration header and the materialized count.
func TestTerminalsEmptyReport(t *testing.T) {
	c, root, _ := t23Campaign(t, "terminals-empty")
	code, out, errS := run(t, "--root", root, "terminals", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "attacker baseline: call_any_entry_point\n" +
		"shortest path to each terminal state (0 multi-step paths " +
		"enumerated):\nmaterialized terminal chains: 0\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

func TestTerminalsNoSuchCampaign(t *testing.T) {
	_, root, _ := t23Campaign(t, "terminals-nocamp")
	code, out, errS := run(t, "--root", root, "terminals", "C-aaaaaaaaaa")
	if code != 1 || out != "" || !strings.Contains(errS,
		"error: no such campaign: ") {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
}

// TestTerminalsPrinter pins the direct/chain path lines, the capital money
// column and the `; net at risk $N` suffix (cli.py _cap_suffix).
func TestTerminalsPrinter(t *testing.T) {
	rep := validation.VObj(
		kvT("baseline", validation.VArr(validation.VStr("call_any_entry_point"))),
		kvT("terminal_chains", validation.VArr(validation.VObj())),
		kvT("shortest_by_terminal", validation.VArr(
			validation.VObj(
				kvT("terminal_capability", validation.VStr("drain_treasury")),
				kvT("path", validation.VArr(validation.VStr("F-a"))),
				kvT("total_capital_required_usd", validation.VFloat(1000)),
				kvT("capital_breakdown", validation.VObj(
					kvT("net_at_risk_usd", validation.VFloat(250.5))))),
			validation.VObj(
				kvT("terminal_capability", validation.VStr("mint")),
				kvT("path", validation.VArr(validation.VStr("F-a"),
					validation.VStr("F-b"))),
				kvT("total_capital_required_usd", validation.VFloat(2000)),
				kvT("capital_breakdown", validation.VObj(
					kvT("net_at_risk_usd", validation.VFloat(9000))))))),
		kvT("materialized_terminal_chains", validation.VArr(validation.VObj(
			kvT("chain_id", validation.VStr("CHAIN-9")),
			kvT("status", validation.VStr("CHAIN")),
			kvT("terminal", validation.VObj(
				kvT("capability", validation.VStr("drain_treasury")),
				kvT("via_finding", validation.VStr("F-b")))),
			kvT("evidence_floor", validation.VStr("E5"))))),
	)
	var buf bytes.Buffer
	printTerminals(&Runner{Out: &buf}, rep)
	want := "attacker baseline: call_any_entry_point\n" +
		"shortest path to each terminal state (1 multi-step paths " +
		"enumerated):\n" +
		"  [direct] -> drain_treasury: F-a (capital $1,000; net at risk $250)\n" +
		"  [chain] -> mint: F-a -> F-b (capital $2,000)\n" +
		"materialized terminal chains: 1\n" +
		"  CHAIN-9 [CHAIN] -> drain_treasury via F-b (floor E5)\n"
	if buf.String() != want {
		t.Fatalf("stdout\n%q\nwant\n%q", buf.String(), want)
	}
}

// TestTerminalsPrinterAbsentNet covers the missing / not-below-cap branches.
func TestTerminalsPrinterAbsentNet(t *testing.T) {
	rep := validation.VObj(
		kvT("baseline", validation.VArr()),
		kvT("terminal_chains", validation.VArr()),
		kvT("shortest_by_terminal", validation.VArr(validation.VObj(
			kvT("terminal_capability", validation.VStr("cap")),
			kvT("path", validation.VArr(validation.VStr("F-a"))),
			kvT("total_capital_required_usd", validation.VFloat(0))))),
		kvT("materialized_terminal_chains", validation.VArr()),
	)
	var buf bytes.Buffer
	printTerminals(&Runner{Out: &buf}, rep)
	want := "attacker baseline: (none)\n" +
		"shortest path to each terminal state (0 multi-step paths " +
		"enumerated):\n" +
		"  [direct] -> cap: F-a (capital $0)\n" +
		"materialized terminal chains: 0\n"
	if buf.String() != want {
		t.Fatalf("stdout\n%q\nwant\n%q", buf.String(), want)
	}
}
