package cli

// cmd_privileged tests — `privileged` (ord 10): argparse vectors, the
// captured empty track, and the role block formatting (baseline, band,
// constraint qualifiers, direct/chains paths with the capital suffix).

import (
	"bytes"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestPrivilegedArgparse(t *testing.T) {
	t23WantHelp(t, []string{"privileged", "--help"}, t23PrivilegedHelp)
}

// TestPrivilegedEmptyReport is the captured Python vector.
func TestPrivilegedEmptyReport(t *testing.T) {
	c, root, _ := t23Campaign(t, "privileged-empty")
	code, out, errS := run(t, "--root", root, "privileged", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "privileged track (0 role(s), separate from the EOA terminal " +
		"report)\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

func TestPrivilegedNoSuchCampaign(t *testing.T) {
	_, root, _ := t23Campaign(t, "privileged-nocamp")
	code, out, errS := run(t, "--root", root, "privileged", "C-aaaaaaaaaa")
	if code != 1 || out != "" || !strings.Contains(errS,
		"error: no such campaign: ") {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
}

// TestPrivilegedPrinter pins one full role block, including the (none)
// branches, the qualifier rendering and the capital suffix.
func TestPrivilegedPrinter(t *testing.T) {
	role := validation.VObj(
		kvT("role", validation.VStr("GOV")),
		kvT("role_label", validation.VStr("governance")),
		kvT("baseline", validation.VArr(validation.VStr("call_any_entry_point"),
			validation.VStr("hold_gov"))),
		kvT("exposure_band", validation.VStr("high")),
		kvT("constraints", validation.VArr(
			validation.VObj(
				kvT("capability", validation.VStr("admin")),
				kvT("mechanism", validation.VStr("timelock")),
				kvT("timelocked", validation.VBool(true)),
				kvT("multisig_threshold", validation.VNull())),
			validation.VObj(
				kvT("capability", validation.VStr("")),
				kvT("mechanism", validation.VStr("")),
				kvT("timelocked", validation.VBool(false)),
				kvT("multisig_threshold", validation.VInt(2))),
			validation.VObj(
				kvT("capability", validation.VStr("owner")),
				kvT("mechanism", validation.VNull()),
				kvT("timelocked", validation.VBool(false)),
				kvT("multisig_threshold", validation.VNull())))),
		kvT("direct", validation.VArr(validation.VObj(
			kvT("path", validation.VArr(validation.VStr("F-a"))),
			kvT("terminal_capability", validation.VStr("drain")),
			kvT("total_capital_required_usd", validation.VFloat(100)),
			kvT("capital_breakdown", validation.VObj(
				kvT("net_at_risk_usd", validation.VFloat(10))))))),
		kvT("chains", validation.VArr(validation.VObj(
			kvT("path", validation.VArr(validation.VStr("F-a"),
				validation.VStr("F-b"))),
			kvT("terminal_capability", validation.VStr("mint")),
			kvT("total_capital_required_usd", validation.VFloat(5))))),
	)
	var buf bytes.Buffer
	printPrivilegedRole(&Runner{Out: &buf}, role)
	want := "role: GOV (governance)\n" +
		"  baseline: call_any_entry_point, hold_gov\n" +
		"  band: high\n" +
		"  constraints:\n" +
		"    - admin via timelock (timelocked)\n" +
		"    - (unnamed capability) (threshold 2)\n" +
		"    - owner\n" +
		"  direct: F-a -> drain; net at risk $10\n" +
		"  chains: F-a -> F-b -> mint\n"
	if buf.String() != want {
		t.Fatalf("stdout\n%q\nwant\n%q", buf.String(), want)
	}
}

// TestPrivilegedPrinterEmptyBlocks covers the (none) lines.
// Port of tests/test_cli_privileged.py::
// test_privileged_subcommand_two_run_determinism: rendering the same role
// twice is byte-identical (the printer never iterates a map).
func TestPrivilegedPrinterTwoRunDeterminism(t *testing.T) {
	role := validation.VObj(
		kvT("role", validation.VStr("GOV")),
		kvT("role_label", validation.VStr("governance")),
		kvT("baseline", validation.VArr(validation.VStr("call_any_entry_point"))),
		kvT("exposure_band", validation.VStr("high")),
		kvT("constraints", validation.VArr()),
		kvT("direct", validation.VArr()),
		kvT("chains", validation.VArr()),
	)
	var first, second bytes.Buffer
	printPrivilegedRole(&Runner{Out: &first}, role)
	printPrivilegedRole(&Runner{Out: &second}, role)
	if first.String() != second.String() {
		t.Fatalf("two runs differ:\n%q\n%q", first.String(), second.String())
	}
}

func TestPrivilegedPrinterEmptyBlocks(t *testing.T) {
	role := validation.VObj(
		kvT("role", validation.VStr("R")),
		kvT("role_label", validation.VStr("role")),
		kvT("baseline", validation.VArr()),
		kvT("exposure_band", validation.VStr("low")),
		kvT("constraints", validation.VArr()),
		kvT("direct", validation.VArr()),
		kvT("chains", validation.VArr()),
	)
	var buf bytes.Buffer
	printPrivilegedRole(&Runner{Out: &buf}, role)
	want := "role: R (role)\n" +
		"  baseline: \n" +
		"  band: low\n" +
		"  constraints:\n" +
		"    (none)\n" +
		"  direct: (none)\n" +
		"  chains: (none)\n"
	if buf.String() != want {
		t.Fatalf("stdout\n%q\nwant\n%q", buf.String(), want)
	}
}
