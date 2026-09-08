package cli

// P2 CLI tests — `classify` (ord 60). The verdict block and both refusals
// are byte-for-byte from .scratch/t20/capture_cli.py.

import (
	"testing"
)

// TestClassifyEnvironment pins the environment verdict block.
func TestClassifyEnvironment(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "classify", f.c.CampaignID,
		f.fail)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "exec " + f.fail + " (exit 1): ENVIRONMENT\n" +
		"  signal: docker/daemon/network error pattern in output\n" +
		"  signal: compilation/setup error pattern\n" +
		"  fix the environment; do NOT spend a fresh-context retry on this\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestClassifySucceeded pins the NONE verdict.
func TestClassifySucceeded(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "classify", f.c.CampaignID,
		f.pass)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "exec " + f.pass + " (exit 0): NONE\n" +
		"  exec succeeded; nothing to classify\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestClassifyMissing pins the exit-2 ledger lookup failure.
func TestClassifyMissing(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "classify", f.c.CampaignID,
		"EXEC-nope")
	if code != 2 ||
		errS != "exec EXEC-nope not found in the campaign's exec ledger\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestClassifyArgparseErrors pins both missing-positional messages.
func TestClassifyArgparseErrors(t *testing.T) {
	code, _, errS := run(t, "classify")
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	want := argparseUsageBlocks["classify"] + "webv2 classify: error: " +
		"the following arguments are required: campaign, exec_id\n"
	if errS != want {
		t.Fatalf("err\n%q\nwant\n%q", errS, want)
	}
	code, _, errS = run(t, "classify", "C-x")
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	want = argparseUsageBlocks["classify"] + "webv2 classify: error: " +
		"the following arguments are required: exec_id\n"
	if errS != want {
		t.Fatalf("err\n%q\nwant\n%q", errS, want)
	}
}

// TestClassifyHelp pins the help surface.
func TestClassifyHelp(t *testing.T) {
	code, out, errS := run(t, "classify", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	want := "usage: webv2 classify [-h] campaign exec_id\n\n" +
		"positional arguments:\n  campaign\n  exec_id\n\n" +
		"options:\n  -h, --help  show this help message and exit\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}
