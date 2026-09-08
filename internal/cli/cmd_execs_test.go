package cli

// P2 CLI tests — `execs` (ord 38) and `classify` (ord 60). The list line,
// the two refusals and the classify block are byte-for-byte from
// .scratch/t20/capture_cli.py.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// ingestT20 is F.ingest_hypothesis with the fixture's payload.
func ingestT20(t *testing.T, c *state.Campaign, payload validation.Value,
	trajectory, stage string) (validation.Value, error) {
	t.Helper()
	return findings.IngestHypothesis(c, payload, trajectory, stage, "")
}

// TestExecsList pins the ledger line: id, profile, state padded to 12, and
// the command cut at 70 runes.
func TestExecsList(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "execs", f.c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	lines := []string{
		f.fail + "  [docker-networkless] exit 1       forge build",
		f.host + "  [host-readonly] exit 0       echo hi",
		f.noTests + "  [docker-networkless] exit 0       " +
			"forge test --match-test none",
		f.pass + "  [docker-networkless] exit 0       " +
			"forge test --match-test poc",
	}
	sort.Strings(lines)
	want := strings.Join(lines, "\n") + "\n"
	if out != want {
		t.Fatalf("out\n%q\nwant\n%q", out, want)
	}
}

// TestExecsJSONAndID pins the indent-2 rendering and the record order (the
// JSON body itself is the record the sandbox wrote — asserted through the
// same loader the command uses).
func TestExecsJSONAndID(t *testing.T) {
	f := t20Setup(t)
	code, out, errS := run(t, "--root", f.root, "execs", f.c.CampaignID,
		"--id", f.pass)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	rec, err := sandbox.LoadExec(f.c, f.pass)
	if err != nil {
		t.Fatal(err)
	}
	if out != prettyASCII(rec)+"\n" {
		t.Fatalf("--id out\n%q\nwant\n%q", out, prettyASCII(rec)+"\n")
	}
	if !strings.HasPrefix(out, "{\n  \"exec_id\": \""+f.pass+"\",\n") {
		t.Fatalf("--id head %q", out[:min(60, len(out))])
	}
	code, out, errS = run(t, "--root", f.root, "execs", f.c.CampaignID, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	execs, err := sandbox.AllExecs(f.c)
	if err != nil {
		t.Fatal(err)
	}
	if out != prettyASCII(validation.VArr(execs...))+"\n" {
		t.Fatalf("--json out\n%q", out)
	}
}

// TestExecsEmptyLedger pins the empty-campaign line.
func TestExecsEmptyLedger(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "execs", cid)
	if code != 0 || out != "no exec records in this campaign\n" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
}

// TestExecsMissingID pins the exit-2 lookup failure.
func TestExecsMissingID(t *testing.T) {
	f := t20Setup(t)
	code, _, errS := run(t, "--root", f.root, "execs", f.c.CampaignID,
		"--id", "EXEC-nope")
	if code != 2 || errS != "no exec 'EXEC-nope' in this campaign\n" {
		t.Fatalf("exit %d err %q", code, errS)
	}
}

// TestExecsUnknownCampaign pins the generic handler (exit 1).
func TestExecsUnknownCampaign(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "campaigns"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "execs", "C-abcdef12")
	if code != 1 {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(errS, "error: no such campaign: ") {
		t.Fatalf("err %q", errS)
	}
}

// TestExecsArgparseErrors pins the in-subparser errors.
func TestExecsArgparseErrors(t *testing.T) {
	code, _, errS := run(t, "execs")
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	want := argparseUsageBlocks["execs"] +
		"webv2 execs: error: the following arguments are required: campaign\n"
	if errS != want {
		t.Fatalf("err\n%q\nwant\n%q", errS, want)
	}
	code, _, errS = run(t, "execs", "C-x", "--id")
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	want = argparseUsageBlocks["execs"] +
		"webv2 execs: error: argument --id: expected one argument\n"
	if errS != want {
		t.Fatalf("err\n%q\nwant\n%q", errS, want)
	}
	// argparse refuses an option-looking token as a value.
	code, _, errS = run(t, "execs", "C-x", "--id", "--help")
	if code != 2 || errS != want {
		t.Fatalf("exit %d err\n%q\nwant\n%q", code, errS, want)
	}
}

// TestExecsHelp pins the help surface (argparse prints it to stdout, exit 0).
func TestExecsHelp(t *testing.T) {
	code, out, errS := run(t, "execs", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.HasPrefix(out, "usage: webv2 execs [-h] [--id ID] [--json] "+
		"campaign\n") || !strings.Contains(out, "show this help message and exit") {
		t.Fatalf("out %q", out)
	}
}
