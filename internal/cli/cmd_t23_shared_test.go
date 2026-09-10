package cli

// T23 CLI tests — shared fixtures and the shared surface (chains, terminals,
// privileged, impact, ladder).
//
// Ports: tests/test_chain_engine.py, tests/test_privileged_baseline.py and
// tests/test_privileged_bands.py exercised through the CLI, plus the argparse
// and handler vectors captured from the live Python CLI. The Python twin was retired 2026-09-09; this package is the source of truth.

import (
	"regexp"
	"strings"
	"testing"

	"websec/internal/chainengine"
	"websec/internal/maximization"
	"websec/internal/orchestrator"
	"websec/internal/state"
	"websec/internal/validation"
)

// t23FIDRe is the `ingested F-xxx` line's id.
var t23FIDRe = regexp.MustCompile(`ingested (F-[0-9a-z]+)`)

// t23Campaign opens a campaign with one ingested hypothesis. Returns the
// campaign, the workspace root and the finding id.
func t23Campaign(t *testing.T, program string) (*state.Campaign, string, string) {
	t.Helper()
	c, root := t15Campaign(t, program)
	fid := t23Ingest(t, root, c.CampaignID, "Rounding loss", "logic-error",
		[]string{"drain_treasury"}, nil)
	return c, root, fid
}

// t23Ingest runs `ingest --json-file` and returns the minted finding id.
func t23Ingest(t *testing.T, root, cid, title, class string,
	granted, required []string) string {
	t.Helper()
	payload := validation.VObj(
		kvT("title", validation.VStr(title)),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr(class)),
			kvT("description", validation.VStr(
				"test fixture: rounding loss on deposit")))),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("src/V.sol")),
			kvT("function", validation.VStr("deposit"))))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()))),
		kvT("capabilities", validation.VObj(
			kvT("granted", t23StrArr(granted)),
			kvT("required", t23StrArr(required)))),
	)
	p := t14TestWrite(t, root, "hyp-"+title+".json",
		validation.DumpIndented(payload))
	code, out, errS := run(t, "--root", root, "ingest", cid, "--json-file", p)
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	m := t23FIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("ingest output missing id: %q", out)
	}
	return m[1]
}

func t23StrArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, it := range items {
		out = append(out, validation.VStr(it))
	}
	return validation.VArr(out...)
}

// t23WantArgparse asserts the argparse failure shape: exit 2, empty stdout,
// and exactly usage+message on stderr.
func t23WantArgparse(t *testing.T, args []string, usage, msg string) {
	t.Helper()
	code, out, errS := run(t, args...)
	if code != 2 {
		t.Fatalf("%v: exit %d, want 2 (stderr %q)", args, code, errS)
	}
	if out != "" {
		t.Fatalf("%v: stdout %q, want empty", args, out)
	}
	want := usage + msg
	if errS != want {
		t.Fatalf("%v: stderr\n%q\nwant\n%q", args, errS, want)
	}
}

// t23WantHelp asserts --help: exit 0, exact help on stdout, empty stderr.
func t23WantHelp(t *testing.T, args []string, help string) {
	t.Helper()
	code, out, errS := run(t, args...)
	if code != 0 || errS != "" {
		t.Fatalf("%v: exit %d stderr %q", args, code, errS)
	}
	if out != help {
		t.Fatalf("%v: stdout\n%q\nwant\n%q", args, out, help)
	}
}

// TestT23RegistrationOrdinals pins the cli.py main() registration order.
func TestT23RegistrationOrdinals(t *testing.T) {
	want := map[string]int{"chains": 8, "terminals": 9, "privileged": 10,
		"impact": 47, "ladder": 53}
	for name, ord := range want {
		cmd, ok := commandByName(name)
		if !ok {
			t.Fatalf("command %s not registered", name)
		}
		if cmd.ord != ord {
			t.Fatalf("%s ord %d, want %d", name, cmd.ord, ord)
		}
	}
}

// TestT23Money0 is Python's f"{x:,.0f}" over the CLI's money columns.
func TestT23Money0(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"}, {1000, "1,000"}, {999, "999"}, {1234567.89, "1,234,568"},
		{-1234.5, "-1,234"}, {1234567890, "1,234,567,890"},
	}
	for _, tc := range cases {
		if got := t23Money0(tc.in); got != tc.want {
			t.Fatalf("t23Money0(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestT23PyG is Python's f"{x:g}" over threshold renderings.
func TestT23PyG(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{1, "1"}, {0.5, "0.5"}, {1000000, "1e+06"}, {3, "3"}, {2.5, "2.5"},
	}
	for _, tc := range cases {
		if got := t23PyG(tc.in); got != tc.want {
			t.Fatalf("t23PyG(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestT23NoFlagVerbArgparse pins the one-positional verbs' argparse vectors.
func TestT23NoFlagVerbArgparse(t *testing.T) {
	for _, v := range []struct{ cmd, usage string }{
		{"chains", t23ChainsUsage}, {"terminals", t23TerminalsUsage},
		{"privileged", t23PrivilegedUsage},
	} {
		t23WantArgparse(t, []string{v.cmd}, v.usage,
			"webv2 "+v.cmd+": error: the following arguments are required: "+
				"campaign\n")
		t23WantArgparse(t, []string{v.cmd, "--bogus"}, v.usage,
			"webv2 "+v.cmd+": error: the following arguments are required: "+
				"campaign\n")
		t23WantArgparse(t, []string{v.cmd, "C", "extra"},
			t14TopUsage, "webv2: error: unrecognized arguments: extra\n")
		t23WantArgparse(t, []string{v.cmd, "C", "extra", "--bogus"},
			t14TopUsage,
			"webv2: error: unrecognized arguments: extra --bogus\n")
	}
}

// TestT23NoneText covers the absent-positional rendering shared by the verbs.
func TestT23NoneText(t *testing.T) {
	if t23PyNone("") != "None" || t23PyNone("F-1") != "F-1" {
		t.Fatal("t23PyNone")
	}
	if !strings.Contains(t23HelpFor("ladder"), "positional arguments:") {
		t.Fatal("t23HelpFor(ladder)")
	}
}

// TestT23SeamsWired proves t23WireSeams connects the ports: a sentinel
// installed in the orchestrator seam is replaced by the real chain engine.
func TestT23SeamsWired(t *testing.T) {
	c, _, fid := t23Campaign(t, "t23-seams")
	sentinel := validation.VObj(kvT("sentinel", validation.VBool(true)))
	orchestrator.SetChainEngine(orchestrator.ChainEngineAPI{
		ChainReport: func(*state.Campaign) (validation.Value, error) {
			return sentinel, nil
		}})
	got, err := orchestrator.New(c).Chaining()
	if err != nil {
		t.Fatalf("Chaining: %v", err)
	}
	if validation.DumpIndentedASCII(got) != validation.DumpIndentedASCII(sentinel) {
		t.Fatalf("sentinel not installed: %q", validation.DumpIndentedASCII(got))
	}
	t23WireSeams()
	got, err = orchestrator.New(c).Chaining()
	if err != nil {
		t.Fatalf("Chaining: %v", err)
	}
	want, err := chainengine.ChainReport(c)
	if err != nil {
		t.Fatalf("ChainReport: %v", err)
	}
	if validation.DumpIndentedASCII(got) != validation.DumpIndentedASCII(want) {
		t.Fatalf("orchestrator seam not wired:\n%q\nwant\n%q",
			validation.DumpIndentedASCII(got), validation.DumpIndentedASCII(want))
	}
	if v, err := (t23Maximization{}).LoadLadder(c, fid); err != nil ||
		v.Kind != validation.Null {
		t.Fatalf("absent ladder = %v, %v", v, err)
	}
	if _, err := maximization.StartLadder(c, fid); err != nil {
		t.Fatalf("start ladder: %v", err)
	}
	v, err := (t23Maximization{}).LoadLadder(c, fid)
	if err != nil || v.Kind != validation.Obj {
		t.Fatalf("present ladder = %v, %v", v, err)
	}
}
