package cli

// T-C1 CLI tests: `enforce` (ord 73, IMPROVEMENTS C1) — the enforcement
// timing table over the structural index. argparse vectors pin the usage
// block and the error precedence (house style, cmd_p3_args); the table output
// is pinned on the structidx fixture that carries the prevStateRoot shape.

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// enforceCampaign is a campaign with the structural fixture indexed.
func enforceCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c, root := t15Campaign(t, "enforce")
	tree := t25Tree(t, "structural")
	code, _, errS := run(t, "--root", root, "index", c.CampaignID, "--src", tree)
	if code != 0 {
		t.Fatalf("index exit %d: %q", code, errS)
	}
	return c, root
}

func TestEnforceHelp(t *testing.T) {
	code, out, errS := run(t, "enforce", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if out != enforceHelp {
		t.Fatalf("help\n%q\nwant\n%q", out, enforceHelp)
	}
	if !strings.HasPrefix(out, enforceUsage) ||
		!strings.Contains(out, "positional arguments:") ||
		!strings.Contains(out, "options:") {
		t.Fatalf("help shape: %q", out)
	}
}

func TestEnforceArgparse(t *testing.T) {
	vec := []struct {
		name string
		args []string
		want string
	}{
		{"no args", []string{"enforce"},
			enforceUsage + "webv2 enforce: error: the following arguments are " +
				"required: campaign, name\n"},
		{"missing name", []string{"enforce", "C-aaaaaaaaaa"},
			enforceUsage + "webv2 enforce: error: the following arguments are " +
				"required: name\n"},
		{"flag value", []string{"enforce", "C-aaaaaaaaaa", "v", "--json=1"},
			enforceUsage + "webv2 enforce: error: argument --json: ignored " +
				"explicit argument '1'\n"},
		{"contract value", []string{"enforce", "C-aaaaaaaaaa", "v", "--contract"},
			enforceUsage + "webv2 enforce: error: argument --contract: expected " +
				"one argument\n"},
		{"help value", []string{"enforce", "-h=1"},
			enforceUsage + "webv2 enforce: error: argument -h/--help: ignored " +
				"explicit argument '1'\n"},
		{"unknown", []string{"enforce", "C-aaaaaaaaaa", "v", "--bogus"},
			t14TopUsage + "webv2: error: unrecognized arguments: --bogus\n"},
	}
	for _, v := range vec {
		code, out, errS := run(t, v.args...)
		if code != 2 || out != "" || errS != v.want {
			t.Errorf("%s: exit %d out %q err %q want %q",
				v.name, code, out, errS, v.want)
		}
	}
}

func TestEnforceNoIndex(t *testing.T) {
	c, root := t15Campaign(t, "enforce-no-index")
	code, out, errS := run(t, "--root", root, "enforce", c.CampaignID, "v")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no structural index for "+c.CampaignID) ||
		!strings.Contains(errS, "webv2 index --src SRC") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestEnforceTableText(t *testing.T) {
	c, root := enforceCampaign(t)
	code, out, errS := run(t, "--root", root, "enforce", c.CampaignID, "prevStateRoot")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	for _, want := range []string{
		"enforce: prevStateRoot — storage match, 4 site(s) (1 write, 3 read), " +
			"ordering: call-graph\n",
		"read  StateRoots.commitBatch@14",
		"guard class 4 prevStateRoot[batchIndex] == stateRoot",
		"read  StateRoots.getPrevStateHash@21",
		"guards: none",
		"signals:\n  - unguarded-read: StateRoots.getPrevStateHash@21 reads " +
			"prevStateRoot with no assertion about it\n",
		"stages: 1 (write, read) pair(s), 0 with an unguarded write, " +
			"0 open on both ends\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	// Depths come from the call graph: the entry point first, its callee next.
	if strings.Index(out, "commitBatch@14") > strings.Index(out, "getPrevStateHash@21") {
		t.Errorf("sites out of depth order:\n%s", out)
	}

	code, out, errS = run(t, "--root", root, "enforce", c.CampaignID, "stateRoots")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "no-writer: no function in the index writes "+
		"stateRoots; 1 read site(s) consume whatever is stored") {
		t.Errorf("stateRoots output:\n%s", out)
	}
}

func TestEnforceTableJSON(t *testing.T) {
	c, root := enforceCampaign(t)
	code, out, errS := run(t, "--root", root, "enforce", c.CampaignID,
		"prevStateRoot", "--json")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	tbl := mustJSON(t, out)
	if got := validation.ObjStr(tbl, "name"); got != "prevStateRoot" {
		t.Errorf("name = %q", got)
	}
	if got := validation.ObjStr(tbl, "match"); got != "storage" {
		t.Errorf("match = %q", got)
	}
	if got := validation.ObjStr(tbl, "concept_key"); got != "prev:state:root" {
		t.Errorf("concept_key = %q", got)
	}
	if got := validation.ObjStr(tbl, "ordering"); got != "call-graph" {
		t.Errorf("ordering = %q", got)
	}
	if got := len(objListAt(tbl, "sites")); got != 4 {
		t.Errorf("sites = %d want 4", got)
	}
	if got := intAtForTest(t, tbl, "stats", "writes"); got != 1 {
		t.Errorf("stats.writes = %d", got)
	}
	if got := len(objListAt(tbl, "stages")); got != 1 {
		t.Errorf("stages = %d want 1", got)
	}
}

func TestEnforceContractScope(t *testing.T) {
	c, root := enforceCampaign(t)
	code, out, errS := run(t, "--root", root, "enforce", c.CampaignID,
		"tokenMapping", "--contract", "L1ERC20Gateway")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "filtered to contract L1ERC20Gateway") {
		t.Errorf("scoped table should say it is scoped:\n%s", out)
	}
	if strings.Contains(out, "L2CustomGateway") {
		t.Errorf("scoped table leaked another contract:\n%s", out)
	}
	if got := strings.Count(out, "\n  read  ") + strings.Count(out, "\n  write "); got != 3 {
		t.Errorf("scoped sites = %d want 3:\n%s", got, out)
	}

	code, out, errS = run(t, "--root", root, "enforce", c.CampaignID,
		"tokenMapping", "--contract", "NoSuchContract")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if errS != "enforce: no write or read site for 'tokenMapping' in contract "+
		"NoSuchContract\n" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestEnforceUnknownName(t *testing.T) {
	c, root := enforceCampaign(t)
	code, out, errS := run(t, "--root", root, "enforce", c.CampaignID,
		"totallyUnknownValue")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "enforce: totallyUnknownValue — none match, 0 site(s)") ||
		!strings.Contains(out, "no site reads or writes totallyUnknownValue "+
			"(concept keys tried: ") {
		t.Fatalf("output = %q", out)
	}
}

// intAtForTest reads a nested int field of a parsed JSON object.
func intAtForTest(t *testing.T, v validation.Value, keys ...string) int64 {
	t.Helper()
	cur := v
	for _, k := range keys {
		cur = validation.ObjAt(cur, k)
	}
	if cur.Kind != validation.Int {
		t.Fatalf("field %v: not an int (%v)", keys, cur)
	}
	return cur.I
}
