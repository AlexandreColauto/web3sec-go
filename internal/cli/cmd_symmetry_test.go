package cli

// T-C2 CLI tests: `symmetry` (ord 74, IMPROVEMENTS C2) — the family
// custody-primitive matrix over the structural index. argparse vectors pin the
// usage block and the error precedence (house style, cmd_p3_args); the matrix
// output is pinned on the symmetry fixture that carries the G-02 shape (a base
// recovery path paying out of its own balance while the derived forward path
// burns).

import (
	"strings"
	"testing"

	"websec/internal/state"
)

// symmetryCampaign is a campaign with the symmetry fixture indexed.
func symmetryCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c, root := t15Campaign(t, "symmetry")
	tree := t25Tree(t, "symmetry")
	code, _, errS := run(t, "--root", root, "index", c.CampaignID, "--src", tree)
	if code != 0 {
		t.Fatalf("index exit %d: %q", code, errS)
	}
	return c, root
}

func TestSymmetryHelp(t *testing.T) {
	code, out, errS := run(t, "symmetry", "--help")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	if out != symmetryHelp {
		t.Fatalf("help\n%q\nwant\n%q", out, symmetryHelp)
	}
	if !strings.HasPrefix(out, symmetryUsage) ||
		!strings.Contains(out, "positional arguments:") ||
		!strings.Contains(out, "options:") {
		t.Fatalf("help shape: %q", out)
	}
}

func TestSymmetryArgparse(t *testing.T) {
	vec := []struct {
		name string
		args []string
		want string
	}{
		{"no args", []string{"symmetry"},
			symmetryUsage + "webv2 symmetry: error: the following arguments are " +
				"required: campaign\n"},
		{"flag value", []string{"symmetry", "C-aaaaaaaaaa", "--json=1"},
			symmetryUsage + "webv2 symmetry: error: argument --json: ignored " +
				"explicit argument '1'\n"},
		{"family value", []string{"symmetry", "C-aaaaaaaaaa", "--family"},
			symmetryUsage + "webv2 symmetry: error: argument --family: expected " +
				"one argument\n"},
		{"unknown", []string{"symmetry", "C-aaaaaaaaaa", "--bogus"},
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

func TestSymmetryNoIndex(t *testing.T) {
	c, root := t15Campaign(t, "symmetry-no-index")
	code, out, errS := run(t, "--root", root, "symmetry", c.CampaignID)
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "no structural index for "+c.CampaignID) {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestSymmetryMatrixText: the G-02 shape must render as a family whose
// forward path burns while the drop path transfers out — one funding-mismatch
// question naming both ends.
func TestSymmetryMatrixText(t *testing.T) {
	c, root := symmetryCampaign(t)
	code, out, errS := run(t, "--root", root, "symmetry", c.CampaignID)
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	for _, want := range []string{
		"symmetry: 1 family, 2 member(s),",
		"1 divergence(s)",
		"L1ERC20Gateway (L1ERC20Gateway, L1ReverseCustomGateway)",
		"deposit:   erc20 transfer-in L1ReverseCustomGateway._deposit@",
		"share burn L1ReverseCustomGateway._deposit@",
		"drop:      erc20 transfer-out L1ERC20Gateway.onDropMessage@",
		"! funding-mismatch: L1ERC20Gateway: the forward path " +
			"L1ReverseCustomGateway::_deposit#",
		"who funds the difference?",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

func TestSymmetryMatrixJSONAndFamilyScope(t *testing.T) {
	c, root := symmetryCampaign(t)
	code, out, errS := run(t, "--root", root, "symmetry", c.CampaignID, "--json")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	m := mustJSON(t, out)
	stats := objAt(m, "stats")
	if got := intAtForTest(t, stats, "families"); got != 1 {
		t.Errorf("families = %d", got)
	}
	if got := intAtForTest(t, stats, "funding_mismatches"); got != 1 {
		t.Errorf("funding_mismatches = %d", got)
	}
	if got := intAtForTest(t, stats, "member_disagreements"); got != 0 {
		t.Errorf("member_disagreements = %d", got)
	}
	fams := objListAt(m, "families")
	if len(fams) != 1 {
		t.Fatalf("families = %d", len(fams))
	}
	divs := objListAt(fams[0], "divergences")
	if len(divs) != 1 {
		t.Fatalf("divergences = %d", len(divs))
	}
	if got := objStr(divs[0], "kind"); got != "funding-mismatch" {
		t.Errorf("kind = %q", got)
	}

	code, out, errS = run(t, "--root", root, "symmetry", c.CampaignID,
		"--family", "L1ERC20Gateway")
	if code != 0 || errS != "" {
		t.Fatalf("scoped exit %d err %q", code, errS)
	}
	if !strings.Contains(out, "L1ERC20Gateway (L1ERC20Gateway") {
		t.Errorf("scoped output:\n%s", out)
	}

	code, out, errS = run(t, "--root", root, "symmetry", c.CampaignID,
		"--family", "NoSuchFamily")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if errS != "symmetry: no inheritance family named 'NoSuchFamily' in the "+
		"structural index\n" {
		t.Fatalf("stderr = %q", errS)
	}
}
