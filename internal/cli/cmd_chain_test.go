package cli

// cmd_chain tests — `chain` (ord 72, Go-only): argparse vectors, the
// unproven path end to end (doc + provenance + no super-finding), the proven
// refusal with its --unproven hint, and the missing-campaign mapping.

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

// chainIDRe pulls the minted chain id out of the verb's summary line.
var chainIDRe = regexp.MustCompile(`CHAIN-[A-Za-z0-9]+`)

func TestChainHelp(t *testing.T) {
	t23WantHelp(t, []string{"chain", "--help"}, chainHelp)
}

// TestChainArgparse pins the required-argument and option-value errors
// (argparse exit 2, exact usage block).
func TestChainArgparse(t *testing.T) {
	_, root := t15Campaign(t, "chain-argparse")
	vectors := []struct {
		name string
		args []string
		want string
	}{
		{"no-positionals", []string{"chain"},
			chainUsage + "webv2 chain: error: the following arguments are " +
				"required: campaign, member\n"},
		{"one-positional", []string{"chain", "C-aaaaaaaaaa"},
			chainUsage + "webv2 chain: error: the following arguments are " +
				"required: member\n"},
		{"note-needs-value", []string{"chain", "C-aaaaaaaaaa", "F-1", "--note"},
			chainUsage + "webv2 chain: error: argument --note: expected one " +
				"argument\n"},
		{"title-needs-value", []string{"chain", "C-aaaaaaaaaa", "F-1", "--title"},
			chainUsage + "webv2 chain: error: argument --title: expected one " +
				"argument\n"},
		{"unproven-takes-no-value", []string{"chain", "C-aaaaaaaaaa",
			"F-1", "F-2", "--unproven=true"},
			chainUsage + "webv2 chain: error: argument --unproven: ignored " +
				"explicit argument 'true'\n"},
		{"unknown-flag", []string{"chain", "C-aaaaaaaaaa", "F-1", "F-2", "--bogus"},
			t14TopUsage + "webv2: error: unrecognized arguments: --bogus\n"},
	}
	for _, v := range vectors {
		args := append([]string{"--root", root}, v.args...)
		code, out, errS := run(t, args...)
		if code != 2 || out != "" || errS != v.want {
			t.Errorf("%s: exit %d out %q err\n%q\nwant err\n%q",
				v.name, code, out, errS, v.want)
		}
	}
}

// TestChainNoSuchCampaign is the generic mapper (exit 1).
func TestChainNoSuchCampaign(t *testing.T) {
	_, root := t15Campaign(t, "chain-nocamp")
	code, out, errS := run(t, "--root", root, "chain", "C-aaaaaaaaaa",
		"F-1", "F-2", "--unproven")
	if code != 1 || out != "" || !strings.Contains(errS, "error: no such campaign: ") {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
}

// chainPair ingests the two-member freeze chain at HYPOTHESIS: the first
// grants the pause capability, the second needs it and grants the liveness
// terminal.
func chainPair(t *testing.T, root, cid string) (string, string) {
	t.Helper()
	f1 := t23Ingest(t, root, cid, "Pause gate reachable by arbitrary EOA",
		"access-control", []string{"control_protocol_pause"}, nil)
	f2 := t23Ingest(t, root, cid, "Pause with no timelock freezes withdrawals",
		"chain-freeze", []string{"liveness_loss"},
		[]string{"control_protocol_pause"})
	return f1, f2
}

// TestChainUnprovenMaterializes is the B3 centerpiece end to end: a
// hypothesis-level chain becomes a chain doc with provenance "unproven",
// renders as such in `chains`, and creates NO finding.
func TestChainUnprovenMaterializes(t *testing.T) {
	c, root := t15Campaign(t, "chain-unproven")
	f1, f2 := chainPair(t, root, c.CampaignID)
	code, out, errS := run(t, "--root", root, "chain", c.CampaignID, f1, f2,
		"--unproven", "--note", "EOA pauses; nobody can unpause")
	if code != 0 || errS != "" {
		t.Fatalf("exit %d err %q", code, errS)
	}
	cid := chainIDRe.FindString(out)
	if cid == "" {
		t.Fatalf("no chain id in stdout: %q", out)
	}
	want := cid + ": unproven chain materialized from 2 members " +
		"(evidence floor E0), terminal liveness_loss via " + f2 +
		", no super-finding (hypothesis-level)\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	// the doc is marked, and the links carry the member evidence level.
	ch, err := validation.ReadJson(filepath.Join(c.ChainsDir, cid+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(ch, "provenance"); got != "unproven" {
		t.Errorf("provenance = %q", got)
	}
	link := listAtCLI(ch, "capability_links")[0]
	if got := validation.ObjStr(link, "link_evidence"); got != "E0" {
		t.Errorf("link_evidence = %q, want E0", got)
	}
	if got := validation.ObjStr(ch, "narrative"); got != "EOA pauses; nobody can unpause" {
		t.Errorf("narrative = %q", got)
	}
	// `chains` renders the provenance marker after the unchanged row.
	code, out, errS = run(t, "--root", root, "chains", c.CampaignID)
	if code != 0 {
		t.Fatalf("chains exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "materialized chains: 1 (1 unproven — "+
		"hypothesis-level leads, not evidence)\n") {
		t.Errorf("chains stdout\n%q", out)
	}
	if !strings.Contains(out, "provenance unproven (hypothesis-level)") {
		t.Errorf("chains stdout lacks the provenance marker:\n%q", out)
	}
	// and nothing became a finding.
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if st := validation.ObjStr(f, "status"); st != "HYPOTHESIS" {
			t.Errorf("%s status = %q, want HYPOTHESIS",
				validation.ObjStr(f, "finding_id"), st)
		}
	}
	if len(all) != 2 {
		t.Errorf("findings = %d, want 2", len(all))
	}
}

// TestChainProvenRefusalHintsAtUnproven: the proven gate still refuses
// hypothesis members, and the CLI says how to proceed (exit 2).
func TestChainProvenRefusalHintsAtUnproven(t *testing.T) {
	c, root := t15Campaign(t, "chain-proven-refuse")
	f1, f2 := chainPair(t, root, c.CampaignID)
	code, out, errS := run(t, "--root", root, "chain", c.CampaignID, f1, f2)
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	if !strings.Contains(errS, "must each be CONFIRMED first") ||
		!strings.Contains(errS, "pass --unproven") {
		t.Fatalf("stderr = %q", errS)
	}
	if !strings.HasPrefix(errS, "chain failed: ") {
		t.Fatalf("stderr = %q", errS)
	}
}
