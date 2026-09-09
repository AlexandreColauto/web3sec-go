package cli

// cmd_chains tests — `chains` (ord 8): argparse vectors, the empty report
// (captured from the live Python CLI), a real link report, and the printer's
// proposal/materialized formatting.

import (
	"bytes"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestChainsArgparse(t *testing.T) {
	t23WantHelp(t, []string{"chains", "--help"}, t23ChainsHelp)
}

// TestChainsEmptyReport is the captured Python vector for a campaign whose
// only finding is a hypothesis with no linked capability.
func TestChainsEmptyReport(t *testing.T) {
	c, root, _ := t23Campaign(t, "chains-empty")
	code, out, errS := run(t, "--root", root, "chains", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "capability links: 0\nproposals: 0\nmaterialized chains: 0\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

// TestChainsNoSuchCampaign pins the exit code and the `error:` prefix.
func TestChainsNoSuchCampaign(t *testing.T) {
	_, root, _ := t23Campaign(t, "chains-nocamp")
	code, out, errS := run(t, "--root", root, "chains", "C-aaaaaaaaaa")
	if code != 1 || out != "" || !strings.Contains(errS,
		"error: no such campaign: ") {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
}

// TestChainsLinkReport exercises the link line end to end: a finding that
// grants a capability and one that requires it produce exactly one link.
func TestChainsLinkReport(t *testing.T) {
	c, root, _ := t23Campaign(t, "chains-links")
	granter := t23Ingest(t, root, c.CampaignID, "Granter rounding loss", "logic-error",
		[]string{"admin"}, nil)
	needer := t23Ingest(t, root, c.CampaignID, "Needer rounding loss", "logic-error",
		nil, []string{"admin"})
	code, out, errS := run(t, "--root", root, "chains", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	// Proposals are NOT gated on CONFIRMED (chain_engine.find_chains);
	// only materialization is.
	want := "capability links: 1\n" +
		"  " + granter + " --admin--> " + needer + "\n" +
		"proposals: 1\n" +
		"  " + granter + " -> " + needer + "\n" +
		"materialized chains: 0\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

// TestChainsPrinterProposals covers the proposal and materialized-chain lines
// (the shapes the engine tests already produce, asserted byte-exactly here).
func TestChainsPrinterProposals(t *testing.T) {
	rep := validation.VObj(
		kvT("capability_links", validation.VArr(validation.VObj(
			kvT("from", validation.VStr("F-a")),
			kvT("to", validation.VStr("F-b")),
			kvT("capability", validation.VStr("drain"))))),
		kvT("proposals", validation.VArr(validation.VObj(
			kvT("members", validation.VArr(validation.VStr("F-a"),
				validation.VStr("F-b")))))),
		kvT("materialized", validation.VArr(validation.VObj(
			kvT("chain_id", validation.VStr("CHAIN-1")),
			kvT("status", validation.VStr("CHAIN")),
			kvT("title", validation.VStr("chain title")),
			kvT("evidence_floor", validation.VStr("E2"))))),
	)
	var buf bytes.Buffer
	printChains(&Runner{Out: &buf}, rep)
	want := "capability links: 1\n" +
		"  F-a --drain--> F-b\n" +
		"proposals: 1\n" +
		"  F-a -> F-b\n" +
		"materialized chains: 1\n" +
		"  CHAIN-1 [CHAIN] chain title (floor E2)\n"
	if buf.String() != want {
		t.Fatalf("stdout\n%q\nwant\n%q", buf.String(), want)
	}
}
