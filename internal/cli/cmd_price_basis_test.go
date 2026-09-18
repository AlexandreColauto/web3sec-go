// T26 cmd_price_basis tests: the receipt that pins a finding's USD figures
// to a price row (Python's setdefault("economic_impact", {}) path) and the
// two failure modes. Vectors captured from the live Python CLI
// (parity.py [untracked], steps price_basis*, byte-exact).
package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// t26Hypothesis is examples/hypothesis.example.json (the ingest contract):
// the same payload the cross-twin probe pipes through both twins.
const t26Hypothesis = `{
  "title": "ShareVault deposit inflates the share price for later depositors",
  "root_cause": {
    "class": "share-price-inflation",
    "description": "The first depositor sets the share price with a single wei, so all later depositors buy shares at a price the attacker chose, diluting their position.",
    "mechanism": "deposit() mints shares at total_assets/total_shares before any real assets are in the vault"
  },
  "affected": [
    {"path": "src/ShareVault.sol", "contract": "ShareVault",
     "function": "deposit", "lines": [42, 60], "entry_point": true}
  ],
  "attacker": {"profile": "arbitrary EOA", "capabilities": ["deposit"]},
  "evidence": [],
  "invariant": {
    "id": "INV-1",
    "statement": "a depositor's share of total assets may not decrease as a result of their own deposit"
  },
  "assumptions": [
    {
      "id": "A1",
      "type": "state",
      "claim": "the vault can be empty when the first deposit arrives",
      "status": "UNKNOWN",
      "model_belief": 0.9,
      "blocking": true
    }
  ],
  "preconditions": [
    {
      "kind": "state",
      "description": "vault is empty (total_shares == 0)",
      "satisfied_by": "be the first depositor"
    }
  ],
  "exploit_sequence": [
    {"step": 1, "actor": "attacker", "action": "deposit(1 wei) to set the share price"},
    {"step": 2, "actor": "victim", "action": "deposit(1 ETH) at the attacker-set price"}
  ]
}
`

// ingestOne ingests the example payload and returns the finding id.
func ingestOne(t *testing.T, root, cid string) string {
	t.Helper()
	payload := filepath.Join(t.TempDir(), "payload.json")
	if err := os.WriteFile(payload, []byte(t26Hypothesis), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "ingest", cid, "--json-file",
		payload, "--trajectory", "economic", "--json")
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	m := t26FindingIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("ingest output has no finding id: %q", out)
	}
	return m[1]
}

func TestPriceBasisPinsFinding(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := ingestOne(t, root, cid)
	code, out, errS := run(t, "--root", root, "price", cid, "set", "eth",
		"3200.5", "--source", "coingecko", "--actor", "lead")
	if code != 0 {
		t.Fatalf("price set exit %d: %q", code, errS)
	}
	priceID := strings.Fields(out)[2]
	priceID = strings.TrimSuffix(priceID, ":")

	code, out, errS = run(t, "--root", root, "price-basis", cid, fid, priceID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := fid + ": price basis pinned to " + priceID +
		" (ETH @ $3,200.50)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	// economic_impact did not exist: setdefault creates it, and the key
	// lands inside the finding on disk.
	body, err := os.ReadFile(filepath.Join(root, "campaigns", cid,
		"findings", fid+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"economic_impact": {`) ||
		!strings.Contains(string(body),
			`"price_basis": "`+priceID+`"`) {
		t.Fatalf("finding = %s", body)
	}
}

func TestPriceBasisMissingPriceRow(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	fid := ingestOne(t, root, cid)
	code, out, errS := run(t, "--root", root, "price-basis", cid, fid, "eth")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := "price row eth not found in the price table (set it first: " +
		"`webv2 price " + cid + " set ...`)\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestPriceBasisMissingFinding(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, _ := run(t, "--root", root, "price", cid, "set", "eth",
		"3200.5", "--source", "coingecko", "--actor", "lead")
	if code != 0 {
		t.Fatalf("price set exit %d", code)
	}
	priceID := strings.TrimSuffix(strings.Fields(out)[2], ":")
	code, _, errS := run(t, "--root", root, "price-basis", cid, "F-nope",
		priceID)
	if code != 1 {
		t.Fatalf("exit %d err=%q", code, errS)
	}
	if !strings.Contains(errS, "F-nope") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestPriceBasisArgparse(t *testing.T) {
	code, out, errS := run(t, "price-basis", "C-abc")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := t26PriceBasisUsage + "webv2 price-basis: error: the following " +
		"arguments are required: finding, price_id\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

// t26FindingIDRe matches the ingest --json payload's finding_id.
var t26FindingIDRe = regexp.MustCompile(`"finding_id": "(F-[0-9a-z]+)"`)
