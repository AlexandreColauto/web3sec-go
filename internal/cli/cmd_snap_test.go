package cli

// T32 / D19: the `snap --deployment/--chain` CLI wiring. The reference has no
// CLI-level test for these flags (the library halves are pinned by
// tests/test_snapshot.py::test_deployment_and_chain_pins and
// tests/test_design_upgrades.py::test_manifest_refreshes_when_pins_attach,
// ported as internal/snapshot TestAttachDeploymentAndChainPins and
// TestManifestAttachRefreshesRoots), so this test pins the Go CLI's flag
// effect end to end: the pin members on disk, the spec 5.3 manifest roots,
// the two events, and the printed summary lines. The cross-twin byte
// comparison lives in d19_probe.py [untracked].

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

const t32Deployment = `{
 "network": "ethereum",
 "contracts": [
  {"name": "Vault", "address": "0x1111111111111111111111111111111111111111",
   "bytecode_hash": "0xabababababababababababababababababababababababababababababababab",
   "source_match": "verified"},
  {"name": "Proxy", "address": "0x2222222222222222222222222222222222222222",
   "bytecode_hash": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
   "implementation_address": "0x1111111111111111111111111111111111111111",
   "proxy_admin": "0x3333333333333333333333333333333333333333",
   "source_match": "unverified"}
 ]
}`

const t32Chain = `{
 "network": "ethereum",
 "chain_id": 1,
 "fork_block": 23456789,
 "fork_block_hash": "0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
}`

func t32Target(t *testing.T) string {
	t.Helper()
	tgt := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(filepath.Join(tgt, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tgt, "foundry.toml"),
		[]byte("[profile.default]\nsol = \"0.8.24\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"Vault.sol": "contract Vault { uint256 public total; }\n",
		"Proxy.sol": "contract Proxy { }\n",
	} {
		if err := os.WriteFile(filepath.Join(tgt, "src", name),
			[]byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return tgt
}

// TestSnapDeploymentAndChainFlags is the D19 CLI pin: both flags attach the
// pin to the just-pinned snapshot, refresh the manifest (spec 5.3
// deployment_merkle_root / chain_fingerprint), log the two events and print
// the two summary lines.
func TestSnapDeploymentAndChainFlags(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	dep := filepath.Join(t.TempDir(), "deployment.json")
	chain := filepath.Join(t.TempDir(), "chain.json")
	if err := os.WriteFile(dep, []byte(t32Deployment), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chain, []byte(t32Chain), 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errS := run(t, "--root", root, "snap", cid, tgt,
		"--deployment", dep, "--chain", chain)
	if code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "  deployment: ethereum (2 contracts)\n") {
		t.Fatalf("deployment summary line missing: %q", out)
	}
	if !strings.Contains(out, "  chain: 1 @ 23456789\n") {
		t.Fatalf("chain summary line missing: %q", out)
	}

	camp := filepath.Join(root, "campaigns", cid)
	snapDirs, err := os.ReadDir(filepath.Join(camp, "snapshots"))
	if err != nil || len(snapDirs) != 1 {
		t.Fatalf("snapshots = %v (%v)", snapDirs, err)
	}
	sid := snapDirs[0].Name()
	snap, err := validation.ReadJson(filepath.Join(camp, "snapshots", sid,
		"snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	depPin := validation.ObjAt(snap, "deployment")
	if got := len(validation.ObjAt(depPin, "contracts").A); got != 2 {
		t.Fatalf("deployment.contracts = %d, want 2", got)
	}
	if got := validation.ObjStr(depPin, "network"); got != "ethereum" {
		t.Fatalf("deployment.network = %q", got)
	}
	chPin := validation.ObjAt(snap, "chain")
	if got := scalarStr(validation.ObjAt(chPin, "fork_block")); got != "23456789" {
		t.Fatalf("chain.fork_block = %q", got)
	}
	man := validation.ObjAt(snap, "manifest")
	depRoot := validation.ObjStr(man, "deployment_merkle_root")
	chainFP := validation.ObjStr(man, "chain_fingerprint")
	if len(depRoot) != 64 || len(chainFP) != 64 {
		t.Fatalf("manifest roots: deployment=%q chain=%q", depRoot, chainFP)
	}
	if validation.ObjStr(man, "toolchain_fingerprint") == "" {
		t.Fatalf("toolchain_fingerprint missing: %s", validation.CanonCompact(man))
	}
	st, err := validation.ReadJson(filepath.Join(camp, "campaign_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(st, "active_snapshot_id"); got != sid {
		t.Fatalf("active_snapshot_id = %q, want %q", got, sid)
	}

	// the two events, in order, with their contract payloads
	raw, err := os.ReadFile(filepath.Join(camp, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		types = append(types, e["type"].(string))
	}
	want := []string{"campaign.created", "snapshot.pinned",
		"snapshot.deployment_attached", "snapshot.chain_attached"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("event types = %v, want %v", types, want)
	}
	last := map[string]any{}
	json.Unmarshal([]byte(strings.Split(strings.TrimSpace(string(raw)), "\n")[2]), &last)
	data := last["data"].(map[string]any)
	if data["contracts"].(float64) != 2 || data["network"] != "ethereum" {
		t.Fatalf("deployment event data = %v", data)
	}
}

// TestSnapDeploymentFlagMissingFileFailsLoud: a bad --deployment path is a
// loud error, not a silently dropped flag (the D19 symptom).
func TestSnapDeploymentFlagMissingFileFailsLoud(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	tgt := t32Target(t)
	code, _, errS := run(t, "--root", root, "snap", cid, tgt,
		"--deployment", filepath.Join(t.TempDir(), "nope.json"))
	if code == 0 {
		t.Fatalf("missing deployment file must fail: %q", errS)
	}
	if !strings.Contains(errS, "nope.json") {
		t.Fatalf("error does not name the file: %q", errS)
	}
}
