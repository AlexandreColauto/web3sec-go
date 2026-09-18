// archetypes_test.go: 1:1 ports of tests/test_archetypes.py plus the two
// archetype-owned cases from tests/test_tier1_minor_sweep.py (S4 invalid
// regex, S5 corrupt overrides).
package archetypes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

var expectedIDs = []string{
	"cross-chain-relay-no-authz", "delegatecall-to-user-input",
	"flash-loan-oracle-manipulation", "merkle-proof-no-length-check",
	"multisig-threshold-single-point", "proof-accepted-without-depth-gate",
	"relayer-single-key", "signature-no-separator",
	"unguarded-asset-transfer", "unguarded-initialize", "uninitialized-proxy",
	"vault-share-pricing-surface", "verifier-default-on",
}

// trees is TREES: one planted tree per archetype — each satisfies its own
// checks.
var trees = map[string]string{
	"unguarded-asset-transfer": `
contract Pool {
    uint256 public totalAssets;
    function sweep(address to) external { totalAssets = 0; }
}
`,
	"uninitialized-proxy": `
contract Proxy {
    address public implementation;
    function init() external { implementation = msg.sender; }
    function fallbackCall(bytes calldata data) external returns (bytes memory r) {
        (bool ok, r) = implementation.delegatecall(data);
    }
}
`,
	"flash-loan-oracle-manipulation": `
interface IFlash { function flashLoan(address, uint256) external; }
interface IFeed { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract Exploit {
    function run(IFlash f, IFeed p) external {
        f.flashLoan(address(this), 1);
        int256 x = p.latestRoundData();
    }
}
`,
	"cross-chain-relay-no-authz": `
interface IBridge { function sendMessage(address, bytes calldata) external; }
contract Relayer {
    IBridge public bridge;
    function relay(bytes calldata payload) external {
        bridge.sendMessage(msg.sender, payload);
    }
}
`,
	"unguarded-initialize": `
contract Module {
    bool public initialized;
    address public owner_;
    function initialize(address o) external { initialized = true; owner_ = o; }
}
`,
	"delegatecall-to-user-input": `
contract ExecProxy {
    address public target;
    function exec(bytes calldata data) external returns (bytes memory r) {
        (bool ok, r) = target.delegatecall(data);
    }
}
`,
	"vault-share-pricing-surface": `
contract Vault {
    address public owner;
    uint256 public totalAssets;
    uint256 public totalShares;

    modifier onlyOwner() { require(msg.sender == owner); _; }

    function deposit() external payable onlyOwner { totalAssets += msg.value; }
    function withdraw(uint256 shares) external {}
}
`,
	// G10: inline copies of testdata/sigverify/buggy.sol and
	// testdata/merkleproof/buggy.sol — the fixture files are canonical.
	"signature-no-separator": `
contract SigVerifier {
    function verify(bytes memory signature, address signer) external pure returns (address recovered) {
        bytes32 h = keccak256(abi.encodePacked(signer));
        recovered = ecrecover(h, uint8(signature[0]), bytes32(0), bytes32(0));
    }
}
`,
	"proof-accepted-without-depth-gate": `
contract MerkleDistributor {
    mapping(bytes32 => bool) public accepted;

    function verifyProof(bytes32[] memory proof, bytes32 root) external {
        bytes32 h = proof[0];
        require(h != bytes32(0), "empty proof");
        accepted[root] = true;
    }
}
`,
	// I5a: inline copies of testdata/threshold/buggy.sol and
	// testdata/relayer/buggy.sol — the fixture files are canonical.
	"multisig-threshold-single-point": `
contract HarmonyBridge {
    address[] public owners;
    uint256 public threshold;
    address public owner;

    function setThreshold(uint256 t) external {
        threshold = t;
    }

    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
`,
	"relayer-single-key": `
contract ForceBridge {
    address public relayer;

    modifier onlyBridge() {
        require(msg.sender == relayer, "not relayer");
        _;
    }

    function relayMessage(bytes32 message, bytes calldata proof) external onlyBridge {
        emit Relayed(message);
    }
}
`,
	// I5b: inline copies of testdata/merklepath/buggy.sol and
	// testdata/verifier/buggy.sol — the fixture files are canonical. The
	// merkle tree's `lastCheckpoint` finality gate is deliberate: it keeps
	// proof-accepted-without-depth-gate (G10) absent on this tree so the two
	// merkle archetypes stay separable (see documentedShapeOverlaps).
	"merkle-proof-no-length-check": `
contract BridgeWithdrawal {
    mapping(bytes32 => bool) public processed;
    uint256 public lastCheckpoint;

    function verifyProof(bytes32[] calldata proof, bytes32 root) external {
        bytes32 h = proof[0];
        require(h == root, "bad proof");
        require(lastCheckpoint != 0, "no checkpoint");
        processed[root] = true;
    }
}
`,
	"verifier-default-on": `
contract NomadReplica {
    bool public verified;

    constructor() {
        verified = true;
    }

    function process(bytes32 root) external {
        require(verified, "not verified");
        emit Processed(root);
    }
}
`,
}

// makeTree is make_tree: a campaign + a one-file src tree, indexed.
func makeTree(t *testing.T, sol string) (validation.Value, *state.Campaign) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Arch Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "Tree.sol"), []byte(sol), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := structidx.IndexSnapshot(c, root, structidx.DefaultBackend)
	if err != nil {
		t.Fatal(err)
	}
	return idx, c
}

// TestAvailableArchetypesAreExactlyTheThirteen is the count pin. Wave I Task 4
// (I5b) lands Eleven->Thirteen: this task ships TWO archetypes
// (merkle-proof-no-length-check, verifier-default-on), so the pin moves by
// exactly the two ids appended to expectedIDs — Task 3's Eleven stays
// untouched. Never "fix" this number for another task's files.
func TestAvailableArchetypesAreExactlyTheThirteen(t *testing.T) {
	got, err := AvailableArchetypes()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(expectedIDs, ",") {
		t.Fatalf("available_archetypes() = %v, want %v", got, expectedIDs)
	}
	if len(got) != 13 {
		t.Fatalf("expected 13 archetypes, got %d", len(got))
	}
}

func TestEachArchetypeMatchesItsPlantedTree(t *testing.T) {
	for _, aid := range expectedIDs {
		t.Run(aid, func(t *testing.T) {
			idx, _ := makeTree(t, trees[aid])
			arch, err := LoadArchetypeByName(aid)
			if err != nil {
				t.Fatal(err)
			}
			if got := validation.ObjStr(arch, "id"); got != aid {
				t.Fatalf("archetype id = %q, want %q", got, aid)
			}
			checks := listAt(arch, "checks")
			if len(checks) == 0 {
				t.Fatal("archetype has no checks")
			}
			for _, check := range checks {
				result, detail, err := EvaluatePrecondition(check, idx)
				if err != nil {
					t.Fatalf("%s check %s: %v", aid, validation.ObjStr(check, "type"), err)
				}
				if result != "present" {
					t.Fatalf("%s check %s: %s", aid, validation.ObjStr(check, "type"), detail)
				}
			}
		})
	}
}

func TestEachPlantedTreeMatchesOnlyItsOwnArchetype(t *testing.T) {
	// Discrimination matrix: each planted tree has ALL checks present for its
	// own archetype and at least one absent check for each of the other
	// twelve, unless the pair is a documented shape overlap (see
	// documentedShapeOverlaps).
	for _, aid := range expectedIDs {
		t.Run(aid, func(t *testing.T) {
			idx, _ := makeTree(t, trees[aid])
			for _, other := range expectedIDs {
				arch, err := LoadArchetypeByName(other)
				if err != nil {
					t.Fatal(err)
				}
				results := []string{}
				for _, c := range listAt(arch, "checks") {
					res, _, err := EvaluatePrecondition(c, idx)
					if err != nil {
						t.Fatal(err)
					}
					results = append(results, res)
				}
				if other == aid {
					for _, r := range results {
						if r != "present" {
							t.Fatalf("%s should fully match its own tree", other)
						}
					}
					continue
				}
				absent := false
				for _, r := range results {
					if r == "absent" {
						absent = true
					}
				}
				if documentedShapeOverlaps[aid][other] {
					// The pair is recorded as sharing a shape, so a full
					// match is expected — and a stale entry fails loud.
					if absent {
						t.Fatalf("%s no longer fully matches %s's tree: "+
							"remove the documentedShapeOverlaps entry",
							other, aid)
					}
					continue
				}
				if !absent {
					t.Fatalf("%s must not fully match %s's tree "+
						"(an overlap is a finding: record it in "+
						"documentedShapeOverlaps, do not widen the predicate)",
						other, aid)
				}
			}
		})
	}
}

// documentedShapeOverlaps are (tree, archetype) pairs that genuinely share the
// whole shape the archetype looks for, so the discrimination matrix cannot
// demand an absent check for them. Recording the pair is a FINDING about the
// two predicates, never a silenced one: the archetype still matches in
// prescreen, and the matrix fails if a pair stops overlapping, so the list
// cannot rot into a dumping ground for real discrimination failures.
//
// Both entries below are I5b's merkle_proof_no_length_check, which reads a
// names-matched entry point with an array/bytes-shaped selector and no own
// guard mentioning `length`:
//
//   - proof-accepted-without-depth-gate (G10) tree: its
//     verifyProof(bytes32[] proof, bytes32 root) with `require(h !=
//     bytes32(0))` IS a Merkle path consumed with no length check. The two
//     archetypes ask different questions of the same code (finality depth vs
//     path completeness), and this fixture carries neither gate's evidence.
//   - relayer-single-key (I5a) tree: its relayMessage(bytes32, bytes calldata
//     proof) takes a bytes path parameter that no guard mentions the length
//     of. The parameter is unused in that fixture, which is exactly the
//     documented false-hit class of selector-only evidence (the index carries
//     no parameter names or usage, so "declared" and "consumed" cannot be
//     told apart).
var documentedShapeOverlaps = map[string]map[string]bool{
	"proof-accepted-without-depth-gate": {"merkle-proof-no-length-check": true},
	"relayer-single-key":                {"merkle-proof-no-length-check": true},
}

// C0: `unguarded_entry_writes` reads the writer list through
// structidx.WritersOf, so an entry point whose only storage write is an
// indexed lvalue (which the parser's writes_storage omits) still satisfies it.
func TestUnguardedEntryWritesSeesIndexedStatementWrites(t *testing.T) {
	idx, _ := makeTree(t, `
contract Ledger {
    mapping(address => uint256) balances;
    function setBalance(address who, uint256 v) external { balances[who] = v; }
}
`)
	check := validation.VObj(
		validation.KV{K: "type", V: validation.VStr("unguarded_entry_writes")},
		validation.KV{K: "var_pattern", V: validation.VStr("^balances$")})
	result, detail, err := EvaluatePrecondition(check, idx)
	if err != nil {
		t.Fatal(err)
	}
	if result != "present" {
		t.Fatalf("indexed statement write not seen: %s %s", result, detail)
	}
}

func TestAbsentCheckReportsNearMatches(t *testing.T) {
	// totalStaked is a near-miss for an asset-var archetype: the operator
	// sees WHY it did not match instead of a silent false miss.
	idx, _ := makeTree(t, "contract P { uint256 public totalStaked; }")
	arch, err := LoadArchetypeByName("unguarded-asset-transfer")
	if err != nil {
		t.Fatal(err)
	}
	var varCheck validation.Value
	for _, c := range listAt(arch, "checks") {
		if validation.ObjStr(c, "type") == "state_var_exists" {
			varCheck = c
			break
		}
	}
	if varCheck.Kind != validation.Obj {
		t.Fatal("fixture archetype has no state_var_exists check")
	}
	result, _, err := EvaluatePrecondition(varCheck, idx)
	if err != nil {
		t.Fatal(err)
	}
	if result != "absent" {
		t.Fatalf("result = %q, want absent", result)
	}
	near := NearMatches(varCheck, idx, 3)
	if !containsStr(near, "totalStaked") {
		t.Fatalf("near_matches = %v, want totalStaked", near)
	}
}

func TestUnknownCheckTypeFailsLoud(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yaml")
	body := "id: bad-arch\nname: Bad\ncriticality: high\n" +
		"checks:\n  - type: not_a_real_check\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArchetype(p); err == nil {
		t.Fatal("an unknown check type must fail loud")
	} else if !strings.Contains(err.Error(), "not_a_real_check") {
		t.Fatalf("error %q does not name the unknown type", err)
	}
}

func TestPrescreenArtifactEventAndForce(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Pre Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "Tree.sol"),
		[]byte(trees["unguarded-initialize"]), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Prescreen(c, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(strSlice(validation.ObjAt(rep, "matched_ids")), "unguarded-initialize") {
		t.Fatalf("matched_ids = %v", validation.ObjAt(rep, "matched_ids"))
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, PrescreenFile)); err != nil {
		t.Fatalf("archetype_prescreen.json missing: %v", err)
	}
	// operator override: force a non-matching archetype into the report
	rep2, err := Prescreen(c, root, []string{"delegatecall-to-user-input"})
	if err != nil {
		t.Fatal(err)
	}
	forced := rowByID(t, rep2, "delegatecall-to-user-input")
	if !validation.ObjAt(forced, "forced").B || validation.ObjAt(forced, "match").B {
		t.Fatalf("forced row = %v", forced)
	}
	// the override persists across re-runs (it is operator state)
	rep3, err := Prescreen(c, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !validation.ObjAt(rowByID(t, rep3, "delegatecall-to-user-input"), "forced").B {
		t.Fatal("the override did not persist across re-runs")
	}
	verdict, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.OK {
		t.Fatalf("verify_log: %v", verdict.Problems)
	}
}

// ---- tier1 minor sweep: S4 + S5 -----------------------------------------

func TestS4InvalidRegexPatternFailsLoudWithValueError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad-regex.yaml")
	body := "id: bad-regex-arch\nname: Bad Regex\ncriticality: high\n" +
		"checks:\n  - type: state_var_exists\n    pattern: \"([\"\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadArchetype(p)
	if err == nil {
		t.Fatal("an invalid regex must fail loud")
	}
	if !strings.Contains(err.Error(), "bad-regex-arch") {
		t.Fatalf("error %q does not name the archetype", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "state_var_exists") || !strings.Contains(msg, "([") {
		t.Fatalf("error %q must name the check type and the pattern", msg)
	}
}

// treeCampaign is _tree_campaign: the unguarded-initialize tree.
func treeCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Prescreen Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "contract Module {\n" +
		"    bool public initialized;\n" +
		"    address public owner_;\n" +
		"    function initialize(address o) external { initialized = true; owner_ = o; }\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(src, "Tree.sol"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return c, root
}

func TestS5CorruptOverridesDegradeGracefully(t *testing.T) {
	cases := map[string]string{
		"not-json":       "{not valid json",
		"not-a-list":     `{"archetype_id": "unguarded-initialize"}`,
		"missing-id-key": `[{"no_archetype_id": true}]`,
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			c, root := treeCampaign(t)
			p := filepath.Join(c.ArtifactsDir, overridesFile)
			if err := os.WriteFile(p, []byte(corrupt), 0o644); err != nil {
				t.Fatal(err)
			}
			rep, err := Prescreen(c, root, nil)
			if err != nil {
				t.Fatalf("prescreen crashed on a corrupt overrides file: %v", err)
			}
			if !containsStr(strSlice(validation.ObjAt(rep, "matched_ids")), "unguarded-initialize") {
				t.Fatalf("matched_ids = %v", validation.ObjAt(rep, "matched_ids"))
			}
			for _, r := range listAt(rep, "results") {
				if validation.ObjAt(r, "forced").B {
					t.Fatalf("a corrupt overrides file force-applied %s",
						validation.ObjStr(r, "id"))
				}
			}
			found := false
			for _, prob := range strSlice(validation.ObjAt(rep, "problems")) {
				if strings.Contains(prob, "archetype_overrides.json") {
					found = true
				}
			}
			if !found {
				t.Fatalf("problems = %v, want an archetype_overrides.json note",
					validation.ObjAt(rep, "problems"))
			}
			if v, verr := c.VerifyLog(); verr != nil || !v.OK {
				t.Fatalf("verify_log not ok: %v", verr)
			}
		})
	}
}

// ---- embed byte-identity -------------------------------------------------

// The former twin byte-identity acceptance check moved to
// assets.TestAssetPackManifest (committed SHA-256 manifest, no external tree).

// ---- test helpers --------------------------------------------------------

func rowByID(t *testing.T, report validation.Value, id string) validation.Value {
	t.Helper()
	for _, r := range listAt(report, "results") {
		if validation.ObjStr(r, "id") == id {
			return r
		}
	}
	t.Fatalf("report carries no row for %s", id)
	return validation.VNull()
}

func strSlice(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		out = append(out, e.S)
	}
	return out
}

// TestPrescreenArtifactCarriesCampaignID pins the FIX-E binding: the
// prescreen artifact carries the campaign id it ran under (the same binding
// the recon stamps carry), so the L-04 divergence gate can refuse a prescreen
// copied from another campaign's artifacts directory — not only a stale one.
func TestPrescreenArtifactCarriesCampaignID(t *testing.T) {
	c, root := treeCampaign(t)
	rep, err := Prescreen(c, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(rep, "campaign_id"); got != c.CampaignID {
		t.Fatalf("report campaign_id = %q, want %q", got, c.CampaignID)
	}
	// the on-disk artifact carries it too
	disk, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		PrescreenFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(disk, "campaign_id"); got != c.CampaignID {
		t.Fatalf("artifact campaign_id = %q, want %q", got, c.CampaignID)
	}
}
