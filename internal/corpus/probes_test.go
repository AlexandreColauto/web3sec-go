// probes_test.go: 1:1 port of tests/test_corpus_surface_probes.py — the
// coverage rule plus per-predicate positive/negative fixtures.
package corpus

import (
	"strings"
	"testing"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// ---- fixture sources ------------------------------------------------------
// Fixture note (predicate-vs-fixture disagreement, plan Task 6 step 4): the
// structural index records `tgt.meth(` call shapes; a chained
// `IERC20(payable(0xdead)).transfer(` is invisible to it. The fixture routes
// the same external call through a typed local so the mechanism it pins
// (external call + storage write, guard vs no guard) is what the index sees.

const reentrancySol = `
contract Vault {
    uint256 public totalDeposits;
    function deposit() external {
        totalDeposits += msg.value;
        IERC20 token = IERC20(payable(0xdead));
        token.transfer(msg.sender, 1);
    }
}
interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }
`

const safeReentrancySol = `
contract Vault {
    bool private _locked;
    uint256 public totalDeposits;
    modifier nonReentrant() { _locked = true; _; _locked = false; }
    function deposit() external nonReentrant {
        totalDeposits += msg.value;
        IERC20 token = IERC20(payable(0xdead));
        token.transfer(msg.sender, 1);
    }
}
interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }
`

const donationSol = `
contract Vault {
    uint256 public totalAssets;
    uint256 public totalShares;
    uint256 public pricePerShare;
    function deposit(uint256 amount) external {
        totalAssets += amount;
        totalShares += 1;
        pricePerShare = totalAssets / totalShares;
    }
}
`

const plainSol = `
contract Greet {
    string public name;
    function set(string calldata n) external { name = n; }
}
`

// ---- coverage rule --------------------------------------------------------

func TestCoverageRuleAgainstLiveCorpus(t *testing.T) {
	// Every class in the LIVE stores is probed/aliased/unprobed.
	classes := []string{
		"access-control", "bridge-message", "centralization-risk", "donation",
		"dos-griefing", "flash-loan", "liquidation-logic", "logic-error",
		"oracle-manipulation", "precision-rounding", "reentrancy",
		"share-price-accounting", "share-price-inflation", "signature-replay",
		"token-integration", "unchecked-external-call", "upgrade-initializer",
	}
	rows := make([]validation.Value, 0, len(classes))
	for i, cls := range classes {
		rows = append(rows, wrapRow(seedRow(t,
			"MEM-cov"+pad4(i), cls, cls+" incident.")))
	}
	withSeams(t, rows, nil)
	inv, err := ClassInventory(newCampaign(t, "test-program"))
	if err != nil {
		t.Fatal(err)
	}
	gaps := CoverageGaps(inv)
	if len(gaps) != 0 {
		t.Fatalf("corpus classes without probe/alias/unprobed entry: %v", gaps)
	}
	if len(objAt(inv, "classes").O) != len(classes) {
		t.Fatalf("inventory classes = %d, want %d",
			len(objAt(inv, "classes").O), len(classes))
	}
}

// ---- per-predicate positive/negative --------------------------------------

func TestReentrancyFiresWithoutGuard(t *testing.T) {
	out := ProbeClasses(indexFor(t, reentrancySol))
	r := probeOf(t, out, "reentrancy")
	if !objAt(r, "exposed").B {
		t.Fatal("reentrancy must be exposed")
	}
	if !strings.HasSuffix(objStr(listAt(r, "hits")[0], "node_id"), ".deposit") {
		t.Fatalf("hit node = %q, want *.deposit", objStr(listAt(r, "hits")[0], "node_id"))
	}
}

// C0: the parser's per-function writes_storage only fires when the assignment
// operator follows the variable name directly (`stateWriteRe`), so an indexed
// or member lvalue (`balances[who] = v`, `s.field = v`) is recorded in the
// statement-level `uses` but NOT in the list. A probe that answers "who writes
// storage" from the list alone therefore misses the function entirely; with
// structidx.WritersOf (the reconciled list) it fires.
const indexedWriteSol = `
contract Ledger {
    mapping(address => uint256) balances;
    function setBalance(address who, uint256 v) external { balances[who] = v; }
}
`

func TestIndexedStatementWriteIsSeenByTheProbes(t *testing.T) {
	idx := indexFor(t, indexedWriteSol)
	// the divergence, pinned: the raw list is empty for the writer
	fn := fnNodeOf(t, idx, "setBalance")
	if got := listAt(fn, "writes_storage"); len(got) != 0 {
		t.Fatalf("parser now records indexed writes (%v): the C0 note is stale",
			got)
	}
	if got := structidx.WritersOf(idx, fn); len(got) != 1 || got[0] != "balances" {
		t.Fatalf("WritersOf = %v, want [balances]", got)
	}
	r := probeOf(t, ProbeClasses(idx), "access-control")
	if !objAt(r, "exposed").B {
		t.Fatal("an unguarded entry point writing an indexed lvalue must be exposed")
	}
	if got := objStr(listAt(r, "hits")[0], "node_id"); !strings.HasSuffix(got, ".setBalance") {
		t.Fatalf("hit node = %q, want *.setBalance", got)
	}
	if detail := objStr(listAt(r, "hits")[0], "detail"); !strings.Contains(detail, "balances") {
		t.Fatalf("hit detail = %q, want it to name the written variable", detail)
	}
}

func TestReentrancySilentWithGuard(t *testing.T) {
	out := ProbeClasses(indexFor(t, safeReentrancySol))
	r := probeOf(t, out, "reentrancy")
	if objAt(r, "exposed").B {
		t.Fatalf("guarded reentrancy must be silent, hits = %v", listAt(r, "hits"))
	}
	if objStr(r, "confidence") != "high" {
		t.Fatalf("confidence = %q, want high", objStr(r, "confidence"))
	}
}

func TestSharePriceInflationFiresOnDonationShape(t *testing.T) {
	out := ProbeClasses(indexFor(t, donationSol))
	r := probeOf(t, out, "share-price-inflation")
	if !objAt(r, "exposed").B {
		t.Fatal("share-price-inflation must be exposed")
	}
	// aliased classes report the same hits under their own names
	d := probeOf(t, out, "donation")
	if !objAt(d, "exposed").B {
		t.Fatal("donation alias must be exposed")
	}
	if validation.DumpsOrdered(objAt(d, "hits"), false) !=
		validation.DumpsOrdered(objAt(r, "hits"), false) {
		t.Fatal("alias hits must equal the canonical hits")
	}
}

func TestAliasHitsAreCopiesNotSharedLists(t *testing.T) {
	// Regression (Task 6 review): an alias row must not share the canonical
	// row's hits LIST OBJECT — mutating one row's hits downstream (e.g. the
	// report/bundle layer trimming hits) must never corrupt the other.
	out := ProbeClasses(indexFor(t, donationSol))
	canon := probeOf(t, out, "share-price-inflation")
	alias := probeOf(t, out, "donation")
	if validation.DumpsOrdered(objAt(alias, "hits"), false) !=
		validation.DumpsOrdered(objAt(canon, "hits"), false) {
		t.Fatal("alias hits must equal the canonical hits")
	}
	if len(listAt(canon, "hits")) == 0 {
		t.Fatal("fixture must expose the class for this test to bite")
	}
	n := len(listAt(canon, "hits"))
	aliasHits := objAt(alias, "hits")
	aliasHits.A = append(aliasHits.A, validation.VObj(
		validation.KV{K: "node_id", V: validation.VStr("tainted")},
		validation.KV{K: "detail", V: validation.VStr("post-hoc mutation")}))
	if len(listAt(canon, "hits")) != n {
		t.Fatalf("canonical hits = %d, want %d after alias mutation",
			len(listAt(canon, "hits")), n)
	}
	for _, h := range listAt(canon, "hits") {
		if objStr(h, "node_id") == "tainted" {
			t.Fatal("alias mutation leaked into the canonical row")
		}
	}
	// and the reverse direction: mutating the canonical row leaves the
	// alias's own list untouched
	canonHits := objAt(canon, "hits")
	canonHits.A = append(canonHits.A, validation.VObj(
		validation.KV{K: "node_id", V: validation.VStr("tainted-2")},
		validation.KV{K: "detail", V: validation.VStr("canonical edit")}))
	for _, h := range listAt(alias, "hits") {
		if objStr(h, "node_id") == "tainted-2" {
			t.Fatal("canonical mutation leaked into the alias row")
		}
	}
}

func TestPlainContractHasNoExposure(t *testing.T) {
	out := ProbeClasses(indexFor(t, plainSol))
	var exposed []string
	for _, x := range out {
		if objAt(x, "exposed").B {
			exposed = append(exposed, objStr(x, "bug_class"))
		}
	}
	// a plain string setter exposes nothing structural
	for _, cls := range exposed {
		if cls == "reentrancy" || cls == "share-price-inflation" {
			t.Fatalf("plain setter exposed %q", cls)
		}
	}
	if len(out) != len(Probes)+len(Aliases) {
		t.Fatalf("rows = %d, want %d", len(out), len(Probes)+len(Aliases))
	}
}

func TestUnprobedClassesCarryReasons(t *testing.T) {
	if Unprobed["precision-rounding"] == "" || Unprobed["signature-replay"] == "" {
		t.Fatal("unprobed classes must carry reasons")
	}
	// nothing is both probed and unprobed
	for cls := range Probes {
		if _, both := Unprobed[cls]; both {
			t.Fatalf("%q is both probed and unprobed", cls)
		}
	}
	for alias, target := range Aliases {
		if _, ok := Probes[target]; !ok {
			t.Fatalf("alias %q -> unknown class %q", alias, target)
		}
	}
}

// ---- paren-less call shapes (Task-12 review: dead trailing-\( regexes) -----
// The structural index records calls_external WITHOUT a trailing paren —
// `token.transferFrom`, never `token.transferFrom(`. Any predicate grepping
// for `\.(...)\(` can never fire on a real index. These fixtures pin the
// paren-less shape the indexer actually emits.

const tokenIfaceSol = `
contract Router {
    function pull(address to, uint256 amt) external {
        IERC20 token = IERC20(payable(0xdead));
        token.transferFrom(msg.sender, to, amt);
    }
}
interface IERC20 { function transferFrom(address from, address to, uint256 v) external returns (bool); }
`

const flashInOutSol = `
contract Arb {
    function flash(address poolAddr, address tokenAddr, uint256 amt) external {
        IPool pool = IPool(poolAddr);
        IERC20 token = IERC20(tokenAddr);
        pool.borrow(amt);
        token.transfer(msg.sender, amt);
    }
}
interface IPool { function borrow(uint256 amt) external; }
interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }
`

const authzValueMoveSol = `
contract Safe {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "!auth"); _; }
    function sweep(address tokenAddr, address to, uint256 amt) external onlyOwner {
        IERC20 t = IERC20(tokenAddr);
        t.transfer(to, amt);
    }
}
interface IERC20 { function transfer(address to, uint256 v) external returns (bool); }
`

func TestTokenIntegrationFiresOnParenlessTransferfrom(t *testing.T) {
	out := ProbeClasses(indexFor(t, tokenIfaceSol))
	r := probeOf(t, out, "token-integration")
	if !objAt(r, "exposed").B {
		t.Fatal("transferFrom recorded without parens must still fire")
	}
	if objStr(r, "confidence") != "low" {
		t.Fatalf("confidence = %q, want low", objStr(r, "confidence"))
	}
}

func TestTransferOutNeverMatchesTransferfromPrefix(t *testing.T) {
	// '.transfer' must not swallow '.transferFrom': no word boundary exists
	// between the two word chars 'r' and 'F'.
	if TransferOutRe.MatchString("asset.transferFrom") ||
		TransferOutRe.MatchString("asset.transferFrom(user, 1)") {
		t.Fatal(".transfer must not match .transferFrom")
	}
	// positive controls: the shapes the leg must keep catching
	if !TransferOutRe.MatchString("asset.transfer") ||
		!TransferOutRe.MatchString("pool.withdraw") {
		t.Fatal("the transfer/withdraw legs must still match")
	}
}

func TestFlashLoanNotExposedByTransferfromAlone(t *testing.T) {
	// 'token.transferFrom' satisfies the IN leg but no OUT leg; the in-out
	// predicate must not fire on a transfer-from-only flow (fixture names
	// avoid the flashloan/lendingpool name leg so only call shapes count).
	out := ProbeClasses(indexFor(t, tokenIfaceSol))
	r := probeOf(t, out, "flash-loan")
	if objAt(r, "exposed").B {
		t.Fatalf("flash-loan must stay silent, hits = %v", listAt(r, "hits"))
	}
}

func TestFlashLoanInOutLegFiresOnParenlessCalls(t *testing.T) {
	out := ProbeClasses(indexFor(t, flashInOutSol))
	r := probeOf(t, out, "flash-loan")
	if !objAt(r, "exposed").B {
		t.Fatal("pool.borrow + token.transfer (no parens) must fire")
	}
	// every hit must come from the call-shape leg ("transfer-in + out"), not
	// from the flashloan/lendingpool NAME leg — the fixture names avoid it
	hits := listAt(r, "hits")
	if len(hits) == 0 {
		t.Fatal("no hits")
	}
	for _, h := range hits {
		if objStr(h, "detail") != "transfer-in + out" {
			t.Fatalf("detail = %q, want transfer-in + out", objStr(h, "detail"))
		}
		if !strings.HasSuffix(objStr(h, "node_id"), ".flash") {
			t.Fatalf("node = %q, want *.flash", objStr(h, "node_id"))
		}
	}
}

func TestCentralizationValueMoveLegFiresOnParenlessTransfer(t *testing.T) {
	out := ProbeClasses(indexFor(t, authzValueMoveSol))
	r := probeOf(t, out, "centralization-risk")
	if !objAt(r, "exposed").B {
		t.Fatal("authz transfer (no parens) must fire the value-move leg")
	}
	if objStr(listAt(r, "hits")[0], "detail") != "authz value move" {
		t.Fatalf("detail = %q, want authz value move",
			objStr(listAt(r, "hits")[0], "detail"))
	}
}

// ---- helpers -------------------------------------------------------------

func probeOf(t *testing.T, out []validation.Value, cls string) validation.Value {
	t.Helper()
	for _, x := range out {
		if objStr(x, "bug_class") == cls {
			return x
		}
	}
	t.Fatalf("no probe row for %q", cls)
	return validation.VNull()
}

// fnNodeOf finds a function node by name.
func fnNodeOf(t *testing.T, index validation.Value, name string) validation.Value {
	t.Helper()
	for _, n := range objAt(index, "nodes").A {
		if objStr(n, "kind") == "function" && objStr(n, "name") == name {
			return n
		}
	}
	t.Fatalf("no function node %q", name)
	return validation.VNull()
}

func pad4(i int) string {
	s := "0000" + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
