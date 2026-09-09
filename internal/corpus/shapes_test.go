// shapes_test.go: 1:1 ports of tests/test_poc_shapes.py and
// tests/test_shape_match.py — deterministic call-shape extraction, the pinned
// cache, and the exact/near-miss matcher.
package corpus

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/archetypes"
	"websec/internal/validation"
)

const pocSol = `
interface IVault { function deposit(uint256 amount) external; }
contract Exploit {
    function run() public {
        IVault(v).deposit(100);
        token.transferFrom(msg.sender, address(this), 5);
        IERC20(address(token)).approve(v, uint256(0));
    }
}
`

const targetSol = `
contract Vault {
    function deposit(uint256 amount) external {}
    function withdraw(uint256 shares) external {}
    function mint(address to, uint256 value) external {}
}
`

// pocShapes is POC_SHAPES.
var pocShapes = ShapeIndex{
	"src/test/2021-01/CaseA_exp.sol": {
		{Callee: "deposit", ParamTypes: "uint256", ReceiverHint: "IVault"},
		{Callee: "redeemShares", ParamTypes: "address,uint256", ReceiverHint: "vault"},
		{Callee: "mint", ParamTypes: "address,uint256", ReceiverHint: "token"},
	},
}

func git(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
}

// makeGitPocRepo is _make_git_poc_repo.
func makeGitPocRepo(t *testing.T, extraFiles ...[2]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "pocs")
	dir := filepath.Join(root, "src", "test", "2021-01")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "CaseA_exp.sol"), []byte(pocSol), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ef := range extraFiles {
		if err := os.WriteFile(filepath.Join(dir, ef[0]), []byte(ef[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, root, "init", "-q")
	git(t, root, "add", "-A")
	git(t, root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "one")
	return root
}

// ---- extraction ----------------------------------------------------------

func TestExtractShapesFindsTypedCalls(t *testing.T) {
	byCallee := map[string][]string{}
	for _, s := range ExtractCallShapes(pocSol) {
		byCallee[s.Callee] = append(byCallee[s.Callee], s.ParamTypes)
	}
	// literal args carry no identifier -> the shared normalizer's "?" slot
	if got := byCallee["deposit"]; len(got) != 1 || got[0] != "?" {
		t.Fatalf("deposit param_types = %v, want [\"?\"]", got)
	}
	// transferFrom(addr, addr, uint) -> 3 param types
	found := false
	for _, p := range byCallee["transferFrom"] {
		if len(strings.Split(p, ",")) == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("transferFrom shapes = %v, want a 3-param shape", byCallee["transferFrom"])
	}
}

func TestExtractShapesCastReceiverHint(t *testing.T) {
	hints := map[[2]string]bool{}
	for _, s := range ExtractCallShapes(pocSol) {
		hints[[2]string{s.Callee, s.ReceiverHint}] = true
	}
	for _, want := range [][2]string{{"deposit", "IVault"},
		{"approve", "IERC20"}, {"transferFrom", "token"}} {
		if !hints[want] {
			t.Fatalf("hint %v missing from %v", want, hints)
		}
	}
}

func TestExtractShapesLowercaseBuiltinCastReceiver(t *testing.T) {
	// Regression: lowercase built-in-type casts are NOT misses.
	src := "contract Exploit {\n" +
		"    function run() public {\n" +
		"        address(vault).call(abi.encodeWithSignature(\"deposit()\"));\n" +
		"        uint256(x).foo(1);\n" +
		"    }\n" +
		"}\n"
	hints := map[string]string{}
	for _, s := range ExtractCallShapes(src) {
		hints[s.Callee] = s.ReceiverHint
	}
	if hints["call"] != "address" {
		t.Fatalf("call hint = %q, want address", hints["call"])
	}
	if hints["foo"] != "uint256" {
		t.Fatalf("foo hint = %q, want uint256", hints["foo"])
	}
}

func TestExtractShapesDeterministic(t *testing.T) {
	a := ExtractCallShapes(pocSol)
	b := ExtractCallShapes(pocSol)
	if validation.DumpsOrdered(shapesValue(a), false) !=
		validation.DumpsOrdered(shapesValue(b), false) {
		t.Fatal("extract_call_shapes is not deterministic")
	}
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("shapes = %d/%d, want equal and non-empty", len(a), len(b))
	}
}

func shapesValue(shapes []Shape) validation.Value {
	out := make([]validation.Value, 0, len(shapes))
	for _, s := range shapes {
		out = append(out, s.Value())
	}
	return validation.VArr(out...)
}

// ---- index + cache -------------------------------------------------------

func TestBuildIndexOnlyExpFiles(t *testing.T) {
	root := makeGitPocRepo(t, [2]string{"helper.sol", "contract H {}"})
	idx, err := BuildPocShapeIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	files := idx.SortedFiles()
	if len(files) != 1 || files[0] != "src/test/2021-01/CaseA_exp.sol" {
		t.Fatalf("files = %v, want only CaseA_exp.sol", files)
	}
	if len(idx["src/test/2021-01/CaseA_exp.sol"]) == 0 {
		t.Fatal("the PoC must yield shapes")
	}
}

func TestCacheReuseAndRebuildOnHeadMove(t *testing.T) {
	root := makeGitPocRepo(t)
	c := newCampaign(t, "cache-program")
	first, err := LoadOrBuildPocShapes(c, &root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Shapes["src/test/2021-01/CaseA_exp.sol"]; !ok {
		t.Fatalf("shapes = %v", first.Shapes.SortedFiles())
	}
	head1 := first.DatasetHead
	// same dataset -> cache reuse (generated_at unchanged, no re-parse)
	second, err := LoadOrBuildPocShapes(c, &root)
	if err != nil {
		t.Fatal(err)
	}
	if second.GeneratedAt != first.GeneratedAt {
		t.Fatalf("generated_at = %q, want the cached %q",
			second.GeneratedAt, first.GeneratedAt)
	}
	// move the head (new PoC file committed) -> rebuild
	dir := filepath.Join(root, "src", "test", "2021-01")
	if err := os.WriteFile(filepath.Join(dir, "CaseB_exp.sol"), []byte(pocSol), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "-A")
	git(t, root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "two")
	third, err := LoadOrBuildPocShapes(c, &root)
	if err != nil {
		t.Fatal(err)
	}
	if third.DatasetHead == head1 {
		t.Fatalf("dataset_head = %q, want a moved head", third.DatasetHead)
	}
	if _, ok := third.Shapes["src/test/2021-01/CaseB_exp.sol"]; !ok {
		t.Fatalf("rebuilt shapes = %v, want CaseB", third.Shapes.SortedFiles())
	}
}

func TestNonGitCheckoutFailsLoud(t *testing.T) {
	root := filepath.Join(t.TempDir(), "notgit")
	dir := filepath.Join(root, "src", "test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "X_exp.sol"), []byte(pocSol), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newCampaign(t, "notgit-program")
	_, err := LoadOrBuildPocShapes(c, &root)
	if err == nil {
		t.Fatal("a non-git checkout must fail loud")
	}
	if !strings.Contains(err.Error(), "git") {
		t.Fatalf("error = %q, want it to mention git", err)
	}
}

// ---- matching ------------------------------------------------------------

func targetIndex(t *testing.T) validation.Value {
	t.Helper()
	return indexFor(t, targetSol)
}

func TestExactHitOnMatchingSignature(t *testing.T) {
	out := MatchShapes(targetIndex(t), pocShapes)
	if len(out) != 1 {
		t.Fatalf("out = %d rows, want 1", len(out))
	}
	e := listAt(out[0], "exact_hits")
	deposit, mint := false, false
	for _, h := range e {
		if objStr(h, "callee") == "deposit" && objStr(h, "param_types") == "uint256" {
			deposit = true
		}
		if objStr(h, "callee") == "mint" {
			mint = true
		}
	}
	if !deposit || !mint {
		t.Fatalf("exact hits = %v, want deposit+uint256 and mint", e)
	}
}

func TestNoExactHitOnWrongParamTypes(t *testing.T) {
	shapes := ShapeIndex{"f.sol": {
		{Callee: "deposit", ParamTypes: "uint128", ReceiverHint: "v"}}}
	out := MatchShapes(targetIndex(t), shapes)
	exact := []validation.Value(nil)
	if len(out) > 0 {
		exact = listAt(out[0], "exact_hits")
	}
	for _, h := range exact {
		if objStr(h, "callee") == "deposit" {
			t.Fatal("wrong param types must not produce an exact hit")
		}
	}
}

func TestNearMissUsesThreshold(t *testing.T) {
	// redeemShares vs withdraw: low similarity; deposit-adjacent name should
	// surface as near-miss at the current threshold, or be absent — pin the
	// behavior either way by recomputing with the module's own jaccard.
	shapes := ShapeIndex{"f.sol": {
		{Callee: "depositX", ParamTypes: "uint256", ReceiverHint: "v"}}}
	out := MatchShapes(targetIndex(t), shapes)
	var near []validation.Value
	if len(out) > 0 {
		near = listAt(out[0], "near_misses")
	}
	for _, nm := range near {
		if floatAt(nm, "score") < NEAR_MISS_THRESHOLD {
			t.Fatalf("score = %v, below the threshold", floatAt(nm, "score"))
		}
		target := objStr(nm, "nearest_target")
		if validation.PythonRound(archetypes.Jaccard("depositX", target), 4) !=
			floatAt(nm, "score") {
			t.Fatalf("score %v != jaccard(depositX, %q)", floatAt(nm, "score"), target)
		}
	}
	if len(near) > 0 && objStr(near[0], "callee") != "depositX" {
		t.Fatalf("near = %v, want depositX", near)
	}
}

func TestEmptySurfaceNoCrash(t *testing.T) {
	out := MatchShapes(indexFor(t, "contract E {}"), pocShapes)
	if out == nil {
		t.Fatal("match_shapes must return an empty slice, not nil")
	}
	for _, row := range out {
		if len(listAt(row, "exact_hits")) == 0 && len(listAt(row, "near_misses")) == 0 {
			t.Fatalf("row %v carries no signal and must be omitted", row)
		}
	}
}

func TestDeterministicOrdering(t *testing.T) {
	a := MatchShapes(targetIndex(t), pocShapes)
	b := MatchShapes(targetIndex(t), pocShapes)
	if validation.DumpsOrdered(validation.VArr(a...), false) !=
		validation.DumpsOrdered(validation.VArr(b...), false) {
		t.Fatal("match_shapes is not deterministic")
	}
	if len(a) != len(b) {
		t.Fatalf("rows = %d/%d", len(a), len(b))
	}
}

// TestExtractShapesStructLiteralArgsKeepTopLevelSplit pins the reference's
// _param_types depth rule on a struct-literal argument (Ronin PoC shape): only
// "(" and "[" nest, so the literal's own top-level commas split and every
// field name lands in param_types — including the "x993e1c42" identifier the
// normalizer lifts out of the `// 0x993e1c42` comment inside the literal.
func TestExtractShapesStructLiteralArgsKeepTopLevelSplit(t *testing.T) {
	src := `contract E {
    function testExploit() public {
        IRoninBridge(roninBridge).withdrawERC20For({ // 0x993e1c42
            _withdrawalId: 2_000_000,
            _user: attacker,
            _token: WETH,
            _amount: 1,
            _signatures: hex"aa"
        });
    }
}`
	shapes := ExtractCallShapes(src)
	if len(shapes) != 1 {
		t.Fatalf("shapes = %v, want exactly one call site", shapes)
	}
	if got := shapes[0].ParamTypes; got !=
		"x993e1c42,_user,_token,_amount,_signatures" {
		t.Fatalf("param_types = %q", got)
	}
	if got := shapes[0].ReceiverHint; got != "IRoninBridge" {
		t.Fatalf("receiver_hint = %q", got)
	}
	if got := shapes[0].Callee; got != "withdrawERC20For" {
		t.Fatalf("callee = %q", got)
	}
}
