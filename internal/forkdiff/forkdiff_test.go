package forkdiff

// Ports tests/test_forkdiff.py: fingerprint (same parser as T0) +
// weighted-Jaccard match against operator-supplied baselines. Advisory only;
// baseline drift is an audit failure.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/audit"
	"websec/internal/state"
	"websec/internal/validation"
)

const aSol = `
contract Alpha {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function burn(uint256 amt) external { totalSupply -= amt; }
}
`

const bSol = `
contract Beta {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; totalSupply += amt; }
    function burn(uint256 amt) external { totalSupply -= amt; }
    function sweep(address to) external { /* new surface */ }
}
`

// trees writes the A/B fixtures and points BaselinesDir at a temp dir.
func trees(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	a := filepath.Join(base, "a")
	b := filepath.Join(base, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(a, "A.sol"), []byte(aSol), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, "B.sol"), []byte(bSol), 0o644); err != nil {
		t.Fatal(err)
	}
	old := BaselinesDir
	SetBaselinesDir(filepath.Join(base, "baselines"))
	t.Cleanup(func() { SetBaselinesDir(old) })
	return a, b
}

func fpOf(t *testing.T, root string) validation.Value {
	t.Helper()
	fp, err := FingerprintTree(root)
	if err != nil {
		t.Fatalf("FingerprintTree: %v", err)
	}
	return fp
}

func TestFingerprintDeterministic(t *testing.T) {
	a, _ := trees(t)
	fp := fpOf(t, a)
	if FingerprintSha256(fp) != FingerprintSha256(fpOf(t, a)) {
		t.Fatal("fingerprint is not deterministic")
	}
	if !containsStr(strs(fp, "selectors"), "mint(address,uint256)") {
		t.Fatalf("selectors %v", strs(fp, "selectors"))
	}
	if !containsStr(strs(fp, "state_vars"), "totalSupply") {
		t.Fatalf("state_vars %v", strs(fp, "state_vars"))
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestMatchStrongPartialNone(t *testing.T) {
	a, b := trees(t)
	fpa, fpb := fpOf(t, a), fpOf(t, b)
	same := Match(fpa, fpa, "self")
	if objStr(same, "verdict") != "strong" || scoreOf(same) != 1.0 {
		t.Fatalf("self match %v", same)
	}
	near := Match(fpa, fpb, "near")
	if v := objStr(near, "verdict"); v != "strong" && v != "partial" {
		t.Fatalf("near verdict %q", v)
	}
	if !containsStr(strs(near, "missing_selectors"), "sweep(address)") {
		t.Fatalf("missing_selectors %v", strs(near, "missing_selectors"))
	}
}

func TestBaselineAddListRemove(t *testing.T) {
	a, _ := trees(t)
	url, lic := "https://example/x", "MIT"
	meta, err := AddBaseline("alpha-ref", a, &url, &lic)
	if err != nil {
		t.Fatalf("AddBaseline: %v", err)
	}
	if objStr(meta, "fingerprint_sha256") !=
		FingerprintSha256(fpOf(t, a)) {
		t.Fatal("fingerprint_sha256 mismatch")
	}
	rows, err := ListBaselines()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || objStr(rows[0], "name") != "alpha-ref" {
		t.Fatalf("list %v", rows)
	}
	if err := RemoveBaseline("alpha-ref"); err != nil {
		t.Fatal(err)
	}
	rows, err = ListBaselines()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("list after remove %v", rows)
	}
}

func TestBaselineNameIsTraversalSafe(t *testing.T) {
	a, _ := trees(t)
	if _, err := AddBaseline("../evil", a, nil, nil); err == nil {
		t.Fatal("../evil accepted")
	}
	if _, err := AddBaseline("UPPER", a, nil, nil); err == nil {
		t.Fatal("UPPER accepted")
	}
	if err := RemoveBaseline("../evil"); err == nil {
		t.Fatal("RemoveBaseline ../evil accepted")
	}
}

func TestReaddBaselineWithItselfAsSourceFails(t *testing.T) {
	a, _ := trees(t)
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(BaselinesDir, "alpha-ref", "src")
	if _, err := AddBaseline("alpha-ref", dest, nil, nil); err == nil {
		t.Fatal("self-referential add accepted")
	}
}

func TestReaddBaselineReplacesContent(t *testing.T) {
	a, _ := trees(t)
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, "A.sol"),
		[]byte(aSol+"\ncontract Extra { function z() external {} }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	fp := fpOf(t, filepath.Join(BaselinesDir, "alpha-ref", "src"))
	if !containsStr(strs(fp, "contracts"), "Extra") {
		t.Fatalf("re-add did not replace content: %v", strs(fp, "contracts"))
	}
}

func mkFP(selectors, stateVars, modifiers, contracts []string) validation.Value {
	return validation.VObj(
		validation.KV{K: "selectors", V: strArr(selectors)},
		validation.KV{K: "state_vars", V: strArr(stateVars)},
		validation.KV{K: "modifiers", V: strArr(modifiers)},
		validation.KV{K: "contracts", V: strArr(contracts)},
	)
}

func TestMatchWeightsArePinned(t *testing.T) {
	base := mkFP([]string{"s1", "s2"}, []string{"v1"}, []string{"m1"}, []string{"C1"})
	cases := []struct {
		sel, st, mod, con []string
		want              float64
	}{
		{[]string{"s1", "s2"}, []string{"v9"}, []string{"m9"}, []string{"C9"}, 0.5},
		{[]string{"s9", "s8"}, []string{"v1"}, []string{"m9"}, []string{"C9"}, 0.3},
		{[]string{"s9", "s8"}, []string{"v9"}, []string{"m1"}, []string{"C9"}, 0.1},
		{[]string{"s9", "s8"}, []string{"v9"}, []string{"m9"}, []string{"C1"}, 0.1},
	}
	for i, tc := range cases {
		got := Match(mkFP(tc.sel, tc.st, tc.mod, tc.con), base, "w")
		if scoreOf(got) != tc.want {
			t.Errorf("case %d score %v, want %v", i, scoreOf(got), tc.want)
		}
	}
}

func TestMatchBoundaries(t *testing.T) {
	base := mkFP([]string{"s1", "s2"}, []string{"v1"}, []string{"m1"}, []string{"C1"})
	at := Match(mkFP([]string{"s1", "s2"}, []string{"v9"}, []string{"m9"},
		[]string{"C1"}), base, "b")
	if scoreOf(at) != 0.6 || objStr(at, "verdict") != "strong" {
		t.Fatalf("strong boundary %v", at)
	}
	below := Match(mkFP([]string{"s1", "s2"}, []string{"v9"}, []string{"m9"},
		[]string{"C9"}), base, "b")
	if scoreOf(below) != 0.5 || objStr(below, "verdict") != "partial" {
		t.Fatalf("partial boundary %v", below)
	}
	base5 := mkFP([]string{"s1", "s2", "s3", "s4", "s5"}, []string{"v1"},
		[]string{"m1"}, []string{"C1"})
	part := Match(mkFP([]string{"s1", "s2", "s3"}, []string{"v9"}, []string{"m9"},
		[]string{"C1"}), base5, "b")
	if scoreOf(part) != 0.4 || objStr(part, "verdict") != "partial" {
		t.Fatalf("partial 0.4 boundary %v", part)
	}
}

// campaign makes a fresh campaign under its own temp dir.
func campaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, program, state.InitOpts{})
	if err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	return c
}

func TestForkdiffReportArtifactAndEvent(t *testing.T) {
	a, b := trees(t)
	c := campaign(t, "fd-program")
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := ForkdiffReport(c, b)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(rep, "matched_baseline") != "alpha-ref" {
		t.Fatalf("matched_baseline %q", objStr(rep, "matched_baseline"))
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, "fork_diff.json")); err != nil {
		t.Fatalf("artifact: %v", err)
	}
	verdict, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.OK {
		t.Fatalf("verify_log not ok: %+v", verdict)
	}
}

func TestForkdiffReportWithoutBaselines(t *testing.T) {
	a, _ := trees(t)
	c := campaign(t, "fd-program")
	rep, err := ForkdiffReport(c, a)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(rep, "matched_baseline").Kind != validation.Null {
		t.Fatal("matched_baseline must be null")
	}
	if n := len(objListAt(rep, "all_matches")); n != 0 {
		t.Fatalf("all_matches len %d", n)
	}
	if objStr(rep, "diff_summary") != "no baselines registered" {
		t.Fatalf("diff_summary %q", objStr(rep, "diff_summary"))
	}
}

func TestAuditFlagsBaselineDrift(t *testing.T) {
	a, _ := trees(t)
	c := campaign(t, "audit-program")
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(aSol, "function burn",
		"function sneaky() external {}\n    function burn", 1)
	p := filepath.Join(BaselinesDir, "alpha-ref", "src", "A.sol")
	if err := os.WriteFile(p, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	Wire()
	audit.Setup()
	rep, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	sec := objAt(objAt(rep, "sections"), "baselines")
	if ok := objAt(sec, "ok"); ok.Kind == validation.Bool && ok.B {
		t.Fatalf("baselines section ok despite drift: %v", sec)
	}
	found := false
	for _, pr := range objListAt(sec, "problems") {
		if pr.Kind == validation.Str && strings.Contains(pr.S, "alpha-ref") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no alpha-ref problem in %v", objListAt(sec, "problems"))
	}
}

func TestAuditSurvivesManifestMissingBaselinesKey(t *testing.T) {
	a, _ := trees(t)
	c := campaign(t, "audit-program")
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath(), []byte(`{"updated_at": "x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	Wire()
	audit.Setup()
	rep, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	sec := objAt(objAt(rep, "sections"), "baselines")
	if ok := objAt(sec, "ok"); ok.Kind == validation.Bool && ok.B {
		t.Fatalf("baselines section ok despite bad manifest: %v", sec)
	}
}

func TestAuditSurvivesCorruptManifestJSON(t *testing.T) {
	a, _ := trees(t)
	c := campaign(t, "audit-program")
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	Wire()
	audit.Setup()
	rep, err := audit.AuditCampaign(c) // must not raise a decode error
	if err != nil {
		t.Fatal(err)
	}
	sec := objAt(objAt(rep, "sections"), "baselines")
	if ok := objAt(sec, "ok"); ok.Kind == validation.Bool && ok.B {
		t.Fatalf("baselines section ok despite corrupt manifest: %v", sec)
	}
	found := false
	for _, pr := range objListAt(sec, "problems") {
		if pr.Kind == validation.Str && strings.Contains(pr.S, "manifest") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no manifest problem in %v", objListAt(sec, "problems"))
	}
}

func TestAuditSurvivesUnreadableBaselineEntry(t *testing.T) {
	a, _ := trees(t)
	c := campaign(t, "audit-program")
	if _, err := AddBaseline("alpha-ref", a, nil, nil); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(BaselinesDir, "alpha-ref", "baseline.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	Wire()
	audit.Setup()
	rep, err := audit.AuditCampaign(c) // per-baseline failure is a problem, not a crash
	if err != nil {
		t.Fatal(err)
	}
	sec := objAt(objAt(rep, "sections"), "baselines")
	if ok := objAt(sec, "ok"); ok.Kind == validation.Bool && ok.B {
		t.Fatalf("baselines section ok despite unreadable entry: %v", sec)
	}
	found := false
	for _, pr := range objListAt(sec, "problems") {
		if pr.Kind == validation.Str && strings.Contains(pr.S, "alpha-ref") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no alpha-ref problem in %v", objListAt(sec, "problems"))
	}
}
