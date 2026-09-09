// histmining_test.go ports tests/test_history_learning.py's history-mining
// tests and tests/test_recency.py 1:1 (Python wins). Git fixtures are real
// temp repos with pinned author/committer dates (no wall-clock dependence).
//
// The recency tests install a fake structural_index through SetIndexAPI:
// internal/structidx is the peer task's package, and the Python tests' own
// fixture (two .sol files with one asset writer and one entry point) is what
// the fake index describes.
package histmining

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// git runs one git command in cwd with a fixed identity (test fixtures).
func gitRun(t *testing.T, cwd string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// commitAt stages everything and commits with the date pinned `daysAgo`
// back at midday UTC.
func commitAt(t *testing.T, cwd, message string, daysAgo int) {
	t.Helper()
	stamp := time.Now().UTC().AddDate(0, 0, -daysAgo).Format("2006-01-02")
	cmd := exec.Command("git", "commit", "-q", "-m", message)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_AUTHOR_DATE="+stamp+"T12:00:00+00:00",
		"GIT_COMMITTER_DATE="+stamp+"T12:00:00+00:00",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func campaign(t *testing.T, program string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), program, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// gitTarget is the test_history_learning.py fixture.
func gitTarget(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(d, "Vault.sol"), "contract Vault {}")
	gitRun(t, d, "init", "-q")
	gitRun(t, d, "add", "-A")
	gitRun(t, d, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm",
		"init")
	writeFile(t, filepath.Join(d, "Vault.sol"),
		"contract Vault { modifier guard() { _; } }")
	gitRun(t, d, "add", "-A")
	gitRun(t, d, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm",
		"fix: reentrancy in withdraw path")
	return d
}

func TestMineGitHistoryFindsFix(t *testing.T) {
	c := campaign(t, "Acme Program")
	report, err := MineGitHistory(c, gitTarget(t), 500)
	if err != nil {
		t.Fatal(err)
	}
	subs := []string{}
	for _, k := range objAt(report, "security_relevant_commits").A {
		subs = append(subs, objStr(k, "subject"))
	}
	found := false
	for _, s := range subs {
		low := strings.ToLower(s)
		if strings.Contains(low, "fix") && strings.Contains(low, "reentrancy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("subjects = %v, want the fix commit", subs)
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir,
		"history_mining.json")); err != nil {
		t.Errorf("history_mining.json missing: %v", err)
	}
}

func TestPatchDeltaHypotheses(t *testing.T) {
	c := campaign(t, "Acme Program")
	report, err := MineGitHistory(c, gitTarget(t), 500)
	if err != nil {
		t.Fatal(err)
	}
	hyps := PatchDeltaHypotheses(report)
	if len(hyps) == 0 {
		t.Fatalf("no hypotheses")
	}
	for _, h := range hyps {
		if !strings.Contains(objStr(h, "question"), "sibling") {
			t.Errorf("question = %q, want sibling", objStr(h, "question"))
		}
	}
	if f := objStr(hyps[0], "file"); !strings.HasSuffix(f, "Vault.sol") {
		t.Errorf("file = %q, want Vault.sol", f)
	}
	if id := objStr(hyps[0], "hypothesis_id"); !strings.HasPrefix(id, "PD-001-") {
		t.Errorf("hypothesis_id = %q, want PD-001-*", id)
	}
}

func TestDeploymentVerificationVerdicts(t *testing.T) {
	c := campaign(t, "Acme Program")
	target := filepath.Join(t.TempDir(), "t")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "V.sol"), "contract V {}")
	snap, err := snapshot.PinSourceSnapshot(c, target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := objStr(snap, "snapshot_id")
	deployed := []validation.Value{
		validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Vault")},
			validation.KV{K: "address", V: validation.VStr("0x" + strings.Repeat("11", 20))},
			validation.KV{K: "bytecode_hash", V: validation.VStr("aaa")}),
		validation.VObj(
			validation.KV{K: "name", V: validation.VStr("Ghost")},
			validation.KV{K: "address", V: validation.VStr("0x" + strings.Repeat("22", 20))},
			validation.KV{K: "bytecode_hash", V: validation.VStr("bbb")}),
	}
	if _, err := VerifyDeploymentSource(c, sid, deployed,
		map[string]string{"Vault": "aaa"}); err != nil {
		t.Fatal(err)
	}
	pin, err := validation.ReadJson(filepath.Join(c.Dir, "snapshots", sid,
		"snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	matches := map[string]string{}
	for _, k := range objAt(objAt(pin, "deployment"), "contracts").A {
		matches[objStr(k, "name")] = objStr(k, "source_match")
	}
	if matches["Vault"] != "verified" || matches["Ghost"] != "unverified" {
		t.Errorf("matches = %v, want Vault=verified Ghost=unverified", matches)
	}
	if r := floatField(objAt(pin, "deployment"), "verification_ratio"); r != 0.5 {
		t.Errorf("verification_ratio = %v, want 0.5", r)
	}
	notes := DeploymentRiskNotes(pin)
	found := false
	for _, n := range notes {
		if strings.Contains(n, "Ghost") && strings.Contains(n, "unconfirmed") {
			found = true
		}
	}
	if !found {
		t.Errorf("notes = %v, want a Ghost/unconfirmed note", notes)
	}
}

// --- tests/test_recency.py --------------------------------------------------

// gitTargetRecency is the test_recency.py git_target fixture: hot.sol touched
// 5 days ago (asset writer), cold.sol touched 120 days ago (quiet).
func gitTargetRecency(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(d, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, d, "init", "-q")
	writeFile(t, filepath.Join(d, "src", "cold.sol"),
		"contract Cold { function ping() external {} }\n")
	gitRun(t, d, "add", "-A")
	commitAt(t, d, "cold", 120)
	writeFile(t, filepath.Join(d, "src", "hot.sol"),
		"contract Hot { uint256 public totalAssets;\n"+
			"function sweep(address to) external { totalAssets = 0; } }\n")
	gitRun(t, d, "add", "-A")
	commitAt(t, d, "fix: sweep guard", 5)
	return d
}

// installFakeIndex installs the two-file fixture index described by the
// Python test's structural index.
func installFakeIndex(t *testing.T) {
	t.Helper()
	prev := indexAPI
	SetIndexAPI(IndexAPI{
		EnsureFreshIndex: func(*state.Campaign, string) (validation.Value, error) {
			return validation.VObj(
				validation.KV{K: "nodes", V: validation.VArr(
					validation.VObj(
						validation.KV{K: "kind", V: validation.VStr("function")},
						validation.KV{K: "id", V: validation.VStr("src/hot.sol#sweep")},
						validation.KV{K: "path", V: validation.VStr("src/hot.sol")},
						validation.KV{K: "writes_storage", V: validation.VArr(
							validation.VStr("totalAssets"))},
						validation.KV{K: "is_entry_point", V: validation.VBool(false)}),
					validation.VObj(
						validation.KV{K: "kind", V: validation.VStr("function")},
						validation.KV{K: "id", V: validation.VStr("src/cold.sol#ping")},
						validation.KV{K: "path", V: validation.VStr("src/cold.sol")},
						validation.KV{K: "writes_storage", V: validation.VArr()},
						validation.KV{K: "is_entry_point", V: validation.VBool(true)}),
				)}), nil
		},
		SinkFunctions: func(validation.Value) []validation.Value { return nil },
	})
	t.Cleanup(func() { SetIndexAPI(prev) })
}

func TestRecencyScoresRankFreshExposedFirst(t *testing.T) {
	installFakeIndex(t)
	target := gitTargetRecency(t)
	c := campaign(t, "rec-program")
	rep, err := RecencyScores(c, target, target)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]validation.Value{}
	for _, r := range objAt(rep, "files").A {
		byPath[objStr(r, "path")] = r
	}
	hot, cold := byPath["src/hot.sol"], byPath["src/cold.sol"]
	if d := intField(hot, "days_ago"); d < 4 || d > 6 {
		t.Errorf("hot days_ago = %d, want ~5", d)
	}
	if d := intField(cold, "days_ago"); d < 119 || d > 121 {
		t.Errorf("cold days_ago = %d, want ~120", d)
	}
	if w := floatField(hot, "exposure_weight"); w != 1.0 {
		t.Errorf("hot exposure_weight = %v, want 1.0 (writes totalAssets)", w)
	}
	if w := floatField(cold, "exposure_weight"); w != 0.5 {
		t.Errorf("cold exposure_weight = %v, want 0.5 (entry point)", w)
	}
	if floatField(hot, "score") <= floatField(cold, "score") {
		t.Errorf("hot score %v <= cold score %v (cold is beyond the 90-day "+
			"horizon)", floatField(hot, "score"), floatField(cold, "score"))
	}
	if p := objStr(objAt(rep, "hot_files").A[0], "path"); p != "src/hot.sol" {
		t.Errorf("hot_files[0] = %q, want src/hot.sol", p)
	}
	stats := objAt(rep, "stats")
	if got := intField(stats, "files"); got != 2 {
		t.Errorf("stats.files = %d, want 2", got)
	}
	if got := intField(stats, "changed_in_window"); got != 1 {
		t.Errorf("stats.changed_in_window = %d, want 1", got)
	}
	if got := intField(stats, "scanned_commits"); got != 300 {
		t.Errorf("stats.scanned_commits = %d, want 300", got)
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, "recency.json")); err != nil {
		t.Errorf("recency.json missing: %v", err)
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Errorf("verify_log not ok: %+v %v", v, err)
	}
}

func TestChangedInWindowExcludesStaleButScannedFiles(t *testing.T) {
	prev := indexAPI
	SetIndexAPI(IndexAPI{
		EnsureFreshIndex: func(*state.Campaign, string) (validation.Value, error) {
			return validation.VObj(validation.KV{K: "nodes", V: validation.VArr(
				validation.VObj(
					validation.KV{K: "kind", V: validation.VStr("function")},
					validation.KV{K: "id", V: validation.VStr("src/stale.sol#ping")},
					validation.KV{K: "path", V: validation.VStr("src/stale.sol")},
					validation.KV{K: "writes_storage", V: validation.VArr()},
					validation.KV{K: "is_entry_point", V: validation.VBool(true)}),
				validation.VObj(
					validation.KV{K: "kind", V: validation.VStr("function")},
					validation.KV{K: "id", V: validation.VStr("src/fresh.sol#ping")},
					validation.KV{K: "path", V: validation.VStr("src/fresh.sol")},
					validation.KV{K: "writes_storage", V: validation.VArr()},
					validation.KV{K: "is_entry_point", V: validation.VBool(true)}),
			)}), nil
		},
		SinkFunctions: func(validation.Value) []validation.Value { return nil },
	})
	t.Cleanup(func() { SetIndexAPI(prev) })

	d := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(d, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, d, "init", "-q")
	writeFile(t, filepath.Join(d, "src", "stale.sol"),
		"contract Stale { function ping() external {} }\n")
	writeFile(t, filepath.Join(d, "src", "fresh.sol"),
		"contract Fresh { function ping() external {} }\n")
	gitRun(t, d, "add", "-A")
	commitAt(t, d, "add stale + fresh", 120)
	writeFile(t, filepath.Join(d, "src", "fresh.sol"),
		"contract Fresh { function ping() external {} function pong() external {} }\n")
	gitRun(t, d, "add", "-A")
	commitAt(t, d, "touch fresh", 2)
	c := campaign(t, "rec-program")
	rep, err := RecencyScores(c, d, d)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]validation.Value{}
	for _, r := range objAt(rep, "files").A {
		byPath[objStr(r, "path")] = r
	}
	stale, fresh := byPath["src/stale.sol"], byPath["src/fresh.sol"]
	if d := intField(stale, "days_ago"); d == 0 || d <= 90 {
		t.Errorf("stale days_ago = %d, want > 90", d)
	}
	if s := floatField(stale, "score"); s != 0.0 {
		t.Errorf("stale score = %v, want 0.0", s)
	}
	if d := intField(fresh, "days_ago"); d == 0 || d > 90 {
		t.Errorf("fresh days_ago = %d, want <= 90", d)
	}
	if s := floatField(fresh, "score"); s <= 0.0 {
		t.Errorf("fresh score = %v, want > 0", s)
	}
	if got := intField(objAt(rep, "stats"), "changed_in_window"); got != 1 {
		t.Errorf("stats.changed_in_window = %d, want 1", got)
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Errorf("verify_log not ok: %+v %v", v, err)
	}
}

func TestRecencyScoresWithoutGitHistory(t *testing.T) {
	installFakeIndex(t)
	target := gitTargetRecency(t)
	c := campaign(t, "rec-program")
	rep, err := RecencyScores(c, filepath.Join(t.TempDir(), "no-such-repo"),
		target)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range objAt(rep, "files").A {
		if s := floatField(r, "score"); s != 0.0 {
			t.Errorf("score for %s = %v, want 0.0",
				objStr(r, "path"), s)
		}
	}
	if n := len(objAt(rep, "files").A); n != 2 {
		t.Errorf("files = %d, want 2 (the snapshot tree still lists them)", n)
	}
}

func intField(v validation.Value, key string) int64 {
	f := objAt(v, key)
	if f.Kind == validation.Int {
		return f.I
	}
	return 0
}
