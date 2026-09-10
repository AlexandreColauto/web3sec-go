// Port of the Task 11 step-1 list: pin_source_snapshot over the no-vcs,
// git-clean and git-dirty ladders, prune recording, store-nesting guards,
// and the tampered-copy integrity check.
package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func pinCampaign(t *testing.T, root, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(root, "Acme Program", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func pinTarget(t *testing.T) (root, target string) {
	t.Helper()
	root = t.TempDir()
	target = filepath.Join(root, "target")
	writeFiles(t, target, map[string]string{"src/Vault.sol": "contract Vault {}"})
	return root, target
}

func TestPinNoVCSLadder(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-pinnovicstest")
	snap := mustPin(t, c, target, nil, nil)

	src := objField(t, snap, "source")
	if got := strField(t, src, "ladder"); got != "no-vcs" {
		t.Fatalf("ladder = %q, want no-vcs", got)
	}
	if h := strField(t, src, "content_hash"); len(h) != 64 {
		t.Fatalf("content_hash len = %d, want 64", len(h))
	}
	if !(objField(t, snap, "pinned").Kind == validation.Bool &&
		objField(t, snap, "pinned").B) {
		t.Fatal("pinned is not true")
	}
	if id := strField(t, snap, "snapshot_id"); !strings.HasPrefix(id, "src-content-") {
		t.Fatalf("snapshot_id = %q, want src-content- prefix", id)
	}
	pinnedRoot := strField(t, src, "root")
	if _, err := os.Stat(filepath.Join(pinnedRoot, "src", "Vault.sol")); err != nil {
		t.Fatalf("pinned src/Vault.sol missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pinnedRoot, "snapshot.json")); err != nil {
		t.Fatalf("pinned snapshot.json missing: %v", err)
	}
	// The pin validates against the snapshot schema on write; re-read and
	// re-validate to prove the on-disk dict matches it field-for-field.
	onDisk, err := validation.ReadJson(filepath.Join(pinnedRoot, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validation.Validate(onDisk, "snapshot", 1); err != nil {
		t.Fatalf("on-disk snapshot.json fails schema: %v", err)
	}
	// No toolchain config in this tree -> config stays null.
	if cfg := objField(t, snap, "config"); cfg.Kind != validation.Null {
		t.Fatalf("config = %v, want null", cfg)
	}
}

func TestPinRepinIdenticalIsNoop(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-pinrepin00001")
	s1 := mustPin(t, c, target, nil, nil)
	s2 := mustPin(t, c, target, nil, nil)
	if strField(t, s1, "snapshot_id") != strField(t, s2, "snapshot_id") {
		t.Fatal("re-pin of identical content changed snapshot_id")
	}
	h1 := strField(t, objField(t, s1, "source"), "content_hash")
	h2 := strField(t, objField(t, s2, "source"), "content_hash")
	if h1 != h2 {
		t.Fatal("re-pin of identical content changed content_hash")
	}
}

func TestPinDetectsChangeOldDirImmutable(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-pinchangetest1")
	s1 := mustPin(t, c, target, nil, nil)
	writeFiles(t, target, map[string]string{"src/Vault.sol": "contract Vault2 {}"})
	s2 := mustPin(t, c, target, nil, nil)
	if strField(t, s1, "snapshot_id") == strField(t, s2, "snapshot_id") {
		t.Fatal("changed content kept the same snapshot_id")
	}
	oldRoot := strField(t, objField(t, s1, "source"), "root")
	body, err := os.ReadFile(filepath.Join(oldRoot, "src", "Vault.sol"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "Vault2") {
		t.Fatal("old pinned copy mutated by the later pin")
	}
}

func TestPinGitDirtyLadderExactIDForm(t *testing.T) {
	root, target := pinTarget(t)
	gitSetup(t, target)
	writeFiles(t, target, map[string]string{"dirty.txt": "x"})
	c := pinCampaign(t, root, "C-pingitdirty001")
	snap := mustPin(t, c, target, nil, nil)

	src := objField(t, snap, "source")
	if got := strField(t, src, "ladder"); got != "git-dirty" {
		t.Fatalf("ladder = %q, want git-dirty", got)
	}
	if h := strField(t, src, "content_hash"); len(h) != 64 {
		t.Fatalf("content_hash len = %d, want 64", len(h))
	}
	commit := Git(target, "rev-parse", "HEAD")
	hash := strField(t, src, "content_hash")
	want := "src-" + commit[:8] + "-" + hash[:12]
	if got := strField(t, snap, "snapshot_id"); got != want {
		t.Fatalf("snapshot_id = %q, want %q", got, want)
	}
}

func TestPinGitCleanLadderExactIDForm(t *testing.T) {
	root, target := pinTarget(t)
	gitSetup(t, target)
	c := pinCampaign(t, root, "C-pingitclean001")
	snap := mustPin(t, c, target, nil, nil)
	if got := strField(t, objField(t, snap, "source"), "ladder"); got != "git-clean" {
		t.Fatalf("ladder = %q, want git-clean", got)
	}
	commit := Git(target, "rev-parse", "HEAD")
	want := "src-" + commit[:12]
	if got := strField(t, snap, "snapshot_id"); got != want {
		t.Fatalf("snapshot_id = %q, want %q", got, want)
	}
}

func TestPinTargetContainingStoreNeverNests(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-pinnesting0001")
	// No-vcs branch: the target is the store's own parent.
	snap := mustPin(t, c, root, nil, nil)
	assertNoNestedStore(t, snap)
	// Git-dirty branch: same guard on the copytree fallback path.
	gitSetup(t, target)
	writeFiles(t, target, map[string]string{"dirty.txt": "x"})
	snap2 := mustPin(t, c, target, nil, nil)
	assertNoNestedStore(t, snap2)
}

func TestPinRelativeRootContainingStoreNeverNests(t *testing.T) {
	root, target := pinTarget(t)
	t.Chdir(root)
	c := pinCampaign(t, ".", "C-pinrelstore001")
	snap := mustPin(t, c, ".", nil, nil)
	pinnedRoot := strField(t, objField(t, snap, "source"), "root")
	if _, err := os.Stat(filepath.Join(pinnedRoot, "target", "src", "Vault.sol")); err != nil {
		t.Fatalf("pinned target/src/Vault.sol missing: %v", err)
	}
	assertNoNestedStore(t, snap)
	_ = target
}

func assertNoNestedStore(t *testing.T, snap validation.Value) {
	t.Helper()
	pinnedRoot := strField(t, objField(t, snap, "source"), "root")
	var nested []string
	_ = filepath.WalkDir(pinnedRoot, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == "campaigns" && p != pinnedRoot {
			// The pin root itself may legitimately pass through a
			// campaigns/ component; only nested copies count.
			rel, _ := filepath.Rel(pinnedRoot, p)
			if strings.Contains(rel, "campaigns") {
				nested = append(nested, p)
			}
		}
		return nil
	})
	if len(nested) > 0 {
		t.Fatalf("campaign store leaked into pin: %v", nested[:1])
	}
}

func TestBulkDefaultPrunesDataDir(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeFiles(t, target, map[string]string{
		"app.py":        "print('hi')\n",
		"src/vault.py":  "x = 1\n",
		"data/f000.dat": "x",
		"data/f001.dat": "x",
		"data/f002.dat": "x",
	})
	c := pinCampaign(t, root, "C-pinbulkdata0001")
	snap := mustPin(t, c, target, nil, nil)
	src := objField(t, snap, "source")
	if !strListContains(t, src, "excluded", "data") {
		t.Fatalf("excluded = %v, want it to contain data", objField(t, src, "excluded"))
	}
	pinnedRoot := strField(t, src, "root")
	if _, err := os.Stat(filepath.Join(pinnedRoot, "data")); !os.IsNotExist(err) {
		t.Fatal("data dir survived the prune")
	}
	if n := intField(t, src, "file_count"); n != 2 {
		t.Fatalf("file_count = %d, want 2", n)
	}
}

func TestExtraExcludeIsRecorded(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeFiles(t, target, map[string]string{
		"app.py":       "print('hi')\n",
		"src/vault.py": "x = 1\n",
		"notes/a.md":   "scratch\n",
	})
	c := pinCampaign(t, root, "C-pinextraexcl01")
	snap := mustPin(t, c, target, nil, []string{"notes"})
	src := objField(t, snap, "source")
	ex := objField(t, src, "excluded")
	if len(ex.A) != 1 || ex.A[0].S != "notes" {
		t.Fatalf("excluded = %v, want exactly [notes]", ex)
	}
	if _, err := os.Stat(filepath.Join(strField(t, src, "root"), "notes")); !os.IsNotExist(err) {
		t.Fatal("notes dir survived the prune")
	}
}

// TestDeepExcludeReportsSubpath pins feedback-triage A10: a bulk-excluded
// dir nested UNDER an in-scope project root (a monorepo's contracts/data)
// must be reported at its real depth, not aggregated to the top-level
// directory — the old behaviour made the whole contracts/ tree look out of
// scope.
func TestDeepExcludeReportsSubpath(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeFiles(t, target, map[string]string{
		"README.md":                "# monorepo\n",
		"contracts/foundry.toml":   "[profile.default]\nsolc = \"0.8.24\"\n",
		"contracts/src/Vault.sol":  "contract Vault {}",
		"contracts/data/f000.dat":  "x",
		"contracts/data/f001.dat":  "x",
	})
	c := pinCampaign(t, root, "C-pindeepexcl001")
	snap := mustPin(t, c, target, nil, nil)
	src := objField(t, snap, "source")
	ex := objField(t, src, "excluded")
	// The deep match must be reported by its full relative subpath...
	if len(ex.A) != 1 || ex.A[0].S != "contracts/data" {
		t.Fatalf("excluded = %v, want exactly [contracts/data]", ex)
	}
	// ...and the in-scope project root itself must NOT be pruned.
	if _, err := os.Stat(filepath.Join(strField(t, src, "root"), "contracts", "src", "Vault.sol")); err != nil {
		t.Fatalf("in-scope contracts/src was pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(strField(t, src, "root"), "contracts", "data")); !os.IsNotExist(err) {
		t.Fatal("contracts/data survived the prune")
	}
}

func TestNoPruneNoExcludedField(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeFiles(t, target, map[string]string{
		"app.py":       "print('hi')\n",
		"src/vault.py": "x = 1\n",
	})
	c := pinCampaign(t, root, "C-pinnoprune0001")
	snap := mustPin(t, c, target, nil, nil)
	for _, kv := range objField(t, snap, "source").O {
		if kv.K == "excluded" {
			t.Fatal("clean pin must not carry source.excluded")
		}
	}
}

func TestGitCleanWorktreeAlsoPruned(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeFiles(t, target, map[string]string{
		"app.py":        "print('hi')\n",
		"src/vault.py":  "x = 1\n",
		"data/f000.dat": "x",
		"data/f001.dat": "x",
		"data/f002.dat": "x",
	})
	gitSetup(t, target)
	c := pinCampaign(t, root, "C-pinworktree001")
	snap := mustPin(t, c, target, nil, nil)
	src := objField(t, snap, "source")
	if got := strField(t, src, "ladder"); got != "git-clean" {
		t.Fatalf("ladder = %q, want git-clean", got)
	}
	if _, err := os.Stat(filepath.Join(strField(t, src, "root"), "data")); !os.IsNotExist(err) {
		t.Fatal("git worktree path must also honor the prune set")
	}
	if !strListContains(t, src, "excluded", "data") {
		t.Fatal("excluded must contain data on the worktree path")
	}
}

// A pruned pin of a dirty tree must hash exactly like a pin of the clean
// tree — the prune changes nothing about what the audit covers.
func TestPruneMakesPinEquivalentToCleanTree(t *testing.T) {
	base := t.TempDir()
	mkTree := func(name string, withData bool) string {
		target := filepath.Join(base, name, "target")
		files := map[string]string{
			"app.py":       "print('hi')\n",
			"src/vault.py": "x = 1\n",
		}
		if withData {
			for i := 0; i < 200; i++ {
				files[fmt.Sprintf("data/f%04d.dat", i)] = strings.Repeat("x", 32)
			}
		}
		writeFiles(t, target, files)
		return target
	}
	c1 := pinCampaign(t, filepath.Join(base, "c1"), "C-pineqtest00001")
	c2 := pinCampaign(t, filepath.Join(base, "c2"), "C-pineqtest00002")
	s1 := mustPin(t, c1, mkTree("dirty", true), nil, nil)
	s2 := mustPin(t, c2, mkTree("clean", false), nil, nil)
	src1, src2 := objField(t, s1, "source"), objField(t, s2, "source")
	if got, want := strField(t, src1, "content_hash"), strField(t, src2, "content_hash"); got != want {
		t.Errorf("content_hash: pruned-dirty %s != clean %s", got, want)
	}
	if got, want := intField(t, src1, "file_count"), intField(t, src2, "file_count"); got != want {
		t.Errorf("file_count: %d != %d", got, want)
	}
}

func TestRepinDetectsTamperedImmutableCopy(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "src")
	writeFiles(t, target, map[string]string{"A.sol": "contract A {}"})
	c := pinCampaign(t, root, "C-pintamper00001")
	s1 := mustPin(t, c, target, nil, nil)
	pinnedID := strField(t, s1, "snapshot_id")
	pinnedFile := filepath.Join(root, "campaigns", "C-pintamper00001", "snapshots", pinnedID, "A.sol")
	writeFiles(t, filepath.Dir(pinnedFile), map[string]string{"A.sol": "contract A { bool tampered; }"})
	_, err := PinSourceSnapshot(c, target, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("tampered re-pin err = %v, want RuntimeError 'no longer matches'", err)
	}
	body, rerr := os.ReadFile(pinnedFile)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(body), "tampered") {
		t.Fatal("tampered copy was repaired instead of refused")
	}
}

func TestPinRecordsActiveSnapshot(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-pinactive00001")
	snap := mustPin(t, c, target, nil, nil)
	got, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != strField(t, snap, "snapshot_id") {
		t.Fatalf("active snapshot = %v, want the pinned id", got)
	}
}

func mustPin(t *testing.T, c *state.Campaign, target string, cfg *validation.Value, extra []string) validation.Value {
	t.Helper()
	snap, err := PinSourceSnapshot(c, target, cfg, extra)
	if err != nil {
		t.Fatalf("PinSourceSnapshot(%s): %v", target, err)
	}
	return snap
}

func objField(t *testing.T, v validation.Value, key string) validation.Value {
	t.Helper()
	if v.Kind != validation.Obj {
		t.Fatalf("objField(%s): not an object: %v", key, v.Kind)
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	t.Fatalf("objField: key %q missing", key)
	return validation.VNull()
}

func strField(t *testing.T, v validation.Value, key string) string {
	t.Helper()
	got := objField(t, v, key)
	if got.Kind != validation.Str {
		t.Fatalf("%s is not a string: %v", key, got.Kind)
	}
	return got.S
}

func intField(t *testing.T, v validation.Value, key string) int64 {
	t.Helper()
	got := objField(t, v, key)
	if got.Kind != validation.Int {
		t.Fatalf("%s is not an int: %v", key, got.Kind)
	}
	return got.I
}

func strListContains(t *testing.T, v validation.Value, key, want string) bool {
	t.Helper()
	list := objField(t, v, key)
	if list.Kind != validation.Arr {
		t.Fatalf("%s is not an array: %v", key, list.Kind)
	}
	for _, e := range list.A {
		if e.Kind == validation.Str && e.S == want {
			return true
		}
	}
	return false
}
