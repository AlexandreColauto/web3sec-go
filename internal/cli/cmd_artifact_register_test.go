package cli

// P1b CLI tests — `artifact-register` (ord 23).
//
// Ports: tests/test_role_isolation.py's artifact/register path through the
// CLI plus the register-by-path failure shape (cli.py cmd_artifact_register:
// a missing file is a one-line exit-2 error, never a traceback).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactRegister(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	path := filepath.Join(root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		path, "--kind", "other", "--note", "the invariant check")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "OTH-") ||
		!strings.Contains(out, ": kind=other path="+path) {
		t.Fatalf("output %q", out)
	}
}

func TestArtifactRegisterDefaultsToKindOther(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	path := filepath.Join(root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		path)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, ": kind=other path=") {
		t.Fatalf("output %q", out)
	}
}

func TestArtifactRegisterMissingFileExits2(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	missing := filepath.Join(root, "nope.md")
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		missing)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if out != "" {
		t.Fatalf("stdout %q, want empty", out)
	}
	if errS != "artifact register failed: no such file: "+missing+"\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestArtifactRegisterMissingArgsIsArgparse(t *testing.T) {
	code, _, errS := run(t, "artifact-register")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["artifact-register"] +
		"webv2 artifact-register: error: the following arguments are required: " +
		"campaign, path\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// Task 5 (trust-boundary hardening, Phase B): the registry keys a row by the
// file's RESOLVED path, not by the bytes the operator typed. Registering ONE
// file under any spelling of it — bare relative, "./"-prefixed, absolute,
// uncleaned, or through a symlinked directory — must name the row already
// there and REFRESH it. Minting a second row per spelling is the D3
// supersession defect the RUNBOOK's "a path holds one registry row" law
// forbids: the registry would carry two ids for one file, only the newest of
// which anything ever re-hashes, and the audit's re-hash-every-row check would
// go red permanently.
//
// The seam already resolved BOTH sides before comparing at HEAD
// (state/artifacts.go:463 `resolved := resolvePath(path)` and :470
// `resolvePath(c.resolveArtifactPath(a)) == resolved`), so this test is the
// PIN, not the fix: routing the verb back through the append primitive
// (RegisterArtifact) — the pre-r34-F3 shape — makes it red by minting one row
// per spelling. The handler stays a thin pass-through; the law lives in the
// shared seam.
//
// The symlinked-directory spelling is load-bearing: only a comparison that
// expands symlinks (resolvePath, i.e. Abs + EvalSymlinks) folds it into the
// registered row, so this test would go red for a bare filepath.Abs compare.
func TestArtifactRegisterDeduplicatesByResolvedPath(t *testing.T) {
	c, root := t15Campaign(t, "artifact-register-resolved")
	if err := os.MkdirAll(filepath.Join(root, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(root, "target", "a.sol")
	if err := os.WriteFile(abs, []byte("contract A {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "target"),
		filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	// The relative spellings are resolved by the CLI against the process cwd,
	// exactly as the operator's shell resolves them, so the operator stands in
	// the workspace root for them.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}

	spellings := []string{
		"target/a.sol",                   // bare relative
		"./target/a.sol",                 // dot-prefixed relative
		abs,                              // absolute
		root + "/target/../target/a.sol", // absolute, uncleaned
		"alias/a.sol",                    // through a symlinked directory
	}
	ids := make([]string, 0, len(spellings))
	for _, spelling := range spellings {
		code, out, errS := run(t, "--root", root, "artifact-register",
			c.CampaignID, spelling)
		if code != 0 {
			t.Fatalf("register %q exit %d: out=%q err=%q",
				spelling, code, out, errS)
		}
		ids = append(ids, r34Id(t, out))
	}
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("spelling %q minted %s, want the row already registered "+
				"at this file (%s); all ids: %v",
				spellings[i], id, ids[0], ids)
		}
	}
	rows := r34ArtifactRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("A PATH HOLDS ONE REGISTRY ROW: %d rows for one file (%s)",
			len(rows), spellings)
	}
	if got := objStr(rows[0], "artifact_id"); got != ids[0] {
		t.Fatalf("row id = %q, want %s", got, ids[0])
	}
	// The row's stored path is the one the FIRST registration wrote (relative
	// to the campaign root): a re-spelling refreshes the row, it does not
	// re-key it, so the registry stays stable for every reader that resolves
	// the stored path against the root.
	if got := objStr(rows[0], "path"); got != "target/a.sol" {
		t.Fatalf("stored path = %q, want target/a.sol", got)
	}
	// One registration, one refresh per later spelling: the count is the row's
	// own record of the re-registrations, and refreshArtifact is its only
	// writer.
	if got := objInt(rows[0], "refresh_count"); got != int64(len(spellings)-1) {
		t.Fatalf("refresh_count = %d, want %d", got, len(spellings)-1)
	}
	// The log tells the same story: exactly one artifact.registered, and every
	// later event is the refresh shape the seam already emits — no new event
	// vocabulary for a re-spelling.
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	registered, refreshed := 0, 0
	for _, ev := range events {
		switch objStr(ev, "type") {
		case "artifact.registered":
			registered++
		case "artifact.refreshed":
			refreshed++
		}
	}
	if registered != 1 || refreshed != len(spellings)-1 {
		t.Fatalf("events: %d artifact.registered, %d artifact.refreshed, "+
			"want 1 and %d", registered, refreshed, len(spellings)-1)
	}
	// A DIFFERENT file is still a different row: the dedup is by resolved
	// path, not by "the verb refreshes whatever is already there".
	other := filepath.Join(root, "target", "b.sol")
	if err := os.WriteFile(other, []byte("contract B {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, other)
	if code != 0 {
		t.Fatalf("register %q exit %d: %q", other, code, errS)
	}
	if got := r34Id(t, out); got == ids[0] {
		t.Fatalf("a distinct file reused the row %s", got)
	}
	if rows = r34ArtifactRows(t, c); len(rows) != 2 {
		t.Fatalf("rows after a distinct file: %d, want 2", len(rows))
	}
}

// Task 7d: a successful register says what "register" means. The artifact id
// is immutable, so the operator who wants to revise it must register the
// revision as a NEW artifact — the sharp edge was an operator overwriting the
// file at the registered path and assuming the store followed.
func TestArtifactRegisterPrintsTheImmutabilityNotice(t *testing.T) {
	c, root := t15Campaign(t, "artifacts")
	path := filepath.Join(root, "check.md")
	if err := os.WriteFile(path, []byte("checked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register", c.CampaignID,
		path)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("the notice must ride stdout, not stderr: %q", errS)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout\n%q\nwant the success line plus one notice", out)
	}
	if !strings.HasPrefix(lines[0], "OTH-") {
		t.Fatalf("first line = %q, want the success line", lines[0])
	}
	want := "note: registered artifacts are immutable — to revise, register " +
		"a new artifact (the old one stays for provenance)"
	if lines[1] != want {
		t.Fatalf("notice\n%q\nwant\n%q", lines[1], want)
	}
}
