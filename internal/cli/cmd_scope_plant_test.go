package cli

// Task 9 (G11 scope) CLI test — the plant check through the REAL wiring:
// ensureSeams installs archetypes.WireScopePlant, so PlantCheck runs the
// real structidx indexer over a real snapshot tree and the real
// EvaluatePrecondition over every available archetype. No docker, no exec
// mocking (structidx is pure). The detail rows pin the exact advisory
// format the record's `detail` string carries (newline-joined, capped).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/reproduction"
	"websec/internal/state"
)

// scopeCliTree writes rel→content files under a fresh temp dir.
func scopeCliTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// scopeCliCamp inits a campaign for the plant check's index builder.
func scopeCliCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c
}

const scopePlantVictim = "// SPDX-License-Identifier: MIT\n" +
	"pragma solidity ^0.8.0;\n" +
	"contract V {\n" +
	"    uint256 public total;\n" +
	"    function initialize(uint256 v) public {\n" +
	"        total = v;\n" +
	"    }\n" +
	"}\n"

func TestScopePlantRealHit(t *testing.T) {
	ensureSeams()
	c := scopeCliCamp(t)
	dir := scopeCliTree(t, map[string]string{
		"P.sol": scopePlantVictim,
		"Q.sol": "contract Q {\n    uint256 public total;\n}\n",
	})
	rows, err := reproduction.PlantCheck(c, dir, []string{"P.sol", "Q.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	found := false
	for _, r := range rows {
		if !strings.HasPrefix(r, "patch plants risk: unguarded-initialize P.sol:") ||
			!strings.HasSuffix(r, " (hint-only — triage decides)") {
			t.Fatalf("unexpected risk row shape: %q (rows %q)", r, rows)
		}
		found = true
	}
	if !found {
		t.Fatalf("no unguarded-initialize hit in rows %q", rows)
	}
	// The detail-ride form: rows newline-join under the Task 8 detail.
	detail := reproduction.AppendScopeDetail("post-patch EXEC-2 exits 0", rows)
	if !strings.HasPrefix(detail, "post-patch EXEC-2 exits 0\n") {
		t.Fatalf("detail ride broken: %q", detail)
	}
}

func TestScopePlantRealClean(t *testing.T) {
	ensureSeams()
	c := scopeCliCamp(t)
	dir := scopeCliTree(t, map[string]string{
		"C.sol": "contract C {\n    uint256 public total;\n}\n",
	})
	rows, err := reproduction.PlantCheck(c, dir, []string{"C.sol"})
	if err != nil {
		t.Fatalf("PlantCheck: %v", err)
	}
	want := []string{"patch plants nothing new (1 files checked)"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("rows = %q, want %q", rows, want)
	}
}

func TestScopeDiffRealRows(t *testing.T) {
	oldDir := scopeCliTree(t, map[string]string{
		"A.sol": "contract A { uint256 public x; }\n",
		"C.sol": "contract C { uint256 public z; }\n",
	})
	newDir := scopeCliTree(t, map[string]string{
		"A.sol": "contract A { uint256 public x; }\n// patched\n",
		"D.sol": "contract D { uint256 public w; }\n",
	})
	rows, err := reproduction.ScopeDiff(oldDir, newDir)
	if err != nil {
		t.Fatalf("ScopeDiff: %v", err)
	}
	want := []string{"+ D.sol", "- C.sol", "~ A.sol"}
	if fmt.Sprintf("%q", rows) != fmt.Sprintf("%q", want) {
		t.Fatalf("rows = %q, want %q", rows, want)
	}
}
