// Port of tests/test_snap_toolchain.py (minus the CLI line, owned by the
// Task 17 CLI owner): foundry.toml profile.default.sol detection — string,
// list-joined, absent, malformed, and explicit-config-wins.
package snapshot

import (
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

const foundrySolToml = "[profile.default]\nsol = \"0.8.24\"\noptimizer = true\n"

func TestToolchainSolStringDetected(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-toolchainstr1")
	writeFiles(t, target, map[string]string{"foundry.toml": foundrySolToml})
	snap := mustPin(t, c, target, nil, nil)
	cfg := objField(t, snap, "config")
	if cfg.Kind != validation.Obj {
		t.Fatalf("config kind = %v, want object", cfg.Kind)
	}
	if got := strField(t, cfg, "compiler"); got != "0.8.24" {
		t.Fatalf("compiler = %q, want 0.8.24", got)
	}
	if got := strField(t, cfg, "build_system"); got != "foundry" {
		t.Fatalf("build_system = %q, want foundry", got)
	}
	m := manifestOf(t, snap)
	found := false
	for _, kv := range m.O {
		if kv.K == "toolchain_fingerprint" && kv.V.Kind == validation.Str {
			found = true
		}
	}
	if !found {
		t.Fatal("toolchain_fingerprint is null despite detected config")
	}
}

func TestToolchainSolListJoined(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-toolchainlst1")
	writeFiles(t, target, map[string]string{
		"foundry.toml": "[profile.default]\nsol = [\"0.8.19\", \"0.8.24\"]\n"})
	snap := mustPin(t, c, target, nil, nil)
	if got := strField(t, objField(t, snap, "config"), "compiler"); got != "0.8.19,0.8.24" {
		t.Fatalf("compiler = %q, want 0.8.19,0.8.24", got)
	}
}

func TestToolchainAbsentKeepsConfigNull(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-toolchainabs1")
	snap := mustPin(t, c, target, nil, nil)
	if cfg := objField(t, snap, "config"); cfg.Kind != validation.Null {
		t.Fatalf("config = %v, want null", cfg)
	}
	// Direct probe: no foundry.toml at all.
	if got := DetectToolchain(target); got.Kind != validation.Null {
		t.Fatalf("DetectToolchain without foundry.toml = %v, want null", got)
	}
}

func TestToolchainMalformedIsTotal(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-toolchainbad1")
	writeFiles(t, target, map[string]string{"foundry.toml": "not [valid toml"})
	snap := mustPin(t, c, target, nil, nil)
	if cfg := objField(t, snap, "config"); cfg.Kind != validation.Null {
		t.Fatalf("config with malformed TOML = %v, want null", cfg)
	}
	if got := DetectToolchain(target); got.Kind != validation.Null {
		t.Fatalf("DetectToolchain malformed = %v, want null", got)
	}
}

func TestToolchainExplicitConfigWins(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-toolchainexp1")
	writeFiles(t, target, map[string]string{"foundry.toml": foundrySolToml})
	cfg := validation.VObj(
		validation.KV{K: "compiler", V: validation.VStr("0.8.26")},
		validation.KV{K: "build_system", V: validation.VStr("foundry")},
	)
	snap := mustPin(t, c, target, &cfg, nil)
	if got := strField(t, objField(t, snap, "config"), "compiler"); got != "0.8.26" {
		t.Fatalf("compiler = %q, want explicit 0.8.26", got)
	}
}

// TestToolchainSolcKeyDetected covers python-twin-issues P1: real Foundry
// projects write `solc`, the detector must read it, and `solc` wins over the
// legacy `sol` fallback. The last case pins the faithful semantics: a
// present-but-unusable `solc` suppresses the legacy fallback entirely
// (Python: profile.get("solc") is not None, so "sol" is never consulted).
func TestToolchainSolcKeyDetected(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
		want string // "" = Null
	}{
		{"solcstr", "[profile.default]\nsolc = \"0.8.24\"\noptimizer = true\n", "0.8.24"},
		{"solclist", "[profile.default]\nsolc = [\"0.8.19\", \"0.8.24\"]\n", "0.8.19,0.8.24"},
		{"solcwins", "[profile.default]\nsol = \"0.8.10\"\nsolc = \"0.8.24\"\n", "0.8.24"},
		{"solcfallback", "[profile.default]\nsol = \"0.8.10\"\n", "0.8.10"},
		{"solcintshadow", "[profile.default]\nsol = \"0.8.24\"\nsolc = 80824\n", ""},
	}
	for _, tc := range cases {
		d := filepath.Join(dir, tc.name)
		writeFiles(t, d, map[string]string{"foundry.toml": tc.body})
		got := DetectToolchain(d)
		if tc.want == "" {
			if got.Kind != validation.Null {
				t.Fatalf("%s: DetectToolchain = %v, want null", tc.name, got)
			}
			continue
		}
		if got.Kind != validation.Obj {
			t.Fatalf("%s: DetectToolchain = %v, want object", tc.name, got)
		}
		if c := strField(t, got, "compiler"); c != tc.want {
			t.Fatalf("%s: compiler = %q, want %q", tc.name, c, tc.want)
		}
	}
}

// TestToolchainNestedFoundryToml covers feedback-triage A9: a monorepo
// target keeps its build config under a subdirectory (contracts/) with no
// foundry.toml at the staging root — the detector must find it by walking
// the pinned tree, not only probe the root.
func TestToolchainNestedFoundryToml(t *testing.T) {
	root, target := pinTarget(t)
	c := pinCampaign(t, root, "C-toolchainnst1")
	writeFiles(t, target, map[string]string{
		"contracts/foundry.toml": "[profile.default]\nsolc = \"0.8.24\"\n",
		"contracts/Vault.sol":    "contract Vault {}",
		"README.md":              "# monorepo\n",
	})
	snap := mustPin(t, c, target, nil, nil)
	cfg := objField(t, snap, "config")
	if got := strField(t, cfg, "compiler"); got != "0.8.24" {
		t.Fatalf("compiler = %q, want 0.8.24", got)
	}
	if got := strField(t, cfg, "build_system"); got != "foundry" {
		t.Fatalf("build_system = %q, want foundry", got)
	}
	// Direct probe, no pin involved.
	if got := DetectToolchain(target); got.Kind != validation.Obj {
		t.Fatalf("DetectToolchain nested = %v, want object", got)
	}
}

// TestToolchainNestedSkipsJunkDirs: the A9 walk must not descend into
// build/junk directories, and a top-level file that is present but UNUSABLE
// is overridden by the first usable nested config (first-usable semantics).
func TestToolchainNestedSkipsJunkDirs(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		// unusable at the root -> the walk continues
		"foundry.toml":                "[other]\nsolc = \"0.8.10\"\n",
		"out/foundry.toml":            "[profile.default]\nsolc = \"0.8.11\"\n",
		"node_modules/x/foundry.toml": "[profile.default]\nsolc = \"0.8.12\"\n",
		"contracts/foundry.toml":      "[profile.default]\nsolc = \"0.8.24\"\n",
	})
	got := DetectToolchain(dir)
	if got.Kind != validation.Obj {
		t.Fatalf("DetectToolchain = %v, want object", got)
	}
	if c := strField(t, got, "compiler"); c != "0.8.24" {
		t.Fatalf("compiler = %q, want 0.8.24 (junk dirs skipped, "+
			"first usable wins)", c)
	}
}

func TestToolchainSolEdgeCases(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"emptystr":  "[profile.default]\nsol = \"\"\n",
		"emptylist": "[profile.default]\nsol = []\n",
		"int":       "[profile.default]\nsol = 80824\n",
		"mixedlist": "[profile.default]\nsol = [\"0.8.24\", 42]\n",
		"noprofile": "[other]\nsol = \"0.8.24\"\n",
		"nosol":     "[profile.default]\noptimizer = true\n",
	}
	for name, body := range cases {
		d := filepath.Join(dir, name)
		writeFiles(t, d, map[string]string{"foundry.toml": body})
		if got := DetectToolchain(d); got.Kind != validation.Null {
			t.Fatalf("%s: DetectToolchain = %v, want null", name, got)
		}
	}
}
