// Toolchain detection: the snapshot's config layer, read from the pinned
// tree's own config files. Deterministic, read-only, total: no
// recognizable config -> Null.
//
// Ports web3sec-final/src/webv2/snapshot.py::_detect_toolchain, with the
// TOML subset parser replaced by pelletier/go-toml/v2 (the one go.mod
// change permitted to Task 12). Promoted here from pin.go.
package snapshot

import (
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"websec/internal/validation"
)

// DetectToolchain is _detect_toolchain: foundry.toml [profile.default].solc
// is the solc the build will ask for. Real Foundry projects write “solc“;
// the legacy “sol“ key is a fallback only (python-twin-issues P1: the
// original read only “sol“ and returned None for every real foundry.toml).
// A bare string becomes the compiler; a list of non-empty strings is
// comma-joined. ANY parse error, a missing file, or no usable
// profile.default.solc/sol -> Null (Python: except
// Exception: return None — total, deterministic).
//
// feedback-triage A9: the staging root's foundry.toml wins when it is
// usable; otherwise the pinned tree is walked depth-first in lexicographic
// order (monorepo targets keep the build config under a subdirectory such
// as contracts/) and the first USABLE foundry.toml is used. Build/junk
// directories are skipped.
func DetectToolchain(staging string) validation.Value {
	if v := detectToolchainFile(filepath.Join(staging, "foundry.toml")); v.Kind != validation.Null {
		return v
	}
	for _, p := range nestedFoundryTOMLs(staging) {
		if v := detectToolchainFile(p); v.Kind != validation.Null {
			return v
		}
	}
	return validation.VNull()
}

// foundryWalkSkip are the directories the A9 walk never descends into:
// VCS metadata and build/junk output that may carry foreign foundry.toml
// files but never the target's own build config.
var foundryWalkSkip = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"out":          {},
	"cache":        {},
}

// nestedFoundryTOMLs returns every foundry.toml below staging in
// filepath.WalkDir order (depth-first, lexicographic — deterministic),
// excluding the root's own file (the caller checks it first). Unreadable
// entries are skipped, never fatal.
func nestedFoundryTOMLs(staging string) []string {
	out := []string{}
	_ = filepath.WalkDir(staging, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != staging {
				if _, skip := foundryWalkSkip[d.Name()]; skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if d.Name() == "foundry.toml" {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// detectToolchainFile parses one foundry.toml (the reference's exact
// semantics: any error or unusable profile.default.solc/sol -> Null).
func detectToolchainFile(path string) validation.Value {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull()
	}
	var doc map[string]any
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return validation.VNull()
	}
	var prof map[string]any
	if p, ok := doc["profile"].(map[string]any); ok {
		prof = p
	}
	var def map[string]any
	if prof != nil {
		if d, ok := prof["default"].(map[string]any); ok {
			def = d
		}
	}
	if def == nil {
		return validation.VNull()
	}
	sol, ok := def["solc"]
	if !ok {
		sol, ok = def["sol"] // legacy fallback (python-twin-issues P1)
	}
	if !ok {
		return validation.VNull()
	}
	var compiler string
	switch v := sol.(type) {
	case string:
		if v != "" {
			compiler = v
		}
	case []any:
		if len(v) == 0 {
			return validation.VNull()
		}
		parts := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok || s == "" {
				return validation.VNull()
			}
			parts = append(parts, s)
		}
		compiler = strings.Join(parts, ",")
	default:
		return validation.VNull()
	}
	if compiler == "" {
		return validation.VNull()
	}
	return validation.VObj(
		validation.KV{K: "compiler", V: validation.VStr(compiler)},
		validation.KV{K: "build_system", V: validation.VStr("foundry")},
	)
}
