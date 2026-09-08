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

// DetectToolchain is _detect_toolchain: foundry.toml [profile.default].sol
// is the solc the build will ask for. A bare string becomes the compiler;
// a list of non-empty strings is comma-joined. ANY parse error, a missing
// file, or no usable profile.default.sol -> Null (Python: except
// Exception: return None — total, deterministic).
func DetectToolchain(staging string) validation.Value {
	raw, err := os.ReadFile(filepath.Join(staging, "foundry.toml"))
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
	sol, ok := def["sol"]
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
