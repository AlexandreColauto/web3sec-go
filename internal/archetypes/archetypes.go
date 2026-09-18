// Package archetypes ports webv2.archetypes: critical-bug archetype
// pre-screening.
//
// An archetype is a deterministic predicate over the structural index: if
// every check holds, this shape of critical bug is structurally present in
// the tree. The pre-screen runs BEFORE any model spends tokens on a target
// and tells the operator which hunts are worth opening. HINT-only — a match
// is a search directive, never evidence.
//
// False-miss visibility: every absent check reports near-matches (top-k
// identifiers by bigram-Jaccard against the check's literals) so a silent
// miss on `totalStaked` vs `totalAssets` is visible to the operator. An
// operator who knows better can force an archetype with --force; the override
// is persisted and logged (prescreen.override), never silent.
package archetypes

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"websec/assets"
	"websec/internal/validation"
)

// embeddedDir is the embed.FS prefix holding the shipped archetypes.
const embeddedDir = "archetypes"

// idRe is _ID_RE: the archetype id shape the schema also pins.
var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,40}$`)

// ArchetypesDir is ARCHETYPES_DIR. The empty string means the embedded pack
// (Python resolves REPO_ROOT/archetypes from __file__; a Go binary has no
// source-relative root, so the pack is embedded). Tests and embedders point
// it at their own tree — the twin of a test setting AT.ARCHETYPES_DIR.
var ArchetypesDir string

// SetArchetypesDir points the loader at dir; an empty string restores the
// embedded pack.
func SetArchetypesDir(dir string) { ArchetypesDir = dir }

// listFiles is sorted(ARCHETYPES_DIR.glob("*.yaml")).
func listFiles() ([]string, error) {
	if ArchetypesDir == "" {
		entries, err := fs.Glob(assets.ArchetypesFS, embeddedDir+"/*.yaml")
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			out = append(out, filepath.Base(e))
		}
		sort.Strings(out)
		return out, nil
	}
	entries, err := os.ReadDir(ArchetypesDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// readPackFile reads one pack file by name.
func readPackFile(name string) ([]byte, error) {
	if ArchetypesDir == "" {
		return assets.ArchetypesFS.ReadFile(embeddedDir + "/" + name)
	}
	return os.ReadFile(filepath.Join(ArchetypesDir, name))
}

// LoadArchetypeByName loads the archetype with this id from the configured
// pack (Python: load_archetype(ARCHETYPES_DIR / f"{aid}.yaml")).
func LoadArchetypeByName(id string) (validation.Value, error) {
	raw, err := readPackFile(id + ".yaml")
	if err != nil {
		return validation.VNull(), err
	}
	return parseArchetype(raw, id+".yaml")
}

// LoadArchetype is load_archetype: load and validate one archetype file. It
// fails loud on bad predicates: per-type discriminator keys are checked
// BEFORE schema validation so a missing/ignored key raises naming the check
// type and the offending key; the schema then enforces value shapes, bounds,
// and the id pattern on top.
func LoadArchetype(path string) (validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), err
	}
	return parseArchetype(raw, path)
}

// parseArchetype is the shared body of load_archetype.
func parseArchetype(raw []byte, path string) (validation.Value, error) {
	data, err := validation.ParseYaml(raw)
	if err != nil {
		return validation.VNull(), validation.ParseYamlFileError(
			"archetype "+path, err)
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("archetype %s: not a mapping", path)
	}
	rawChecks := validation.ObjAt(data, "checks")
	if rawChecks.Kind == validation.Arr {
		for i, check := range rawChecks.A {
			if check.Kind != validation.Obj {
				continue
			}
			t := validation.ObjStr(check, "type")
			if _, ok := checkKeys[t]; !ok {
				return validation.VNull(), unknownTypeErr(archLabel(data, path), i, t)
			}
			if err := validateCheckKeys(archLabel(data, path), i, check); err != nil {
				return validation.VNull(), err
			}
		}
	}
	if err := validation.Validate(data, "archetype", 1); err != nil {
		return validation.VNull(), err
	}
	checks := validation.ObjAt(data, "checks")
	if checks.Kind != validation.Arr {
		return validation.VNull(), fmt.Errorf(
			"archetype %s: 'checks' must be a list", archLabel(data, path))
	}
	id := validation.ObjStr(data, "id")
	for i, check := range checks.A {
		t := validation.ObjStr(check, "type")
		if !containsStr(checkTypes, t) {
			return validation.VNull(), unknownTypeErr(id, i, t)
		}
		if err := validateCheckKeys(id, i, check); err != nil {
			return validation.VNull(), err
		}
	}
	return data, validateCheckPatterns(id, checks.A)
}

// archLabel is `data.get("id") or path` — the name an error message uses.
func archLabel(data validation.Value, path string) string {
	if id := validation.ObjStr(data, "id"); id != "" {
		return id
	}
	return path
}

func unknownTypeErr(arch string, i int, t string) error {
	return fmt.Errorf("archetype %s check %d: unknown type %s; known: %s",
		arch, i, validation.PyReprStr(t), pyListRepr(checkTypes))
}

// validateCheckKeys is _validate_check_keys: each check type must carry
// exactly the keys it consumes — at least one required discriminator, and no
// key its type ignores.
func validateCheckKeys(archID string, i int, check validation.Value) error {
	t := validation.ObjStr(check, "type")
	allowed := checkKeys[t]
	keys := make([]string, 0, len(check.O))
	for _, kv := range check.O {
		if kv.K != "type" {
			keys = append(keys, kv.K)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !allowed[key] {
			return fmt.Errorf("archetype %s check %d (type %s): unexpected key "+
				"%s; type %s uses %s", archID, i, validation.PyReprStr(t),
				validation.PyReprStr(key), validation.PyReprStr(t),
				allowedText(allowed))
		}
	}
	has := func(key string) bool { return pyTruthyBigNonEmpty(validation.ObjAt(check, key)) }
	switch t {
	case "state_var_exists", "function_exists":
		if !has("names") && !has("pattern") {
			return missingDiscriminator(archID, i, t,
				"need 'names' and/or 'pattern'")
		}
	case "unguarded_function_exists", "sig_verify_no_separator",
		"merkle_verify_without_depth_gate":
		if !has("names") {
			return missingDiscriminator(archID, i, t, "need 'names'")
		}
	case "unguarded_entry_writes":
		if !has("var_pattern") {
			return missingDiscriminator(archID, i, t, "need 'var_pattern'")
		}
	case "external_call_pattern":
		if !has("pattern") {
			return missingDiscriminator(archID, i, t, "need 'pattern'")
		}
	}
	return nil
}

func allowedText(allowed map[string]bool) string {
	if len(allowed) == 0 {
		return "no keys"
	}
	return pyListRepr(sortedKeys(allowed))
}

func missingDiscriminator(archID string, i int, t, need string) error {
	return fmt.Errorf("archetype %s check %d (type %s): missing required "+
		"discriminator: %s", archID, i, validation.PyReprStr(t), need)
}

// validateCheckPatterns is _validate_check_patterns: compile every
// regex-bearing key at load so an invalid pattern fails loud here (naming
// archetype, check type, and pattern), not deep in a prescreen run.
func validateCheckPatterns(archID string, checks []validation.Value) error {
	for i, check := range checks {
		if check.Kind != validation.Obj {
			continue
		}
		for _, key := range []string{"pattern", "var_pattern"} {
			v := validation.ObjAt(check, key)
			if v.Kind != validation.Str {
				continue
			}
			context := fmt.Sprintf("archetype %s check %d (type %s) key %s",
				archID, i, validation.PyReprStr(validation.ObjStr(check, "type")),
				validation.PyReprStr(key))
			if _, err := compileRegex(v.S, context); err != nil {
				return err
			}
		}
	}
	return nil
}

// AvailableArchetypes is available_archetypes: sorted archetype ids. A
// schema-valid file whose id disagrees with its filename would be listed
// under an id load can never serve — deployment error, fail loud.
func AvailableArchetypes() ([]string, error) {
	files, err := listFiles()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, name := range files {
		raw, rerr := readPackFile(name)
		if rerr != nil {
			return nil, rerr
		}
		a, aerr := parseArchetype(raw, name)
		if aerr != nil {
			return nil, aerr
		}
		id := validation.ObjStr(a, "id")
		stem := strings.TrimSuffix(name, ".yaml")
		if !idRe.MatchString(id) || id != stem {
			return nil, fmt.Errorf("archetype id %s does not match filename %s",
				validation.PyReprStr(id), name)
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// pyTruthyBigNonEmpty is a DIVERGENT pyTruthy variant (Wave J Task 7), NOT the
// canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except that an Int with any non-empty Big
// text is truthy — including Big == "0", which validation.PyTruthy (and
// CPython) reads falsy. The divergence is reachable only for Values that
// violate jval's invariant that Big is set only when the integer does not fit
// int64.
func pyTruthyBigNonEmpty(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.Big != "" || v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
