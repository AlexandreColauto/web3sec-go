package taxonomy

// Label-alias map layer: repo-level YAML maps that turn a raw dataset
// label into a canonical class — or, deliberately, into "unmapped" — plus
// the YAML node helpers the parser needs. Split from taxonomy.go (same package).
import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"websec/internal/validation"
)

// ---- label-alias map layer ----------------------------------------------
//
// Map files are repo-level config, YAML, in the shape:
//
//	default: unmapped
//	aliases:
//	  <raw-source-label-lowercased>: <canonical-class | unmapped>
//
// One COMMON file plus one file per dataset. A missing per-dataset file is a
// normal miss, not an error; a PRESENT-but-bad file is a deployment error and
// fails loud, the same posture as playbooks.

// mapAlias is one aliases entry, in file order.
type mapAlias struct{ key, target string }

// mapData is the parsed shape of one map file: its default and its ordered
// aliases.
type mapData struct {
	def     string
	aliases []mapAlias
}

// MissingMapError is the twin of the FileNotFoundError validate_map_file
// raises for an absent file. errors.Is(err, fs.ErrNotExist) reports true.
type MissingMapError struct{ Path string }

func (e *MissingMapError) Error() string { return "taxonomy map missing: " + e.Path }

// Is makes errors.Is(err, fs.ErrNotExist) true, like Python's
// FileNotFoundError.
func (e *MissingMapError) Is(target error) bool { return target == fs.ErrNotExist }

// normLabel is _norm_label: case/whitespace/punctuation-insensitive
// normalization so 'Access Control', 'access-control' and 'ACCESS  control'
// are one lookup key.
func normLabel(label string) string {
	return validation.PyStrip(normSpaceRe.ReplaceAllString(strings.ToLower(label), " "))
}

// normSpaceRe is Python's re.sub(r"[^a-z0-9]+", " ", ...): every run of
// characters outside the ASCII alphanumeric set collapses to one space.
var normSpaceRe = regexp.MustCompile(`[^a-z0-9]+`)

// checkMapValue is _check_map_value: every alias value (and the default) must
// be a canonical class or "unmapped".
func checkMapValue(path, where, value string) error {
	if value == UNMAPPED {
		return nil
	}
	if _, ok := knownRaw()[value]; ok {
		return nil
	}
	return fmt.Errorf("taxonomy map %s: %s -> %s is neither a canonical "+
		"class nor %s (%d canonical classes: %s)", path, where,
		validation.PyReprStr(value), validation.PyReprStr(UNMAPPED),
		len(knownRaw()), strings.Join(validation.SortedKeys(knownRaw()), ", "))
}

// readMapFile is _read_map_file: parse + value-check one map file. A missing
// file is nil (a normal miss); a present-but-invalid file is an error (fail
// loud, like a broken playbook).
func readMapFile(path string) (*mapData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("taxonomy map %s is not valid YAML: %s", path, err)
	}
	root := &doc
	if len(doc.Content) > 0 {
		root = doc.Content[0]
	}
	if isNullNode(root) {
		return &mapData{def: UNMAPPED}, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("taxonomy map %s must be a YAML mapping", path)
	}
	out, err := parseMapMapping(path, root)
	if err != nil {
		return nil, err
	}
	if err := checkMapValue(path, "default", out.def); err != nil {
		return nil, err
	}
	for _, a := range out.aliases {
		where := fmt.Sprintf("aliases[%s]", validation.PyReprStr(a.key))
		if err := checkMapValue(path, where, a.target); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseMapMapping reads the default/aliases fields of a map mapping node and
// applies Python's type checks (both must be str, aliases a str -> str map).
func parseMapMapping(path string, root *yaml.Node) (*mapData, error) {
	typeErr := fmt.Errorf("taxonomy map %s: expected 'default' (str) and "+
		"'aliases' (mapping of str -> str)", path)
	out := &mapData{def: UNMAPPED}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "default":
			s, ok := strScalar(val)
			if !ok {
				return nil, typeErr
			}
			out.def = s
		case "aliases":
			if isFalsyNode(val) {
				continue
			}
			if val.Kind != yaml.MappingNode {
				return nil, typeErr
			}
			for j := 0; j+1 < len(val.Content); j += 2 {
				k, ok1 := strScalar(val.Content[j])
				v, ok2 := strScalar(val.Content[j+1])
				if !ok1 || !ok2 {
					return nil, typeErr
				}
				out.aliases = putAlias(out.aliases, k, v)
			}
		}
	}
	return out, nil
}

// putAlias is dict assignment: an existing raw key keeps its position and
// takes the new value, a new key appends.
func putAlias(aliases []mapAlias, key, target string) []mapAlias {
	for i := range aliases {
		if aliases[i].key == key {
			aliases[i].target = target
			return aliases
		}
	}
	return append(aliases, mapAlias{key: key, target: target})
}

// LoadMaps is load_maps: merge the common map with the per-dataset map files
// into one lookup — an ordered object {"default": str, "aliases": {label:
// target}}. Dataset-specific aliases WIN over common ones. A nil datasets
// slice is Python's None (load every per-dataset file present, sorted by name
// for determinism); an empty non-nil slice loads only the common map. A
// missing file is a normal miss, never an error.
func LoadMaps(datasets []string) (validation.Value, error) {
	common, err := readMapFile(filepath.Join(ConfigDir, CommonMapName))
	if err != nil {
		return validation.VNull(), err
	}
	var merged *mapData
	if common != nil {
		merged = common
	}
	var names []string
	if datasets == nil {
		matches, err := filepath.Glob(filepath.Join(ConfigDir, datasetMapGlob))
		if err != nil {
			return validation.VNull(), err
		}
		for _, m := range matches {
			base := filepath.Base(m)
			if base == CommonMapName {
				continue
			}
			stem := strings.TrimSuffix(base, filepath.Ext(base))
			names = append(names, strings.TrimPrefix(stem, "taxonomy_"))
		}
		sort.Strings(names)
	} else {
		names = append(names, datasets...)
	}
	for _, name := range names {
		data, err := readMapFile(filepath.Join(ConfigDir, "taxonomy_"+name+".yaml"))
		if err != nil {
			return validation.VNull(), err
		}
		if data == nil {
			continue
		}
		if merged == nil {
			// Python would raise KeyError('aliases') here (a dataset map
			// with no common map to merge into); the twin starts an empty
			// projection instead of crashing.
			merged = &mapData{def: UNMAPPED}
		}
		for _, a := range data.aliases {
			merged.aliases = putAlias(merged.aliases, a.key, a.target)
		}
		merged.def = data.def
	}
	if merged == nil {
		return validation.VObj(), nil
	}
	return mapValue(merged), nil
}

// mapValue renders a parsed map as the ordered object load_maps returns:
// {"default": str, "aliases": {label: target}} in file order.
func mapValue(m *mapData) validation.Value {
	pairs := make([]validation.KV, 0, len(m.aliases))
	for _, a := range m.aliases {
		pairs = append(pairs, kv(a.key, validation.VStr(a.target)))
	}
	return validation.VObj(
		kv("default", validation.VStr(m.def)),
		kv("aliases", validation.VObj(pairs...)),
	)
}

// NormalizeClass is normalize_class: map a raw dataset label to
// (canonical | "unmapped", mapped).
//
// Lookup is case/whitespace/punctuation-insensitive. An alias explicitly
// mapped to "unmapped" is a RECORDED DECISION (that dataset label is
// deliberately not one of ours), not a miss — but it is still not a canonical
// class, so mapped is false. A label that names a canonical class outright
// maps to itself even when no alias mentions it. Anything else falls back to
// the maps' default ("unmapped") with mapped=false — honesty over coverage.
//
// A nil label is Python's None; nil maps loads the configured map files.
func NormalizeClass(label *string, maps *validation.Value) (string, bool, error) {
	var m validation.Value
	if maps == nil {
		loaded, err := LoadMaps(nil)
		if err != nil {
			return "", false, err
		}
		m = loaded
	} else {
		m = *maps
	}
	def := validation.ObjStr(m, "default")
	if def == "" {
		def = UNMAPPED
	}
	if label == nil || validation.PyStrip(*label) == "" {
		return def, false, nil
	}
	norm := normLabel(*label)
	for _, a := range validation.ObjAt(m, "aliases").O {
		if normLabel(a.K) == norm {
			return a.V.S, a.V.S != UNMAPPED, nil
		}
	}
	for _, cls := range validation.SortedKeys(knownRaw()) {
		if normLabel(cls) == norm {
			return cls, true, nil
		}
	}
	return def, false, nil
}

// ValidateMapFile is validate_map_file: alias values (and default) must each
// be a canonical class or "unmapped". A bad map is a deployment error — fail
// loud, never silently degrade the adapters' class labels. A missing file
// yields *MissingMapError: you asked about a specific file, and LoadMaps
// treats absence as a miss.
func ValidateMapFile(path string) error {
	p := filepath.Clean(path)
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &MissingMapError{Path: p}
		}
		return err
	}
	_, err := readMapFile(p)
	return err
}

// ---- local helpers -------------------------------------------------------

// isNullNode reports whether a YAML node is the null document/valued node.
func isNullNode(n *yaml.Node) bool {
	if n == nil || n.Kind == 0 {
		return true
	}
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Tag == "")
}

// strScalar is Python's isinstance(value, str) on a YAML node.
func strScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", false
	}
	return n.Value, true
}

// isFalsyNode is Python truthiness on a YAML node, for `data.get("aliases")
// or {}`: null, false, zero, the empty string and empty collections all fall
// back to an empty mapping.
func isFalsyNode(n *yaml.Node) bool {
	if isNullNode(n) {
		return true
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!bool":
			return n.Value == "false"
		case "!!int":
			return n.Value == "0" || n.Value == "0x0" || n.Value == "0o0"
		case "!!float":
			return n.Value == "0" || n.Value == "0.0"
		case "!!str":
			return n.Value == ""
		}
		return false
	case yaml.SequenceNode, yaml.MappingNode:
		return len(n.Content) == 0
	}
	return false
}
