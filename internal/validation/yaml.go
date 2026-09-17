// yaml.go: the YAML → Value bridge. Python loads repo-level data (playbooks,
// archetypes, taxonomy maps) with yaml.safe_load and validates the resulting
// dict against a JSON schema; this is the same conversion, preserving the
// file's key order (write_json dumps insertion order, so the order matters)
// and Python's scalar typing (str / int / float / bool / None).
package validation

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseYaml is yaml.safe_load into an ordered Value. A YAML error is
// returned as-is (the caller decides how to phrase it, exactly like the
// Python callers wrap yaml.YAMLError).
func ParseYaml(raw []byte) (Value, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return VNull(), err
	}
	root := &doc
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return VNull(), nil
		}
		root = doc.Content[0]
	}
	return yamlNodeValue(root)
}

func yamlNodeValue(n *yaml.Node) (Value, error) {
	if n == nil {
		return VNull(), nil
	}
	switch n.Kind {
	case yaml.AliasNode:
		return yamlNodeValue(n.Alias)
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return VNull(), nil
		}
		return yamlNodeValue(n.Content[0])
	case yaml.SequenceNode:
		out := make([]Value, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlNodeValue(c)
			if err != nil {
				return VNull(), err
			}
			out = append(out, v)
		}
		return VArr(out...), nil
	case yaml.MappingNode:
		out := make([]KV, 0, len(n.Content)/2)
		// A repeated key inside ONE mapping is a Python/Go read disagreement
		// (safe_load keeps the last, the ordered Value kept both), so refuse
		// it. The guard is per mapping: the same key in a sibling, a sequence
		// item or an aliased mapping is still fine.
		seen := make(map[string]struct{}, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := yamlNodeValue(n.Content[i])
			if err != nil {
				return VNull(), err
			}
			key := yamlKeyText(k)
			if _, dup := seen[key]; dup {
				return VNull(), fmt.Errorf("yaml: duplicate mapping key %q", key)
			}
			seen[key] = struct{}{}
			v, err := yamlNodeValue(n.Content[i+1])
			if err != nil {
				return VNull(), err
			}
			out = append(out, KV{K: key, V: v})
		}
		return VObj(out...), nil
	case yaml.ScalarNode:
		return yamlScalarValue(n)
	}
	return VNull(), nil
}

// yamlKeyText renders a mapping key: Python keeps the loaded object as the
// key (a str for every schema we read), and a non-str key still has to key
// the Go map, so it renders through its JSON spelling.
func yamlKeyText(k Value) string {
	if k.Kind == Str {
		return k.S
	}
	if k.Kind == Null {
		return "None"
	}
	return DumpsOrdered(k, false)
}

// yamlScalarValue maps a scalar node's resolved tag onto Python's types.
func yamlScalarValue(n *yaml.Node) (Value, error) {
	switch n.Tag {
	case "!!null", "":
		return VNull(), nil
	case "!!bool":
		return VBool(strings.EqualFold(n.Value, "true")), nil
	case "!!int":
		return yamlIntValue(n.Value)
	case "!!float":
		return yamlFloatValue(n.Value), nil
	default:
		return VStr(n.Value), nil
	}
}

// yamlIntValue parses a !!int scalar the way PyYAML does (decimal, 0x, 0o,
// underscores). Anything that does not fit an int64 keeps its exact digits as
// a big integer, never a lossy float.
func yamlIntValue(text string) (Value, error) {
	clean := strings.ReplaceAll(text, "_", "")
	if i, err := strconv.ParseInt(clean, 0, 64); err == nil {
		return VInt(i), nil
	}
	if u, err := strconv.ParseUint(clean, 0, 64); err == nil {
		return VBigInt(strconv.FormatUint(u, 10)), nil
	}
	return VBigInt(clean), nil
}

// yamlFloatValue parses a !!float scalar, including the YAML infinities and
// NaN that strconv.ParseFloat does not spell the same way.
func yamlFloatValue(text string) Value {
	clean := strings.ReplaceAll(text, "_", "")
	switch clean {
	case ".inf", ".Inf", ".INF", "+.inf":
		return VFloat(math.Inf(1))
	case "-.inf", "-.Inf", "-.INF":
		return VFloat(math.Inf(-1))
	case ".nan", ".NaN", ".NAN":
		return VFloat(math.NaN())
	}
	f, err := strconv.ParseFloat(clean, 64)
	if err != nil {
		return VFloat(0)
	}
	return VFloat(f)
}

// ParseYamlFileError phrases a YAML failure the way the Python loaders do:
// "<what> is not valid YAML: <detail>".
func ParseYamlFileError(what string, err error) error {
	return fmt.Errorf("%s is not valid YAML: %s", what, err)
}
