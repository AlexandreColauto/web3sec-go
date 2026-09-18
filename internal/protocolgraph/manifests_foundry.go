package protocolgraph

import (
	"encoding/json"
	"errors"
	"strings"

	"websec/internal/validation"
)

// ---- foundry.lock ---------------------------------------------------------

// parseFoundryJSON reads forge's foundry.lock: a JSON object keyed by the
// installed dependency path, each value carrying a `tag`/`branch` object
// (whose `name` is the pinned version) or a bare `rev`. A dependency path is
// the package name (its last path segment).
func parseFoundryJSON(name string, raw []byte) ([]depEntry, error) {
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, manifestError(name, jsonErrorLine(raw, err),
			"malformed foundry.lock (%s)", err)
	}
	if doc.Kind != validation.Obj {
		return nil, manifestError(name, 1,
			"malformed foundry.lock (want a JSON object)")
	}
	lines := manifestLines(raw)
	out := []depEntry{}
	for _, pair := range doc.O {
		ver := ""
		if tag := validation.ObjAt(pair.V, "tag"); tag.Kind == validation.Obj {
			ver = validation.ObjAt(tag, "name").S
		}
		if ver == "" {
			if br := validation.ObjAt(pair.V, "branch"); br.Kind == validation.Obj {
				ver = validation.ObjAt(br, "name").S
			}
		}
		if ver == "" {
			ver = validation.ObjAt(pair.V, "rev").S
		}
		line, ok := entryStartLine(lines, pair.K)
		if !ok {
			line = 1
		}
		if ver == "" {
			return nil, manifestError(name, line,
				"foundry.lock entry %q has no tag, branch or rev", pair.K)
		}
		out = append(out, depEntry{pkg: pathBase(pair.K), ver: ver,
			pin: rawEntryText(lines, line)})
	}
	return out, nil
}

// pathBase is the last path segment of a dependency path (the package name).
func pathBase(p string) string {
	t := strings.TrimSuffix(p, "/")
	if s := strings.LastIndex(t, "/"); s >= 0 {
		return t[s+1:]
	}
	return t
}

// entryStartLine finds the line that opens entry key's object, so a
// malformed entry can be reported with a line and its text captured.
func entryStartLine(lines []string, key string) (int, bool) {
	needle := `"` + key + `"`
	for i, raw := range lines {
		if strings.HasPrefix(strings.TrimSpace(raw), needle) {
			return i, true
		}
	}
	return 0, false
}

// rawEntryText is the verbatim text of the JSON entry opening at start: from
// its key line through the line that closes its braces.
func rawEntryText(lines []string, start int) string {
	depth := 0
	opened := false
	for i := start; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{")
		depth -= strings.Count(lines[i], "}")
		if strings.Contains(lines[i], "{") {
			opened = true
		}
		if opened && depth <= 0 {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// jsonErrorLine maps an encoding/json syntax error offset onto a 1-based
// line number (the readers report file+line, like every other entry error).
func jsonErrorLine(raw []byte, err error) int {
	var se *json.SyntaxError
	if errors.As(err, &se) && se.Offset > 0 {
		off := int(se.Offset)
		if off > len(raw) {
			off = len(raw)
		}
		return 1 + strings.Count(string(raw[:off]), "\n")
	}
	return 1
}
