package protocolgraph

import (
	"regexp"
	"strings"
)

// ---- remappings.txt -------------------------------------------------------

// versionTagRe finds an @<version> tag inside a remapping target. The LAST
// match wins, so a scoped or nested target still yields its trailing tag.
var versionTagRe = regexp.MustCompile(`@([A-Za-z0-9][A-Za-z0-9._-]*)`)

// parseRemappings reads forge's remappings.txt: one dependency fact per
// non-empty, non-comment line. package is the remapping prefix (its trailing
// path separator is syntax, not part of the name), version is the target's
// @<version> tag when it carries one (else ""), and pin is the line verbatim.
func parseRemappings(name string, lines []string) ([]depEntry, error) {
	out := []depEntry{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, manifestError(name, i+1,
				"malformed remapping (no '=')")
		}
		left := strings.TrimSpace(line[:eq])
		right := strings.TrimSpace(line[eq+1:])
		if left == "" || right == "" {
			return nil, manifestError(name, i+1,
				"malformed remapping (empty prefix or target)")
		}
		out = append(out, depEntry{
			pkg: strings.TrimSuffix(left, "/"),
			ver: versionTag(right),
			pin: raw,
		})
	}
	return out, nil
}

// versionTag is the last @<version> tag in a remapping target, or "".
func versionTag(target string) string {
	m := versionTagRe.FindAllStringSubmatch(target, -1)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1][1]
}
