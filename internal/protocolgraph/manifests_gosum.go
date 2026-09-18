package protocolgraph

import (
	"strings"
)

// ---- go.sum ---------------------------------------------------------------

// parseGoSum reads go.sum's `<module> <version> <hash>` lines. Each module
// appears twice (the module hash and the go.mod hash of the same
// module@version); the /go.mod mirror lines are folded into their entry
// rather than emitted twice, which is a format rule, not a silent skip.
func parseGoSum(name string, lines []string) ([]depEntry, error) {
	out := []depEntry{}
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, manifestError(name, i+1,
				"malformed go.sum line (want '<module> <version> <hash>')")
		}
		if strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		if !strings.HasPrefix(fields[1], "v") {
			return nil, manifestError(name, i+1,
				"malformed go.sum version %q", fields[1])
		}
		out = append(out, depEntry{pkg: fields[0], ver: fields[1], pin: line})
	}
	return out, nil
}
