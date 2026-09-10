// execs.go: the audit's EXEC record glob (Task 13). Minimal reader-only
// port of webv2.sandbox.all_execs — the full sandbox module is a later
// phase; this reads exec records for the audit's execs section.
package state

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/validation"
)

// AllExecs is sandbox.all_execs: the sorted reads of
// execs_dir/EXEC-*/exec_record.json ([] when the dir is absent).
func AllExecs(c *Campaign) ([]validation.Value, error) {
	entries, err := os.ReadDir(c.ExecsDir)
	if err != nil {
		return nil, nil // dir absent
	}
	// ReadDir + prefix filter instead of filepath.Glob: a Glob treats the
	// WHOLE path as a pattern, so a campaign root containing a glob
	// metacharacter ([ ] ?) would silently match nothing.
	var matches []string
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "EXEC-") {
			continue
		}
		rec := filepath.Join(c.ExecsDir, e.Name(), "exec_record.json")
		if _, err := os.Stat(rec); err == nil {
			matches = append(matches, rec)
		}
	}
	sort.Strings(matches)
	out := make([]validation.Value, 0, len(matches))
	for _, p := range matches {
		v, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
