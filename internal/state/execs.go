// execs.go: the audit's EXEC record glob (Task 13). Minimal reader-only
// port of webv2.sandbox.all_execs — the full sandbox module is a later
// phase; this reads exec records for the audit's execs section.
package state

import (
	"os"
	"path/filepath"
	"sort"

	"websec/internal/validation"
)

// AllExecs is sandbox.all_execs: the sorted reads of
// execs_dir/EXEC-*/exec_record.json ([] when the dir is absent).
func AllExecs(c *Campaign) ([]validation.Value, error) {
	if _, err := os.Stat(c.ExecsDir); err != nil {
		return nil, nil
	}
	matches, _ := filepath.Glob(filepath.Join(c.ExecsDir, "EXEC-*", "exec_record.json"))
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
