// Section 4: findings — every finding file must still conform to the
// schema. A file that is not valid JSON propagates (only a SchemaError is
// caught), exactly like Python's audit.py (read_json raises uncaught there).
package sections

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// findingFiles is Python's fdir.glob("F-*.json"): sorted finding file
// paths ([] when the dir is missing). Shared by sections 4 and 5.
func findingFiles(c *state.Campaign) []string {
	if _, err := os.Stat(c.FindingsDir); err != nil {
		return nil
	}
	matches := validation.ListPrefixed(c.FindingsDir, "F-", ".json")
	sort.Strings(matches)
	return matches
}

// Findings is audit.py section 4: {checked, problems, ok}.
func Findings(c *state.Campaign) (validation.Value, error) {
	files := findingFiles(c)
	var problems []validation.Value
	for _, p := range files {
		v, err := validation.ReadJson(p)
		if err != nil {
			// Python: read_json raises uncaught (only SchemaError caught).
			return validation.Value{}, err
		}
		if err := validation.Validate(v, "finding", 1); err != nil {
			var se *validation.SchemaError
			if errors.As(err, &se) {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: %s", filepath.Base(p), se.Msg)))
				continue
			}
			return validation.Value{}, err
		}
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(files)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}
