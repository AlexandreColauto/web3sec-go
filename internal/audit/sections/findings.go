// Section 4: findings — every finding file must still conform to the
// schema. A file that is not valid JSON propagates (only a SchemaError is
// caught), exactly like Python's audit.py (read_json raises uncaught there).
package sections

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// findingFiles is Python's fdir.glob("F-*.json"): sorted finding file paths.
// Shared by sections 4, 5 and the projection. r43a: a missing findings/
// directory is a campaign with no findings ([] — a fresh campaign still
// audits green), but a findings/ directory that cannot be listed is a
// refusal: reporting "checked: 0" for a store the audit could not read is
// exactly the pass that let an unreadable evidence store certify clean.
func findingFiles(c *state.Campaign) ([]string, error) {
	matches, err := validation.ListPrefixedOptional(c.FindingsDir, "F-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the findings store %s cannot be listed: %v",
			c.FindingsDir, err)
	}
	sort.Strings(matches)
	return matches, nil
}

// Findings is audit.py section 4: {checked, problems, ok}.
func Findings(c *state.Campaign) (validation.Value, error) {
	files, err := findingFiles(c)
	if err != nil {
		return validation.Value{}, err
	}
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
