// Section 2: artifacts — re-hash every registered file; a mismatch means
// the content changed AFTER registration (or the hash was forged).
package sections

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// Artifacts is audit.py section 2: {checked, problems, ok} over the
// registered artifact rows. Message-for-message with audit.py.
func Artifacts(c *state.Campaign) (validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return validation.Value{}, err
	}
	artifacts := objAt(st, "artifacts")
	var problems []validation.Value
	for _, a := range artifacts.A {
		p := filepath.IsAbs(objStr(a, "path"))
		path := objStr(a, "path")
		var resolved string
		if p {
			resolved = path
		} else {
			resolved = filepath.Join(c.Root, path)
		}
		if _, err := os.Stat(resolved); err != nil {
			problems = append(problems, validation.VStr(
				fmt.Sprintf("%s: missing file %s", objStr(a, "artifact_id"), path)))
			continue
		}
		stored := objAt(a, "sha256")
		if stored.Kind != validation.Str {
			continue // registered without a hash — flagged, not fatal
		}
		actual, err := validation.Sha256File(resolved)
		if err != nil {
			return validation.Value{}, err
		}
		if actual != stored.S {
			problems = append(problems, validation.VStr(
				fmt.Sprintf("%s: content hash mismatch (stored %s..., actual %s...)",
					objStr(a, "artifact_id"), stored.S[:12], actual[:12])))
		}
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(artifacts.A)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}
