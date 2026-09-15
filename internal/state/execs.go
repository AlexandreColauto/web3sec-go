// execs.go: the audit's EXEC record glob (Task 13). Minimal reader-only
// port of webv2.sandbox.all_execs — the full sandbox module is a later
// phase; this reads exec records for the audit's execs section.
package state

import (
	"fmt"
	"sort"

	"websec/internal/validation"
)

// AllExecs is all_execs: the sorted reads of
// execs_dir/EXEC-*/exec_record.json.
//
// r44a: this is the ONE implementation of that law. sandbox.AllExecs — the
// r43a-fixed twin whose readers (relations, classify, execs, sequence,
// briefing) call it under that name — delegates here, because sandbox
// imports state and not the reverse; two functions with one name and
// OPPOSITE refusal semantics are a bug in themselves, and the audit's exec
// section reads THIS one.
//
// Absence is a fact: a campaign that has run nothing has no execs/ directory,
// and an empty list is the honest answer — ONLY os.IsNotExist is folded into
// emptiness (validation.ListSubPrefixedOptional, the r43 helper). A store
// that cannot be listed is a different thing: "zero execs" is a claim about a
// store, and a store that could not be read supports no claim, so EACCES,
// ENOTDIR and EIO refuse, naming the path and the errno. Before r44a this
// reader returned nil for EVERY ReadDir error, so `chmod 000 <c>/execs/`
// (or replacing execs/ with a regular file) made `audit` certify
// "execs=0 problem(s)" exit 0 on a store it never read.
//
// The listing is ReadDir + prefix filter, never filepath.Glob: a Glob treats
// the WHOLE path as a pattern, so a campaign root containing a glob
// metacharacter ([ ] ?) would silently match nothing (ListSubPrefixed is the
// one helper that owns that shape).
func AllExecs(c *Campaign) ([]validation.Value, error) {
	matches, err := validation.ListSubPrefixedOptional(c.ExecsDir, "EXEC-",
		"exec_record.json")
	if err != nil {
		return nil, fmt.Errorf("the exec store %s cannot be listed: %v",
			c.ExecsDir, err)
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
