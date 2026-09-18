// exec_query.go: reading exec records back out of the ledger (load_exec,
// all_execs).
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"websec/internal/state"
	"websec/internal/validation"
)

// LoadExec is load_exec: the stored exec record, or the FileNotFoundError
// text Python's read_json raises (cmd_mint's generic handler prints it).
func LoadExec(c *state.Campaign, execID string) (validation.Value, error) {
	path := filepath.Join(c.ExecsDir, execID, "exec_record.json")
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Errorf(
			"[Errno 2] No such file or directory: %s",
			validation.PyReprStr(path))
	}
	return validation.ReadJson(path)
}

// AllExecs is all_execs: every EXEC record, sorted by path.
//
// r44a: ONE implementation per law. The body moved to state.AllExecs and this
// is a thin alias. r43a fixed the refusal on THIS side while the state twin —
// the one the audit's exec section reads — still returned an empty list for
// any error: two functions with one name and OPPOSITE refusal semantics are a
// bug in themselves, and `chmod 000 <c>/execs/` certified `audit PASS
// execs=0` through the state reader. sandbox imports state (never the
// reverse), so the canonical reader lives on the state side; the r43a
// contract is unchanged — absent store is empty, unlistable store refuses
// naming the path and the errno.
func AllExecs(c *state.Campaign) ([]validation.Value, error) {
	return state.AllExecs(c)
}
