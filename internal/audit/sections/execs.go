// Section 3: exec records — schema-valid, and stdout/stderr files match
// the hashes recorded at execution time.
package sections

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// Execs is audit.py section 3: {checked, problems, ok} over all_execs.
// Each record validates against "sandbox_execution"; a valid record's
// artifact_hashes are re-checked against the output files on disk. r13
// adds the ledger->disk direction: exec events whose record was deleted
// are a problem (documented divergence from the ported section, same law
// as the projection check's un-gating).
func Execs(c *state.Campaign) (validation.Value, error) {
	execs, err := state.AllExecs(c)
	if err != nil {
		return validation.Value{}, err
	}
	var problems []validation.Value
	for _, rec := range execs {
		eid := getStrOr(rec, "exec_id", "?")
		if err := validation.Validate(rec, "sandbox_execution", 1); err != nil {
			var se *validation.SchemaError
			if errors.As(err, &se) {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: %s", eid, se.Msg)))
				continue
			}
			// A non-schema error (schema missing, etc.) propagates.
			return validation.Value{}, err
		}
		if eid == "?" {
			eid = ""
		}
		hashes := objAt(rec, "artifact_hashes")
		if hashes.Kind != validation.Obj {
			continue
		}
		for _, h := range hashes.O {
			name := h.K
			stored := h.V.S
			p := filepath.Join(c.ExecsDir, eid, name)
			if _, err := os.Stat(p); err != nil {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: missing output file %s", eid, name)))
				continue
			}
			actual, err := validation.Sha256File(p)
			if err != nil {
				return validation.Value{}, err
			}
			if actual != stored {
				problems = append(problems, validation.VStr(
					fmt.Sprintf("%s: %s hash mismatch after execution", eid, name)))
			}
		}
	}
	// r13: the mirror direction the projection law demands for execs —
	// the ledger CLAIMS an execution happened (sandbox.exec.registered
	// names the EXEC id); deleting execs/EXEC-*/ wholesale left the
	// events asserting a run whose record is gone, and the audit stayed
	// green because section 3 iterated only surviving records. An event
	// without its record is now a problem. (Records without events stay
	// lenient — legacy campaigns predate the event, same rule as
	// projection's state->log direction.)
	if evts, err := c.Events(); err == nil {
		seen := map[string]bool{}
		for _, rec := range execs {
			seen[objStr(rec, "exec_id")] = true
		}
		for _, e := range evts {
			typ := objStr(e, "type")
			if typ != "sandbox.exec.registered" && typ != "sandbox.exec" {
				continue
			}
			eid := objStr(e, "ref")
			if eid == "" || seen[eid] {
				continue
			}
			problems = append(problems, validation.VStr(
				fmt.Sprintf("%s: the ledger records exec %s but no "+
					"exec record survives on disk — delete the events "+
					"only through a sanctioned verb, never the store",
					typ, eid)))
		}
	} else if !os.IsNotExist(err) {
		return validation.Value{}, err
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(execs)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// getStrOr renders a key the way Python's f"{d.get(k, dflt)}" would: the
// raw value's str() when present (None->"None", int->decimal, ...), the
// dflt only when the key is absent.
func getStrOr(v validation.Value, key, dflt string) string {
	for _, kv := range v.O {
		if kv.K == key {
			switch kv.V.Kind {
			case validation.Str:
				return kv.V.S
			case validation.Null:
				return "None"
			case validation.Bool:
				if kv.V.B {
					return "True"
				}
				return "False"
			case validation.Int:
				return validation.IntText(kv.V)
			case validation.Flt:
				return validation.PythonFloat(kv.V.F)
			default:
				return validation.PyRepr(kv.V)
			}
		}
	}
	return dflt
}
